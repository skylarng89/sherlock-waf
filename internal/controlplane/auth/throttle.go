package auth

import (
	"sync"
	"time"
)

// ipLimiter is a sliding-window limiter keyed by client address: at most
// limit attempts per window. State is in memory and bounded; at the cap the
// oldest idle keys are dropped, which only ever loosens the limit for a
// long-quiet client.
type ipLimiter struct {
	limit  int
	window time.Duration
	maxKey int
	now    func() time.Time

	mu   sync.Mutex
	hits map[string][]time.Time
}

func newIPLimiter(limit int, window time.Duration, now func() time.Time) *ipLimiter {
	return &ipLimiter{limit: limit, window: window, maxKey: 10_000, now: now, hits: map[string][]time.Time{}}
}

// allow records an attempt for key and reports whether it is within the limit;
// when it is not, retryAfter says how long until a slot frees.
func (l *ipLimiter) allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.window)
	h := l.hits[key]
	for len(h) > 0 && !h[0].After(cutoff) {
		h = h[1:]
	}
	if len(h) >= l.limit {
		l.hits[key] = h
		return false, h[0].Add(l.window).Sub(now)
	}
	if _, exists := l.hits[key]; !exists && len(l.hits) >= l.maxKey {
		l.evictLocked(cutoff)
	}
	l.hits[key] = append(h, now)
	return true, 0
}

// peek reports whether key is already at its limit, without counting anything.
// It lets a caller refuse work before doing it and count only the failures.
func (l *ipLimiter) peek(key string) (blocked bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.window)
	h := l.hits[key]
	for len(h) > 0 && !h[0].After(cutoff) {
		h = h[1:]
	}
	l.hits[key] = h
	if len(h) >= l.limit {
		return true, h[0].Add(l.window).Sub(now)
	}
	return false, 0
}

// coalescer counts events per key and says when a summary row is due: the
// first event of a key, then the first one after each window. The count it
// returns is the events since the previous due row, so a flood yields one row
// per window instead of one per request.
type coalescer struct {
	window time.Duration
	maxKey int
	now    func() time.Time

	mu     sync.Mutex
	counts map[string]*coalesced
}

type coalesced struct {
	last  time.Time
	count int
}

func newCoalescer(window time.Duration, maxKey int, now func() time.Time) *coalescer {
	return &coalescer{window: window, maxKey: maxKey, now: now, counts: map[string]*coalesced{}}
}

// note counts one event for key and reports the count to write, if one is due.
func (c *coalescer) note(key string) (count int, due bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	e := c.counts[key]
	if e == nil {
		if len(c.counts) >= c.maxKey {
			c.pruneLocked(now)
		}
		e = &coalesced{}
		c.counts[key] = e
	}
	e.count++
	if !e.last.IsZero() && now.Sub(e.last) < c.window {
		return 0, false
	}
	count, e.count, e.last = e.count, 0, now
	return count, true
}

// pruneLocked forgets idle keys. Under a flood of distinct addresses it may
// forget a key that still had a pending count, which only under-reports it.
func (c *coalescer) pruneLocked(now time.Time) {
	for k, e := range c.counts {
		if now.Sub(e.last) >= c.window {
			delete(c.counts, k)
		}
	}
	for k := range c.counts {
		if len(c.counts) < c.maxKey {
			break
		}
		delete(c.counts, k)
	}
}

func (l *ipLimiter) evictLocked(cutoff time.Time) {
	for k, h := range l.hits {
		if len(h) == 0 || !h[len(h)-1].After(cutoff) {
			delete(l.hits, k)
		}
	}
	// Still full of active keys: refuse to grow without bound by dropping arbitrary entries.
	for k := range l.hits {
		if len(l.hits) < l.maxKey {
			break
		}
		delete(l.hits, k)
	}
}

// lockoutFor is the lock duration after the nth consecutive failure: nothing
// for the first four, then 1, 2, 4, 8 minutes, capped at 15.
func lockoutFor(failures int) time.Duration {
	const free = 4
	if failures <= free {
		return 0
	}
	d := time.Minute << (failures - free - 1)
	if failures-free-1 > 4 || d > 15*time.Minute {
		return 15 * time.Minute
	}
	return d
}
