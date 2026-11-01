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

// LoginPolicy tunes login throttling and account locking. The defaults suit a
// node reachable from the internet; operators behind a VPN or an SSO gateway
// may relax them, and a known administrator who is being locked out by a
// remote guesser (ASVS S-07) can raise the lock threshold or turn locking off
// and rely on the rate limits alone.
type LoginPolicy struct {
	// IPAttempts is the attempts per minute allowed from one client address,
	// and from one (address, username) pair.
	IPAttempts int
	// UsernameAttempts is the attempts per minute allowed against one
	// username from all clients together.
	UsernameAttempts int
	// LockAfter is the number of consecutive failures tolerated before the
	// account locks; zero turns account locking off.
	LockAfter int
	// LockMax caps the lock duration, which doubles from one minute.
	LockMax time.Duration
}

// DefaultLoginPolicy is used when nothing is configured.
var DefaultLoginPolicy = LoginPolicy{IPAttempts: 5, UsernameAttempts: 20, LockAfter: 4, LockMax: 15 * time.Minute}

// withDefaults fills zero fields, except LockAfter where zero is meaningful.
func (p LoginPolicy) withDefaults() LoginPolicy {
	if p.IPAttempts < 1 {
		p.IPAttempts = DefaultLoginPolicy.IPAttempts
	}
	if p.UsernameAttempts < 1 {
		p.UsernameAttempts = DefaultLoginPolicy.UsernameAttempts
	}
	if p.LockMax < time.Minute {
		p.LockMax = DefaultLoginPolicy.LockMax
	}
	return p
}

// lockoutFor is the lock duration after the nth consecutive failure: nothing
// up to LockAfter, then 1, 2, 4, 8 minutes, capped at LockMax.
func (p LoginPolicy) lockoutFor(failures int) time.Duration {
	if p.LockAfter < 1 || failures <= p.LockAfter {
		return 0
	}
	shift := failures - p.LockAfter - 1
	if shift > 10 {
		return p.LockMax
	}
	return min(time.Minute<<shift, p.LockMax)
}
