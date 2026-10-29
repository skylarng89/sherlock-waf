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
