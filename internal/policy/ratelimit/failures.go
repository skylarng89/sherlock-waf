package ratelimit

import "time"

// AddAt counts one event for key unconditionally and returns the window
// estimate including it. AllowAt stops counting once a key is at its limit,
// which is right for requests but wrong for failures, where the count itself is
// the evidence (login protection records failures after the response and asks
// separately whether a key is over its threshold).
func (l *Limiter) AddAt(key string, window time.Duration, now time.Time) float64 {
	sh := l.shardOf(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := sh.m[key]
	if e == nil {
		e = &entry{key: key, window: window}
		e.elem = sh.lru.PushFront(e)
		sh.m[key] = e
		if sh.lru.Len() > l.perCap {
			oldest := sh.lru.Back()
			sh.lru.Remove(oldest)
			delete(sh.m, oldest.Value.(*entry).key) //nolint:forcetypeassert // the list only holds *entry
		}
	} else {
		sh.lru.MoveToFront(e.elem)
	}
	if e.window != window {
		*e = entry{key: key, window: window, elem: e.elem}
	}
	elapsed := roll(e, window, now)
	e.cur++
	return float64(e.prev)*(1-elapsed) + float64(e.cur)
}

// EstimateAt returns the window estimate for key without counting anything and
// without creating or refreshing the key, so asking about a stranger costs no
// memory.
func (l *Limiter) EstimateAt(key string, window time.Duration, now time.Time) float64 {
	sh := l.shardOf(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := sh.m[key]
	if e == nil || e.window != window {
		return 0
	}
	elapsed := roll(e, window, now)
	return float64(e.prev)*(1-elapsed) + float64(e.cur)
}

// roll advances e to the window containing now and returns how far into it now
// is (0..1). Callers hold the shard lock.
func roll(e *entry, window time.Duration, now time.Time) float64 {
	w := int64(window)
	idx := now.UnixNano() / w
	switch idx {
	case e.idx:
	case e.idx + 1:
		e.prev, e.cur, e.idx = e.cur, 0, idx
	default:
		e.prev, e.cur, e.idx = 0, 0, idx
	}
	return float64(now.UnixNano()-idx*w) / float64(w)
}

// shardOf maps a key to its shard with the same FNV-1a hash AllowAt uses, but
// without allocating.
func (l *Limiter) shardOf(key string) *shard {
	h := uint32(2166136261)
	for i := range len(key) {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &l.shards[h%shardCount]
}
