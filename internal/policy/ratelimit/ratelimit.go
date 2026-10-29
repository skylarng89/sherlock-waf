// Package ratelimit implements a sliding-window rate limiter for the request
// path: a two-bucket approximation (the previous window's count, weighted by
// how much of it still overlaps, plus the current window's), sharded to keep
// lock contention low, with a hard memory cap enforced by LRU eviction.
//
// The approximation never undercounts a burst by more than one window's worth
// of weighting and uses O(1) memory per key, which is why it is preferred to
// storing timestamps.
package ratelimit

import (
	"container/list"
	"context"
	"hash/fnv"
	"sync"
	"time"
)

// Result is the outcome of one Allow call.
type Result struct {
	Allowed    bool
	Remaining  int           // requests left in the window (0 when denied)
	RetryAfter time.Duration // zero when allowed
}

// Backend decides rate-limit questions. The in-process Limiter is the default;
// the interface is the seam for a shared store (a future extension point), so
// callers pass the rule in each call rather than binding it at construction.
type Backend interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (Result, error)
}

const shardCount = 64

type entry struct {
	key    string
	window time.Duration
	idx    int64 // window number of cur
	cur    int
	prev   int
	elem   *list.Element
}

type shard struct {
	mu  sync.Mutex
	m   map[string]*entry
	lru *list.List // front = most recently used
}

// Limiter is an in-process Backend. The zero value is not usable; use New.
type Limiter struct {
	shards [shardCount]shard
	perCap int
	now    func() time.Time
}

// New returns a Limiter holding at most maxKeys keys in total. When full, the
// least recently used key of the shard is dropped, which can only make the
// limiter more lenient to a client that was idle, never stricter.
func New(maxKeys int) *Limiter { return newWithClock(maxKeys, time.Now) }

func newWithClock(maxKeys int, now func() time.Time) *Limiter {
	if maxKeys < shardCount {
		maxKeys = shardCount
	}
	l := &Limiter{perCap: maxKeys / shardCount, now: now}
	for i := range l.shards {
		l.shards[i] = shard{m: map[string]*entry{}, lru: list.New()}
	}
	return l
}

// Allow implements Backend.
func (l *Limiter) Allow(_ context.Context, key string, limit int, window time.Duration) (Result, error) {
	return l.AllowAt(key, limit, window, l.now()), nil
}

// AllowAt counts one request for key at now. It is exported so callers that
// already hold a timestamp avoid a second clock read.
func (l *Limiter) AllowAt(key string, limit int, window time.Duration, now time.Time) Result {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	sh := &l.shards[h.Sum32()%shardCount]

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
	if e.window != window { // the rule changed under this key: start clean
		*e = entry{key: key, window: window, elem: e.elem}
	}

	w := int64(window)
	idx := now.UnixNano() / w
	switch idx {
	case e.idx:
	case e.idx + 1:
		e.prev, e.cur, e.idx = e.cur, 0, idx
	default:
		e.prev, e.cur, e.idx = 0, 0, idx
	}
	elapsed := float64(now.UnixNano()-idx*w) / float64(w) // 0..1 into the current window
	estimate := float64(e.prev)*(1-elapsed) + float64(e.cur)

	if estimate+1 > float64(limit) {
		return Result{Allowed: false, RetryAfter: retryAfter(e, limit, window, elapsed)}
	}
	e.cur++
	return Result{Allowed: true, Remaining: max(int(float64(limit)-estimate-1), 0)}
}

// retryAfter is when the estimate falls far enough for one more request.
func retryAfter(e *entry, limit int, window time.Duration, elapsed float64) time.Duration {
	w := float64(window)
	// Inside the current window the estimate is prev*(1-f)+cur; one more request
	// fits when prev*(1-f)+cur+1 <= limit.
	if e.cur+1 <= limit {
		if e.prev == 0 {
			return time.Millisecond // unreachable in practice: it would have been allowed
		}
		if f := 1 - float64(limit-e.cur-1)/float64(e.prev); f <= 1 {
			return max(time.Duration((f-elapsed)*w), time.Millisecond)
		}
	}
	// Otherwise wait for the boundary, where cur becomes prev and decays from there.
	toBoundary := (1 - elapsed) * w
	f := max(1-float64(limit-1)/float64(e.cur), 0)
	return max(time.Duration(toBoundary+f*w), time.Millisecond)
}

// Len is the number of tracked keys (for metrics and tests).
func (l *Limiter) Len() int {
	n := 0
	for i := range l.shards {
		l.shards[i].mu.Lock()
		n += len(l.shards[i].m)
		l.shards[i].mu.Unlock()
	}
	return n
}
