package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var t0 = time.Unix(1_800_000_000, 0).Truncate(time.Minute)

func TestTenPerMinuteThenBlocked(t *testing.T) {
	l := New(1024)
	for i := range 10 {
		r := l.AllowAt("ip1", 10, time.Minute, t0.Add(time.Duration(i)*time.Second))
		require.True(t, r.Allowed, "request %d", i+1)
		assert.Equal(t, 9-i, r.Remaining)
	}
	r := l.AllowAt("ip1", 10, time.Minute, t0.Add(30*time.Second))
	require.False(t, r.Allowed, "the 11th request inside the minute is refused")
	assert.Positive(t, r.RetryAfter)
	assert.LessOrEqual(t, r.RetryAfter, time.Minute)
	assert.Zero(t, r.Remaining)

	assert.True(t, l.AllowAt("ip2", 10, time.Minute, t0.Add(30*time.Second)).Allowed, "other keys are independent")
}

func TestWindowSlidesRatherThanResettingAtTheBoundary(t *testing.T) {
	l := New(1024)
	// Fill the last second of window 0.
	for range 10 {
		require.True(t, l.AllowAt("k", 10, time.Minute, t0.Add(59*time.Second)).Allowed)
	}
	// Just after the boundary the previous window still weighs almost fully.
	assert.False(t, l.AllowAt("k", 10, time.Minute, t0.Add(61*time.Second)).Allowed, "a burst at a boundary must not double the limit")
	// Half a window later about half of it has decayed.
	allowed := 0
	for range 10 {
		if l.AllowAt("k", 10, time.Minute, t0.Add(90*time.Second)).Allowed {
			allowed++
		}
	}
	assert.InDelta(t, 5, allowed, 1)
	// Two full windows later everything is forgotten.
	assert.Equal(t, 9, l.AllowAt("k", 10, time.Minute, t0.Add(3*time.Minute)).Remaining)
}

func TestRetryAfterIsHonest(t *testing.T) {
	l := New(1024)
	for range 10 {
		l.AllowAt("k", 10, time.Minute, t0.Add(10*time.Second))
	}
	denied := l.AllowAt("k", 10, time.Minute, t0.Add(20*time.Second))
	require.False(t, denied.Allowed)
	// Waiting the advertised time must be enough to succeed (and slightly less must not be).
	assert.True(t, l.AllowAt("k", 10, time.Minute, t0.Add(20*time.Second).Add(denied.RetryAfter+time.Second)).Allowed)

	l2 := New(1024)
	for range 10 {
		l2.AllowAt("k", 10, time.Minute, t0.Add(10*time.Second))
	}
	d2 := l2.AllowAt("k", 10, time.Minute, t0.Add(20*time.Second))
	require.False(t, d2.Allowed)
	assert.False(t, l2.AllowAt("k", 10, time.Minute, t0.Add(20*time.Second).Add(d2.RetryAfter/2)).Allowed)
}

func TestRuleChangeStartsFresh(t *testing.T) {
	l := New(1024)
	for range 5 {
		l.AllowAt("k", 5, time.Minute, t0)
	}
	require.False(t, l.AllowAt("k", 5, time.Minute, t0).Allowed)
	assert.True(t, l.AllowAt("k", 50, time.Second, t0).Allowed, "a different window means a different rule")
}

func TestMemoryIsCappedByLRUEviction(t *testing.T) {
	l := New(256) // 4 keys per shard
	for i := range 100_000 {
		l.AllowAt(fmt.Sprintf("ip-%d", i), 5, time.Minute, t0)
	}
	assert.LessOrEqual(t, l.Len(), 256, "an attacker rotating keys cannot grow memory")

	// A hot key survives while cold ones are evicted.
	l2 := New(256)
	for i := range 5000 {
		l2.AllowAt("hot", 1_000_000, time.Minute, t0)
		l2.AllowAt(fmt.Sprintf("cold-%d", i), 5, time.Minute, t0)
	}
	hot := l2.AllowAt("hot", 1_000_000, time.Minute, t0)
	assert.Less(t, hot.Remaining, 1_000_000-1000, "the hot key kept its count")
}

func TestConcurrentUseNeverExceedsTheLimit(t *testing.T) {
	l := New(1024)
	var wg sync.WaitGroup
	counts := make([]int, 16)
	for g := range 16 {
		wg.Go(func() {
			for range 100 {
				if l.AllowAt("shared", 50, time.Minute, t0).Allowed {
					counts[g]++
				}
			}
		})
	}
	wg.Wait()
	total := 0
	for _, c := range counts {
		total += c
	}
	assert.Equal(t, 50, total, "exactly the limit is admitted across goroutines")
}

func TestBackendInterface(t *testing.T) {
	var b Backend = New(64)
	r, err := b.Allow(context.Background(), "k", 1, time.Minute)
	require.NoError(t, err)
	assert.True(t, r.Allowed)
	r, err = b.Allow(context.Background(), "k", 1, time.Minute)
	require.NoError(t, err)
	assert.False(t, r.Allowed)
}

func BenchmarkAllow(b *testing.B) {
	l := New(1 << 20)
	keys := make([]string, 4096)
	for i := range keys {
		keys[i] = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			l.AllowAt(keys[i%len(keys)], 1_000_000, time.Minute, t0)
			i++
		}
	})
}
