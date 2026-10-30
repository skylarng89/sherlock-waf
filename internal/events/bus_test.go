package events

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ev(i int) *Event { return &Event{ID: strconv.Itoa(i)} }

func ids(evs []*Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.ID
	}
	return out
}

func TestPublishWithoutSubscriberDropsOldest(t *testing.T) {
	b := NewBus(4)
	for i := range 10 {
		b.Publish(ev(i))
	}
	assert.EqualValues(t, 10, b.Published())
	assert.EqualValues(t, 6, b.Dropped(), "10 published into a ring of 4 with nobody reading loses 6")
	assert.Equal(t, 4, b.Len())

	s := b.Subscribe(true)
	defer s.Close()
	buf := make([]*Event, 10)
	n := s.Read(buf)
	assert.Equal(t, []string{"6", "7", "8", "9"}, ids(buf[:n]), "the newest events survive")
}

func TestKeepingSubscriberLosesNothing(t *testing.T) {
	b := NewBus(4)
	s := b.Subscribe(false)
	defer s.Close()
	buf := make([]*Event, 4)
	var got []string
	for i := range 100 {
		b.Publish(ev(i))
		n := s.Read(buf)
		got = append(got, ids(buf[:n])...)
	}
	assert.Len(t, got, 100)
	assert.Zero(t, b.Dropped())
	assert.Zero(t, s.Lagged())
}

func TestSlowSubscriberLagsWithoutAffectingOthers(t *testing.T) {
	b := NewBus(4)
	fast, slow := b.Subscribe(false), b.Subscribe(false)
	defer fast.Close()
	defer slow.Close()
	buf := make([]*Event, 16)
	var fastGot int
	for i := range 20 {
		b.Publish(ev(i))
		fastGot += fast.Read(buf)
	}
	assert.Equal(t, 20, fastGot)
	assert.Zero(t, fast.Lagged())

	n := slow.Read(buf)
	assert.Equal(t, []string{"16", "17", "18", "19"}, ids(buf[:n]))
	assert.EqualValues(t, 16, slow.Lagged())
	assert.EqualValues(t, 16, b.Dropped(), "dropped counts events lost to the slowest consumer")
}

func TestSubscribeLiveSeesOnlyNewEvents(t *testing.T) {
	b := NewBus(8)
	b.Publish(ev(0))
	s := b.Subscribe(false)
	defer s.Close()
	buf := make([]*Event, 8)
	assert.Zero(t, s.Read(buf))
	b.Publish(ev(1))
	n := s.Read(buf)
	assert.Equal(t, []string{"1"}, ids(buf[:n]))
}

func TestWaitWakesOnPublishCloseAndContext(t *testing.T) {
	b := NewBus(8)
	s := b.Subscribe(false)

	done := make(chan bool, 1)
	go func() { done <- s.Wait(t.Context()) }()
	time.Sleep(20 * time.Millisecond)
	b.Publish(ev(1))
	select {
	case ok := <-done:
		assert.True(t, ok)
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not wake on publish")
	}
	buf := make([]*Event, 1)
	require.Equal(t, 1, s.Read(buf))

	go func() { done <- s.Wait(t.Context()) }()
	time.Sleep(20 * time.Millisecond)
	s.Close()
	select {
	case ok := <-done:
		assert.False(t, ok, "closed and drained")
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not wake on close")
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	assert.False(t, b.Subscribe(false).Wait(ctx))
}

func TestReadMoreThanBuffer(t *testing.T) {
	b := NewBus(16)
	s := b.Subscribe(false)
	defer s.Close()
	for i := range 10 {
		b.Publish(ev(i))
	}
	buf := make([]*Event, 4)
	var total int
	for s.Wait(t.Context()) {
		n := s.Read(buf)
		total += n
		if total == 10 {
			break
		}
	}
	assert.Equal(t, 10, total)
}

func TestConcurrentPublishAndRead(t *testing.T) {
	b := NewBus(64)
	s := b.Subscribe(false)
	var wg sync.WaitGroup
	const producers, each = 8, 2000
	for range producers {
		wg.Go(func() {
			for i := range each {
				b.Publish(ev(i))
			}
		})
	}
	var read atomic.Int64
	stop := make(chan struct{})
	go func() {
		buf := make([]*Event, 32)
		for {
			select {
			case <-stop:
				return
			default:
				read.Add(int64(s.Read(buf)))
			}
		}
	}()
	wg.Wait()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	s.Close()
	assert.EqualValues(t, producers*each, b.Published())
	assert.LessOrEqual(t, b.Dropped(), b.Published())
	assert.Positive(t, read.Load(), "the reader must have consumed events")
}

func TestNilAndMinimumCapacity(t *testing.T) {
	var nilBus *Bus
	nilBus.Publish(ev(1)) // must not panic
	b := NewBus(0)
	b.Publish(nil)
	b.Publish(ev(1))
	b.Publish(ev(2))
	assert.Equal(t, 1, b.Len())
	assert.EqualValues(t, 1, b.Dropped())
}

// TestMillionEventsNoSubscriber is AC5: a tight publish loop with nobody
// reading never blocks, and the drop counter is exact.
func TestMillionEventsNoSubscriber(t *testing.T) {
	const n = 1_000_000
	b := NewBus(DefaultBusCapacity)
	e := ev(0)
	start := time.Now()
	for range n {
		b.Publish(e)
	}
	assert.Less(t, time.Since(start), 10*time.Second, "publishing must not stall")
	assert.EqualValues(t, n, b.Published())
	assert.EqualValues(t, n-DefaultBusCapacity, b.Dropped())
	assert.Equal(t, DefaultBusCapacity, b.Len())
}
