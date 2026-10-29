package events

import (
	"context"
	"sync"
	"sync/atomic"
)

// DefaultBusCapacity is the ring size from ADR-0007.
const DefaultBusCapacity = 65536

// Bus is a bounded ring buffer shared by all subscribers (ADR-0007).
//
// Publish never blocks on consumers: it takes a short mutex, writes one slot
// and, when the ring is full, overwrites the oldest event. An overwritten
// event counts as dropped if any subscriber had not read it yet, or if there
// are no subscribers at all. Each subscriber has its own cursor, so a slow
// exporter loses its own backlog without affecting anyone else.
type Bus struct {
	mu   sync.Mutex
	ring []*Event // slot i holds sequence number s where s%len(ring) == i
	next uint64   // sequence number of the next event to publish
	subs map[*Subscription]struct{}

	published atomic.Uint64
	dropped   atomic.Uint64
}

// NewBus returns a bus holding at most capacity events (minimum 1).
func NewBus(capacity int) *Bus {
	if capacity < 1 {
		capacity = 1
	}
	return &Bus{ring: make([]*Event, capacity), subs: map[*Subscription]struct{}{}}
}

// Publish stores ev and wakes subscribers. It never blocks on a consumer.
// The bus takes ownership: callers and subscribers must not mutate ev.
func (b *Bus) Publish(ev *Event) {
	if b == nil || ev == nil {
		return
	}
	b.mu.Lock()
	seq := b.next
	if seq >= uint64(len(b.ring)) {
		overwritten := seq - uint64(len(b.ring))
		if b.unreadLocked(overwritten) {
			b.dropped.Add(1)
		}
	}
	b.ring[seq%uint64(len(b.ring))] = ev
	b.next++
	for s := range b.subs {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	b.mu.Unlock()
	b.published.Add(1)
}

// unreadLocked reports whether the event with sequence seq is about to be
// lost for at least one consumer (or for everyone, when there are none).
func (b *Bus) unreadLocked(seq uint64) bool {
	if len(b.subs) == 0 {
		return true
	}
	for s := range b.subs {
		if s.cursor <= seq {
			return true
		}
	}
	return false
}

// Published is the total number of events accepted.
func (b *Bus) Published() uint64 { return b.published.Load() }

// Dropped is the total number of events overwritten before being read
// (sherlock_events_dropped_total).
func (b *Bus) Dropped() uint64 { return b.dropped.Load() }

// Len is the number of events currently retained.
func (b *Bus) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return int(min(b.next, uint64(len(b.ring)))) //nolint:gosec // bounded by len(ring)
}

// Subscribe registers a consumer. With fromOldest it starts at the oldest
// retained event (a writer draining at startup); otherwise it only sees events
// published after this call (live tail, exporters). Close it when done.
func (b *Bus) Subscribe(fromOldest bool) *Subscription {
	s := &Subscription{bus: b, wake: make(chan struct{}, 1)}
	b.mu.Lock()
	s.cursor = b.next
	if fromOldest && b.next > uint64(len(b.ring)) {
		s.cursor = b.next - uint64(len(b.ring))
	} else if fromOldest {
		s.cursor = 0
	}
	if s.cursor < b.next {
		s.wake <- struct{}{}
	}
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s
}

// Subscription is one consumer's cursor into the bus. It is used by a single
// goroutine.
type Subscription struct {
	bus    *Bus
	cursor uint64 // guarded by bus.mu
	wake   chan struct{}
	lagged atomic.Uint64
	closed atomic.Bool
}

// Lagged is how many events this subscriber missed because the ring wrapped
// past its cursor.
func (s *Subscription) Lagged() uint64 { return s.lagged.Load() }

// Read copies up to len(dst) pending events into dst without blocking and
// returns how many it copied. If the ring wrapped past this subscriber, the
// missed events are added to Lagged and reading resumes at the oldest retained
// event.
func (s *Subscription) Read(dst []*Event) int {
	if len(dst) == 0 {
		return 0
	}
	b := s.bus
	b.mu.Lock()
	defer b.mu.Unlock()
	size := uint64(len(b.ring))
	if b.next > size && s.cursor < b.next-size {
		s.lagged.Add(b.next - size - s.cursor)
		s.cursor = b.next - size
	}
	n := 0
	for n < len(dst) && s.cursor < b.next {
		dst[n] = b.ring[s.cursor%size]
		s.cursor++
		n++
	}
	if s.cursor < b.next {
		select { // more is pending; make the next Wait return immediately
		case s.wake <- struct{}{}:
		default:
		}
	}
	return n
}

// Wait blocks until events may be available, the subscription is closed, or
// ctx is done. It returns false when no more events will ever arrive.
func (s *Subscription) Wait(ctx context.Context) bool {
	if s.closed.Load() {
		return false
	}
	select {
	case <-s.wake:
		return !s.closed.Load() || s.pending()
	case <-ctx.Done():
		return false
	}
}

func (s *Subscription) pending() bool {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	return s.cursor < s.bus.next
}

// Close unregisters the subscription; a blocked Wait returns false once the
// remaining events have been read.
func (s *Subscription) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.bus.mu.Lock()
	delete(s.bus.subs, s)
	s.bus.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
