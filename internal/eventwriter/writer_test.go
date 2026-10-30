package eventwriter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

var quiet = slog.New(slog.DiscardHandler)

func newStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "e.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// flaky fails (or delays) Tx calls on demand.
type flaky struct {
	store.Store
	failing atomic.Bool
	failN   atomic.Int64 // fail this many more calls, then succeed
	delay   time.Duration
	calls   atomic.Int64
}

func (f *flaky) Tx(ctx context.Context, fn func(context.Context, store.Tx) error) error {
	f.calls.Add(1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.failing.Load() || f.failN.Add(-1) >= 0 {
		return errors.New("database unavailable")
	}
	return f.Store.Tx(ctx, fn)
}

var t0 = time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)

func ev(i int, site, action string, at time.Time, rules ...string) *events.Event {
	fs := make([]events.Finding, len(rules))
	for j, r := range rules {
		fs[j] = events.Finding{Module: "waf", RuleID: r, Severity: "critical"}
	}
	return &events.Event{
		ID: fmt.Sprintf("01EV%08d", i), Schema: events.SchemaV1, TS: at, SiteID: site, Action: action, Mode: "block",
		Client: events.Client{IP: "192.0.2.1"}, Request: events.Request{Method: "GET", Host: "h", Path: "/p"},
		Response: events.Response{Status: 403}, Findings: fs,
	}
}

func count(t *testing.T, st store.Store) int {
	t.Helper()
	var n int
	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
		n, err = tx.CountEvents(ctx)
		return err
	}))
	return n
}

func start(t *testing.T, bus *events.Bus, st store.Store, opts Options) (*Writer, func()) {
	t.Helper()
	w := New(bus, st, quiet, opts)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	return w, func() { cancel(); <-done }
}

func TestStoresEventsAndRollups(t *testing.T) {
	st, bus := newStore(t), events.NewBus(4096)
	w, stop := start(t, bus, st, Options{Batch: 100, FlushEvery: 10 * time.Millisecond})
	defer stop()

	for i := range 1200 {
		site := []string{"shop", "blog"}[i%2]
		action := []string{"block", "log", "block"}[i%3]
		bus.Publish(ev(i, site, action, t0.Add(time.Duration(i)*time.Second), "942100", "949110"))
	}
	require.Eventually(t, func() bool { return count(t, st) == 1200 }, 5*time.Second, 10*time.Millisecond)
	assert.EqualValues(t, 1200, w.Stored())

	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		rolls, err := tx.ListRollups(ctx, t0.Truncate(time.Minute), t0.Add(time.Hour))
		require.NoError(t, err)
		var total int64
		for _, r := range rolls {
			total += r.Count
			assert.Zero(t, r.Bucket.Second(), "rollups are per minute")
		}
		assert.EqualValues(t, 1200, total, "rollup counts equal stored events")

		got, err := tx.GetEvent(ctx, "01EV00000007")
		require.NoError(t, err)
		assert.Equal(t, []string{"942100", "949110"}, got.RuleIDs)
		assert.Contains(t, string(got.Body), `"schema":"sherlock.event.v1"`, "the full event document is kept")

		matched, cur := 0, store.Cursor{}
		for {
			page, err := tx.ListEvents(ctx, store.EventFilter{RuleID: "942100"}, cur, 500)
			require.NoError(t, err)
			matched += len(page)
			if len(page) < 500 {
				break
			}
			cur = store.Cursor{Time: page[len(page)-1].TS, ID: page[len(page)-1].ID}
		}
		assert.Equal(t, 1200, matched, "every stored event is found by its rule id, across pages")
		return nil
	}))
}

func TestRetriesAfterAStoreOutage(t *testing.T) {
	inner, bus := newStore(t), events.NewBus(4096)
	st := &flaky{Store: inner}
	st.failN.Store(3)
	w, stop := start(t, bus, st, Options{Batch: 50, FlushEvery: 10 * time.Millisecond})
	defer stop()
	for i := range 200 {
		bus.Publish(ev(i, "shop", "block", t0, "942100"))
	}
	require.Eventually(t, func() bool { return count(t, inner) == 200 }, 5*time.Second, 10*time.Millisecond)
	assert.GreaterOrEqual(t, w.Failed(), uint64(3), "failed attempts were counted")
	assert.Zero(t, w.Dropped(), "nothing is lost while the backlog is within bounds")
	assert.EqualValues(t, 200, w.Stored(), "and nothing is stored twice")
}

func TestBacklogIsBoundedWhileTheStoreIsDown(t *testing.T) {
	inner, bus := newStore(t), events.NewBus(1<<16)
	st := &flaky{Store: inner}
	st.failing.Store(true)
	w, stop := start(t, bus, st, Options{Batch: 10, FlushEvery: 5 * time.Millisecond})
	defer stop()

	const total = 1000 // far above 8 batches x 10 events
	for i := range total {
		bus.Publish(ev(i, "shop", "block", t0))
	}
	require.Eventually(t, func() bool { return w.Dropped() > 0 }, 5*time.Second, 10*time.Millisecond, "the writer sheds its oldest backlog")

	st.failing.Store(false)
	require.Eventually(t, func() bool { return count(t, inner) > 0 }, 5*time.Second, 10*time.Millisecond, "and recovers once the store is back")
	assert.Equal(t, uint64(total), w.Stored()+w.Dropped(), "every event is either stored or counted as dropped")
}

func TestFinalDrainOnShutdown(t *testing.T) {
	st, bus := newStore(t), events.NewBus(4096)
	_, stop := start(t, bus, st, Options{Batch: 100, FlushEvery: time.Hour}) // the ticker never fires
	for i := range 250 {
		bus.Publish(ev(i, "shop", "block", t0))
	}
	stop()
	assert.Equal(t, 250, count(t, st), "events published before shutdown are written by the final drain")
}

func TestPublisherIsNeverSlowedByASlowStore(t *testing.T) {
	inner, bus := newStore(t), events.NewBus(4096)
	st := &flaky{Store: inner, delay: 200 * time.Millisecond}
	_, stop := start(t, bus, st, Options{Batch: 10, FlushEvery: 5 * time.Millisecond})
	defer stop()

	start := time.Now()
	for i := range 100_000 {
		bus.Publish(ev(i, "shop", "block", t0))
	}
	assert.Less(t, time.Since(start), 3*time.Second, "publishing 100k events must not wait on the database")
}

func TestRetentionDeletesOnlyExpiredEvents(t *testing.T) {
	st := newStore(t)
	now := t0
	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		for i := range 10_050 { // more than one deletion batch
			row, err := toRow(ev(i, "shop", "block", now.Add(-40*24*time.Hour)))
			require.NoError(t, err)
			require.NoError(t, tx.InsertEvent(ctx, row))
		}
		for i := range 7 {
			row, err := toRow(ev(100_000+i, "shop", "block", now.Add(-10*24*time.Hour)))
			require.NoError(t, err)
			require.NoError(t, tx.InsertEvent(ctx, row))
		}
		require.NoError(t, tx.AddRollup(ctx, store.Rollup{Bucket: now.Add(-500 * 24 * time.Hour).Truncate(time.Minute), SiteID: "s", Action: "block", Count: 1}))
		require.NoError(t, tx.AddRollup(ctx, store.Rollup{Bucket: now.Add(-24 * time.Hour).Truncate(time.Minute), SiteID: "s", Action: "block", Count: 1}))
		return nil
	}))

	n, err := Retention(t.Context(), st, 30, now)
	require.NoError(t, err)
	assert.Equal(t, 10_050, n)
	assert.Equal(t, 7, count(t, st), "events inside the window survive")

	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		rolls, err := tx.ListRollups(ctx, now.Add(-600*24*time.Hour), now)
		require.NoError(t, err)
		assert.Len(t, rolls, 1, "rollups older than 400 days are removed, newer ones kept")
		return nil
	}))

	n, err = Retention(t.Context(), st, 30, now)
	require.NoError(t, err)
	assert.Zero(t, n, "idempotent")
}

func TestRunRetentionHonoursALiveSetting(t *testing.T) {
	st := newStore(t)
	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		row, _ := toRow(ev(1, "shop", "block", time.Now().Add(-3*24*time.Hour)))
		return tx.InsertEvent(ctx, row)
	}))
	var days atomic.Int64
	days.Store(30)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		RunRetention(ctx, st, quiet, 10*time.Millisecond, func() int { return int(days.Load()) })
		close(done)
	}()

	time.Sleep(60 * time.Millisecond)
	assert.Equal(t, 1, count(t, st), "within a 30 day window the event stays")
	days.Store(1) // an operator shortens retention
	require.Eventually(t, func() bool { return count(t, st) == 0 }, 2*time.Second, 10*time.Millisecond)
	cancel()
	<-done
}

func TestToRowDeduplicatesRuleIDs(t *testing.T) {
	row, err := toRow(ev(1, "shop", "block", t0, "942100", "942100", "949110"))
	require.NoError(t, err)
	assert.Equal(t, []string{"942100", "949110"}, row.RuleIDs)
	assert.Equal(t, 403, row.Status)
}
