package exporters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fake is a controllable destination.
type fake struct {
	mu     sync.Mutex
	down   error
	block  chan struct{}
	got    []extension.ExportRecord
	closed bool
}

func (f *fake) Send(ctx context.Context, batch []extension.ExportRecord) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down != nil {
		return f.down
	}
	f.got = append(f.got, batch...)
	return nil
}

func (f *fake) Close() error { f.mu.Lock(); f.closed = true; f.mu.Unlock(); return nil }

func (f *fake) setDown(err error) { f.mu.Lock(); f.down = err; f.mu.Unlock() }

func (f *fake) ids() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.got))
	for i, r := range f.got {
		out[i] = r.ID
	}
	return out
}

type fakeType struct {
	exp *fake
	err error
}

func (fakeType) Name() string { return "fake" }
func (t fakeType) Validate(cfg json.RawMessage) error {
	if string(cfg) == `"bad"` {
		return errors.New("bad settings")
	}
	return nil
}

func (t fakeType) New(json.RawMessage) (extension.Exporter, error) {
	if t.err != nil {
		return nil, t.err
	}
	return t.exp, nil
}

var fastOpts = RunnerOptions{BackoffMin: time.Millisecond, BackoffMax: 5 * time.Millisecond, Poll: 5 * time.Millisecond, Batch: 50}

func newRunner(t *testing.T, bus *events.Bus, f *fake, dir string, opts RunnerOptions) *Runner {
	t.Helper()
	r, err := NewRunner("x", "X", "fake", StreamEvents, f, bus, dir, opts, quiet)
	require.NoError(t, err)
	r.Start(t.Context())
	return r
}

func publish(bus *events.Bus, from, to int) {
	for i := from; i < to; i++ {
		bus.Publish(&events.Event{ID: fmt.Sprintf("e%04d", i), Schema: events.SchemaV1, TS: time.Now()})
	}
}

func TestRunnerDeliversEventsInOrder(t *testing.T) {
	bus := events.NewBus(1024)
	f := &fake{}
	r := newRunner(t, bus, f, t.TempDir(), fastOpts)
	defer r.Stop()
	publish(bus, 0, 120)

	require.Eventually(t, func() bool { return len(f.ids()) == 120 }, 5*time.Second, 5*time.Millisecond)
	ids := f.ids()
	assert.Equal(t, "e0000", ids[0])
	assert.Equal(t, "e0119", ids[119])
	assert.EqualValues(t, 120, r.Status().Sent)
	assert.NotZero(t, r.Status().LastSuccess)

	var ev events.Event
	require.NoError(t, json.Unmarshal(f.got[0].Body, &ev))
	assert.Equal(t, events.SchemaV1, ev.Schema, "the body is the v1 event document")
	assert.Equal(t, StreamEvents, f.got[0].Stream)
}

func TestOutageLosesNothingAndRecovers(t *testing.T) {
	bus := events.NewBus(256) // far smaller than the outage: the spool must carry it
	f := &fake{}
	f.setDown(errors.New("connection refused"))
	r := newRunner(t, bus, f, t.TempDir(), fastOpts)
	defer r.Stop()

	for i := 0; i < 2000; i += 50 {
		publish(bus, i, i+50)
		time.Sleep(2 * time.Millisecond) // let the ingest goroutine keep pace, as it does in production
	}
	require.Eventually(t, func() bool { return r.Status().Pending == 2000 }, 5*time.Second, 5*time.Millisecond)
	assert.Zero(t, r.Status().Lagged)
	assert.NotEmpty(t, r.Status().LastError)
	assert.Positive(t, r.Status().SendFailures)

	f.setDown(nil)
	require.Eventually(t, func() bool { return len(f.ids()) == 2000 }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, "e0000", f.ids()[0])
	assert.Equal(t, "e1999", f.ids()[1999])
	assert.Zero(t, r.Status().Pending)
}

func TestRestartResumesFromSpool(t *testing.T) {
	dir := t.TempDir()
	bus := events.NewBus(1024)
	f1 := &fake{}
	f1.setDown(errors.New("down"))
	r := newRunner(t, bus, f1, dir, fastOpts)
	publish(bus, 0, 30)
	require.Eventually(t, func() bool { return r.Status().Pending == 30 }, 5*time.Second, 5*time.Millisecond)
	r.Stop()

	f2 := &fake{}
	r2 := newRunner(t, events.NewBus(8), f2, dir, fastOpts)
	defer r2.Stop()
	require.Eventually(t, func() bool { return len(f2.ids()) == 30 }, 5*time.Second, 5*time.Millisecond)
}

func TestPermanentFailureDiscardsBatchAndContinues(t *testing.T) {
	bus := events.NewBus(1024)
	f := &fake{}
	f.setDown(fmt.Errorf("receiver said 400: %w", extension.ErrPermanent))
	r := newRunner(t, bus, f, t.TempDir(), fastOpts)
	defer r.Stop()
	publish(bus, 0, 10)
	require.Eventually(t, func() bool { return r.Status().Discarded == 10 }, 5*time.Second, 5*time.Millisecond)
	assert.Zero(t, r.Status().Pending, "a rejected batch must not block the queue")
	assert.Zero(t, r.Status().SendFailures, "it is not retried")

	f.setDown(nil)
	publish(bus, 10, 12)
	require.Eventually(t, func() bool { return len(f.ids()) == 2 }, 5*time.Second, 5*time.Millisecond)
}

func TestSlowExporterNeverBlocksPublish(t *testing.T) {
	bus := events.NewBus(256)
	f := &fake{block: make(chan struct{})} // Send hangs until released
	r := newRunner(t, bus, f, t.TempDir(), fastOpts)
	defer r.Stop()
	defer close(f.block)

	start := time.Now()
	publish(bus, 0, 20000)
	assert.Less(t, time.Since(start), 2*time.Second, "Publish does not wait for a stuck destination")
}

func TestSpoolOverflowIsCountedAsDropped(t *testing.T) {
	bus := events.NewBus(1024)
	f := &fake{}
	f.setDown(errors.New("down"))
	opts := fastOpts
	opts.Spool = SpoolOptions{MaxBytes: 8 << 10, SegmentBytes: 2 << 10}
	r := newRunner(t, bus, f, t.TempDir(), opts)
	defer r.Stop()
	for i := 0; i < 1000; i += 50 {
		publish(bus, i, i+50)
		time.Sleep(2 * time.Millisecond)
	}
	require.Eventually(t, func() bool { st := r.Status(); return accounted(st) == 1000 }, 5*time.Second, 5*time.Millisecond)
	st := r.Status()
	assert.NotZero(t, st.SpoolDropped)
	assert.LessOrEqual(t, st.SpoolBytes, int64(8<<10)+2<<10)
	assert.EqualValues(t, 1000, accounted(st), "every record is either still queued or counted as dropped")
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	r := &Runner{opts: RunnerOptions{BackoffMin: time.Second, BackoffMax: 8 * time.Second}}
	for attempt, hi := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second, 8 * time.Second} {
		for range 50 {
			d := r.backoff(attempt)
			assert.GreaterOrEqual(t, d, hi/2, "attempt %d", attempt)
			assert.LessOrEqual(t, d, hi, "attempt %d", attempt)
		}
	}
}

func TestOfferRespectsStream(t *testing.T) {
	f := &fake{}
	r, err := NewRunner("a", "A", "fake", StreamAudit, f, nil, t.TempDir(), fastOpts, quiet)
	require.NoError(t, err)
	r.Start(t.Context())
	defer r.Stop()

	require.NoError(t, r.Offer(extension.ExportRecord{ID: "ev", Stream: StreamEvents, Body: json.RawMessage(`{}`)}))
	require.NoError(t, r.Offer(extension.ExportRecord{ID: "au", Stream: StreamAudit, Body: json.RawMessage(`{}`)}))
	require.Eventually(t, func() bool { return len(f.ids()) == 1 }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, []string{"au"}, f.ids(), "an audit-only exporter ignores events")
}

func TestManagerApplyReconciles(t *testing.T) {
	dir := t.TempDir()
	bus := events.NewBus(256)
	f := &fake{}
	m := NewManager(bus, dir, fastOpts, quiet)
	require.NoError(t, m.RegisterType(fakeType{exp: f}))
	assert.Error(t, m.RegisterType(fakeType{}), "duplicate type names are refused")
	defer m.Stop()

	c := Config{ID: "siem", Name: "SIEM", Type: "fake", Stream: StreamEvents, Enabled: true, Settings: json.RawMessage(`{}`)}
	require.NoError(t, m.Apply(t.Context(), []Config{c}))
	require.Len(t, m.Status(), 1)
	publish(bus, 0, 3)
	require.Eventually(t, func() bool { return len(f.ids()) == 3 }, 5*time.Second, 5*time.Millisecond)

	c.Enabled = false
	require.NoError(t, m.Apply(t.Context(), []Config{c}))
	assert.Empty(t, m.Status(), "disabled exporters stop")
	assert.DirExists(t, dir+"/siem", "but keep their spool")

	require.NoError(t, m.Apply(t.Context(), nil))
	assert.NoDirExists(t, dir+"/siem", "removed exporters lose their spool")
}

func TestManagerRejectsBadConfigsWithoutStoppingOthers(t *testing.T) {
	m := NewManager(events.NewBus(8), t.TempDir(), fastOpts, quiet)
	require.NoError(t, m.RegisterType(fakeType{exp: &fake{}}))
	defer m.Stop()

	good := Config{ID: "ok", Type: "fake", Stream: StreamEvents, Enabled: true}
	cases := map[string]Config{
		"path traversal id": {ID: "../evil", Type: "fake", Stream: StreamEvents, Enabled: true},
		"unknown type":      {ID: "u", Type: "nope", Stream: StreamEvents, Enabled: true},
		"bad stream":        {ID: "s", Type: "fake", Stream: "all", Enabled: true},
		"bad settings":      {ID: "b", Type: "fake", Stream: StreamEvents, Enabled: true, Settings: json.RawMessage(`"bad"`)},
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, m.Validate(bad))
			err := m.Apply(t.Context(), []Config{good, bad})
			require.Error(t, err)
			assert.Len(t, m.Status(), 1, "the valid exporter still runs")
		})
	}
}

func TestManagerTest(t *testing.T) {
	m := NewManager(events.NewBus(8), t.TempDir(), fastOpts, quiet)
	require.NoError(t, m.RegisterType(fakeType{exp: &fake{}}))
	c := Config{ID: "t", Type: "fake", Stream: StreamEvents}
	assert.ErrorIs(t, m.Test(t.Context(), c), ErrNoTester)
	c.Type = "nope"
	assert.ErrorIs(t, m.Test(t.Context(), c), ErrUnknownType)
}

func TestApplyRestartsOnChangeAndKeepsOnNoChange(t *testing.T) {
	bus := events.NewBus(8)
	m := NewManager(bus, t.TempDir(), fastOpts, quiet)
	f := &fake{}
	require.NoError(t, m.RegisterType(fakeType{exp: f}))
	defer m.Stop()
	c := Config{ID: "a", Type: "fake", Stream: StreamEvents, Enabled: true, Settings: json.RawMessage(`{"x":1}`)}
	require.NoError(t, m.Apply(t.Context(), []Config{c}))
	first := m.running["a"].runner
	require.NoError(t, m.Apply(t.Context(), []Config{c}))
	assert.Same(t, first, m.running["a"].runner, "an unchanged config keeps its runner")
	c.Settings = json.RawMessage(`{"x":2}`)
	require.NoError(t, m.Apply(t.Context(), []Config{c}))
	assert.NotSame(t, first, m.running["a"].runner, "a changed config restarts it")
}

func TestEventExporterWaitsForBus(t *testing.T) {
	m := NewManager(nil, t.TempDir(), fastOpts, quiet)
	f := &fake{}
	require.NoError(t, m.RegisterType(fakeType{exp: f}))
	defer m.Stop()
	c := Config{ID: "a", Type: "fake", Stream: StreamEvents, Enabled: true}
	require.NoError(t, m.Apply(t.Context(), []Config{c}))
	assert.Empty(t, m.Status(), "no bus yet, so nothing starts and nothing silently ships nothing")

	bus := events.NewBus(64)
	require.NoError(t, m.SetBus(bus))
	require.Len(t, m.Status(), 1)
	publish(bus, 0, 2)
	require.Eventually(t, func() bool { return len(f.ids()) == 2 }, 5*time.Second, 5*time.Millisecond)
}

func TestMetricsReflectDelivery(t *testing.T) {
	bus := events.NewBus(64)
	m := NewManager(bus, t.TempDir(), fastOpts, quiet)
	f := &fake{}
	require.NoError(t, m.RegisterType(fakeType{exp: f}))
	defer m.Stop()
	require.NoError(t, m.Apply(t.Context(), []Config{{ID: "a", Type: "fake", Stream: StreamEvents, Enabled: true}}))
	publish(bus, 0, 5)
	require.Eventually(t, func() bool { return len(f.ids()) == 5 }, 5*time.Second, 5*time.Millisecond)

	reg := prometheus.NewRegistry()
	RegisterMetrics(reg, m)
	RegisterMetrics(reg, m) // replacing is allowed
	fams, err := reg.Gather()
	require.NoError(t, err)
	byName := map[string]int{}
	var sent float64
	for _, fam := range fams {
		byName[fam.GetName()] = len(fam.GetMetric())
		if fam.GetName() == "sherlock_exporter_sent_total" {
			sent = fam.GetMetric()[0].GetCounter().GetValue()
		}
	}
	assert.EqualValues(t, 5, sent)
	assert.Equal(t, 3, byName["sherlock_exporter_dropped_total"], "one series per drop reason")
	assert.Equal(t, 1, byName["sherlock_exporter_pending"])
}

// accounted is every record that is either still queued or known to be lost.
func accounted(st Status) uint64 {
	return uint64(st.Pending) + st.SpoolDropped //nolint:gosec // Pending is never negative
}
