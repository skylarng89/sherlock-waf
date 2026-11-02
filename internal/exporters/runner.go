package exporters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// Streams an exporter can be configured to ship.
const (
	StreamEvents = extension.StreamEvents
	StreamAudit  = extension.StreamAudit
	StreamBoth   = "both"
)

// Runner defaults.
const (
	DefaultBatch       = 500
	DefaultBatchBytes  = 1 << 20
	DefaultSendTimeout = 10 * time.Second
	DefaultBackoffMin  = time.Second
	DefaultBackoffMax  = time.Minute
	DefaultPoll        = time.Second

	maxErrorLen = 200
	ingestBatch = 512
	syncEvery   = time.Second
)

// RunnerOptions tunes a Runner; zero values use the defaults.
type RunnerOptions struct {
	Spool       SpoolOptions
	Batch       int
	BatchBytes  int
	SendTimeout time.Duration
	BackoffMin  time.Duration
	BackoffMax  time.Duration
	Poll        time.Duration
}

func (o *RunnerOptions) defaults() {
	if o.Batch <= 0 {
		o.Batch = DefaultBatch
	}
	if o.BatchBytes <= 0 {
		o.BatchBytes = DefaultBatchBytes
	}
	if o.SendTimeout <= 0 {
		o.SendTimeout = DefaultSendTimeout
	}
	if o.BackoffMin <= 0 {
		o.BackoffMin = DefaultBackoffMin
	}
	if o.BackoffMax < o.BackoffMin {
		o.BackoffMax = max(DefaultBackoffMax, o.BackoffMin)
	}
	if o.Poll <= 0 {
		o.Poll = DefaultPoll
	}
}

// wireRecord is how an ExportRecord is stored in the spool.
type wireRecord struct {
	ID     string          `json:"id"`
	Stream string          `json:"stream"`
	At     time.Time       `json:"at"`
	Body   json.RawMessage `json:"body"`
}

// Runner moves records for one exporter: bus subscription (own cursor) ->
// bounded disk spool -> Send with retry. The two halves run in separate
// goroutines, so a hung destination only grows the spool; it never slows the
// bus, the event writer or the request path.
type Runner struct {
	id, name, kind string
	stream         string
	exp            extension.Exporter
	spool          *Spool
	sub            *events.Subscription // nil when the exporter ships only audit records
	opts           RunnerOptions
	logger         *slog.Logger

	wake chan struct{}

	sent      atomic.Uint64
	failures  atomic.Uint64
	discarded atomic.Uint64 // permanent rejections and unreadable records
	lagged    atomic.Uint64 // missed because the bus ring wrapped past this cursor
	lastOK    atomic.Int64  // unix nanoseconds
	lastErr   atomic.Pointer[errInfo]

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type errInfo struct {
	msg string
	at  time.Time
}

// NewRunner builds a Runner. sub may be nil for a runner fed only through
// Offer. The spool lives in spoolDir.
func NewRunner(id, name, kind, stream string, exp extension.Exporter, bus *events.Bus, spoolDir string, opts RunnerOptions, logger *slog.Logger) (*Runner, error) {
	opts.defaults()
	if logger == nil {
		logger = slog.Default()
	}
	spool, err := OpenSpool(spoolDir, opts.Spool)
	if err != nil {
		return nil, fmt.Errorf("opening spool for exporter %q: %w", id, err)
	}
	r := &Runner{
		id: id, name: name, kind: kind, stream: stream,
		exp: exp, spool: spool, opts: opts, wake: make(chan struct{}, 1),
		logger: logger.With("exporter", id, "exporter_type", kind),
	}
	if bus != nil && (stream == StreamEvents || stream == StreamBoth) {
		// Live only: an exporter created now ships what happens from now on, not
		// the ring's history.
		r.sub = bus.Subscribe(false)
	}
	return r, nil
}

// Start launches the runner's goroutines; they stop when ctx ends or Stop is called.
func (r *Runner) Start(ctx context.Context) {
	ctx, r.cancel = context.WithCancel(ctx)
	if r.sub != nil {
		r.wg.Add(1)
		go r.ingest(ctx)
	}
	r.wg.Add(1)
	go r.send(ctx)
}

// Stop ends the goroutines, makes a last attempt to spool anything still on the
// bus, and closes the subscription, spool and exporter. Undelivered records stay
// on disk and are sent on the next start.
func (r *Runner) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	if r.sub != nil {
		r.drainBus()
		r.sub.Close()
	}
	if err := r.spool.Close(); err != nil {
		r.logger.Warn("closing exporter spool", "error", err)
	}
	if err := r.exp.Close(); err != nil {
		r.logger.Warn("closing exporter", "error", err)
	}
}

// Wants reports whether this exporter ships the given stream.
func (r *Runner) Wants(stream string) bool {
	return r.stream == StreamBoth || r.stream == stream
}

// Offer spools one record directly. It is how the audit stream arrives and
// returns once the record is on disk; a failure is returned, never retried here.
func (r *Runner) Offer(rec extension.ExportRecord) error {
	if !r.Wants(rec.Stream) {
		return nil
	}
	b, err := json.Marshal(wireRecord{ID: rec.ID, Stream: rec.Stream, At: rec.At, Body: rec.Body})
	if err != nil {
		return fmt.Errorf("encoding record: %w", err)
	}
	return r.appendSpool(b)
}

func (r *Runner) appendSpool(recs ...[]byte) error {
	evicted, err := r.spool.Append(recs...)
	if evicted > 0 {
		r.logger.Warn("exporter spool is full; dropped the oldest unsent records", "dropped", evicted)
	}
	r.notify()
	return err
}

func (r *Runner) notify() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *Runner) ingest(ctx context.Context) {
	defer r.wg.Done()
	buf := make([]*events.Event, ingestBatch)
	lastSync := time.Now()
	for r.sub.Wait(ctx) {
		r.pump(buf)
		if time.Since(lastSync) >= syncEvery {
			if err := r.spool.Sync(); err != nil {
				r.logger.Warn("syncing exporter spool", "error", err)
			}
			lastSync = time.Now()
		}
	}
}

func (r *Runner) drainBus() {
	buf := make([]*events.Event, ingestBatch)
	for r.pump(buf) == len(buf) {
	}
}

// pump moves one batch from the subscription into the spool.
func (r *Runner) pump(buf []*events.Event) int {
	n := r.sub.Read(buf)
	if lag := r.sub.Lagged(); lag > r.lagged.Load() {
		r.lagged.Store(lag)
	}
	if n == 0 {
		return 0
	}
	recs := make([][]byte, 0, n)
	for _, ev := range buf[:n] {
		body, err := json.Marshal(ev)
		if err != nil {
			r.discarded.Add(1)
			continue
		}
		b, err := json.Marshal(wireRecord{ID: ev.ID, Stream: StreamEvents, At: ev.TS, Body: body})
		if err != nil {
			r.discarded.Add(1)
			continue
		}
		recs = append(recs, b)
	}
	if err := r.appendSpool(recs...); err != nil {
		r.discarded.Add(uint64(len(recs))) //nolint:gosec // length
		r.recordError(fmt.Errorf("spooling: %w", err))
	}
	return n
}

func (r *Runner) send(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(r.opts.Poll)
	defer ticker.Stop()
	attempt := 0
	for {
		batch, err := r.spool.Next(r.opts.Batch, r.opts.BatchBytes)
		if err != nil {
			r.recordError(err)
			if !sleep(ctx, r.backoff(attempt)) {
				return
			}
			attempt++
			continue
		}
		if batch.Len() == 0 {
			select {
			case <-ctx.Done():
				return
			case <-r.wake:
			case <-ticker.C:
			}
			continue
		}
		recs, bad := decode(batch.Records)
		if bad > 0 {
			r.discarded.Add(uint64(bad)) //nolint:gosec // count
		}
		if len(recs) > 0 {
			if err := r.deliver(ctx, recs); err != nil {
				if errors.Is(err, extension.ErrPermanent) {
					r.discarded.Add(uint64(len(recs))) //nolint:gosec // count
					r.recordError(err)
					r.logger.Warn("exporter destination rejected a batch; discarding it", "records", len(recs), "error", r.errString(err))
				} else {
					if ctx.Err() != nil {
						return
					}
					r.failures.Add(1)
					r.recordError(err)
					if !sleep(ctx, r.backoff(attempt)) {
						return
					}
					attempt++
					continue
				}
			} else {
				r.sent.Add(uint64(len(recs))) //nolint:gosec // count
				r.lastOK.Store(time.Now().UnixNano())
			}
		}
		attempt = 0
		if err := r.spool.Ack(batch); err != nil {
			r.recordError(err)
			r.logger.Warn("persisting exporter cursor; the batch may be sent again", "error", err)
		}
	}
}

func (r *Runner) deliver(ctx context.Context, recs []extension.ExportRecord) error {
	ctx, cancel := context.WithTimeout(ctx, r.opts.SendTimeout)
	defer cancel()
	return r.exp.Send(ctx, recs)
}

func decode(raw [][]byte) (recs []extension.ExportRecord, bad int) {
	recs = make([]extension.ExportRecord, 0, len(raw))
	for _, b := range raw {
		var w wireRecord
		if err := json.Unmarshal(b, &w); err != nil {
			bad++
			continue
		}
		recs = append(recs, extension.ExportRecord{ID: w.ID, Stream: w.Stream, At: w.At, Body: w.Body})
	}
	return recs, bad
}

// backoff is exponential with equal jitter: half the delay is fixed, half
// random, so a fleet of exporters retrying after the same outage spreads out.
func (r *Runner) backoff(attempt int) time.Duration {
	d := r.opts.BackoffMin
	for i := 0; i < attempt && d < r.opts.BackoffMax; i++ {
		d *= 2
	}
	d = min(d, r.opts.BackoffMax)
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1)) //nolint:gosec // retry jitter, not a security decision
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (r *Runner) errString(err error) string {
	s := err.Error()
	if len(s) > maxErrorLen {
		s = s[:maxErrorLen] + "…"
	}
	return s
}

func (r *Runner) recordError(err error) {
	r.lastErr.Store(&errInfo{msg: r.errString(err), at: time.Now()})
}

// Status is a point-in-time view of one exporter for the API and metrics.
type Status struct {
	ID, Name, Type, Stream string
	Sent                   uint64
	SendFailures           uint64
	Discarded              uint64
	Lagged                 uint64
	SpoolDropped           uint64
	Pending                int
	SpoolBytes             int64
	LastSuccess            time.Time
	LastError              string
	LastErrorAt            time.Time
}

// Status snapshots the runner's counters.
func (r *Runner) Status() Status {
	st := r.spool.Stats()
	s := Status{
		ID: r.id, Name: r.name, Type: r.kind, Stream: r.stream,
		Sent: r.sent.Load(), SendFailures: r.failures.Load(), Discarded: r.discarded.Load(),
		Lagged: r.lagged.Load(), SpoolDropped: st.Dropped, Pending: st.Pending, SpoolBytes: st.Bytes,
	}
	if ns := r.lastOK.Load(); ns != 0 {
		s.LastSuccess = time.Unix(0, ns)
	}
	if e := r.lastErr.Load(); e != nil {
		s.LastError, s.LastErrorAt = e.msg, e.at
	}
	return s
}
