// Package eventwriter persists security events from the bus into the store and
// expires old ones. It is a bus subscriber like any exporter: a slow or failing
// database costs the writer its own backlog, never request latency.
package eventwriter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// Defaults from docs/architecture/events.md.
const (
	DefaultBatch          = 500
	DefaultFlushEvery     = time.Second
	DefaultRetentionEvery = 10 * time.Minute
	retentionBatch        = 10000
	rollupRetention       = 400 * 24 * time.Hour
	maxPendingBatches     = 8
)

// Options tunes the writer; zero values use the defaults.
type Options struct {
	Batch      int
	FlushEvery time.Duration
}

// Writer drains a bus subscription into the store.
type Writer struct {
	st     store.Store
	sub    *events.Subscription
	logger *slog.Logger
	opts   Options

	stored  atomic.Uint64
	dropped atomic.Uint64
	failed  atomic.Uint64
}

// New subscribes to bus (starting at the oldest retained event, so nothing
// published before the writer started is missed) and returns a Writer.
func New(bus *events.Bus, st store.Store, logger *slog.Logger, opts Options) *Writer {
	if opts.Batch <= 0 {
		opts.Batch = DefaultBatch
	}
	if opts.FlushEvery <= 0 {
		opts.FlushEvery = DefaultFlushEvery
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Writer{st: st, sub: bus.Subscribe(true), logger: logger, opts: opts}
}

// Stored is the number of events written to the store.
func (w *Writer) Stored() uint64 { return w.stored.Load() }

// Dropped is the number of events discarded because the store stayed
// unavailable past the backlog limit.
func (w *Writer) Dropped() uint64 { return w.dropped.Load() }

// Failed is the number of failed batch attempts.
func (w *Writer) Failed() uint64 { return w.failed.Load() }

// Run writes batches until ctx ends, then drains what is left once and returns.
func (w *Writer) Run(ctx context.Context) {
	defer w.sub.Close()
	buf := make([]*events.Event, w.opts.Batch)
	var pending []*events.Event
	stalled := false // the last write failed: only then is the backlog capped

	flush := func(final bool) {
		for {
			n := w.sub.Read(buf)
			pending = append(pending, buf[:n]...)
			if n < len(buf) {
				break
			}
		}
		if len(pending) == 0 {
			return
		}
		// While the store is failing keep the backlog bounded, oldest events first.
		// A healthy store is never capped: a burst is simply written in batches.
		if limit := maxPendingBatches * w.opts.Batch; stalled && len(pending) > limit && !final {
			over := len(pending) - limit
			w.dropped.Add(uint64(over)) //nolint:gosec // positive by construction
			w.logger.Error("event store unavailable; dropping the oldest events", "dropped", over)
			pending = pending[over:]
		}
		for len(pending) > 0 {
			end := min(len(pending), w.opts.Batch)
			if err := w.write(ctx, pending[:end]); err != nil {
				stalled = true
				w.failed.Add(1)
				w.logger.Error("writing events", "error", err, "pending", len(pending))
				return // retry at the next tick
			}
			pending = pending[end:]
		}
		stalled = false
	}

	for {
		waitCtx, cancel := context.WithTimeout(ctx, w.opts.FlushEvery)
		w.sub.Wait(waitCtx)
		cancel()
		if ctx.Err() != nil {
			// Final drain uses a fresh context: ctx is already cancelled.
			drainCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			ctx = drainCtx
			flush(true)
			stop()
			return
		}
		flush(false)
	}
}

// write stores one batch and its rollups in a single transaction.
func (w *Writer) write(ctx context.Context, batch []*events.Event) error {
	type key struct {
		bucket int64
		site   string
		action string
	}
	counts := map[key]int64{}
	rows := make([]store.EventRow, len(batch))
	for i, e := range batch {
		row, err := toRow(e)
		if err != nil {
			return err
		}
		rows[i] = row
		counts[key{e.TS.Truncate(time.Minute).UnixMicro(), e.SiteID, e.Action}]++
	}
	err := w.st.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		for _, r := range rows {
			if err := tx.InsertEvent(ctx, r); err != nil {
				return err
			}
		}
		for k, n := range counts {
			if err := tx.AddRollup(ctx, store.Rollup{Bucket: time.UnixMicro(k.bucket).UTC(), SiteID: k.site, Action: k.action, Count: n}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	w.stored.Add(uint64(len(rows)))
	return nil
}

func toRow(e *events.Event) (store.EventRow, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return store.EventRow{}, fmt.Errorf("encoding event %s: %w", e.ID, err)
	}
	rules := make([]string, 0, len(e.Findings))
	seen := map[string]bool{}
	for _, f := range e.Findings {
		if f.RuleID != "" && !seen[f.RuleID] {
			seen[f.RuleID] = true
			rules = append(rules, f.RuleID)
		}
	}
	return store.EventRow{
		ID: e.ID, TS: e.TS, SiteID: e.SiteID, Action: e.Action, Mode: e.Mode, ClientIP: e.Client.IP,
		Method: e.Request.Method, Host: e.Request.Host, Path: e.Request.Path, Status: e.Response.Status,
		RuleIDs: rules, Body: body, Country: e.Client.Country,
	}, nil
}

// Retention deletes events older than the retention window in batches, then
// rollups past their longer window. It reports how many events it removed.
func Retention(ctx context.Context, st store.Store, retentionDays int, now time.Time) (int, error) {
	cutoff := now.Add(-time.Duration(retentionDays) * 24 * time.Hour)
	total := 0
	for {
		var n int
		if err := st.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
			n, err = tx.DeleteEventsBefore(ctx, cutoff, retentionBatch)
			return err
		}); err != nil {
			return total, fmt.Errorf("deleting expired events: %w", err)
		}
		total += n
		if n == 0 {
			break
		}
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
	}
	if err := st.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.DeleteRollupsBefore(ctx, now.Add(-rollupRetention))
		return err
	}); err != nil {
		return total, fmt.Errorf("deleting expired rollups: %w", err)
	}
	return total, nil
}

// RunRetention runs Retention every interval until ctx ends. days is read on
// every run so a configuration change takes effect without a restart.
func RunRetention(ctx context.Context, st store.Store, logger *slog.Logger, interval time.Duration, days func() int) {
	if interval <= 0 {
		interval = DefaultRetentionEvery
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := Retention(ctx, st, days(), time.Now())
			if err != nil {
				logger.Error("event retention failed", "error", err)
			} else if n > 0 {
				logger.Info("expired events removed", "count", n)
			}
		}
	}
}
