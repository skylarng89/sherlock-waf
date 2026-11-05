package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
	"github.com/skylarng89/sherlock-waf/internal/events"
)

const (
	securityBusCapacity = events.DefaultBusCapacity
	accessBusCapacity   = 8192
	flushEvery          = time.Second
	securityFile        = "events.jsonl"
	accessFile          = "access.jsonl"
)

// pipeline owns the event buses and their sinks for the life of the process.
// The buses and sinks start with the first configuration; redaction, node
// name, body excerpts and access-log sampling follow every reload. Sink
// selection and file limits need a restart and a reload that changes them
// logs a warning instead of silently ignoring the change.
type pipeline struct {
	dataDir string
	stdout  io.Writer
	logger  *slog.Logger

	mu          sync.Mutex
	started     bool
	accessOn    bool
	first       config.Sinks
	secBus      *events.Bus
	accBus      *events.Bus
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	closers     []func() error
	subscribers []*events.Subscription

	// onStart lets the owner attach more consumers (the store writer) to the
	// security bus. It gets the pipeline's context, cancelled on stop, and
	// returns a function that waits for the consumer to finish its last flush.
	onStart func(ctx context.Context, bus *events.Bus) (wait func())
	waits   []func()
}

func newPipeline(dataDir string, stdout io.Writer, logger *slog.Logger) *pipeline {
	return &pipeline{dataDir: dataDir, stdout: stdout, logger: logger}
}

// pendingChange is a prepared, not yet visible, configuration change.
type pendingChange struct {
	commit func()
	abort  func()
}

// prepare validates cfg and gets the pipeline ready for it without changing
// what requests see: the buses and sinks are started on first use, but the
// publisher modules read is only swapped by commit. abort undoes a first-time
// start so a rejected first configuration leaves nothing running.
func (p *pipeline) prepare(cfg config.Events) (pendingChange, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	red, err := events.NewRedactor(cfg.Redaction.Patterns)
	if err != nil {
		return pendingChange{}, fmt.Errorf("building redactor: %w", err)
	}
	startedHere := false
	if !p.started {
		if err := p.start(cfg); err != nil {
			return pendingChange{}, err
		}
		startedHere = true
	} else if cfg.Sinks != p.first {
		p.logger.Warn("event sink settings changed; they take effect after a restart")
	}
	accessHere := false
	if cfg.AccessLog.Enabled && !p.accessOn {
		if err := p.startAccess(cfg); err != nil {
			if startedHere {
				_ = p.stopLocked()
			}
			return pendingChange{}, err
		}
		accessHere = true
	}

	pub := &events.Publisher{
		Bus:         p.secBus,
		BodyExcerpt: cfg.BodyExcerpt,
		Redactor:    red,
		Node:        nodeName(cfg),
		Country:     acl.CountryOf,
	}
	if cfg.AccessLog.Enabled {
		pub.AccessBus = p.accBus
		pub.AccessSampleRate = *cfg.AccessLog.SampleRate
	}
	return pendingChange{
		commit: func() { events.SetDefault(pub) },
		abort: func() {
			if startedHere {
				p.mu.Lock()
				defer p.mu.Unlock()
				_ = p.stopLocked()
			} else if accessHere {
				p.logger.Debug("access log sink left running after an aborted change")
			}
		},
	}, nil
}

// apply prepares and immediately commits (used by tests).
func (p *pipeline) apply(cfg config.Events) error {
	pc, err := p.prepare(cfg)
	if err != nil {
		return err
	}
	pc.commit()
	return nil
}

func (p *pipeline) start(cfg config.Events) error {
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.secBus = events.NewBus(securityBusCapacity)
	p.accBus = events.NewBus(accessBusCapacity)
	p.first = cfg.Sinks

	var sinks []events.Sink
	if *cfg.Sinks.Stdout {
		sinks = append(sinks, events.NewJSONLWriter(nopCloser{p.stdout}))
	}
	if *cfg.Sinks.File {
		s, err := p.fileSink(securityFile, cfg.Sinks)
		if err != nil {
			p.cancel()
			return err
		}
		sinks = append(sinks, s)
	}
	p.drain(p.secBus, sinks)
	if p.onStart != nil {
		if wait := p.onStart(p.ctx, p.secBus); wait != nil {
			p.waits = append(p.waits, wait)
		}
	}
	p.started = true
	return nil
}

func (p *pipeline) startAccess(cfg config.Events) error {
	s, err := p.fileSink(accessFile, cfg.Sinks)
	if err != nil {
		return err
	}
	p.drain(p.accBus, []events.Sink{s})
	p.accessOn = true
	return nil
}

func (p *pipeline) fileSink(name string, s config.Sinks) (events.Sink, error) {
	rf, err := events.NewRotatingFile(filepath.Join(p.dataDir, name), int64(s.FileMaxMB)<<20, s.FileKeep)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", name, err)
	}
	return events.NewJSONLWriter(rf), nil
}

func (p *pipeline) drain(bus *events.Bus, sinks []events.Sink) {
	sub := bus.Subscribe(true)
	p.subscribers = append(p.subscribers, sub)
	for _, s := range sinks {
		p.closers = append(p.closers, s.Close)
	}
	p.wg.Go(func() { events.Drain(p.ctx, sub, flushEvery, sinks...) })
}

// stats exposes bus counters for metrics.
func (p *pipeline) stats() (published, dropped uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.secBus == nil {
		return 0, 0
	}
	return p.secBus.Published(), p.secBus.Dropped()
}

// stop removes the publisher, drains what is buffered and closes the sinks.
func (p *pipeline) stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopLocked()
}

func (p *pipeline) stopLocked() error {
	if !p.started {
		return nil
	}
	events.SetDefault(nil)
	p.cancel()
	p.wg.Wait()
	for _, wait := range p.waits {
		wait()
	}
	p.waits = nil
	for _, s := range p.subscribers {
		s.Close()
	}
	var errs []error
	for _, c := range p.closers {
		errs = append(errs, c())
	}
	p.started, p.accessOn = false, false
	p.closers, p.subscribers = nil, nil
	return errors.Join(errs...)
}

func nodeName(cfg config.Events) string {
	if cfg.NodeName != "" {
		return cfg.NodeName
	}
	h, err := os.Hostname()
	if err != nil {
		return "sherlock"
	}
	return h
}

// nopCloser stops the JSONL writer from closing os.Stdout.
type nopCloser struct{ io.Writer }
