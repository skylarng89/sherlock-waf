// Package exporters ships security events and audit records to external
// systems (SIEMs, webhooks, OpenTelemetry collectors). Each exporter has its
// own bus subscription, bounded disk spool and retry loop, so a slow or dead
// destination never affects the data plane, the event writer or other exporters
// (ADR-0007, M10).
package exporters

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// Errors returned by the Manager.
var (
	ErrUnknownType = errors.New("exporters: unknown exporter type")
	ErrNoTester    = errors.New("exporters: this exporter type has no connectivity test")
	ErrInvalid     = errors.New("exporters: invalid exporter configuration")
)

// idPattern keeps an exporter id usable as a directory name.
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// Config describes one configured exporter.
type Config struct {
	ID      string
	Name    string
	Type    string
	Stream  string
	Enabled bool
	// Settings is the type-specific JSON; it may hold secrets, so the Manager
	// never logs it.
	Settings json.RawMessage
}

func (c Config) fingerprint() [sha256.Size]byte {
	h := sha256.New()
	for _, s := range []string{c.Name, c.Type, c.Stream} {
		fmt.Fprintf(h, "%d:%s", len(s), s)
	}
	h.Write(c.Settings)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

type running struct {
	cfg    Config
	print  [sha256.Size]byte
	runner *Runner
}

// Manager owns the registered exporter types and the running exporters.
type Manager struct {
	bus    *events.Bus
	dir    string
	opts   RunnerOptions
	logger *slog.Logger

	mu      sync.Mutex
	types   map[string]extension.ExporterType
	running map[string]*running
	desired map[string]Config // last Apply; kept so SetBus can start what was waiting for the bus
	ctx     context.Context   //nolint:containedctx // parent of every runner: exporters outlive any one API request
}

// NewManager returns a Manager that keeps spools under dir/<exporter id>. ctx is
// the parent of every runner, so pass one that lives as long as the process. bus may
// be nil and supplied later with SetBus, because the data plane creates the bus
// when it starts.
func NewManager(ctx context.Context, bus *events.Bus, dir string, opts RunnerOptions, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		ctx: ctx, bus: bus, dir: dir, opts: opts, logger: logger,
		types: map[string]extension.ExporterType{}, running: map[string]*running{},
	}
}

// RegisterType adds an exporter type. A duplicate name is an error so an
// extension cannot silently replace a built-in.
func (m *Manager) RegisterType(t extension.ExporterType) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := t.Name()
	if name == "" {
		return errors.New("exporters: exporter type has an empty name")
	}
	if _, dup := m.types[name]; dup {
		return fmt.Errorf("exporters: exporter type %q is already registered", name)
	}
	m.types[name] = t
	return nil
}

// Types lists the registered type names, sorted.
func (m *Manager) Types() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.types))
	for n := range m.types {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Validate checks a configuration without starting anything.
func (m *Manager) Validate(c Config) error {
	if !idPattern.MatchString(c.ID) {
		return fmt.Errorf("%w: id must match %s", ErrInvalid, idPattern)
	}
	switch c.Stream {
	case StreamEvents, StreamAudit, StreamBoth:
	default:
		return fmt.Errorf("%w: stream must be events, audit or both", ErrInvalid)
	}
	m.mu.Lock()
	t, ok := m.types[c.Type]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownType, c.Type)
	}
	if err := t.Validate(c.Settings); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}

// Apply makes the running set match cfgs. Unchanged exporters keep running;
// changed ones are restarted (their spool survives); exporters no longer listed
// are stopped and their spool deleted; disabled ones are stopped but keep their
// spool. One bad configuration does not stop the others: errors are joined.
func (m *Manager) Apply(cfgs []Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	want := make(map[string]Config, len(cfgs))
	for _, c := range cfgs {
		if !idPattern.MatchString(c.ID) {
			errs = append(errs, fmt.Errorf("%w: id %q", ErrInvalid, c.ID))
			continue
		}
		want[c.ID] = c
	}
	m.desired = want
	return errors.Join(append(errs, m.reconcileLocked())...)
}

// SetBus supplies the event bus. Exporters that ship events and were waiting
// for it start now; running ones are restarted on the new bus.
func (m *Manager) SetBus(bus *events.Bus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, r := range m.running {
		r.runner.Stop()
		delete(m.running, id)
	}
	m.bus = bus
	return m.reconcileLocked()
}

func (m *Manager) reconcileLocked() error {
	var errs []error
	for id, r := range m.running {
		if c, ok := m.desired[id]; ok && c.Enabled && c.fingerprint() == r.print {
			continue
		}
		r.runner.Stop()
		delete(m.running, id)
	}
	errs = append(errs, m.removeOrphanSpools(m.desired)...)

	ids := make([]string, 0, len(m.desired))
	for id := range m.desired {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c := m.desired[id]
		if _, ok := m.running[id]; ok || !c.Enabled {
			continue
		}
		if m.bus == nil && c.Stream != StreamAudit {
			continue // starts when SetBus delivers the bus
		}
		r, err := m.start(m.ctx, c)
		if err != nil {
			errs = append(errs, fmt.Errorf("starting exporter %q: %w", id, err))
			continue
		}
		m.running[id] = r
	}
	return errors.Join(errs...)
}

// removeOrphanSpools deletes spools of exporters that are no longer configured.
// A disabled exporter is still configured, so its spool stays.
func (m *Manager) removeOrphanSpools(want map[string]Config) []error {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return []error{fmt.Errorf("listing exporter spools: %w", err)}
	}
	var errs []error
	for _, e := range entries {
		id := e.Name()
		if _, ok := want[id]; ok || !e.IsDir() || !idPattern.MatchString(id) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(m.dir, id)); err != nil {
			errs = append(errs, fmt.Errorf("removing spool of exporter %q: %w", id, err))
		}
	}
	return errs
}

func (m *Manager) start(ctx context.Context, c Config) (*running, error) {
	t, ok := m.types[c.Type]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, c.Type)
	}
	switch c.Stream {
	case StreamEvents, StreamAudit, StreamBoth:
	default:
		return nil, fmt.Errorf("%w: stream %q", ErrInvalid, c.Stream)
	}
	if err := t.Validate(c.Settings); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	exp, err := t.New(c.Settings)
	if err != nil {
		return nil, fmt.Errorf("creating exporter: %w", err)
	}
	runner, err := NewRunner(c.ID, c.Name, c.Type, c.Stream, exp, m.bus, filepath.Join(m.dir, c.ID), m.opts, m.logger)
	if err != nil {
		_ = exp.Close()
		return nil, err
	}
	runner.Start(ctx)
	return &running{cfg: c, print: c.fingerprint(), runner: runner}, nil
}

// Offer hands a record (the audit stream) to every running exporter that wants
// its stream. A failure in one exporter is logged and does not affect the rest.
func (m *Manager) Offer(rec extension.ExportRecord) {
	m.mu.Lock()
	rs := make([]*Runner, 0, len(m.running))
	for _, r := range m.running {
		rs = append(rs, r.runner)
	}
	m.mu.Unlock()
	for _, r := range rs {
		if err := r.Offer(rec); err != nil {
			m.logger.Warn("spooling record for exporter", "exporter", r.id, "stream", rec.Stream, "error", r.errString(err))
		}
	}
}

// Test builds a throwaway exporter from c and runs its connectivity check.
func (m *Manager) Test(ctx context.Context, c Config) error {
	if err := m.Validate(c); err != nil {
		return err
	}
	m.mu.Lock()
	t := m.types[c.Type]
	m.mu.Unlock()
	exp, err := t.New(c.Settings)
	if err != nil {
		return fmt.Errorf("creating exporter: %w", err)
	}
	defer exp.Close()
	tester, ok := exp.(extension.ExporterTester)
	if !ok {
		return ErrNoTester
	}
	return tester.Test(ctx)
}

// Status lists the running exporters, sorted by id.
func (m *Manager) Status() []Status {
	m.mu.Lock()
	rs := make([]*Runner, 0, len(m.running))
	for _, r := range m.running {
		rs = append(rs, r.runner)
	}
	m.mu.Unlock()
	out := make([]Status, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Status())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Stop stops every exporter, leaving their spools on disk for the next start.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, r := range m.running {
		r.runner.Stop()
		delete(m.running, id)
	}
}
