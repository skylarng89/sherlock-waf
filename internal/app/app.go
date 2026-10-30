// Package app runs the data plane: it loads the YAML config, compiles it to
// Caddy JSON and drives an in-process Caddy. Configuration is only ever
// swapped in after it has validated and compiled, so a bad file on reload
// leaves the running config untouched.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	// Only the Caddy modules the compiler emits, instead of modules/standard,
	// to keep the dependency and licence surface small.
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	_ "github.com/caddyserver/caddy/v2/modules/caddytls" // tls app, acme issuer, file certificate loader
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
	_ "github.com/skylarng89/sherlock-waf/internal/dataplane/api"       // registers sherlock_api
	_ "github.com/skylarng89/sherlock-waf/internal/dataplane/bot"       // registers sherlock_bot
	_ "github.com/skylarng89/sherlock-waf/internal/dataplane/core"      // registers sherlock_core
	_ "github.com/skylarng89/sherlock-waf/internal/dataplane/ratelimit" // registers sherlock_ratelimit
	"github.com/skylarng89/sherlock-waf/internal/dataplane/waf"         // registers sherlock_waf
	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/metrics"
	"github.com/skylarng89/sherlock-waf/internal/policy/ipset"
)

// App owns the lifecycle of the embedded Caddy. Caddy keeps process-global
// state, so only one App may be running per process.
type App struct {
	path   string
	opts   compiler.Options
	logger *slog.Logger
	pipe   *pipeline
	admin  *adminServer
	ready  atomic.Bool

	mu      sync.Mutex
	running bool
}

// Option customises an App.
type Option func(*App)

// WithEventsOutput sends the events stdout sink to w instead of os.Stdout.
func WithEventsOutput(w io.Writer) Option {
	return func(a *App) { a.pipe.stdout = w }
}

// WithSecurityBusHook calls hook when the security event bus starts, so the
// control plane can store events. hook gets a context that ends when the
// pipeline stops and returns a function that blocks until its consumer has
// flushed; Stop waits for it before returning.
func WithSecurityBusHook(hook func(ctx context.Context, bus *events.Bus) (wait func())) Option {
	return func(a *App) { a.pipe.onStart = hook }
}

// New returns an App that reads configPath. opts.DataDir (default: the user
// data directory) holds certificates and the events files.
func New(configPath string, opts compiler.Options, logger *slog.Logger, options ...Option) *App {
	if logger == nil {
		logger = slog.Default()
	}
	opts.DataDir = ResolveDataDir(opts.DataDir)
	a := &App{path: configPath, opts: opts, logger: logger}
	a.pipe = newPipeline(opts.DataDir, os.Stdout, logger)
	a.admin = newAdminServer(a.ready.Load)
	for _, o := range options {
		o(a)
	}
	return a
}

// ResolveDataDir returns dir, or the default per-user data directory
// ($XDG_DATA_HOME/sherlock, ~/.local/share/sherlock) when dir is empty.
func ResolveDataDir(dir string) string {
	if dir != "" {
		return dir
	}
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "sherlock")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "share", "sherlock")
	}
	return "sherlock-data"
}

// Start loads the config and starts serving. It fails without side effects if
// the config is invalid.
func (a *App) Start(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running {
		return errors.New("app already started")
	}
	if err := a.apply(ctx); err != nil {
		return err
	}
	a.running = true
	return nil
}

// Reload re-reads the file and swaps the configuration. On any failure
// (validation, compilation, or Caddy refusing the config) the previous
// configuration keeps serving.
func (a *App) Reload(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		return errors.New("app not started")
	}
	return a.apply(ctx)
}

func (a *App) apply(ctx context.Context) error {
	root, err := config.Load(a.path)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	return a.activate(ctx, root)
}

// activate makes a validated configuration live. It is two-phase so that a
// configuration Caddy rejects changes nothing observable:
//
//  1. compile, and prepare the event pipeline and admin listener (a new admin
//     address is bound, but the old one keeps serving);
//  2. caddy.Load, which rolls back to the previous config itself on failure;
//  3. only then commit the prepared changes.
func (a *App) activate(ctx context.Context, root *config.Root) error {
	cfg, err := compiler.Compile(root, a.opts)
	if err != nil {
		return fmt.Errorf("compiling config: %w", err)
	}
	pipe, err := a.pipe.prepare(root.Global.Events)
	if err != nil {
		return fmt.Errorf("starting event pipeline: %w", err)
	}
	newLists, err := buildLists(root)
	if err != nil {
		pipe.abort()
		return fmt.Errorf("building ip lists: %w", err)
	}
	admin, err := a.admin.prepare(ctx, root.Global.Admin)
	if err != nil {
		pipe.abort()
		return err
	}
	// Lists are swapped around the Caddy load: first the union of old and new, so
	// both generations of handlers find every list they name, then exactly the new
	// ones. On failure the previous lists are restored.
	prevLists := acl.Lists()
	acl.MergeLists(newLists)
	if err := caddy.Load(cfg, true); err != nil {
		acl.SetLists(prevLists)
		admin.abort()
		pipe.abort()
		return fmt.Errorf("applying config: %w", err)
	}
	acl.SetLists(newLists)
	pipe.commit()
	admin.commit()

	sum := sha256.Sum256(cfg)
	metrics.SetConfigVersion(hex.EncodeToString(sum[:6]))
	metrics.SetCRSVersion(waf.CRSVersion)
	metrics.RegisterEventCounters(a.pipe.stats)
	a.ready.Store(true)
	a.logger.Info("config applied", "path", a.path, "sites", len(root.Sites))
	return nil
}

// Activate makes root the live configuration (the configsvc.Activator
// contract). It is safe to call concurrently with Reload and Stop, and works
// whether or not a file-based Start happened: the control plane drives the data
// plane through this method alone.
func (a *App) Activate(ctx context.Context, root *config.Root) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.activate(ctx, root); err != nil {
		return err
	}
	a.running = true
	return nil
}

// EventStats reports how many security events were published and dropped since start.
func (a *App) EventStats() (published, dropped uint64) { return a.pipe.stats() }

// AdminAddr returns the admin listener's bound address, or nil when it is off.
func (a *App) AdminAddr() net.Addr { return a.admin.Addr() }

// Stop shuts Caddy down gracefully.
func (a *App) Stop(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		return nil
	}
	a.running = false
	a.ready.Store(false)
	caddyErr := caddy.Stop()
	pipeErr := a.pipe.stop() // after Caddy, so in-flight requests still publish
	a.admin.close(ctx)
	if caddyErr != nil {
		caddyErr = fmt.Errorf("stopping caddy: %w", caddyErr)
	}
	return errors.Join(caddyErr, pipeErr)
}

// Run starts the app, reloads on every value received from reload (SIGHUP in
// production) and stops when ctx is done. A failed reload is logged and
// serving continues on the old config.
func (a *App) Run(ctx context.Context, reload <-chan os.Signal) error {
	if err := a.Start(ctx); err != nil {
		return err
	}
	for {
		select {
		case <-reload:
			a.logger.Info("reload requested", "path", a.path)
			if err := a.Reload(ctx); err != nil {
				a.logger.Error("reload failed; keeping previous config", "error", err)
			}
		case <-ctx.Done():
			return a.Stop(ctx)
		}
	}
}

// buildLists turns the configured ip_lists into immutable sets.
func buildLists(root *config.Root) (map[string]*ipset.Set, error) {
	out := make(map[string]*ipset.Set, len(root.Global.IPLists))
	for _, l := range root.Global.IPLists {
		s, err := ipset.Parse(l.CIDRs)
		if err != nil {
			return nil, fmt.Errorf("list %q: %w", l.Name, err)
		}
		out[l.Name] = s
	}
	return out, nil
}
