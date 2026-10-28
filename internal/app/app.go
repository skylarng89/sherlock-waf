// Package app runs the data plane: it loads the YAML config, compiles it to
// Caddy JSON and drives an in-process Caddy. Configuration is only ever
// swapped in after it has validated and compiled, so a bad file on reload
// leaves the running config untouched.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

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
	_ "github.com/skylarng89/sherlock-waf/internal/dataplane/core" // registers sherlock_core
	_ "github.com/skylarng89/sherlock-waf/internal/dataplane/waf"  // registers sherlock_waf
)

// App owns the lifecycle of the embedded Caddy. Caddy keeps process-global
// state, so only one App may be running per process.
type App struct {
	path   string
	opts   compiler.Options
	logger *slog.Logger

	mu      sync.Mutex
	running bool
}

// New returns an App that reads configPath.
func New(configPath string, opts compiler.Options, logger *slog.Logger) *App {
	if logger == nil {
		logger = slog.Default()
	}
	return &App{path: configPath, opts: opts, logger: logger}
}

// Start loads the config and starts serving. It fails without side effects if
// the config is invalid.
func (a *App) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running {
		return errors.New("app already started")
	}
	if err := a.apply(); err != nil {
		return err
	}
	a.running = true
	return nil
}

// Reload re-reads the file and swaps the configuration. On any failure
// (validation, compilation, or Caddy refusing the config) the previous
// configuration keeps serving.
func (a *App) Reload() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		return errors.New("app not started")
	}
	return a.apply()
}

func (a *App) apply() error {
	root, err := config.Load(a.path)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	cfg, err := compiler.Compile(root, a.opts)
	if err != nil {
		return fmt.Errorf("compiling config: %w", err)
	}
	// Caddy rolls back to the previous config itself if the new one fails to
	// provision or start.
	if err := caddy.Load(cfg, true); err != nil {
		return fmt.Errorf("applying config: %w", err)
	}
	a.logger.Info("config applied", "path", a.path, "sites", len(root.Sites))
	return nil
}

// Stop shuts Caddy down gracefully.
func (a *App) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		return nil
	}
	a.running = false
	if err := caddy.Stop(); err != nil {
		return fmt.Errorf("stopping caddy: %w", err)
	}
	return nil
}

// Run starts the app, reloads on every value received from reload (SIGHUP in
// production) and stops when ctx is done. A failed reload is logged and
// serving continues on the old config.
func (a *App) Run(ctx context.Context, reload <-chan os.Signal) error {
	if err := a.Start(); err != nil {
		return err
	}
	for {
		select {
		case <-reload:
			a.logger.Info("reload requested", "path", a.path)
			if err := a.Reload(); err != nil {
				a.logger.Error("reload failed; keeping previous config", "error", err)
			}
		case <-ctx.Done():
			return a.Stop()
		}
	}
}
