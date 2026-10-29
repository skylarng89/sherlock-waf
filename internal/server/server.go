// Package server assembles the control plane around the data plane: the
// database, node key, audit log, configuration service, event writer, the
// TLS API listener and the extension host. `sherlock run` without --config is
// this server; `sherlock run --config` stays the file-driven data plane alone.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/app"
	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/certstore"
	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/tlscert"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/eventwriter"
	"github.com/skylarng89/sherlock-waf/internal/feeds"
	"github.com/skylarng89/sherlock-waf/internal/ops"
	"github.com/skylarng89/sherlock-waf/internal/policy"
	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// Environment variables for the control-plane listener. They are read from the
// environment (not the database) so that a bad stored state cannot lock the
// operator out of the API they need to repair it.
const (
	EnvListen       = "SHERLOCK_ADMIN_LISTEN"
	EnvAllowedCIDRs = "SHERLOCK_ADMIN_ALLOWED_CIDRS"

	// DefaultListen keeps the control plane on loopback unless the operator opts out.
	DefaultListen = "127.0.0.1:9443"

	checkpointEvery = 5 * time.Minute
	tlsRefreshEvery = 6 * time.Hour
)

// Options configures Run.
type Options struct {
	DataDir      string
	DatabaseURL  string
	Listen       string // "" -> $SHERLOCK_ADMIN_LISTEN -> DefaultListen
	AllowedCIDRs []string
	Compiler     compiler.Options
	Info         api.Info
	UI           http.Handler
	Extensions   []extension.Extension
	Logger       *slog.Logger
	// EventsOutput receives the events stdout sink (default os.Stdout).
	EventsOutput io.Writer
	// Ready, when set, is called with the bound API address once serving.
	Ready func(net.Addr)
	// TestHook, when set, receives a function that restarts only the control
	// plane's HTTP listener (graceful stop, then bind the same address again).
	// It exists to prove the data plane does not depend on the API listener.
	TestHook func(restartAPI func(context.Context) error)
}

// Run starts the control plane and blocks until ctx ends, then shuts down in
// order: API listener, data plane (draining events), background jobs, store.
func Run(ctx context.Context, o Options) error {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	log := o.Logger
	dataDir := app.ResolveDataDir(o.DataDir)
	o.Compiler.DataDir = dataDir

	unlock, err := ops.Lock(dataDir)
	if err != nil {
		return fmt.Errorf("starting server: %w", err)
	}
	defer unlock()

	env, err := ops.Open(ctx, ops.OpenOptions{DataDir: dataDir, DatabaseURL: o.DatabaseURL, Logger: log})
	if err != nil {
		return err
	}
	defer func() { _ = env.Close() }()

	bg, stopBG := context.WithCancel(context.WithoutCancel(ctx))
	var jobs sync.WaitGroup
	defer func() { stopBG(); jobs.Wait() }()

	retention := func() int { return 30 }
	writerOpts := eventwriter.Options{}

	// Uploaded certificates reach Caddy as files, written on demand while a
	// configuration compiles; block page templates are loaded before the first
	// activation so a stored configuration that uses one boots with it.
	certFiles := &certstore.Files{Store: env.Store, Secrets: env.Secrets, Dir: filepath.Join(dataDir, "certs")}
	o.Compiler.CertFiles = certFiles.Paths
	if err := loadBlockPages(ctx, env.Store, log); err != nil {
		return err
	}
	dp := app.New("", o.Compiler, log, app.WithEventsOutput(outputOr(o.EventsOutput)),
		app.WithSecurityBusHook(func(pctx context.Context, bus *events.Bus) func() {
			w := eventwriter.New(bus, env.Store, log, writerOpts)
			done := make(chan struct{})
			go func() { defer close(done); w.Run(pctx) }()
			return func() { <-done }
		}))

	fm := feeds.New(feeds.Options{DataDir: dataDir, Logger: log})
	jobs.Go(func() { fm.Run(bg) })
	if err := loadBans(ctx, env, log); err != nil {
		return err
	}
	jobs.Go(func() { persistBans(bg, env, log) })
	defer acl.SetBanSink(nil)

	cfg := configsvc.New(env.Store, env.Audit, &activator{dp: dp, feeds: fm}, log)
	cfg.SetReferenceChecker(ops.ReferenceChecker(env.Store))
	if err := cfg.Boot(ctx); err != nil {
		// Stay up so an operator can fix or roll back through the API; /readyz reports it.
		log.Error("stored configuration could not be activated; serving the API in degraded mode", "error", err)
	}

	host := newHost(o, env, log)
	for _, ext := range o.Extensions {
		if err := ext.Init(ctx, host); err != nil {
			_ = dp.Stop(ctx)
			return fmt.Errorf("initialising extension %s: %w", ext.Name(), err)
		}
		log.Info("extension loaded", "name", ext.Name())
	}
	for _, s := range host.auditSinks {
		env.Audit.AddSink(s)
	}

	authSvc := auth.New(auth.Config{Store: env.Store, Secrets: env.Secrets, Audit: env.Audit, Hasher: env.Hasher, Logger: log})
	info := o.Info
	info.Features = append([]string{"control-plane"}, info.Features...)
	for _, e := range o.Extensions {
		info.Features = append(info.Features, "extension:"+e.Name())
	}
	gate, err := setupGate(ctx, env, dataDir, log)
	if err != nil {
		_ = dp.Stop(ctx)
		return err
	}
	apiSrv, err := api.New(api.Deps{
		Store: env.Store, Config: cfg, Auth: authSvc, Audit: env.Audit, Hasher: env.Hasher,
		Info: info, Authorizer: host.authorizer, Logger: log,
		Secrets: env.Secrets, Certs: certFiles, Setup: gate, DataDir: dataDir,
		Feeds: func() []api.FeedStatus { return feedStatuses(fm) }, EventStats: dp.EventStats,
	})
	if err != nil {
		_ = dp.Stop(ctx)
		return fmt.Errorf("building api: %w", err)
	}

	certs, err := tlscert.New(tlscert.FromEnv(tlscert.Options{DataDir: dataDir, Logger: log}))
	if err != nil {
		_ = dp.Stop(ctx)
		return fmt.Errorf("preparing admin tls: %w", err)
	}
	jobs.Go(func() { certs.Run(bg, tlsRefreshEvery) })
	jobs.Go(func() { audit.RunCheckpointer(bg, env.Store, log, checkpointEvery) })
	jobs.Go(func() { eventwriter.RunRetention(bg, env.Store, log, 0, retention) })

	allow, err := policy.ParseCIDRSet(cidrs(o))
	if err != nil {
		_ = dp.Stop(ctx)
		return fmt.Errorf("admin allowed cidrs: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle(api.BasePath+"/", apiSrv.Handler())
	mountProviders(mux, host.providers)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { plain(w, http.StatusOK, "ok\n") })
	mux.HandleFunc("GET /readyz", readyz(env, cfg))
	ui := o.UI
	if ui == nil {
		ui = http.NotFoundHandler()
	}
	mux.Handle("/", ui)

	addr := listenAddr(o)
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		_ = dp.Stop(ctx)
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	apiL := &apiListener{
		handler: restrict(allow, mux), tlsConf: certs.Config(), addr: ln.Addr().String(),
	}
	apiL.start(ln)
	log.Info("control plane listening", "addr", ln.Addr().String(), "tls_spki_sha256", certs.Fingerprint(), "database", string(env.Store.Dialect()))
	if o.Ready != nil {
		o.Ready(ln.Addr())
	}
	if o.TestHook != nil {
		o.TestHook(apiL.restart)
	}

	var errs []error
	select {
	case err := <-apiL.failed:
		errs = append(errs, fmt.Errorf("serving control plane: %w", err))
	case <-ctx.Done():
	}

	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := apiL.stop(shutdown); err != nil {
		errs = append(errs, fmt.Errorf("shutting down control plane: %w", err))
	}
	if err := dp.Stop(shutdown); err != nil {
		errs = append(errs, fmt.Errorf("stopping data plane: %w", err))
	}
	return errors.Join(errs...)
}

// apiListener owns the control plane's http.Server so it can be stopped and
// started without touching the data plane, which has its own listeners.
type apiListener struct {
	handler http.Handler
	tlsConf *tls.Config
	addr    string

	mu     sync.Mutex
	srv    *http.Server
	errc   chan error
	failed chan error // receives an unexpected Serve error
}

func (a *apiListener) start(ln net.Listener) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failed == nil {
		a.failed = make(chan error, 1)
	}
	srv := &http.Server{
		Handler:           a.handler,
		TLSConfig:         a.tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		err := srv.Serve(tls.NewListener(ln, a.tlsConf))
		errc <- err
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case a.failed <- err:
			default:
			}
		}
	}()
	a.srv, a.errc = srv, errc
}

func (a *apiListener) stop(ctx context.Context) error {
	a.mu.Lock()
	srv, errc := a.srv, a.errc
	a.srv, a.errc = nil, nil
	a.mu.Unlock()
	if srv == nil {
		return nil
	}
	if err := srv.Shutdown(ctx); err != nil {
		return err
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (a *apiListener) restart(ctx context.Context) error {
	if err := a.stop(ctx); err != nil {
		return err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", a.addr)
	if err != nil {
		return fmt.Errorf("rebinding control plane on %s: %w", a.addr, err)
	}
	a.start(ln)
	return nil
}

func outputOr(w io.Writer) io.Writer {
	if w == nil {
		return os.Stdout
	}
	return w
}

func listenAddr(o Options) string {
	switch {
	case o.Listen != "":
		return o.Listen
	case os.Getenv(EnvListen) != "":
		return os.Getenv(EnvListen)
	}
	return DefaultListen
}

func cidrs(o Options) []string {
	if len(o.AllowedCIDRs) > 0 {
		return o.AllowedCIDRs
	}
	var out []string
	for _, c := range strings.Split(os.Getenv(EnvAllowedCIDRs), ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// restrict refuses peers outside the allow-list before anything else runs. An
// empty list allows everyone (the listener binds to loopback by default).
func restrict(allow policy.CIDRSet, next http.Handler) http.Handler {
	if allow.Len() == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, err := policy.ParseRemoteAddr(r.RemoteAddr)
		if err != nil || !allow.Contains(ip) { // fail closed on unparsable peers
			plain(w, http.StatusForbidden, "forbidden\n")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func readyz(env *ops.Env, cfg *configsvc.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case env.Store.Ping(r.Context()) != nil:
			plain(w, http.StatusServiceUnavailable, "database unavailable\n")
		case cfg.Head() == "":
			plain(w, http.StatusServiceUnavailable, "no configuration yet\n")
		case !cfg.Ready():
			plain(w, http.StatusServiceUnavailable, "configuration could not be activated\n")
		default:
			plain(w, http.StatusOK, "ready\n")
		}
	}
}

func plain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// loadBlockPages installs the stored block page templates into the data plane.
func loadBlockPages(ctx context.Context, st store.Store, log *slog.Logger) error {
	var pages []store.BlockPage
	if err := st.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		pages, err = tx.ListBlockPages(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("loading block pages: %w", err)
	}
	for _, p := range pages {
		if err := blockpage.SetTemplate(p.ID, p.HTML); err != nil {
			// A stored template that no longer renders falls back to the built-in page.
			log.Error("stored block page is unusable; the default page will be used", "id", p.ID, "error", err)
		}
	}
	return nil
}

// setupGate opens first-run administrator creation when the node has no
// users, writing the one-time token to a file in the data directory.
func setupGate(ctx context.Context, env *ops.Env, dataDir string, log *slog.Logger) (*api.SetupGate, error) {
	var n int
	if err := env.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		n, err = tx.CountUsers(ctx)
		return err
	}); err != nil {
		return nil, fmt.Errorf("counting users: %w", err)
	}
	if n > 0 {
		_ = os.Remove(filepath.Join(dataDir, api.SetupTokenFile)) // a stale token must not outlive setup
		return nil, nil
	}
	g, err := api.NewSetupGate(dataDir)
	if err != nil {
		return nil, err
	}
	log.Warn("first-run setup is open: this node has no users. Create one with `sherlock user create --admin`, or open the dashboard and enter the one-time token stored in the file below",
		"setup_token_file", g.Path())
	return g, nil
}
