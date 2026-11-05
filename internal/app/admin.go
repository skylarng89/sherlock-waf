package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/metrics"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

// adminServer serves /metrics, /healthz and /readyz on the admin listener,
// which is separate from proxied traffic. Access is limited to the configured
// CIDRs (empty means any); everything else is refused, and only GET/HEAD are
// accepted.
type adminServer struct {
	ready func() bool

	mu      sync.Mutex
	srv     *http.Server
	addr    string // configured listen value
	bound   net.Addr
	allowed policy.CIDRSet
	errc    chan error
}

func newAdminServer(ready func() bool) *adminServer { return &adminServer{ready: ready} }

// prepare gets the admin listener ready for cfg without changing what is
// served: a new address is bound immediately (so a bind failure rejects the
// change), but the old listener keeps serving until commit. abort closes a
// listener bound here.
func (a *adminServer) prepare(ctx context.Context, cfg config.Admin) (pendingChange, error) {
	allowed, err := policy.ParseCIDRSet(cfg.AllowedCIDRs)
	if err != nil {
		return pendingChange{}, fmt.Errorf("admin allowed_cidrs: %w", err)
	}
	a.mu.Lock()
	current := a.addr
	a.mu.Unlock()

	setAllowed := func() {
		a.mu.Lock()
		a.allowed = allowed
		a.mu.Unlock()
	}
	switch cfg.Listen {
	case current:
		return pendingChange{commit: setAllowed, abort: func() {}}, nil
	case config.AdminOff:
		return pendingChange{
			commit: func() {
				a.mu.Lock()
				defer a.mu.Unlock()
				a.allowed = allowed
				a.closeLocked(ctx)
				a.addr = cfg.Listen
			},
			abort: func() {},
		}, nil
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return pendingChange{}, fmt.Errorf("admin listener %s: %w", cfg.Listen, err)
	}
	return pendingChange{
		commit: func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.allowed = allowed
			a.closeLocked(ctx)
			srv := &http.Server{
				Handler:           a.handler(),
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       10 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       60 * time.Second,
				MaxHeaderBytes:    16 << 10,
			}
			errc := make(chan error, 1)
			go func() { errc <- srv.Serve(ln) }()
			a.srv, a.bound, a.addr, a.errc = srv, ln.Addr(), cfg.Listen, errc
		},
		abort: func() { _ = ln.Close() },
	}, nil
}

// configure prepares and immediately commits cfg.
func (a *adminServer) configure(ctx context.Context, cfg config.Admin) error {
	pc, err := a.prepare(ctx, cfg)
	if err != nil {
		return err
	}
	pc.commit()
	return nil
}

func (a *adminServer) closeLocked(ctx context.Context) {
	if a.srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_ = a.srv.Shutdown(ctx)
	if err := <-a.errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Warn("admin listener stopped unexpectedly", "error", err)
	}
	a.srv, a.bound, a.errc = nil, nil, nil
}

// close stops the listener.
func (a *adminServer) close(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closeLocked(ctx)
	a.addr = ""
}

// Addr returns the bound address, or nil when the listener is off.
func (a *adminServer) Addr() net.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.bound
}

func (a *adminServer) permitted(remote string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.allowed.Len() == 0 {
		return true
	}
	ip, err := policy.ParseRemoteAddr(remote)
	return err == nil && a.allowed.Contains(ip) // fail closed on unparsable peers
}

func (a *adminServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{Registry: metrics.Registry}))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		plain(w, http.StatusOK, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if a.ready != nil && a.ready() {
			plain(w, http.StatusOK, "ready\n")
			return
		}
		plain(w, http.StatusServiceUnavailable, "not ready\n")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.permitted(r.RemoteAddr) {
			plain(w, http.StatusForbidden, "forbidden\n")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func plain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
