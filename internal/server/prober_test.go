package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// fakeConfig serves a fixed configuration to the background jobs.
type fakeConfig struct {
	root *config.Root
	err  error
}

func (f *fakeConfig) Current(context.Context) (store.ConfigVersion, *config.Root, error) {
	return store.ConfigVersion{}, f.root, f.err
}

func siteWith(id string, u config.Upstreams) config.Site {
	return config.Site{ID: id, Hosts: []string{id + ".example.test"}, Upstreams: u}
}

func hostPort(t *testing.T, rawURL string) string {
	t.Helper()
	return strings.TrimPrefix(rawURL, "http://")
}

func unhealthyTarget(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

func newTestProber(cfg activeConfig) *upstreamProber {
	return newUpstreamProber(cfg, nil, discard())
}

func statusOf(p *upstreamProber, site, target string) (bool, bool) {
	for _, s := range p.Snapshot() {
		if s.Site == site && s.Upstream == target {
			return s.Healthy, true
		}
	}
	return false, false
}

func TestProberFollowsTheHealthCheckPathFromHealthyToUnhealthy(t *testing.T) {
	var code atomic.Int32
	code.Store(http.StatusOK)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(int(code.Load()))
	}))
	target := hostPort(t, origin.URL)
	cfg := &fakeConfig{root: &config.Root{Sites: []config.Site{siteWith("shop", config.Upstreams{
		Targets:     []string{target},
		HealthCheck: config.HealthCheck{Path: "/healthz", Timeout: config.Duration(time.Second)},
	})}}}
	p := newTestProber(cfg)

	p.probeOnce(t.Context())
	healthy, ok := statusOf(p, "shop", target)
	require.True(t, ok)
	assert.True(t, healthy)

	code.Store(http.StatusServiceUnavailable)
	p.probeOnce(t.Context())
	healthy, _ = statusOf(p, "shop", target)
	assert.False(t, healthy, "a 5xx from the health path is unhealthy")

	origin.Close()
	p.probeOnce(t.Context())
	healthy, _ = statusOf(p, "shop", target)
	assert.False(t, healthy, "a closed origin is unhealthy")
}

func TestProberDoesNotFollowRedirects(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()
	target := hostPort(t, origin.URL)
	p := newTestProber(&fakeConfig{root: &config.Root{Sites: []config.Site{siteWith("shop", config.Upstreams{
		Targets: []string{target}, HealthCheck: config.HealthCheck{Path: "/healthz"},
	})}}})

	p.probeOnce(t.Context())
	healthy, _ := statusOf(p, "shop", target)
	assert.False(t, healthy, "a redirect is not a proof the origin answers the health path")
}

func TestProberWithoutAHealthPathOnlyDialsTheTarget(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	open := ln.Addr().String()
	closed := unhealthyTarget(t)

	p := newTestProber(&fakeConfig{root: &config.Root{Sites: []config.Site{siteWith("shop", config.Upstreams{
		Targets: []string{open, closed},
	})}}})
	p.probeOnce(t.Context())

	healthy, _ := statusOf(p, "shop", open)
	assert.True(t, healthy)
	healthy, _ = statusOf(p, "shop", closed)
	assert.False(t, healthy)
}

func TestProberPublishesNothingForSitesWithoutUpstreams(t *testing.T) {
	p := newTestProber(&fakeConfig{root: &config.Root{Sites: []config.Site{{ID: "bare", Hosts: []string{"bare.example.test"}}}}})
	p.probeOnce(t.Context())
	assert.Empty(t, p.Snapshot())
}

func TestProberBeforeAnyConfigurationReportsNothing(t *testing.T) {
	p := newTestProber(&fakeConfig{err: configsvc.ErrNotFound})
	p.probeOnce(t.Context())
	assert.Empty(t, p.Snapshot())
}

func TestProberKeepsTheLastSnapshotWhenTheConfigurationCannotBeRead(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	cfg := &fakeConfig{root: &config.Root{Sites: []config.Site{siteWith("shop", config.Upstreams{Targets: []string{ln.Addr().String()}})}}}
	p := newTestProber(cfg)
	p.probeOnce(t.Context())

	cfg.err = errReadFailed
	p.probeOnce(t.Context())
	healthy, ok := statusOf(p, "shop", ln.Addr().String())
	assert.True(t, ok && healthy, "a transient read failure must not blank the gauge")
}

func TestProberRunStopsWhenTheContextEnds(t *testing.T) {
	p := newTestProber(&fakeConfig{err: configsvc.ErrNotFound})
	p.every = time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); p.Run(ctx) }()
	time.Sleep(5 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }
