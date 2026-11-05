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
	"sync"
	"sync/atomic"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/metrics"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

const (
	probeEvery          = 15 * time.Second
	probeConcurrency    = 8
	defaultProbeTimeout = 2 * time.Second
)

// activeConfig is the part of configsvc.Service the background jobs read.
type activeConfig interface {
	Current(ctx context.Context) (store.ConfigVersion, *config.Root, error)
}

// upstreamProber checks every configured origin on a fixed cadence, off the
// request path. Caddy keeps its own upstream pool state private, so the health
// shown in sherlock_upstream_healthy is Sherlock's own probe, not Caddy's.
type upstreamProber struct {
	cfg activeConfig
	// clientCertPaths materialises an upstream client certificate for the
	// probe; nil means the probe cannot present one.
	clientCertPaths func(id string) (certFile, keyFile string, err error)
	logger          *slog.Logger
	every           time.Duration

	snap atomic.Pointer[[]metrics.UpstreamStatus]
}

func newUpstreamProber(cfg activeConfig, clientCertPaths func(string) (string, string, error), logger *slog.Logger) *upstreamProber {
	return &upstreamProber{cfg: cfg, clientCertPaths: clientCertPaths, logger: logger, every: probeEvery}
}

// Snapshot returns the results of the last completed cycle. It never does I/O,
// so it is safe to call from a scrape.
func (p *upstreamProber) Snapshot() []metrics.UpstreamStatus {
	if s := p.snap.Load(); s != nil {
		return *s
	}
	return nil
}

// Run probes until ctx ends. It returns only after the last cycle has finished,
// so the caller can wait for it during shutdown.
func (p *upstreamProber) Run(ctx context.Context) {
	ticker := time.NewTicker(p.every)
	defer ticker.Stop()
	for {
		p.probeOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type probeJob struct {
	site   config.Site
	target string
}

func (p *upstreamProber) probeOnce(ctx context.Context) {
	_, root, err := p.cfg.Current(ctx)
	switch {
	case errors.Is(err, configsvc.ErrNotFound):
		p.snap.Store(&[]metrics.UpstreamStatus{})
		return
	case err != nil:
		p.logger.Warn("upstream probe skipped: configuration unavailable", "error", err)
		return
	}

	var jobs []probeJob
	for _, s := range root.Sites {
		for _, t := range s.Upstreams.Targets {
			jobs = append(jobs, probeJob{site: s, target: t})
		}
	}
	results := make([]metrics.UpstreamStatus, len(jobs))
	sem := make(chan struct{}, probeConcurrency)
	var wg sync.WaitGroup
	for i, j := range jobs {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Go(func() {
			defer func() { <-sem }()
			results[i] = metrics.UpstreamStatus{Site: j.site.ID, Upstream: j.target, Healthy: p.probe(ctx, j)}
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return // a cycle cut short by shutdown must not replace the last full snapshot
	}
	p.snap.Store(&results)
}

// probe reports whether one origin is healthy. Without a health check path it
// only needs a TCP connection; with one, it needs a 2xx answer to a GET.
func (p *upstreamProber) probe(ctx context.Context, j probeJob) bool {
	u := j.site.Upstreams
	timeout := u.HealthCheck.Timeout.Std()
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", j.target)
	}
	if u.HealthCheck.Path == "" {
		conn, err := dial(ctx, "tcp", j.target)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}

	tlsConf, err := p.probeTLS(u)
	if err != nil {
		p.logger.Warn("upstream probe cannot present its client certificate", "site", j.site.ID, "upstream", j.target, "error", err)
		return false
	}
	scheme := "http"
	if u.TLS.Enabled {
		scheme = "https"
	}
	// The transport always dials the probed target, and redirects are not followed,
	// so the answer comes from this origin and never from a redirect target.
	transport := &http.Transport{DialContext: dial, TLSClientConfig: tlsConf, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+j.target+u.HealthCheck.Path, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.CopyN(io.Discard, resp.Body, 4<<10)
	// 2xx matches Caddy's default expectation for active health checks.
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (p *upstreamProber) probeTLS(u config.Upstreams) (*tls.Config, error) {
	if !u.TLS.Enabled {
		return nil, nil
	}
	conf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Mirrors the operator's upstream setting, which Caddy applies to traffic too.
		InsecureSkipVerify: u.TLS.InsecureSkipVerify, //nolint:gosec // operator-chosen per upstream
	}
	if id := u.TLS.ClientCertID; id != "" {
		if p.clientCertPaths == nil {
			return nil, errors.New("no certificate source configured")
		}
		certFile, keyFile, err := p.clientCertPaths(id)
		if err != nil {
			return nil, err
		}
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate %s: %w", id, err)
		}
		conf.Certificates = []tls.Certificate{pair}
	}
	return conf, nil
}
