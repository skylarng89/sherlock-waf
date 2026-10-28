package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
)

// launch starts the data plane for cfg and returns its HTTP port. The app is
// stopped (and checked for a clean shutdown) when the test ends.
func launch(t *testing.T, cfg string) int {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sherlock.yaml")
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0o600))

	port := freePort(t)
	a := New(path, compiler.Options{HTTPPort: port, HTTPSPort: freePort(t), DataDir: filepath.Join(dir, "data")}, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, make(chan os.Signal)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(15 * time.Second):
			t.Error("Run did not return after context cancel")
		}
	})
	require.Eventually(t, func() bool {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 20*time.Second, 50*time.Millisecond)
	return port
}

func upstreamServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func send(t *testing.T, port int, method, host, target string, hdr map[string]string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, fmt.Sprintf("http://127.0.0.1:%d%s", port, target), nil)
	require.NoError(t, err)
	req.Host = host
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return reply{status: resp.StatusCode, header: resp.Header, body: string(b)}
}

// TestEndpointPolicyLive is acceptance criterion 5: global PL1, site block,
// endpoint PL2 on POST /login. "1 or 2" only scores at PL2 and above.
func TestEndpointPolicyLive(t *testing.T) {
	up := upstreamServer(t)
	port := launch(t, fmt.Sprintf(`
schema_version: 1
global:
  defaults: { waf: { paranoia_level: 1 } }
sites:
  - id: shop
    hosts: [shop.localhost]
    tls: { mode: none }
    policy: { mode: block }
    upstreams: { targets: ["%s"] }
    endpoints:
      - id: login
        match: { path: /login, methods: [POST] }
        policy: { waf: { paranoia_level: 2 } }
`, up))

	probe := "?q=" + url.QueryEscape("1 or 2")

	assert.Equal(t, http.StatusOK, send(t, port, http.MethodGet, "shop.localhost", "/search"+probe, nil).status, "site default stays at PL1")
	assert.Equal(t, http.StatusOK, send(t, port, http.MethodGet, "shop.localhost", "/login"+probe, nil).status, "GET /login is not the endpoint (method-specific)")
	assert.Equal(t, http.StatusOK, send(t, port, http.MethodPost, "shop.localhost", "/other"+probe, nil).status, "other paths stay at PL1")
	assert.Equal(t, http.StatusForbidden, send(t, port, http.MethodPost, "shop.localhost", "/login"+probe, nil).status, "POST /login runs at PL2")
}

func TestModeOffEndpointIsNotInspected(t *testing.T) {
	up := upstreamServer(t)
	port := launch(t, fmt.Sprintf(`
schema_version: 1
sites:
  - id: shop
    hosts: [shop.localhost]
    tls: { mode: none }
    policy: { mode: block }
    upstreams: { targets: ["%s"] }
    endpoints:
      - id: health
        match: { path: /healthz }
        policy: { mode: off }
`, up))
	attack := "?id=" + url.QueryEscape("1' OR '1'='1")
	assert.Equal(t, http.StatusOK, send(t, port, http.MethodGet, "shop.localhost", "/healthz"+attack, nil).status)
	assert.Equal(t, http.StatusForbidden, send(t, port, http.MethodGet, "shop.localhost", "/other"+attack, nil).status)
}

func TestTrustedProxiesConfigServesLive(t *testing.T) {
	up := upstreamServer(t)
	port := launch(t, fmt.Sprintf(`
schema_version: 1
global:
  trusted_proxies: ["127.0.0.0/8"]
sites:
  - id: shop
    hosts: [shop.localhost]
    tls: { mode: none }
    policy: { mode: block }
    upstreams: { targets: ["%s"] }
`, up))
	r := send(t, port, http.MethodGet, "shop.localhost", "/get?id="+url.QueryEscape("1' OR '1'='1"), map[string]string{"X-Forwarded-For": "198.51.100.7"})
	assert.Equal(t, http.StatusForbidden, r.status)
}
