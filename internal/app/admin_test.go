package app

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/config"
)

func adminGet(t *testing.T, addr, method, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, "http://"+addr+path, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(b)
}

func TestAdminServerEndpointsAndReadiness(t *testing.T) {
	ready := false
	a := newAdminServer(func() bool { return ready })
	require.NoError(t, a.configure(t.Context(), config.Admin{Listen: "127.0.0.1:0"}))
	defer a.close(t.Context())
	addr := a.Addr().String()

	code, body := adminGet(t, addr, http.MethodGet, "/healthz")
	assert.Equal(t, 200, code)
	assert.Equal(t, "ok\n", body)

	code, _ = adminGet(t, addr, http.MethodGet, "/readyz")
	assert.Equal(t, http.StatusServiceUnavailable, code, "not ready until the app says so")
	ready = true
	code, _ = adminGet(t, addr, http.MethodGet, "/readyz")
	assert.Equal(t, 200, code)

	code, body = adminGet(t, addr, http.MethodGet, "/metrics")
	assert.Equal(t, 200, code)
	assert.Contains(t, body, "go_goroutines")

	code, _ = adminGet(t, addr, http.MethodGet, "/nope")
	assert.Equal(t, 404, code)
	code, _ = adminGet(t, addr, http.MethodPost, "/metrics")
	assert.Equal(t, http.StatusMethodNotAllowed, code, "only GET/HEAD")
}

func TestAdminServerCIDRAllowList(t *testing.T) {
	a := newAdminServer(nil)
	require.NoError(t, a.configure(t.Context(), config.Admin{Listen: "127.0.0.1:0", AllowedCIDRs: []string{"10.0.0.0/8"}}))
	defer a.close(t.Context())
	code, _ := adminGet(t, a.Addr().String(), http.MethodGet, "/healthz")
	assert.Equal(t, http.StatusForbidden, code, "127.0.0.1 is outside the allow-list")

	require.NoError(t, a.configure(t.Context(), config.Admin{Listen: "127.0.0.1:0", AllowedCIDRs: []string{"127.0.0.0/8"}}))
	code, _ = adminGet(t, a.Addr().String(), http.MethodGet, "/healthz")
	assert.Equal(t, 200, code, "allow-list changes apply without rebinding")

	assert.False(t, a.permitted("garbage"), "unparsable peers fail closed")
}

func TestAdminServerOffMoveAndErrors(t *testing.T) {
	a := newAdminServer(nil)
	defer a.close(t.Context())
	require.NoError(t, a.configure(t.Context(), config.Admin{Listen: config.AdminOff}))
	assert.Nil(t, a.Addr())

	require.NoError(t, a.configure(t.Context(), config.Admin{Listen: "127.0.0.1:0"}))
	first := a.Addr().String()
	require.NotNil(t, a.Addr())

	// A port that is already taken must fail and leave the old listener serving.
	busy := newAdminServer(nil)
	require.NoError(t, busy.configure(t.Context(), config.Admin{Listen: "127.0.0.1:0"}))
	defer busy.close(t.Context())
	err := a.configure(t.Context(), config.Admin{Listen: busy.Addr().String()})
	require.Error(t, err)
	assert.Equal(t, first, a.Addr().String())
	code, _ := adminGet(t, first, http.MethodGet, "/healthz")
	assert.Equal(t, 200, code)

	require.NoError(t, a.configure(t.Context(), config.Admin{Listen: config.AdminOff}))
	assert.Nil(t, a.Addr())
	require.Error(t, a.configure(t.Context(), config.Admin{Listen: "off", AllowedCIDRs: []string{"x"}}))
}

// TestMetricsAndHealthLive checks the series that exist after real traffic.
func TestMetricsAndHealthLive(t *testing.T) {
	up := upstreamServer(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sherlock.yaml")
	require.NoError(t, os.WriteFile(cfgPath, fmt.Appendf(nil, `
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
  events: { sinks: { stdout: false, file: false } }
sites:
  - id: shop
    hosts: [shop.localhost]
    tls: { mode: none }
    policy: { mode: block }
    upstreams: { targets: ["%s"] }
`, up), 0o600))

	port := freePort(t)
	a := New(cfgPath, compiler.Options{HTTPPort: port, HTTPSPort: freePort(t), DataDir: filepath.Join(dir, "data")}, nil)
	require.NoError(t, a.Start(t.Context()))
	defer func() { require.NoError(t, a.Stop(t.Context())) }()
	admin := a.AdminAddr().String()

	code, _ := adminGet(t, admin, http.MethodGet, "/readyz")
	assert.Equal(t, 200, code, "ready after the first successful config load")

	assert.Equal(t, 200, send(t, port, http.MethodGet, "shop.localhost", "/ok", nil).status)
	assert.Equal(t, 403, send(t, port, http.MethodGet, "shop.localhost", "/x?id=1%27%20OR%20%271%27=%271", nil).status)

	require.Eventually(t, func() bool {
		_, body := adminGet(t, admin, http.MethodGet, "/metrics")
		return strings.Contains(body, `sherlock_requests_total{action="block",site="shop"} 1`)
	}, 5*time.Second, 25*time.Millisecond)

	_, body := adminGet(t, admin, http.MethodGet, "/metrics")
	for _, want := range []string{
		`sherlock_requests_total{action="allow",site="shop"} 1`,
		`sherlock_request_duration_seconds_count{site="shop"} 2`,
		`sherlock_waf_duration_seconds_count{site="shop"} 2`,
		`sherlock_crs_version_info{version="4.25.0"} 1`,
		`sherlock_config_version_info{version="`,
		"sherlock_events_published_total 1",
		"sherlock_events_dropped_total 0",
		"sherlock_internal_errors_total",
	} {
		assert.Contains(t, body, want)
	}

	require.NoError(t, a.Reload(t.Context()))
	_, body = adminGet(t, admin, http.MethodGet, "/metrics")
	assert.Equal(t, 1, strings.Count(body, "sherlock_config_version_info{"), "only the active config version is published")
}
