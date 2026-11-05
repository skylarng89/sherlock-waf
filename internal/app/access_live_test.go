package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
)

const accessConfig = `
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
  trusted_proxies: ["127.0.0.0/8"]
  client_ip_headers: ["X-Forwarded-For"]
  ip_lists:
    - { name: office, cidrs: ["203.0.113.0/24"] }
    - { name: bad, cidrs: ["198.51.100.0/24"] }
sites:
  - id: shop-acl
    hosts: [shop.localhost]
    tls: { mode: none }
    upstreams: { targets: ["%s"] }
    policy:
      mode: block
      acl: { allow_lists: [office], deny_lists: %s }
      rate_limits:
        - { name: limited, match: { paths: ["/limited"] }, limit: 10, window: 1m, action: block }
      auto_ban: { blocks_threshold: 3, window: 5m, ban_duration: 30m }
`

func as(t *testing.T, port int, client, target string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, target), nil)
	require.NoError(t, err)
	req.Host = "shop.localhost"
	req.Header.Set("X-Forwarded-For", client)
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// TestAccessControlEndToEnd runs ACL, rate limits and auto-ban through a real
// Caddy, including a configuration reload that must change list contents
// without a restart.
func TestAccessControlEndToEnd(t *testing.T) {
	acl.Bans.Replace(nil)
	t.Cleanup(func() { acl.Bans.Replace(nil) })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer upstream.Close()
	addr := strings.TrimPrefix(upstream.URL, "http://")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sherlock.yaml")
	write := func(deny string) {
		require.NoError(t, os.WriteFile(cfgPath, fmt.Appendf(nil, accessConfig, addr, deny), 0o600))
	}
	write("[bad]")

	port := freePort(t)
	a := New(cfgPath, compiler.Options{HTTPPort: port, HTTPSPort: freePort(t), DataDir: filepath.Join(dir, "data")}, slog.New(slog.DiscardHandler), WithEventsOutput(io.Discard))
	hup := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, hup) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(20 * time.Second):
			t.Error("did not stop")
		}
	})
	require.Eventually(t, func() bool {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 20*time.Second, 50*time.Millisecond)

	t.Run("deny list", func(t *testing.T) {
		status, body := as(t, port, "198.51.100.7", "/")
		assert.Equal(t, 403, status)
		assert.Contains(t, body, "event_id")
		status, _ = as(t, port, "192.0.2.50", "/")
		assert.Equal(t, 200, status)
	})

	t.Run("rate limit: 10 per minute then 429 with Retry-After", func(t *testing.T) {
		for i := range 10 {
			status, _ := as(t, port, "192.0.2.60", "/limited")
			require.Equal(t, 200, status, "request %d", i+1)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/limited", port), nil)
		require.NoError(t, err)
		req.Host = "shop.localhost"
		req.Header.Set("X-Forwarded-For", "192.0.2.60")
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_ = res.Body.Close()
		assert.Equal(t, 429, res.StatusCode)
		assert.NotEmpty(t, res.Header.Get("Retry-After"))

		status, _ := as(t, port, "192.0.2.61", "/limited")
		assert.Equal(t, 200, status, "another client is unaffected")
	})

	t.Run("allow list exempts a client from rate limits", func(t *testing.T) {
		for i := range 15 {
			status, _ := as(t, port, "203.0.113.9", "/limited")
			require.Equal(t, 200, status, "request %d", i+1)
		}
	})

	t.Run("allow list does not skip the WAF", func(t *testing.T) {
		status, _ := as(t, port, "203.0.113.9", "/get?id="+url.QueryEscape("1' OR '1'='1"))
		assert.Equal(t, 403, status, "an allow-listed client is still inspected")
	})

	t.Run("auto-ban after repeated blocks", func(t *testing.T) {
		attack := "/get?id=" + url.QueryEscape("1' OR '1'='1")
		for range 4 {
			status, _ := as(t, port, "192.0.2.70", attack)
			require.Equal(t, 403, status)
		}
		require.Eventually(t, func() bool {
			_, banned := acl.Bans.Active(netipAddr(t, "192.0.2.70"), "shop-acl", time.Now())
			return banned
		}, 3*time.Second, 20*time.Millisecond, "the fourth block bans the client")
		status, _ := as(t, port, "192.0.2.70", "/")
		assert.Equal(t, 403, status, "a banned client is refused even for a benign request")
		status, _ = as(t, port, "192.0.2.71", "/")
		assert.Equal(t, 200, status)
	})

	t.Run("reload changes lists without a restart", func(t *testing.T) {
		write("[]")
		hup <- syscall.SIGHUP
		require.Eventually(t, func() bool {
			status, _ := as(t, port, "198.51.100.7", "/")
			return status == 200
		}, 10*time.Second, 100*time.Millisecond, "the denied client passes once the list is no longer applied")
		write("[bad]")
		hup <- syscall.SIGHUP
		require.Eventually(t, func() bool {
			status, _ := as(t, port, "198.51.100.7", "/")
			return status == 403
		}, 10*time.Second, 100*time.Millisecond)
	})
}

func netipAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	require.NoError(t, err)
	return a
}
