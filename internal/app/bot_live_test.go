package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
)

const botConfig = `
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
  trusted_proxies: ["127.0.0.0/8"]
  client_ip_headers: ["X-Forwarded-For"]
sites:
  - id: shop-bot
    hosts: [shop.localhost]
    tls: { mode: none }
    upstreams: { targets: ["%s"] }
    policy:
      mode: block
      rate_limits: [{ name: hammer, match: { paths: ["/search"] }, limit: 3, window: 1m, action: challenge }]
      bot:
        difficulty: 2
        rules: [{ match: { paths: ["/checkout/*"] } }]
`

type botClient struct {
	t    *testing.T
	port int
}

type botReply struct {
	StatusCode int
	Header     http.Header
	Cookies    []*http.Cookie
}

func (c botClient) do(method, target, xff, accept, cookie string, form url.Values) (botReply, string) {
	c.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(c.t.Context(), method, fmt.Sprintf("http://127.0.0.1:%d%s", c.port, target), body)
	require.NoError(c.t, err)
	req.Host = "shop.localhost"
	req.Header.Set("X-Forwarded-For", xff)
	req.Header.Set("User-Agent", "Mozilla/5.0 e2e")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "__sherlock_clearance", Value: cookie}) //nolint:gosec // a request cookie in a test
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := cl.Do(req)
	require.NoError(c.t, err)
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return botReply{StatusCode: res.StatusCode, Header: res.Header, Cookies: res.Cookies()}, string(b)
}

var tokenRE = regexp.MustCompile(`data-token="([^"]+)"`)

// solve mirrors what the browser script does.
func solvePoW(token string, digits int) int {
	prefix := strings.Repeat("0", digits)
	for c := 0; ; c++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", token, c)))
		if strings.HasPrefix(hex.EncodeToString(sum[:]), prefix) {
			return c
		}
	}
}

func TestBotDefenceEndToEnd(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "origin") }))
	defer upstream.Close()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sherlock.yaml")
	require.NoError(t, os.WriteFile(cfgPath, fmt.Appendf(nil, botConfig, strings.TrimPrefix(upstream.URL, "http://")), 0o600))

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
	c := botClient{t: t, port: port}
	const html = "text/html"

	res, body := c.do("GET", "/about", "192.0.2.10", html, "", nil)
	assert.Equal(t, 200, res.StatusCode, "unprotected paths are untouched")
	assert.Equal(t, "origin", body)

	// curl-like clients without JS or an HTML Accept header cannot get clearance.
	res, body = c.do("GET", "/checkout/pay", "192.0.2.10", "*/*", "", nil)
	assert.Equal(t, 403, res.StatusCode)
	assert.NotContains(t, body, "<html")
	assert.Contains(t, body, "event_id")

	// A browser gets the page, solves it, and is let through.
	res, body = c.do("GET", "/checkout/pay", "192.0.2.10", html, "", nil)
	require.Equal(t, 403, res.StatusCode)
	assert.Contains(t, res.Header.Get("Content-Security-Policy"), "script-src 'self'")
	m := tokenRE.FindStringSubmatch(body)
	require.Len(t, m, 2)
	counter := solvePoW(m[1], 2)

	res, _ = c.do("POST", "/.sherlock/challenge/verify", "192.0.2.10", html, "", url.Values{"challenge": {m[1]}, "counter": {fmt.Sprint(counter)}, "return": {"/checkout/pay"}})
	require.Equal(t, 303, res.StatusCode)
	assert.Equal(t, "/checkout/pay", res.Header.Get("Location"))
	var cookie string
	for _, ck := range res.Cookies {
		if ck.Name == "__sherlock_clearance" {
			cookie = ck.Value
			assert.True(t, ck.HttpOnly)
			assert.Equal(t, http.SameSiteLaxMode, ck.SameSite)
		}
	}
	require.NotEmpty(t, cookie)

	res, body = c.do("GET", "/checkout/pay", "192.0.2.10", html, cookie, nil)
	assert.Equal(t, 200, res.StatusCode)
	assert.Equal(t, "origin", body)
	res, _ = c.do("GET", "/checkout/pay", "198.51.100.9", html, cookie, nil)
	assert.Equal(t, 403, res.StatusCode, "the cookie copied to another network prefix is rejected")

	// The script the page loads is served by the data plane itself, from this origin.
	res, body = c.do("GET", "/.sherlock/challenge.js", "192.0.2.10", "", "", nil)
	assert.Equal(t, 200, res.StatusCode)
	assert.Contains(t, body, "sherlock-challenge")

	// A rate limit with action challenge hands over to the bot module.
	for i := range 3 {
		res, _ = c.do("GET", "/search", "192.0.2.50", html, "", nil)
		require.Equal(t, 200, res.StatusCode, "request %d is within the limit", i+1)
	}
	res, body = c.do("GET", "/search", "192.0.2.50", html, "", nil)
	assert.Equal(t, 403, res.StatusCode)
	assert.Contains(t, body, "Checking your browser", "the 4th request is challenged, not blocked with a 429")
}
