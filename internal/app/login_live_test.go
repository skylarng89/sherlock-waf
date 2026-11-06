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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
)

const loginConfig = `
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
  trusted_proxies: ["127.0.0.0/8"]
  client_ip_headers: ["X-Forwarded-For"]
sites:
  - id: bank-login
    hosts: [bank.localhost]
    tls: { mode: none }
    upstreams: { targets: ["%s"] }
    policy:
      mode: block
      bot: { difficulty: 2 }
      login_protection:
        enabled: true
        endpoints: [{ path: /api/login, username_field: email }]
        thresholds: { per_ip: 3, per_username: 4, per_device: 40, window: 10m }
        action: challenge
`

// loginUpstream fails every login whose password is not "correct horse" with 401
// and remembers how many attempts reached it per username and per client address.
type loginUpstream struct {
	mu     sync.Mutex
	byUser map[string]int
	byIP   map[string]int
	total  int
}

func (u *loginUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/login" {
		_, _ = io.WriteString(w, "<html>sign in</html>")
		return
	}
	_ = r.ParseForm()
	ip, _, _ := strings.Cut(r.Header.Get("X-Forwarded-For"), ",")
	u.mu.Lock()
	u.byUser[r.PostForm.Get("email")]++
	u.byIP[strings.TrimSpace(ip)]++
	u.total++
	u.mu.Unlock()
	if r.PostForm.Get("password") == "correct horse" {
		_, _ = io.WriteString(w, "welcome")
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
}

func TestLoginProtectionEndToEnd(t *testing.T) {
	up := &loginUpstream{byUser: map[string]int{}, byIP: map[string]int{}}
	srv := httptest.NewServer(up)
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sherlock.yaml")
	cfg := strings.ReplaceAll(loginConfig, "id: bank-login", "id: "+uniqueSite("bank-login"))
	require.NoError(t, os.WriteFile(cfgPath, fmt.Appendf(nil, cfg, strings.TrimPrefix(srv.URL, "http://")), 0o600))

	events, logs := &syncBuffer{}, &syncBuffer{}
	port := freePort(t)
	a := New(cfgPath, compiler.Options{HTTPPort: port, HTTPSPort: freePort(t), DataDir: filepath.Join(dir, "data")},
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})), WithEventsOutput(events))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, make(chan os.Signal)) }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(20 * time.Second):
			t.Error("did not stop")
		}
	}
	t.Cleanup(stop)
	require.Eventually(t, func() bool {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 20*time.Second, 50*time.Millisecond)

	type reply struct {
		status  int
		cookies []*http.Cookie
		body    string
	}
	do := func(method, target, xff, ua, accept, cookie string, form url.Values) reply {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequestWithContext(t.Context(), method, fmt.Sprintf("http://127.0.0.1:%d%s", port, target), body)
		require.NoError(t, err)
		req.Host = "bank.localhost"
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set("User-Agent", ua)
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
		require.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return reply{status: res.StatusCode, cookies: res.Cookies(), body: string(b)}
	}
	login := func(xff, ua, user, pass, cookie string) int {
		t.Helper()
		return do(http.MethodPost, "/api/login", xff, ua, "", cookie, url.Values{"email": {user}, "password": {pass}}).status
	}

	// Credential stuffing, scaled down from the k6 run (test/k6/login-stuffing.js):
	// 50 usernames x 20 passwords from 200 addresses, a different tool build per
	// account, every password wrong. Limits: 3 per address, 4 per account, 40 per device.
	var reached, refused int
	for i := range 1000 {
		xff := fmt.Sprintf("10.9.%d.%d", i%200/100, i%200%100+1) // 200 distinct addresses
		ua := fmt.Sprintf("stuffing-kit/%d", i%50)
		user := fmt.Sprintf("user-%02d@bank.test", i%50)
		switch st := login(xff, ua, user, fmt.Sprintf("guess-%d", i), ""); st {
		case http.StatusUnauthorized:
			reached++
		case http.StatusForbidden:
			refused++
		default:
			t.Fatalf("attempt %d: unexpected status %d", i, st)
		}
	}
	up.mu.Lock()
	maxPerUser, maxPerIP := 0, 0
	for k, n := range up.byUser {
		if strings.HasPrefix(k, "user-") {
			maxPerUser = max(maxPerUser, n)
		}
	}
	for _, n := range up.byIP {
		maxPerIP = max(maxPerIP, n)
	}
	up.mu.Unlock()
	assert.LessOrEqual(t, maxPerUser, 4, "no account was guessed at more than its threshold")
	assert.LessOrEqual(t, maxPerIP, 3, "no address got more than its threshold")
	assert.LessOrEqual(t, reached, 200, "at most 4 guesses at each of the 50 accounts reached the origin")
	assert.GreaterOrEqual(t, refused, 800, "the rest were refused before reaching the origin")

	// A normal customer, elsewhere, with their own browser, signs in throughout.
	const ownerUA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"
	assert.Equal(t, http.StatusOK, login("203.0.113.200", ownerUA, "ada@bank.test", "correct horse", ""),
		"the attack does not lock real customers out")

	// The owner of an attacked account is challenged, once, and then signs in:
	// the account is over its limit for the attacker, so the real owner is asked
	// to prove they are a browser.
	const owner = "203.0.113.201"
	assert.Equal(t, http.StatusForbidden, login(owner, ownerUA, "user-07@bank.test", "correct horse", ""), "the attempt itself is refused")
	page := do(http.MethodGet, "/login", owner, ownerUA, "text/html", "", nil)
	require.Equal(t, http.StatusForbidden, page.status, "the bot module now serves this client its challenge")
	assert.Contains(t, page.body, "Checking your browser")
	m := tokenRE.FindStringSubmatch(page.body)
	require.Len(t, m, 2)
	verify := do(http.MethodPost, "/.sherlock/challenge/verify", owner, ownerUA, "text/html", "",
		url.Values{"challenge": {m[1]}, "counter": {fmt.Sprint(solvePoW(m[1], 2))}, "return": {"/login"}})
	require.Equal(t, http.StatusSeeOther, verify.status)
	var cookie string
	for _, ck := range verify.cookies {
		if ck.Name == "__sherlock_clearance" {
			cookie = ck.Value
		}
	}
	require.NotEmpty(t, cookie)
	assert.Equal(t, http.StatusOK, login(owner, ownerUA, "user-07@bank.test", "correct horse", cookie), "a cleared client signs in")
	assert.Equal(t, http.StatusOK, do(http.MethodGet, "/login", owner, ownerUA, "text/html", cookie, nil).status)

	// Privacy: findings reached the event stream, and no username, password or
	// hash of one is in the events or the logs.
	require.Eventually(t, func() bool {
		return strings.Contains(events.String(), `"login-username"`) && strings.Contains(events.String(), `"module":"login"`)
	}, 10*time.Second, 50*time.Millisecond, "login findings are in the event stream")
	stop()
	for name, text := range map[string]string{"events": events.String(), "logs": logs.String()} {
		assert.NotContains(t, text, "user-", name)
		assert.NotContains(t, text, "bank.test", name)
		assert.NotContains(t, text, "guess-", name)
		assert.NotContains(t, text, "correct horse", name)
	}
}
