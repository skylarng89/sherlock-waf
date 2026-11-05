package core

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

func newHandler(t *testing.T, mode config.Mode, fail config.FailMode, proxies, headers []string) *Handler {
	t.Helper()
	h := &Handler{SiteID: "shop", Mode: mode, FailMode: fail, TrustedProxies: proxies, ClientIPHeaders: headers}
	require.NoError(t, h.Provision(caddy.Context{}))
	require.NoError(t, h.Validate())
	return h
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func request(t *testing.T, remote string, hdr map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://shop.example.com/get?token=secret", nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestResolveClientIP(t *testing.T) {
	trusted, err := policy.ParseCIDRSet([]string{"10.0.0.0/8"})
	require.NoError(t, err)
	xff := []string{"X-Forwarded-For"}
	tests := []struct {
		name    string
		remote  string
		hdr     map[string]string
		headers []string
		want    string
	}{
		{"untrusted peer ignores header", "203.0.113.9:1", map[string]string{"X-Forwarded-For": "1.1.1.1"}, xff, "203.0.113.9"},
		{"trusted peer uses header", "10.0.0.5:1", map[string]string{"X-Forwarded-For": "198.51.100.7"}, xff, "198.51.100.7"},
		{"rightmost untrusted wins over spoofed left", "10.0.0.5:1", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.7, 10.0.0.9"}, xff, "198.51.100.7"},
		{"all trusted falls back to peer", "10.0.0.5:1", map[string]string{"X-Forwarded-For": "10.1.1.1, 10.2.2.2"}, xff, "10.0.0.5"},
		{"garbled hop stops the walk", "10.0.0.5:1", map[string]string{"X-Forwarded-For": "6.6.6.6, garbage, 10.0.0.9"}, xff, "10.0.0.5"},
		{"no header falls back to peer", "10.0.0.5:1", nil, xff, "10.0.0.5"},
		{"second header used", "10.0.0.5:1", map[string]string{"CF-Connecting-IP": "198.51.100.8"}, []string{"X-Forwarded-For", "CF-Connecting-IP"}, "198.51.100.8"},
		{"ipv6 peer", "[2001:db8::1]:443", nil, xff, "2001:db8::1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveClientIP(request(t, tc.remote, tc.hdr), trusted, tc.headers)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.String())
		})
	}

	_, err = resolveClientIP(request(t, "not-an-address", nil), trusted, xff)
	require.Error(t, err)
}

func TestServeHTTPCreatesDecisionAndLogsFindings(t *testing.T) {
	logs := captureLogs(t)
	h := newHandler(t, config.ModeDetect, config.FailOpen, nil, nil)

	var seen *policy.Decision
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		seen = policy.DecisionFrom(r.Context())
		require.NotNil(t, seen)
		seen.AddFinding(policy.Finding{Module: "waf", RuleID: "942100", Severity: policy.SeverityCritical, Matched: "secret-payload"})
		seen.SetAction(policy.ActionLog)
		w.WriteHeader(http.StatusOK)
		return nil
	})

	rec := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(rec, request(t, "192.0.2.4:5", nil), next))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "192.0.2.4", seen.ClientIP.String())
	assert.Len(t, seen.EventID, 26)

	var line map[string]any
	require.NoError(t, json.Unmarshal(logs.Bytes(), &line))
	assert.Equal(t, "decision", line["msg"])
	assert.Equal(t, seen.EventID, line["event_id"])
	assert.Equal(t, "log", line["action"])
	assert.Equal(t, "/get", line["path"])
	assert.EqualValues(t, 200, line["status"])
	assert.NotContains(t, logs.String(), "token=secret", "query strings must not be logged")
	assert.NotContains(t, logs.String(), "secret-payload", "matched data must not be logged")
	assert.Contains(t, logs.String(), "942100")
}

func TestCleanRequestsAreNotLogged(t *testing.T) {
	logs := captureLogs(t)
	h := newHandler(t, config.ModeBlock, config.FailClosed, nil, nil)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), request(t, "192.0.2.4:5", nil), next))
	assert.Empty(t, logs.String())
}

func TestDownstreamPanicIsRecovered(t *testing.T) {
	logs := captureLogs(t)
	before := policy.InternalErrors.Load()
	h := newHandler(t, config.ModeBlock, config.FailClosed, nil, nil)
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { panic("boom") })

	r := request(t, "192.0.2.4:5", nil)
	r.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(rec, r, next))

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.NotEmpty(t, rec.Header().Get(blockpage.EventIDHeader))
	assert.Equal(t, before+1, policy.InternalErrors.Load())
	assert.Contains(t, logs.String(), "recovered panic")
	assert.NotContains(t, rec.Body.String(), "boom", "panic text must not reach the client")
}

func TestPanicAfterResponseStartedDoesNotWriteTwice(t *testing.T) {
	captureLogs(t)
	h := newHandler(t, config.ModeBlock, config.FailClosed, nil, nil)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		panic("late")
	})
	rec := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(rec, request(t, "192.0.2.4:5", nil), next))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "partial", rec.Body.String())
}

func TestAbortHandlerPanicPropagates(t *testing.T) {
	captureLogs(t)
	h := newHandler(t, config.ModeBlock, config.FailClosed, nil, nil)
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { panic(http.ErrAbortHandler) })
	assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
		_ = h.ServeHTTP(httptest.NewRecorder(), request(t, "192.0.2.4:5", nil), next)
	})
}

func TestSetupFailureFollowsFailMode(t *testing.T) {
	captureLogs(t)
	for _, tc := range []struct {
		fail       config.FailMode
		wantCode   int
		wantCalled bool
	}{
		{config.FailClosed, http.StatusServiceUnavailable, false},
		{config.FailOpen, http.StatusOK, true},
	} {
		t.Run(string(tc.fail), func(t *testing.T) {
			h := newHandler(t, config.ModeBlock, tc.fail, nil, nil)
			called := false
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
				called = true
				w.WriteHeader(http.StatusOK)
				return nil
			})
			rec := httptest.NewRecorder()
			// An unparsable peer address makes IP resolution fail.
			require.NoError(t, h.ServeHTTP(rec, request(t, "garbage", nil), next))
			assert.Equal(t, tc.wantCode, rec.Code)
			assert.Equal(t, tc.wantCalled, called)
		})
	}
}

func TestValidateAndProvision(t *testing.T) {
	require.Error(t, (&Handler{}).Validate())
	require.Error(t, (&Handler{SiteID: "a", Mode: "bogus", FailMode: config.FailOpen}).Validate())
	require.Error(t, (&Handler{SiteID: "a", Mode: config.ModeBlock, FailMode: "bogus"}).Validate())
	require.Error(t, (&Handler{TrustedProxies: []string{"nope"}}).Provision(caddy.Context{}))
}

func TestModuleInfo(t *testing.T) {
	info := (&Handler{}).CaddyModule()
	assert.Equal(t, caddy.ModuleID("http.handlers.sherlock_core"), info.ID)
	assert.IsType(t, &Handler{}, info.New())
}

func TestEventIDsAreUniquePerRequest(t *testing.T) {
	captureLogs(t)
	h := newHandler(t, config.ModeDetect, config.FailOpen, nil, nil)
	h.now = func() time.Time { return time.UnixMilli(1_700_000_000_000) }
	seen := map[string]bool{}
	next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
		id := policy.DecisionFrom(r.Context()).EventID
		assert.False(t, seen[id])
		seen[id] = true
		return nil
	})
	for range 100 {
		require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), request(t, "192.0.2.4:5", nil), next))
	}
}

func TestBlockWebSocketsRefusesUpgradesInEveryMode(t *testing.T) {
	for _, mode := range []config.Mode{config.ModeDetect, config.ModeBlock} {
		h := newHandler(t, mode, config.FailOpen, nil, nil)
		h.BlockWebSockets = true

		reached := false
		next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { reached = true; return nil })

		r := request(t, "192.0.2.4:5", map[string]string{"Upgrade": "websocket", "Connection": "keep-alive, Upgrade"})
		rec := httptest.NewRecorder()
		require.NoError(t, h.ServeHTTP(rec, r, next))
		assert.Equal(t, http.StatusForbidden, rec.Code, "mode %s", mode)
		assert.False(t, reached, "the upgrade must not reach the origin (mode %s)", mode)
		assert.NotEmpty(t, rec.Header().Get(blockpage.EventIDHeader), "the refusal carries an event id like any block")

		// Ordinary requests, and Upgrade headers without a Connection: upgrade token, pass.
		for _, hdr := range []map[string]string{nil, {"Upgrade": "websocket"}, {"Connection": "upgrade"}} {
			reached = false
			rec = httptest.NewRecorder()
			require.NoError(t, h.ServeHTTP(rec, request(t, "192.0.2.4:5", hdr), next))
			assert.True(t, reached, "%v must pass (mode %s)", hdr, mode)
		}
	}

	allowed := newHandler(t, config.ModeBlock, config.FailOpen, nil, nil)
	reached := false
	require.NoError(t, allowed.ServeHTTP(httptest.NewRecorder(),
		request(t, "192.0.2.4:5", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}),
		caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { reached = true; return nil })))
	assert.True(t, reached, "upgrades pass unless the site denies them")
}
