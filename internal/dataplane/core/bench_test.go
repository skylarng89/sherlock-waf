package core

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

type discardWriter struct{ h http.Header }

func (d *discardWriter) Header() http.Header       { return d.h }
func (*discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (*discardWriter) WriteHeader(int)             {}

func benchHandler(b *testing.B, trusted, headers []string) *Handler {
	b.Helper()
	h := &Handler{SiteID: "shop", Mode: config.ModeBlock, FailMode: config.FailClosed, TrustedProxies: trusted, ClientIPHeaders: headers}
	if err := h.Provision(caddy.Context{}); err != nil {
		b.Fatal(err)
	}
	return h
}

// BenchmarkServeHTTPClean is the per-request overhead of sherlock_core for a
// clean request: IP resolution, event ID, decision, recorder and metrics.
func BenchmarkServeHTTPClean(b *testing.B) {
	h := benchHandler(b, nil, nil)
	r := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "http://shop.example.com/get?id=1", nil)
	r.RemoteAddr = "192.0.2.10:4000"
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error { w.WriteHeader(http.StatusOK); return nil })
	w := &discardWriter{h: http.Header{}}
	b.ReportAllocs()
	for b.Loop() {
		_ = h.ServeHTTP(w, r, next)
	}
}

// BenchmarkServeHTTPFinding includes building and publishing a redacted event.
func BenchmarkServeHTTPFinding(b *testing.B) {
	h := benchHandler(b, nil, nil)
	red, _ := events.NewRedactor(nil)
	events.SetDefault(&events.Publisher{Bus: events.NewBus(events.DefaultBusCapacity), Redactor: red, Node: "bench"})
	b.Cleanup(func() { events.SetDefault(nil) })
	r := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "http://shop.example.com/get?id=1&password=x", nil)
	r.RemoteAddr = "192.0.2.10:4000"
	r.Header.Set("User-Agent", "bench")
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		policy.DecisionFrom(r.Context()).AddFinding(policy.Finding{Module: "waf", RuleID: "942100", Severity: policy.SeverityCritical, Target: "ARGS:id", Matched: "1' OR '1'='1"})
		w.WriteHeader(http.StatusOK)
		return nil
	})
	w := &discardWriter{h: http.Header{}}
	b.ReportAllocs()
	for b.Loop() {
		_ = h.ServeHTTP(w, r, next)
	}
}

func BenchmarkResolveClientIPTrusted(b *testing.B) {
	trusted, _ := policy.ParseCIDRSet([]string{"10.0.0.0/8"})
	r := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.5:1"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.7, 10.0.0.9")
	hdrs := []string{"X-Forwarded-For"}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = resolveClientIP(r, trusted, hdrs)
	}
}
