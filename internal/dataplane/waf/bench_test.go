package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

func benchServe(b *testing.B, h *Handler, method, target, ct, body string) {
	b.Helper()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		w.WriteHeader(http.StatusOK)
		return nil
	})
	w := httptest.NewRecorder()
	b.ReportAllocs()
	for b.Loop() {
		var rdr io.Reader = http.NoBody
		if body != "" {
			rdr = strings.NewReader(body)
		}
		r := httptest.NewRequestWithContext(b.Context(), method, "http://shop.example.com"+target, rdr)
		r.RemoteAddr = "192.0.2.10:4000"
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0")
		r.Header.Set("Accept", "text/html")
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		d := policy.NewDecision("01BENCH", "shop", policy.Mode(h.Mode), netip.MustParseAddr("192.0.2.10"))
		r = r.WithContext(policy.WithDecision(r.Context(), d))
		w.Body.Reset()
		_ = h.ServeHTTP(w, r, next)
	}
}

func benchHandler(b *testing.B, mode config.Mode, pl int) *Handler {
	b.Helper()
	h := &Handler{
		SiteID: "shop", FailMode: config.FailClosed,
		Settings: Settings{Mode: mode, ParanoiaLevel: pl, BlockingParanoiaLevel: pl, InboundThreshold: 5, OutboundThreshold: 4, MaxBodyBytes: 10 << 20},
	}
	if err := h.Validate(); err != nil {
		b.Fatal(err)
	}
	if err := h.Provision(caddyContext()); err != nil {
		b.Fatal(err)
	}
	return h
}

func BenchmarkInspectBenignGETPL1(b *testing.B) {
	benchServe(b, benchHandler(b, config.ModeBlock, 1), http.MethodGet, "/products?category=shoes&page=2&sort=price", "", "")
}

func BenchmarkInspectBenignGETPL4(b *testing.B) {
	benchServe(b, benchHandler(b, config.ModeBlock, 4), http.MethodGet, "/products?category=shoes&page=2&sort=price", "", "")
}

func BenchmarkInspectAttackGETPL1(b *testing.B) {
	benchServe(b, benchHandler(b, config.ModeBlock, 1), http.MethodGet, "/get?id="+url.QueryEscape("1' OR '1'='1"), "", "")
}

func BenchmarkInspectJSONPOSTPL1(b *testing.B) {
	body := `{"customer_id":42,"items":[{"sku":"SKU-0042","qty":2}],"note":"Please leave at the front door"}`
	benchServe(b, benchHandler(b, config.ModeBlock, 1), http.MethodPost, "/api/v1/orders", "application/json", body)
}

func BenchmarkInspectStaticSkipped(b *testing.B) {
	h := benchHandler(b, config.ModeBlock, 1)
	h.SkipInspectionExtensions = config.DefaultSkipInspectionExtensions()
	_ = h.Provision(caddyContext())
	benchServe(b, h, http.MethodGet, "/static/app.js", "", "")
}
