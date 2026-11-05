package events

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

// BenchmarkPublishNoSubscriber is the AC5 loop: a full ring and nobody
// reading must stay cheap and never block.
func BenchmarkPublishNoSubscriber(b *testing.B) {
	bus := NewBus(DefaultBusCapacity)
	e := &Event{ID: "x"}
	b.ReportAllocs()
	for b.Loop() {
		bus.Publish(e)
	}
}

func BenchmarkPublishParallel(b *testing.B) {
	bus := NewBus(DefaultBusCapacity)
	sub := bus.Subscribe(false)
	defer sub.Close()
	e := &Event{ID: "x"}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bus.Publish(e)
		}
	})
}

func BenchmarkBuildEvent(b *testing.B) {
	red, _ := NewRedactor(nil)
	p := &Publisher{Bus: NewBus(16), Redactor: red, Node: "bench"}
	d := policy.NewDecision("01BENCH", "shop", policy.ModeBlock, netip.MustParseAddr("192.0.2.9"))
	d.AddFinding(policy.Finding{Module: "waf", RuleID: "942100", Severity: policy.SeverityCritical, Target: "ARGS:id", Matched: "1' OR '1'='1"})
	d.Terminate("sherlock_waf", policy.ActionBlock)
	r := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "http://shop.example.com/login?user=bob&password=hunter2&id=1", nil)
	r.Header.Set("User-Agent", "bench")
	c := Completed{Request: r, Decision: d, Status: 403}
	b.ReportAllocs()
	for b.Loop() {
		_ = p.Build(c)
	}
}

func BenchmarkRedactQuery(b *testing.B) {
	red, _ := NewRedactor(nil)
	q := "user=bob&password=hunter2&note=4111111111111111&page=2&sort=price"
	b.ReportAllocs()
	for b.Loop() {
		_ = red.Query(q)
	}
}
