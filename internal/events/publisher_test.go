package events

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

func newPublisher(t *testing.T) *Publisher {
	t.Helper()
	red, err := NewRedactor(nil)
	require.NoError(t, err)
	return &Publisher{Bus: NewBus(64), Redactor: red, Node: "test-node", BodyExcerpt: true}
}

func completed(t *testing.T, target string, d *policy.Decision) Completed {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://shop.example.com"+target, nil)
	r.Header.Set("User-Agent", "curl/8")
	r.Header.Set("Authorization", "Bearer super-secret")
	r.Header.Set("Cookie", "sid=abc")
	r.Header.Set("Content-Type", "application/json")
	return Completed{Request: r, Decision: d, Start: time.Unix(1_700_000_000, 0), Status: 403, Bytes: 123, Total: 4500 * time.Microsecond}
}

func decision() *policy.Decision {
	return policy.NewDecision("01EVENT", "shop", policy.ModeBlock, netip.MustParseAddr("192.0.2.9"))
}

func drain(b *Bus) []*Event {
	s := b.Subscribe(true)
	defer s.Close()
	buf := make([]*Event, 100)
	return append([]*Event(nil), buf[:s.Read(buf)]...)
}

func TestBuildEventFields(t *testing.T) {
	p := newPublisher(t)
	d := decision()
	d.AddFinding(policy.Finding{Module: "waf", RuleID: "942100", Severity: policy.SeverityCritical, Target: "ARGS:id", Matched: "1' OR '1'='1", Score: 5})
	d.Terminate("sherlock_waf", policy.ActionBlock)
	d.AddWAFTime(1500 * time.Microsecond)
	d.SetAnomalyScore(7, 0)

	p.Publish(completed(t, "/login?user=bob&password=hunter2&note=4111111111111111", d))
	evs := drain(p.Bus)
	require.Len(t, evs, 1)
	ev := evs[0]

	assert.Equal(t, "01EVENT", ev.ID)
	assert.Equal(t, SchemaV1, ev.Schema)
	assert.Equal(t, "test-node", ev.Node)
	assert.Equal(t, "block", ev.Action)
	assert.Equal(t, "sherlock_waf", ev.TerminatedBy)
	assert.Equal(t, "192.0.2.9", ev.Client.IP)
	assert.Equal(t, "user=bob&password=[REDACTED]&note=[PAN:****1111]", ev.Request.Query)
	assert.Equal(t, 4.5, ev.Timing.TotalMS)
	assert.Equal(t, 1.5, ev.Timing.WAFMS)
	assert.Equal(t, AnomalyScore{Inbound: 7}, ev.AnomalyScore)
	assert.Equal(t, 403, ev.Response.Status)
	require.Len(t, ev.Findings, 1)
	assert.Equal(t, "critical", ev.Findings[0].Severity)

	assert.Equal(t, map[string]string{"User-Agent": "curl/8", "Content-Type": "application/json"}, ev.Request.Headers,
		"only allow-listed headers; Authorization and Cookie never captured")

	b, err := json.Marshal(ev)
	require.NoError(t, err)
	for _, secret := range []string{"hunter2", "4111111111111111", "super-secret", "sid=abc"} {
		assert.NotContains(t, string(b), secret)
	}
}

func TestBodyExcerptRedactedAndOptional(t *testing.T) {
	p := newPublisher(t)
	d := decision()
	d.Terminate("sherlock_waf", policy.ActionBlock)
	d.SetBodySample("application/json", []byte(`{"user":"bob","password":"hunter2","card":"4111111111111111","note":"4111111111111111"}`))
	p.Publish(completed(t, "/x", d))
	ev := drain(p.Bus)[0]
	assert.NotContains(t, ev.Request.BodyExcerpt, "hunter2")
	assert.NotContains(t, ev.Request.BodyExcerpt, "4111111111111111")
	assert.Contains(t, ev.Request.BodyExcerpt, "bob")

	p2 := newPublisher(t)
	p2.BodyExcerpt = false
	p2.Publish(completed(t, "/x", d))
	assert.Empty(t, drain(p2.Bus)[0].Request.BodyExcerpt, "off by default")
}

func TestCleanRequestsGoToAccessBusOnlyWhenSampled(t *testing.T) {
	p := newPublisher(t)
	clean := decision()

	p.Publish(completed(t, "/ok", clean))
	assert.Equal(t, 0, p.Bus.Len(), "clean requests are not security events")

	p.AccessBus = NewBus(64)
	p.AccessSampleRate = 0
	p.Publish(completed(t, "/ok", clean))
	assert.Equal(t, 0, p.AccessBus.Len(), "rate 0 logs nothing")

	p.AccessSampleRate = 1
	p.Publish(completed(t, "/ok", clean))
	assert.Equal(t, 1, p.AccessBus.Len())
	assert.Equal(t, 0, p.Bus.Len(), "access log is separate from security events")

	// A fixed sequence 0.0, 0.1, ... 0.9 at rate 0.3 admits exactly 0.0, 0.1, 0.2.
	p.AccessSampleRate = 0.3
	i := 0
	p.sample = func() float64 { v := float64(i%10) / 10; i++; return v }
	before := p.AccessBus.Published()
	for range 10 {
		p.Publish(completed(t, "/ok", clean))
	}
	assert.EqualValues(t, 3, p.AccessBus.Published()-before, "sampling honours the rate")
}

func TestLoggedOnlyDecisionIsSecurityEvent(t *testing.T) {
	d := decision()
	d.AddFinding(policy.Finding{Module: "waf"})
	assert.True(t, IsSecurityEvent(d))
	d2 := decision()
	d2.SetAction(policy.ActionRateLimit)
	assert.True(t, IsSecurityEvent(d2))
	assert.False(t, IsSecurityEvent(decision()))
}

func TestNilPublisherAndDefault(t *testing.T) {
	var p *Publisher
	p.Publish(Completed{})
	assert.False(t, p.BodyExcerptEnabled())
	assert.Nil(t, Default())
	pub := newPublisher(t)
	SetDefault(pub)
	t.Cleanup(func() { SetDefault(nil) })
	assert.Same(t, pub, Default())
}

func TestPathAndHeaderBounds(t *testing.T) {
	p := newPublisher(t)
	d := decision()
	d.Terminate("x", policy.ActionBlock)
	c := completed(t, "/"+strings.Repeat("a", 5000), d)
	c.Request.Header.Set("User-Agent", strings.Repeat("u", 5000))
	p.Publish(c)
	ev := drain(p.Bus)[0]
	assert.LessOrEqual(t, len(ev.Request.Path), maxPathBytes)
	assert.LessOrEqual(t, len(ev.Request.Headers["User-Agent"]), maxHeaderBytes)
}
