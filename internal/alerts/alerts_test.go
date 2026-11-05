package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/metrics"
	"github.com/skylarng89/sherlock-waf/internal/notify"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeSource struct {
	mu        sync.Mutex
	blocks    []SiteCount
	recent    []CountryCount
	past      []CountryCount
	certs     []CertExpiry
	feeds     []FeedStatus
	dropped   uint64
	upstreams []Upstream
	err       error
	windows   [][2]time.Time
}

func (f *fakeSource) BlocksBySite(context.Context, time.Time, time.Time) ([]SiteCount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blocks, f.err
}

func (f *fakeSource) TopCountries(_ context.Context, _ string, from, to time.Time) ([]CountryCount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.windows = append(f.windows, [2]time.Time{from, to})
	if len(f.windows)%2 == 1 {
		return f.recent, f.err
	}
	return f.past, f.err
}

func (f *fakeSource) CertExpiries(context.Context) ([]CertExpiry, error) { return f.certs, f.err }
func (f *fakeSource) FeedStatuses(context.Context) ([]FeedStatus, error) { return f.feeds, f.err }
func (f *fakeSource) Upstreams(context.Context) ([]Upstream, error)      { return f.upstreams, f.err }

func (f *fakeSource) EventsDropped(context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dropped, f.err
}

type sent struct {
	channel string
	msg     notify.Message
}

type fakeNotifier struct {
	mu   sync.Mutex
	sent []sent
	fail map[string]error
	hang chan struct{}
}

func (n *fakeNotifier) Notify(ctx context.Context, ch string, m notify.Message) error {
	if n.hang != nil && ch == "hang" {
		select {
		case <-n.hang:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := n.fail[ch]; err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, sent{ch, m})
	return nil
}

func (n *fakeNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.sent)
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

type harness struct {
	e   *Engine
	src *fakeSource
	n   *fakeNotifier
	clk *clock
	r   *[]Rule
}

func newHarness(rules ...Rule) *harness {
	h := &harness{src: &fakeSource{}, n: &fakeNotifier{}, clk: &clock{t: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}}
	rs := rules
	h.r = &rs
	h.e = New(Options{
		Source: h.src, Notifier: h.n, Now: h.clk.now, Logger: quiet,
		Rules: func(context.Context) ([]Rule, error) { return *h.r, nil },
	})
	return h
}

func (h *harness) tick(t *testing.T) {
	t.Helper()
	h.e.EvaluateOnce(t.Context())
	h.e.Wait()
}

func params(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func blocksRule() Rule {
	return Rule{
		ID: "r1", Name: "Block spike", Enabled: true, Kind: KindBlocksThreshold, Severity: "critical",
		Params: params(blocksParams{Threshold: 100, WindowSeconds: 300}), CooldownSeconds: 600, ChannelIDs: []string{"mail", "chat"},
	}
}

func TestFiresWithinOneTickNoRepeatInCooldownThenFiresAgain(t *testing.T) {
	h := newHarness(blocksRule())
	h.src.blocks = []SiteCount{{"shop", 50}}
	h.tick(t)
	assert.Zero(t, h.n.count(), "below the threshold nothing fires")

	h.clk.advance(DefaultEvery)
	h.src.blocks = []SiteCount{{"shop", 101}}
	h.tick(t)
	require.Equal(t, 2, h.n.count(), "the first evaluation after the condition holds notifies both channels")
	m := h.n.sent[0].msg
	assert.Equal(t, "critical", m.Severity)
	assert.Equal(t, "shop", m.Fields["site"])
	assert.Equal(t, "101", m.Fields["blocks"])

	for range 19 { // 19 more ticks = 9.5 minutes, inside the 10 minute cool-down
		h.clk.advance(DefaultEvery)
		h.tick(t)
	}
	assert.Equal(t, 2, h.n.count(), "no repeat during the cool-down")
	st := h.e.Status()[0]
	assert.EqualValues(t, 19, st.Suppressed)
	assert.True(t, st.Firing)

	h.clk.advance(DefaultEvery) // 10 minutes after the first alert
	h.tick(t)
	assert.Equal(t, 4, h.n.count(), "fires again after the cool-down while still true")
	assert.EqualValues(t, 2, h.e.Status()[0].Fired)
}

func TestConditionClearingInsideCooldownDoesNotReArm(t *testing.T) {
	h := newHarness(blocksRule())
	h.src.blocks = []SiteCount{{"shop", 500}}
	h.tick(t)
	h.clk.advance(time.Minute)
	h.src.blocks = nil
	h.tick(t)
	assert.False(t, h.e.Status()[0].Firing)
	h.clk.advance(time.Minute)
	h.src.blocks = []SiteCount{{"shop", 500}}
	h.tick(t)
	assert.Equal(t, 2, h.n.count(), "a flapping condition does not bypass the cool-down")

	h.clk.advance(20 * time.Minute)
	h.src.blocks = nil
	h.tick(t) // cleared and cooled down: dedup entry is pruned
	h.src.blocks = []SiteCount{{"shop", 500}}
	h.clk.advance(time.Second)
	h.tick(t)
	assert.Equal(t, 4, h.n.count())
}

func TestDedupIsPerSubject(t *testing.T) {
	h := newHarness(blocksRule())
	h.src.blocks = []SiteCount{{"a", 200}}
	h.tick(t)
	h.src.blocks = []SiteCount{{"a", 200}, {"b", 300}}
	h.clk.advance(time.Minute)
	h.tick(t)
	assert.Equal(t, 4, h.n.count(), "site b alerts even though a is cooling down")
}

func TestThresholdIsStrictlyGreaterThanAndSiteFilter(t *testing.T) {
	r := blocksRule()
	r.Params = params(blocksParams{SiteID: "shop", Threshold: 100, WindowSeconds: 300})
	h := newHarness(r)
	h.src.blocks = []SiteCount{{"shop", 100}, {"other", 9999}}
	h.tick(t)
	assert.Zero(t, h.n.count())
}

func TestNewCountry(t *testing.T) {
	r := Rule{
		ID: "c", Name: "New country", Enabled: true, Kind: KindNewCountry, ChannelIDs: []string{"chat"},
		Params: params(countryParams{WindowSeconds: 300, BaselineSeconds: 86400}),
	}
	h := newHarness(r)
	h.src.recent = []CountryCount{{"NG", 5}, {"DE", 3}, {"<<", 9}}
	h.src.past = nil
	h.tick(t)
	assert.Zero(t, h.n.count(), "without a baseline every country looks new, so nothing fires")

	h.src.windows = nil
	h.src.past = []CountryCount{{"DE", 100}, {"US", 50}}
	h.clk.advance(time.Minute)
	h.tick(t)
	require.Equal(t, 1, h.n.count())
	assert.Equal(t, "NG", h.n.sent[0].msg.Fields["country"], "DE is known and the malformed code is ignored")
	require.Len(t, h.src.windows, 2)
	assert.Equal(t, h.src.windows[0][0], h.src.windows[1][1], "the baseline ends where the window begins")
}

func TestCertExpiring(t *testing.T) {
	r := Rule{ID: "x", Name: "Cert", Enabled: true, Kind: KindCertExpiring, Params: params(certParams{Days: 14}), ChannelIDs: []string{"mail"}}
	h := newHarness(r)
	now := h.clk.now()
	h.src.certs = []CertExpiry{
		{"shop", "ok.example", now.Add(60 * 24 * time.Hour)},
		{"shop", "soon.example", now.Add(5*24*time.Hour + time.Hour)},
		{"shop", "old.example", now.Add(-time.Hour)},
	}
	h.tick(t)
	require.Equal(t, 2, h.n.count())
	hosts := []string{h.n.sent[0].msg.Fields["host"], h.n.sent[1].msg.Fields["host"]}
	assert.ElementsMatch(t, []string{"soon.example", "old.example"}, hosts)
}

func TestFeedFailureAndUpstream(t *testing.T) {
	h := newHarness(
		Rule{ID: "f", Name: "Feed", Enabled: true, Kind: KindFeedFailure, ChannelIDs: []string{"c"}},
		Rule{ID: "u", Name: "Up", Enabled: true, Kind: KindUpstreamUnhealthy, Params: params(upstreamParams{SiteID: "shop"}), ChannelIDs: []string{"c"}},
	)
	h.src.feeds = []FeedStatus{{"firehol", true}, {"geoip", false}}
	h.src.upstreams = []Upstream{{"shop", "10.0.0.1:80", false}, {"blog", "10.0.0.2:80", false}, {"shop", "10.0.0.3:80", true}}
	h.tick(t)
	require.Equal(t, 2, h.n.count())
	got := map[string]string{}
	for _, s := range h.n.sent {
		got[s.msg.RuleID] = s.msg.Fields["feed"] + s.msg.Fields["upstream"]
	}
	assert.Equal(t, map[string]string{"f": "firehol", "u": "10.0.0.1:80"}, got)
}

func TestEventsDroppedNeedsABaselineAndFiresOnIncrease(t *testing.T) {
	h := newHarness(Rule{ID: "d", Name: "Dropped", Enabled: true, Kind: KindEventsDropped, CooldownSeconds: 60, ChannelIDs: []string{"c"}})
	h.src.dropped = 40 // dropped before the engine started
	h.tick(t)
	assert.Zero(t, h.n.count())
	h.clk.advance(2 * time.Minute)
	h.tick(t)
	assert.Zero(t, h.n.count(), "no increase, no alert")
	h.clk.advance(2 * time.Minute)
	h.src.dropped = 47
	h.tick(t)
	require.Equal(t, 1, h.n.count())
	assert.Equal(t, "7", h.n.sent[0].msg.Fields["dropped"])
	h.src.dropped = 3 // process restarted
	h.clk.advance(2 * time.Minute)
	h.tick(t)
	assert.Equal(t, 1, h.n.count(), "a counter reset is not an increase")
}

func TestFailingChannelAndFailingRuleDoNotBlockOthers(t *testing.T) {
	h := newHarness(blocksRule(),
		Rule{ID: "f", Name: "Feed", Enabled: true, Kind: KindFeedFailure, ChannelIDs: []string{"chat"}})
	h.n.fail = map[string]error{"mail": errors.New("smtp down")}
	h.src.blocks = []SiteCount{{"shop", 500}}
	h.src.feeds = []FeedStatus{{"firehol", true}}
	h.tick(t)

	assert.Equal(t, 2, h.n.count(), "chat gets the block alert and the feed alert despite mail failing")
	states := map[string]RuleState{}
	for _, s := range h.e.Status() {
		states[s.RuleID] = s
	}
	assert.Contains(t, states["r1"].LastNotifyError, "smtp down")
	assert.Empty(t, states["f"].LastNotifyError)
}

func TestSourceErrorIsRecordedPerRule(t *testing.T) {
	h := newHarness(blocksRule(), Rule{ID: "f", Name: "Feed", Enabled: true, Kind: KindFeedFailure, ChannelIDs: []string{"c"}})
	h.src.err = errors.New("db locked")
	h.tick(t)
	for _, s := range h.e.Status() {
		assert.Contains(t, s.LastError, "db locked")
		assert.False(t, s.Firing)
	}
	h.src.err = nil
	h.tick(t)
	for _, s := range h.e.Status() {
		assert.Empty(t, s.LastError, "the error clears once evaluation succeeds")
	}
}

func TestNotifierPanicIsContained(t *testing.T) {
	h := newHarness(blocksRule())
	h.e.o.Notifier = notifierFunc(func(context.Context, string, notify.Message) error { panic("boom") })
	h.src.blocks = []SiteCount{{"shop", 500}}
	h.tick(t)
	assert.Contains(t, h.e.Status()[0].LastNotifyError, "panicked")
}

type notifierFunc func(context.Context, string, notify.Message) error

func (f notifierFunc) Notify(ctx context.Context, ch string, m notify.Message) error {
	return f(ctx, ch, m)
}

func TestDisabledAndRemovedRulesAreForgotten(t *testing.T) {
	h := newHarness(blocksRule())
	h.src.blocks = []SiteCount{{"shop", 500}}
	h.tick(t)
	require.Len(t, h.e.Status(), 1)

	(*h.r)[0].Enabled = false
	h.tick(t)
	assert.Empty(t, h.e.Status())
	assert.Empty(t, h.e.tracked)

	(*h.r)[0].Enabled = true
	h.clk.advance(time.Minute)
	h.tick(t)
	assert.Equal(t, 4, h.n.count(), "re-enabling starts fresh and alerts")

	*h.r = nil
	h.tick(t)
	assert.Empty(t, h.e.Status())
	assert.Empty(t, h.e.tracked)
}

func TestFindingsAndTrackingAreBounded(t *testing.T) {
	h := newHarness(blocksRule())
	for i := range 200 {
		h.src.blocks = append(h.src.blocks, SiteCount{fmt.Sprintf("s%03d", i), 1000})
	}
	h.tick(t)
	assert.Equal(t, maxFindings*2, h.n.count(), "a flood of subjects is capped per evaluation")
	assert.Len(t, h.e.tracked, maxFindings)
}

func TestRunEvaluatesImmediatelyAndOnTheTimerAndWaitsForSends(t *testing.T) {
	h := newHarness(blocksRule())
	h.src.blocks = []SiteCount{{"shop", 500}}
	h.e.o.Every = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { h.e.Run(ctx); close(done) }()
	require.Eventually(t, func() bool { return h.n.count() == 2 }, 2*time.Second, 5*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestHungChannelDoesNotStopEvaluation(t *testing.T) {
	h := newHarness(Rule{ID: "f", Name: "Feed", Enabled: true, Kind: KindFeedFailure, ChannelIDs: []string{"hang", "chat"}})
	h.n.hang = make(chan struct{})
	h.src.feeds = []FeedStatus{{"firehol", true}}
	h.e.EvaluateOnce(t.Context())
	require.Eventually(t, func() bool { return h.n.count() == 1 }, 2*time.Second, 5*time.Millisecond, "chat is notified while the other channel hangs")
	close(h.n.hang)
	h.e.Wait()
}

func TestValidate(t *testing.T) {
	good := blocksRule()
	tests := []struct {
		name   string
		mutate func(*Rule)
		ok     bool
	}{
		{"valid", func(*Rule) {}, true},
		{"empty name", func(r *Rule) { r.Name = " " }, false},
		{"bad severity", func(r *Rule) { r.Severity = "fatal" }, false},
		{"cooldown too short", func(r *Rule) { r.CooldownSeconds = 10 }, false},
		{"cooldown too long", func(r *Rule) { r.CooldownSeconds = MaxCooldownSeconds + 1 }, false},
		{"cooldown default", func(r *Rule) { r.CooldownSeconds = 0 }, true},
		{"too many channels", func(r *Rule) {
			r.ChannelIDs = nil
			for i := range MaxChannels + 1 {
				r.ChannelIDs = append(r.ChannelIDs, fmt.Sprint(i))
			}
		}, false},
		{"duplicate channel", func(r *Rule) { r.ChannelIDs = []string{"a", "a"} }, false},
		{"unknown kind", func(r *Rule) { r.Kind = "magic" }, false},
		{"threshold zero", func(r *Rule) { r.Params = params(blocksParams{Threshold: 0, WindowSeconds: 300}) }, false},
		{"window too small", func(r *Rule) { r.Params = params(blocksParams{Threshold: 1, WindowSeconds: 59}) }, false},
		{"window too large", func(r *Rule) { r.Params = params(blocksParams{Threshold: 1, WindowSeconds: MaxWindowSeconds + 1}) }, false},
		{"unknown param", func(r *Rule) { r.Params = json.RawMessage(`{"threshold":1,"window_seconds":60,"x":1}`) }, false},
		{"bad site id", func(r *Rule) { r.Params = params(blocksParams{SiteID: "a b", Threshold: 1, WindowSeconds: 60}) }, false},
		{"cert days 0", func(r *Rule) { r.Kind, r.Params = KindCertExpiring, params(certParams{Days: 0}) }, false},
		{"cert days 366", func(r *Rule) { r.Kind, r.Params = KindCertExpiring, params(certParams{Days: 366}) }, false},
		{"cert days ok", func(r *Rule) { r.Kind, r.Params = KindCertExpiring, params(certParams{Days: 30}) }, true},
		{"feed failure no params", func(r *Rule) { r.Kind, r.Params = KindFeedFailure, nil }, true},
		{"feed failure with params", func(r *Rule) { r.Kind, r.Params = KindFeedFailure, json.RawMessage(`{"a":1}`) }, false},
		{"new country ok", func(r *Rule) {
			r.Kind, r.Params = KindNewCountry, params(countryParams{WindowSeconds: 300, BaselineSeconds: 3600})
		}, true},
		{"new country no baseline", func(r *Rule) { r.Kind, r.Params = KindNewCountry, params(countryParams{WindowSeconds: 300}) }, false},
		{"upstream any site", func(r *Rule) { r.Kind, r.Params = KindUpstreamUnhealthy, nil }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := good
			tc.mutate(&r)
			err := ValidateRule(r)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
	assert.ElementsMatch(t, Kinds(), []string{KindBlocksThreshold, KindNewCountry, KindCertExpiring, KindFeedFailure, KindEventsDropped, KindUpstreamUnhealthy})
}

func TestStoreSource(t *testing.T) {
	var gotDim string
	var gotFilter store.EventFilter
	src := StoreSource{
		TopValues: func(_ context.Context, dim string, f store.EventFilter, _ int) ([]store.ValueCount, error) {
			gotDim, gotFilter = dim, f
			return []store.ValueCount{{Value: "shop", Count: 7}}, nil
		},
		Certs:   func() []metrics.CertExpiry { return []metrics.CertExpiry{{Site: "s", Host: "h"}} },
		Feeds:   func() []FeedStatus { return []FeedStatus{{"f", true}} },
		Dropped: func() uint64 { return 9 },
		Upstream: func() []metrics.UpstreamStatus {
			return []metrics.UpstreamStatus{{Site: "s", Upstream: "u", Healthy: true}}
		},
	}
	from, to := time.Unix(0, 0), time.Unix(60, 0)
	bs, err := src.BlocksBySite(t.Context(), from, to)
	require.NoError(t, err)
	assert.Equal(t, []SiteCount{{"shop", 7}}, bs)
	assert.Equal(t, store.DimSite, gotDim)
	assert.Equal(t, "block", gotFilter.Action, "only blocked requests count")

	cs, err := src.TopCountries(t.Context(), "shop", from, to)
	require.NoError(t, err)
	assert.Equal(t, []CountryCount{{"shop", 7}}, cs)
	assert.Equal(t, store.DimCountry, gotDim)
	assert.Equal(t, "shop", gotFilter.SiteID)

	n, _ := src.EventsDropped(t.Context())
	assert.EqualValues(t, 9, n)
	ups, _ := src.Upstreams(t.Context())
	assert.Equal(t, []Upstream{{"s", "u", true}}, ups)
	certs, _ := src.CertExpiries(t.Context())
	assert.Len(t, certs, 1)
	fs, _ := src.FeedStatuses(t.Context())
	assert.Len(t, fs, 1)

	_, err = StoreSource{}.BlocksBySite(t.Context(), from, to)
	require.Error(t, err, "an unwired dependency is an error, not a silent no-op")
}
