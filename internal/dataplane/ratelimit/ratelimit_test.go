package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

func newHandler(t *testing.T, site string, h Handler) *Handler {
	t.Helper()
	h.SiteID = site
	require.NoError(t, h.Provision(caddy.Context{}))
	require.NoError(t, h.Validate())
	t.Cleanup(func() { _ = h.Cleanup() })
	return &h
}

type result struct {
	status  int
	reached bool
	d       *policy.Decision
	header  http.Header
}

func do(t *testing.T, h *Handler, method, target, ip string, hdr map[string]string, mutate func(*policy.Decision)) result {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, "http://shop.example.test"+target, nil)
	d := policy.NewDecision("01TESTEVENT000000000000000", h.SiteID, policy.ModeDetect, netip.MustParseAddr(ip))
	if mutate != nil {
		mutate(d)
	}
	r = r.WithContext(policy.WithDecision(r.Context(), d))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	out := result{d: d}
	require.NoError(t, h.ServeHTTP(rec, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		out.reached = true
		w.WriteHeader(http.StatusOK)
		return nil
	})))
	out.status, out.header = rec.Code, rec.Header()
	return out
}

func TestTenPerMinuteThen429OnTheEleventh(t *testing.T) {
	h := newHandler(t, "rl-basic", Handler{Rules: []Rule{{Name: "login", Paths: []string{"/api/login"}, Methods: []string{"POST"}, Key: "ip", Limit: 10, Window: "1m", Action: "block"}}})
	for i := range 10 {
		require.True(t, do(t, h, "POST", "/api/login", "203.0.113.1", nil, nil).reached, "request %d", i+1)
	}
	o := do(t, h, "POST", "/api/login", "203.0.113.1", nil, nil)
	assert.Equal(t, 429, o.status)
	assert.False(t, o.reached)
	assert.NotEmpty(t, o.header.Get("Retry-After"))
	assert.Equal(t, policy.ActionRateLimit, o.d.Action())
	assert.Equal(t, "login", o.d.Findings()[0].RuleID)

	assert.True(t, do(t, h, "GET", "/api/login", "203.0.113.1", nil, nil).reached, "other methods are not matched")
	assert.True(t, do(t, h, "POST", "/other", "203.0.113.1", nil, nil).reached, "other paths are not matched")
	assert.True(t, do(t, h, "POST", "/api/login", "203.0.113.2", nil, nil).reached, "other clients have their own budget")
}

func TestKeysAndPathGlobs(t *testing.T) {
	h := newHandler(t, "rl-keys", Handler{Rules: []Rule{{Name: "key", Paths: []string{"/api/*"}, Key: "header:X-Api-Key", Limit: 2, Window: "1m", Action: "block"}}})
	key := func(v string) map[string]string { return map[string]string{"X-Api-Key": v} }
	assert.True(t, do(t, h, "GET", "/api/v1/users/7", "203.0.113.1", key("a"), nil).reached, "/api/* covers everything below")
	assert.True(t, do(t, h, "GET", "/api/x", "203.0.113.2", key("a"), nil).reached, "the key is the header, not the address")
	assert.Equal(t, 429, do(t, h, "GET", "/api/x", "203.0.113.3", key("a"), nil).status)
	assert.True(t, do(t, h, "GET", "/api/x", "203.0.113.3", key("b"), nil).reached, "another key value")
	// Without the header the client's address is the key.
	do(t, h, "GET", "/api/x", "203.0.113.9", nil, nil)
	do(t, h, "GET", "/api/x", "203.0.113.9", nil, nil)
	assert.Equal(t, 429, do(t, h, "GET", "/api/x", "203.0.113.9", nil, nil).status)
	assert.True(t, do(t, h, "GET", "/apiary", "203.0.113.4", key("z"), nil).reached, "/apiary is not below /api")
}

func TestLogActionRecordsButDoesNotBlockAndChallengeIsEnforced(t *testing.T) {
	h := newHandler(t, "rl-actions", Handler{Rules: []Rule{
		{Name: "watch", Paths: []string{"/w"}, Key: "ip", Limit: 1, Window: "1m", Action: "log"},
		{Name: "gate", Paths: []string{"/c"}, Key: "ip", Limit: 1, Window: "1m", Action: "challenge"},
	}})
	do(t, h, "GET", "/w", "203.0.113.1", nil, nil)
	o := do(t, h, "GET", "/w", "203.0.113.1", nil, nil)
	assert.True(t, o.reached, "log never blocks")
	assert.Len(t, o.d.Findings(), 1)

	do(t, h, "GET", "/c", "203.0.113.1", nil, nil)
	assert.Equal(t, 429, do(t, h, "GET", "/c", "203.0.113.1", nil, nil).status, "until the bot module exists a challenge limit is enforced as a block")
}

func TestAllowlistedClientsAreExempt(t *testing.T) {
	h := newHandler(t, "rl-allow", Handler{Rules: []Rule{{Name: "tight", Key: "ip", Limit: 1, Window: "1m", Action: "block"}}})
	allow := func(d *policy.Decision) { d.Allowlisted = true }
	for range 5 {
		assert.True(t, do(t, h, "GET", "/", "203.0.113.1", nil, allow).reached)
	}
}

func TestAutoBanAfterRepeatedBlocks(t *testing.T) {
	acl.Bans.Replace(nil)
	var sunk []acl.Ban
	acl.SetBanSink(func(b acl.Ban) { sunk = append(sunk, b) })
	t.Cleanup(func() { acl.SetBanSink(nil); acl.Bans.Replace(nil) })

	_ = newHandler(t, "ab-site", Handler{AutoBan: &AutoBan{Threshold: 3, Window: "5m", Duration: "30m"}})
	ip := netip.MustParseAddr("203.0.113.5")
	blocked := func() {
		d := policy.NewDecision("e", "ab-site", policy.ModeBlock, ip)
		d.Terminate("waf", policy.ActionBlock)
		policy.NotifyBlock(d)
	}
	for range 3 {
		blocked()
	}
	_, banned := acl.Bans.Active(ip, "ab-site", time.Now())
	assert.False(t, banned, "three blocks are within the threshold")
	blocked()
	b, banned := acl.Bans.Active(ip, "ab-site", time.Now())
	require.True(t, banned, "the fourth block in the window bans the client")
	assert.Equal(t, "auto", b.Source)
	assert.WithinDuration(t, time.Now().Add(30*time.Minute), b.Until, time.Minute)
	require.Len(t, sunk, 1, "the control plane is told so it can persist and audit the ban")

	_, other := acl.Bans.Active(ip, "another-site", time.Now())
	assert.False(t, other, "the ban is scoped to the site where the blocks happened")

	// More blocks while banned do not extend or duplicate the ban.
	blocked()
	blocked()
	assert.Len(t, sunk, 1)
}

func TestAutoBanIgnoresACLDenialsAllowlistedAndUnconfiguredSites(t *testing.T) {
	acl.Bans.Replace(nil)
	t.Cleanup(func() { acl.Bans.Replace(nil) })
	_ = newHandler(t, "ab-site2", Handler{AutoBan: &AutoBan{Threshold: 1, Window: "5m", Duration: "30m"}})
	ip := netip.MustParseAddr("203.0.113.6")
	for range 5 {
		d := policy.NewDecision("e", "ab-site2", policy.ModeBlock, ip)
		d.Terminate("acl", policy.ActionBlock)
		policy.NotifyBlock(d)

		d2 := policy.NewDecision("e", "ab-site2", policy.ModeBlock, ip)
		d2.Allowlisted = true
		d2.Terminate("waf", policy.ActionBlock)
		policy.NotifyBlock(d2)

		d3 := policy.NewDecision("e", "no-autoban-site", policy.ModeBlock, ip)
		d3.Terminate("waf", policy.ActionBlock)
		policy.NotifyBlock(d3)
	}
	assert.Empty(t, acl.Bans.List(time.Now()))
}

func TestAutoBanSettingsFollowReloads(t *testing.T) {
	old := newHandler(t, "ab-reload", Handler{AutoBan: &AutoBan{Threshold: 1, Window: "5m", Duration: "30m"}})
	fresh := newHandler(t, "ab-reload", Handler{AutoBan: &AutoBan{Threshold: 9, Window: "5m", Duration: "30m"}})
	require.NoError(t, old.Cleanup()) // the previous configuration is torn down after the new one is provisioned
	autoMu.RLock()
	got := autoSettings["ab-reload"]
	autoMu.RUnlock()
	assert.Same(t, fresh.AutoBan, got, "cleaning up the old module must not remove the new settings")
}

func TestValidation(t *testing.T) {
	for name, h := range map[string]Handler{
		"no site":    {Rules: []Rule{{Name: "a", Limit: 1, Window: "1m", Action: "block"}}},
		"zero limit": {SiteID: "s", Rules: []Rule{{Name: "a", Limit: 0, Window: "1m", Action: "block"}}},
		"bad action": {SiteID: "s", Rules: []Rule{{Name: "a", Limit: 1, Window: "1m", Action: "ban"}}},
	} {
		assert.Error(t, h.Validate(), name)
	}
	bad := Handler{SiteID: "s", Rules: []Rule{{Name: "a", Limit: 1, Window: "soon", Action: "block"}}}
	assert.Error(t, bad.Provision(caddy.Context{}))
}

type claims map[string]string

func (c claims) Claim(n string) (string, bool) { v, ok := c[n]; return v, ok }

func TestAPIKeys(t *testing.T) {
	h := newHandler(t, "bank", Handler{Rules: []Rule{
		{Name: "per-client", Key: "jwt:client_id", Limit: 2, Window: "1m", Action: "block"},
	}})
	as := func(client string) func(*policy.Decision) {
		return func(d *policy.Decision) {
			if client != "" {
				d.SetClaims(claims{"client_id": client})
			}
		}
	}
	// Two clients behind one address have separate buckets.
	for range 2 {
		assert.Equal(t, 200, do(t, h, "GET", "/x", "192.0.2.1", nil, as("app-a")).status)
		assert.Equal(t, 200, do(t, h, "GET", "/x", "192.0.2.1", nil, as("app-b")).status)
	}
	assert.Equal(t, 429, do(t, h, "GET", "/x", "192.0.2.1", nil, as("app-a")).status)
	assert.Equal(t, 429, do(t, h, "GET", "/x", "192.0.2.1", nil, as("app-b")).status)
	// The same client from another address shares its bucket.
	assert.Equal(t, 429, do(t, h, "GET", "/x", "192.0.2.99", nil, as("app-a")).status)
	// No verified claim: the address is the key, so an anonymous client cannot hide in another's bucket.
	for range 2 {
		assert.Equal(t, 200, do(t, h, "GET", "/x", "192.0.2.50", nil, as("")).status)
	}
	assert.Equal(t, 429, do(t, h, "GET", "/x", "192.0.2.50", nil, as("")).status)
}

func TestAPIKeyHeaderIsHashedAndCertSubjectKeys(t *testing.T) {
	h := newHandler(t, "bank2", Handler{Rules: []Rule{
		{Name: "key", Key: "api_key:X-Api-Key", Limit: 1, Window: "1m", Action: "block"},
		{Name: "cert", Key: "mtls_subject", Limit: 1, Window: "1m", Action: "block", Paths: []string{"/cert"}},
	}})
	hdr := func(k string) map[string]string { return map[string]string{"X-Api-Key": k} }
	assert.Equal(t, 200, do(t, h, "GET", "/x", "192.0.2.1", hdr("k1"), nil).status)
	assert.Equal(t, 429, do(t, h, "GET", "/x", "192.0.2.2", hdr("k1"), nil).status, "same key, other address")
	assert.Equal(t, 200, do(t, h, "GET", "/x", "192.0.2.1", hdr("k2"), nil).status)

	subj := func(s string) func(*policy.Decision) { return func(d *policy.Decision) { d.SetClientCert(s) } }
	assert.Equal(t, 200, do(t, h, "GET", "/cert", "192.0.2.3", nil, subj("CN=tpp-1")).status)
	assert.Equal(t, 429, do(t, h, "GET", "/cert", "192.0.2.4", nil, subj("CN=tpp-1")).status)
	assert.Equal(t, 200, do(t, h, "GET", "/cert", "192.0.2.5", nil, subj("CN=tpp-2")).status)
}
