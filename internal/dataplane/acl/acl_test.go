package acl

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"

	"github.com/skylarng89/sherlock-waf/internal/policy"
	"github.com/skylarng89/sherlock-waf/internal/policy/ipset"
)

type fakeGeo map[string]string

func (g fakeGeo) Country(ip netip.Addr) (string, bool) { c, ok := g[ip.String()]; return c, ok }

func set(t *testing.T, entries ...string) *ipset.Set {
	t.Helper()
	s, err := ipset.Parse(entries)
	require.NoError(t, err)
	return s
}

func reset(t *testing.T) {
	t.Helper()
	SetLists(map[string]*ipset.Set{})
	SetReputation(nil)
	SetGeo(nil)
	Bans.Replace(nil)
	t.Cleanup(func() {
		SetLists(map[string]*ipset.Set{})
		SetReputation(nil)
		SetGeo(nil)
		Bans.Replace(nil)
	})
}

func newHandler(t *testing.T, h Handler) *Handler {
	t.Helper()
	h.SiteID = "shop"
	require.NoError(t, h.Provision(caddy.Context{}))
	require.NoError(t, h.Validate())
	return &h
}

type outcome struct {
	status  int
	reached bool
	d       *policy.Decision
	header  http.Header
}

func serve(t *testing.T, h *Handler, ip string, hdr map[string]string) outcome {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://shop.example.test/x", nil)
	d := policy.NewDecision("01TESTEVENT000000000000000", "shop", policy.ModeDetect, netip.MustParseAddr(ip))
	r = r.WithContext(policy.WithDecision(r.Context(), d))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	out := outcome{d: d}
	require.NoError(t, h.ServeHTTP(rec, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		out.reached = true
		w.WriteHeader(http.StatusOK)
		return nil
	})))
	out.status, out.header = rec.Code, rec.Header()
	return out
}

func TestDenyListBlocksEvenInDetectMode(t *testing.T) {
	reset(t)
	SetLists(map[string]*ipset.Set{"bad": set(t, "198.51.100.0/24")})
	h := newHandler(t, Handler{DenyLists: []string{"bad"}})

	o := serve(t, h, "198.51.100.7", nil)
	assert.Equal(t, 403, o.status)
	assert.False(t, o.reached)
	assert.Equal(t, policy.ActionBlock, o.d.Action())
	assert.Equal(t, "acl", o.d.Terminated())
	require.Len(t, o.d.Findings(), 1)
	assert.Equal(t, "bad", o.d.Findings()[0].RuleID)

	assert.True(t, serve(t, h, "203.0.113.1", nil).reached, "other clients pass")
}

func TestUnknownListNamesMatchNothing(t *testing.T) {
	reset(t)
	h := newHandler(t, Handler{DenyLists: []string{"missing"}, AllowLists: []string{"missing"}})
	assert.True(t, serve(t, h, "203.0.113.1", nil).reached)
}

func TestBansApplyPerSiteAndExpire(t *testing.T) {
	reset(t)
	h := newHandler(t, Handler{})
	ip := netip.MustParseAddr("203.0.113.9")
	Bans.Add(Ban{IP: ip, Until: time.Now().Add(time.Hour), Source: "auto"})
	Bans.Add(Ban{IP: netip.MustParseAddr("203.0.113.10"), Until: time.Now().Add(time.Hour), Source: "manual", SiteID: "other"})
	Bans.Add(Ban{IP: netip.MustParseAddr("203.0.113.11"), Until: time.Now().Add(-time.Second), Source: "auto"})

	o := serve(t, h, "203.0.113.9", nil)
	assert.Equal(t, 403, o.status)
	assert.Equal(t, policy.ActionBan, o.d.Action())
	assert.True(t, serve(t, h, "203.0.113.10", nil).reached, "a ban scoped to another site does not apply here")
	assert.True(t, serve(t, h, "203.0.113.11", nil).reached, "an expired ban does nothing")

	assert.True(t, Bans.Remove(ip))
	assert.True(t, serve(t, h, "203.0.113.9", nil).reached, "unbanned")
	assert.Len(t, Bans.List(time.Now()), 1, "List drops expired entries")
}

func TestDenyBeatsAllowAndAllowBeatsFeedRules(t *testing.T) {
	reset(t)
	SetLists(map[string]*ipset.Set{"office": set(t, "203.0.113.0/24"), "bad": set(t, "203.0.113.66")})
	SetReputation(set(t, "203.0.113.0/24"))
	SetGeo(fakeGeo{"203.0.113.5": "KP"})
	h := newHandler(t, Handler{AllowLists: []string{"office"}, DenyLists: []string{"bad"}, CountryMode: "deny", Countries: []string{"KP"}, Reputation: true})

	assert.Equal(t, 403, serve(t, h, "203.0.113.66", nil).status, "an explicit deny list entry wins over the allow list")

	o := serve(t, h, "203.0.113.5", nil)
	assert.True(t, o.reached, "an allow-listed client is exempt from country and reputation rules")
	assert.True(t, o.d.Allowlisted)
	assert.False(t, o.d.SkipWAF, "an allow list does not skip the WAF by default")

	h2 := newHandler(t, Handler{AllowLists: []string{"office"}, AllowBypassWAF: true})
	assert.True(t, serve(t, h2, "203.0.113.5", nil).d.SkipWAF, "unless the policy says so")
}

func TestCountryRules(t *testing.T) {
	reset(t)
	SetGeo(fakeGeo{"203.0.113.1": "KP", "203.0.113.2": "NL", "198.51.100.3": "DE"})

	deny := newHandler(t, Handler{CountryMode: "deny", Countries: []string{"kp"}})
	assert.Equal(t, 403, serve(t, deny, "203.0.113.1", nil).status)
	assert.True(t, serve(t, deny, "203.0.113.2", nil).reached)
	assert.Equal(t, "country:KP", serve(t, deny, "203.0.113.1", nil).d.Findings()[0].RuleID)

	allow := newHandler(t, Handler{CountryMode: "allow", Countries: []string{"NL"}})
	assert.True(t, serve(t, allow, "203.0.113.2", nil).reached)
	assert.Equal(t, 403, serve(t, allow, "198.51.100.3", nil).status)
	assert.True(t, serve(t, allow, "10.1.2.3", nil).reached, "private addresses have no country and are never denied by the country rule")
	assert.True(t, serve(t, allow, "203.0.113.200", nil).reached, "an address missing from the database is not denied")

	SetGeo(nil)
	assert.True(t, serve(t, allow, "198.51.100.3", nil).reached, "with no database loaded the rule is silent rather than blocking everyone")
}

func TestReputation(t *testing.T) {
	reset(t)
	SetReputation(set(t, "198.51.100.0/24"))
	block := newHandler(t, Handler{Reputation: true, ReputationAction: "block"})
	assert.Equal(t, 403, serve(t, block, "198.51.100.1", nil).status)
	logOnly := newHandler(t, Handler{Reputation: true, ReputationAction: "log"})
	o := serve(t, logOnly, "198.51.100.1", nil)
	assert.True(t, o.reached)
	assert.Len(t, o.d.Findings(), 1, "log-only still records a finding")
	off := newHandler(t, Handler{})
	assert.True(t, serve(t, off, "198.51.100.1", nil).reached)
}

func testHash(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	require.NoError(t, err)
	sum := argon2.IDKey([]byte(password), salt, 1, 8*1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=8192,t=1,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
}

func basic(user, pass string) map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))}
}

func TestPasswordGate(t *testing.T) {
	reset(t)
	SetLists(map[string]*ipset.Set{"office": set(t, "10.0.0.0/8")})
	h := newHandler(t, Handler{GateUsername: "ada", GateHash: testHash(t, "correct horse"), AllowLists: []string{"office"}})

	o := serve(t, h, "203.0.113.1", nil)
	assert.Equal(t, 401, o.status)
	assert.Contains(t, o.header.Get("WWW-Authenticate"), "Basic")
	assert.Equal(t, policy.ActionChallenge, o.d.Action(), "a missing password is a challenge, not an attack")

	assert.Equal(t, 401, serve(t, h, "203.0.113.1", basic("ada", "wrong")).status)
	assert.Equal(t, 401, serve(t, h, "203.0.113.1", basic("eve", "correct horse")).status, "right password, wrong user")
	assert.True(t, serve(t, h, "203.0.113.1", basic("ada", "correct horse")).reached)
	assert.True(t, serve(t, h, "203.0.113.1", basic("ada", "correct horse")).reached, "cached success")
	assert.Equal(t, 401, serve(t, h, "203.0.113.1", map[string]string{"Authorization": "Basic !!!"}).status)
	assert.True(t, serve(t, h, "10.1.1.1", nil).reached, "allow-listed clients skip the gate")
}

func TestPasswordGateThrottlesGuessing(t *testing.T) {
	reset(t)
	h := newHandler(t, Handler{GateUsername: "ada", GateHash: testHash(t, "correct horse")})
	var last outcome
	for range 25 {
		last = serve(t, h, "203.0.113.50", basic("ada", "guess"))
	}
	assert.Equal(t, 429, last.status)
	assert.NotEmpty(t, last.header.Get("Retry-After"))
	assert.Equal(t, 401, serve(t, h, "203.0.113.51", basic("ada", "guess")).status, "throttling is per client address")
}

func TestPasswordGateRefusesUnsafeHashes(t *testing.T) {
	for name, hash := range map[string]string{
		"not argon":    "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
		"huge memory":  "$argon2id$v=19$m=4194304,t=3,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo",
		"zero threads": "$argon2id$v=19$m=65536,t=3,p=0$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNo",
		"plaintext":    "hunter2",
	} {
		h := Handler{SiteID: "shop", GateUsername: "a", GateHash: hash}
		assert.Error(t, h.Provision(caddy.Context{}), name)
	}
}

func TestNoDecisionPassesThrough(t *testing.T) {
	reset(t)
	h := newHandler(t, Handler{DenyLists: []string{"x"}})
	reached := false
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x/", nil)
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { reached = true; return nil })))
	assert.True(t, reached, "when core could not identify the client there is nothing to evaluate")
}

func TestBlockObserverOnlyFiresForBlocks(t *testing.T) {
	var seen []policy.Action
	policy.SetBlockObserver(func(d *policy.Decision) { seen = append(seen, d.Action()) })
	t.Cleanup(func() { policy.SetBlockObserver(nil) })
	for _, a := range []policy.Action{policy.ActionAllow, policy.ActionLog, policy.ActionBlock, policy.ActionBan, policy.ActionChallenge} {
		d := policy.NewDecision("e", "s", policy.ModeBlock, netip.MustParseAddr("192.0.2.1"))
		d.SetAction(a)
		policy.NotifyBlock(d)
	}
	assert.Equal(t, []policy.Action{policy.ActionBlock, policy.ActionBan}, seen)
}

func BenchmarkACLCheck100kDenyList(b *testing.B) {
	entries := make([]string, 100_000)
	for i := range entries {
		entries[i] = fmt.Sprintf("%d.%d.%d.0/24", 1+i%200, (i/200)%256, (i/51200)%256)
	}
	s, err := ipset.Parse(entries)
	require.NoError(b, err)
	SetLists(map[string]*ipset.Set{"big": s})
	h := &Handler{SiteID: "shop", DenyLists: []string{"big"}}
	require.NoError(b, h.Provision(caddy.Context{}))
	r := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "http://x/", nil)
	d := policy.NewDecision("e", "shop", policy.ModeBlock, netip.MustParseAddr("203.0.113.77"))
	r = r.WithContext(policy.WithDecision(r.Context(), d))
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = h.ServeHTTP(w, r, next)
	}
}
