package login

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/policy"
	"github.com/skylarng89/sherlock-waf/internal/policy/challenge"
	rl "github.com/skylarng89/sherlock-waf/internal/policy/ratelimit"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// rig is a handler in front of an upstream that fails any login whose password
// is not "good" with 401.
type rig struct {
	t        testing.TB
	h        *Handler
	clk      *clock
	upstream int             // requests that reached the upstream
	bodies   []string        // what the upstream read
	cleared  map[string]bool // addresses treated as holding a bot clearance
}

func newRig(t testing.TB, mutate func(*Handler)) *rig {
	t.Helper()
	challenge.Reset()
	t.Cleanup(challenge.Reset)
	h := &Handler{
		SiteID: "bank", Mode: "block", Action: "block", PerIP: 100, PerUsername: 100, PerDevice: 100, Window: "10m",
		Endpoints: []Endpoint{{Path: "/api/login", Method: "POST", UsernameField: "email", FailureStatuses: []int{401, 403}}},
	}
	if mutate != nil {
		mutate(h)
	}
	clk := &clock{t: time.Unix(2_000_000_000, 0)}
	h.now = clk.now
	h.lim = rl.New(1 << 12)
	rg := &rig{t: t, h: h, clk: clk, cleared: map[string]bool{}}
	h.cleared = func(_ *http.Request, ip netip.Addr, _ string) bool { return rg.cleared[ip.String()] }
	require.NoError(t, h.Provision(caddy.Context{}))
	require.NoError(t, h.Validate())
	return rg
}

type attempt struct {
	ip, ua, user, pass string
	path, method       string
	json               bool
	allowlisted        bool
	extraBody          string
}

type result struct {
	status   int
	header   http.Header
	reached  bool
	d        *policy.Decision
	findings []policy.Finding
}

func (g *rig) do(a attempt) result {
	g.t.Helper()
	if a.ip == "" {
		a.ip = "203.0.113.10"
	}
	if a.ua == "" {
		a.ua = "Mozilla/5.0 test " + a.ip
	}
	if a.path == "" {
		a.path = "/api/login"
	}
	if a.method == "" {
		a.method = http.MethodPost
	}
	var body, ct string
	if a.json {
		b, _ := json.Marshal(map[string]string{"email": a.user, "password": a.pass})
		body, ct = string(b), "application/json"
	} else {
		body, ct = "email="+a.user+"&password="+a.pass+a.extraBody, "application/x-www-form-urlencoded"
	}
	r := httptest.NewRequestWithContext(g.t.Context(), a.method, "http://bank.test"+a.path, strings.NewReader(body))
	r.Header.Set("Content-Type", ct)
	r.Header.Set("User-Agent", a.ua)
	d := policy.NewDecision("01TESTEVENT000000000000000", "bank", policy.ModeBlock, netip.MustParseAddr(a.ip))
	d.Allowlisted = a.allowlisted
	r = r.WithContext(policy.WithDecision(r.Context(), d))
	rec := httptest.NewRecorder()
	out := result{d: d}
	require.NoError(g.t, g.h.ServeHTTP(rec, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, req *http.Request) error {
		out.reached = true
		g.upstream++
		b, _ := io.ReadAll(req.Body)
		g.bodies = append(g.bodies, string(b))
		if strings.Contains(string(b), "password=good") || strings.Contains(string(b), `"password":"good"`) {
			w.WriteHeader(http.StatusOK)
			return nil
		}
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	})))
	out.status, out.header, out.findings = rec.Code, rec.Header(), d.Findings()
	return out
}

func (g *rig) fail(n int, mk func(i int) attempt) {
	g.t.Helper()
	for i := range n {
		a := mk(i)
		a.pass = "bad"
		r := g.do(a)
		require.True(g.t, r.reached, "attempt %d should still reach the upstream", i+1)
		require.Equal(g.t, http.StatusUnauthorized, r.status)
	}
}

// ipN is a distinct documentation address per i; it also serves as a distinct
// user-agent or username suffix.
func ipN(i int) string { return fmt.Sprintf("198.51.100.%d", i+1) }

func TestPerIPThresholdBlocksTheNextAttempt(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.PerIP = 3 })
	// A different username and browser every time: only the address repeats.
	g.fail(3, func(i int) attempt { return attempt{user: "u" + ipN(i), ua: "ua-" + ipN(i)} })

	r := g.do(attempt{user: "another", pass: "good", ua: "ua-new"})
	assert.Equal(t, http.StatusTooManyRequests, r.status, "even the right password is refused once the address is over its limit")
	assert.False(t, r.reached, "a refused attempt never reaches the upstream")
	assert.NotEmpty(t, r.header.Get("Retry-After"))
	assert.Equal(t, policy.ActionRateLimit, r.d.Action())
	assert.Equal(t, "login", r.d.Terminated())
	require.NotEmpty(t, r.findings)
	assert.Equal(t, "login-ip", r.findings[0].RuleID)

	other := g.do(attempt{ip: "203.0.113.99", user: "another", pass: "good", ua: "ua-new"})
	assert.Equal(t, http.StatusOK, other.status, "another address is untouched")
}

func TestRefusedAttemptsAreNotCountedSoTheCounterDrains(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.PerIP = 2; h.Window = "1m" })
	g.fail(2, func(i int) attempt { return attempt{user: "u" + ipN(i), ua: "ua-" + ipN(i)} })
	for range 20 {
		assert.Equal(t, http.StatusTooManyRequests, g.do(attempt{user: "x", pass: "bad", ua: "ua-x"}).status)
	}
	g.clk.advance(3 * time.Minute)
	assert.Equal(t, http.StatusOK, g.do(attempt{user: "x", pass: "good", ua: "ua-x"}).status, "two idle windows later the address is forgiven")
}

func TestPerUsernameThresholdFollowsTheAccountAcrossAddresses(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.PerUsername = 3 })
	// Different address and browser every time: only the account repeats.
	g.fail(3, func(i int) attempt { return attempt{ip: ipN(i), user: "ada@bank.test", ua: "ua-" + ipN(i)} })

	r := g.do(attempt{ip: "192.0.2.50", user: "ada@bank.test", pass: "good", ua: "ua-fresh"})
	assert.Equal(t, http.StatusTooManyRequests, r.status, "the account is over its limit, from wherever it is attacked")
	assert.Equal(t, "login-username", r.findings[0].RuleID)

	assert.Equal(t, http.StatusOK, g.do(attempt{ip: "192.0.2.50", user: "bob@bank.test", pass: "good", ua: "ua-fresh"}).status,
		"the same address and browser can still sign in as someone else")
}

func TestUsernameMatchingIgnoresCaseAndSpace(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.PerUsername = 2 })
	g.fail(1, func(int) attempt { return attempt{ip: "198.51.100.1", user: "Ada@Bank.test", ua: "a1"} })
	g.fail(1, func(int) attempt { return attempt{ip: "198.51.100.2", user: "+ada@bank.test", ua: "a2"} }) // '+' is a space in a form
	r := g.do(attempt{ip: "198.51.100.3", user: "ada@bank.test", pass: "bad", ua: "a3"})
	assert.Equal(t, http.StatusTooManyRequests, r.status)
}

func TestPerDeviceThresholdFollowsTheBrowserAcrossAddressesAndUsers(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.PerDevice = 3 })
	const ua = "Mozilla/5.0 stuffing-kit/1.0"
	g.fail(3, func(i int) attempt { return attempt{ip: ipN(i), user: "victim" + ipN(i), ua: ua} })

	r := g.do(attempt{ip: "192.0.2.77", user: "fresh", pass: "bad", ua: ua})
	assert.Equal(t, http.StatusTooManyRequests, r.status)
	assert.Equal(t, "login-device", r.findings[0].RuleID)

	normal := g.do(attempt{ip: "192.0.2.78", user: "fresh", pass: "good", ua: "Mozilla/5.0 a real browser"})
	assert.Equal(t, http.StatusOK, normal.status, "a different browser on a different address signs in")
}

func TestSuccessfulLoginsAndOtherRequestsAreNeverCounted(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.PerIP = 2 })
	for range 10 {
		require.Equal(t, http.StatusOK, g.do(attempt{user: "ada", pass: "good"}).status)
	}
	// Other paths and methods are not login requests.
	for _, a := range []attempt{{path: "/api/other", user: "x", pass: "bad"}, {method: http.MethodGet, user: "x", pass: "bad"}} {
		for range 10 {
			g.do(a)
		}
	}
	assert.Equal(t, http.StatusOK, g.do(attempt{user: "ada", pass: "good"}).status, "ten successes and twenty other failures did not trip anything")
}

func TestWindowIsASlidingWindow(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.PerIP = 4; h.Window = "10m" })
	g.fail(4, func(i int) attempt { return attempt{user: "u" + ipN(i), ua: "ua-" + ipN(i)} })
	assert.Equal(t, http.StatusTooManyRequests, g.do(attempt{user: "z", ua: "ua-z", pass: "good"}).status)
	g.clk.advance(25 * time.Minute)
	assert.Equal(t, http.StatusOK, g.do(attempt{user: "z", ua: "ua-z", pass: "good"}).status)
}

func TestDetectModeAndLogActionOnlyRecord(t *testing.T) {
	for name, mutate := range map[string]func(*Handler){
		"detect mode": func(h *Handler) { h.Mode = "detect"; h.PerIP = 2 },
		"log action":  func(h *Handler) { h.Action = "log"; h.PerIP = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			g := newRig(t, mutate)
			g.fail(2, func(i int) attempt { return attempt{user: "u" + ipN(i), ua: "ua-" + ipN(i)} })
			r := g.do(attempt{user: "x", pass: "good", ua: "ua-x"})
			assert.True(t, r.reached, "never enforced")
			assert.Equal(t, http.StatusOK, r.status)
			assert.Equal(t, policy.ActionAllow, r.d.Action())
			require.NotEmpty(t, r.findings)
			assert.Equal(t, "login-ip", r.findings[0].RuleID, "but the would-have-acted finding is there for the report")
		})
	}
}

func TestChallengeHandoffRefusesTheAttemptAndMarksTheClient(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.Action = "challenge"; h.Handoff = true; h.PerIP = 2 })
	g.fail(2, func(i int) attempt { return attempt{user: "u" + ipN(i), ua: "ua-" + ipN(i)} })

	r := g.do(attempt{user: "ada", pass: "good", ua: "ua-x"})
	assert.Equal(t, http.StatusForbidden, r.status)
	assert.False(t, r.reached)
	assert.Equal(t, policy.ActionChallenge, r.d.Action())
	assert.Equal(t, "login", r.d.Terminated())
	assert.True(t, challenge.Marked(challenge.ClientKey("bank", netip.MustParseAddr("203.0.113.10"))), "the bot module will challenge this address")
	assert.False(t, challenge.Marked(challenge.ClientKey("bank", netip.MustParseAddr("203.0.113.11"))), "and only this one")

	g.cleared["203.0.113.10"] = true
	ok := g.do(attempt{user: "ada", pass: "good", ua: "ua-x"})
	assert.Equal(t, http.StatusOK, ok.status, "a client that passed the challenge signs in")
}

func TestChallengeWithoutABotModuleIsABlock(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.Action = "challenge"; h.Handoff = false; h.PerIP = 2 })
	g.fail(2, func(i int) attempt { return attempt{user: "u" + ipN(i), ua: "ua-" + ipN(i)} })
	r := g.do(attempt{user: "ada", pass: "good", ua: "ua-x"})
	assert.Equal(t, http.StatusTooManyRequests, r.status)
	assert.False(t, challenge.Any(), "nothing is marked when nobody can serve the challenge")
}

func TestAllowlistedClientsAreExempt(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.PerIP = 1 })
	for range 5 {
		r := g.do(attempt{user: "x", pass: "bad", allowlisted: true})
		assert.Equal(t, http.StatusUnauthorized, r.status)
	}
	assert.Equal(t, http.StatusOK, g.do(attempt{user: "x", pass: "good", ua: "other"}).status, "nothing was recorded for the allow-listed client")
}

func TestUpstreamStillReceivesTheWholeBody(t *testing.T) {
	g := newRig(t, nil)
	pad := "&note=" + strings.Repeat("x", 4000)
	g.do(attempt{user: "ada", pass: "bad", extraBody: pad})
	require.Len(t, g.bodies, 1)
	assert.Equal(t, "email=ada&password=bad"+pad, g.bodies[0])

	g.do(attempt{user: "ada", pass: "bad", json: true})
	assert.JSONEq(t, `{"email":"ada","password":"bad"}`, g.bodies[1])
}

func TestJSONBodiesAndPointerFields(t *testing.T) {
	g := newRig(t, func(h *Handler) {
		h.PerUsername = 2
		h.Endpoints[0].UsernameField = "/user/email"
	})
	for i := range 2 {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://bank.test/api/login",
			strings.NewReader(`{"user":{"email":"ada@bank.test"},"password":"bad"}`))
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
		r.Header.Set("User-Agent", "ua-"+ipN(i))
		d := policy.NewDecision("e", "bank", policy.ModeBlock, netip.MustParseAddr(ipN(i)))
		r = r.WithContext(policy.WithDecision(r.Context(), d))
		require.NoError(t, g.h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		})))
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://bank.test/api/login", strings.NewReader(`{"user":{"email":"ADA@bank.test"}}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "ua-new")
	d := policy.NewDecision("e", "bank", policy.ModeBlock, netip.MustParseAddr("192.0.2.9"))
	r = r.WithContext(policy.WithDecision(r.Context(), d))
	rec := httptest.NewRecorder()
	require.NoError(t, g.h.ServeHTTP(rec, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestUnreadableBodiesStillWorkOnAddressAndDevice(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.PerIP = 2 })
	send := func() int {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://bank.test/api/login", strings.NewReader("--x\r\nbinary"))
		r.Header.Set("Content-Type", "multipart/form-data; boundary=x")
		r.Header.Set("User-Agent", "ua")
		d := policy.NewDecision("e", "bank", policy.ModeBlock, netip.MustParseAddr("203.0.113.5"))
		r = r.WithContext(policy.WithDecision(r.Context(), d))
		rec := httptest.NewRecorder()
		require.NoError(t, g.h.ServeHTTP(rec, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			w.WriteHeader(http.StatusUnauthorized)
			return nil
		})))
		return rec.Code
	}
	assert.Equal(t, 401, send())
	assert.Equal(t, 401, send())
	assert.Equal(t, 429, send(), "no username, but the address counter still applies")
}

func TestNoUsernameOrHashLeavesTheModule(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.PerUsername = 1; h.PerIP = 1 })
	const user = "very.secret.user@bank.test"
	g.fail(1, func(int) attempt { return attempt{user: user} })
	r := g.do(attempt{user: user, pass: "good", ip: "192.0.2.4", ua: "ua2"})
	assert.Equal(t, http.StatusTooManyRequests, r.status)

	all, err := json.Marshal(append(r.findings, g.do(attempt{user: user, pass: "bad", ip: "192.0.2.4", ua: "ua2"}).findings...))
	require.NoError(t, err)
	assert.NotContains(t, strings.ToLower(string(all)), "secret", "no finding carries the name")
	assert.NotContains(t, string(all), hashUsername(user), "nor its hash")
	assert.NotContains(t, strings.ToLower(r.header.Get("Retry-After")+r.header.Get("X-Sherlock-Event-Id")), "secret")
}

func TestHashUsername(t *testing.T) {
	assert.Empty(t, hashUsername("  "))
	h := hashUsername("Ada@Bank.test")
	assert.Equal(t, h, hashUsername("  ada@bank.test "))
	assert.Len(t, h, 24)
	assert.NotContains(t, h, "ada")
	assert.NotEqual(t, h, hashUsername("bob@bank.test"))
}

func TestMemoryStaysBoundedUnderKeyChurn(t *testing.T) {
	g := newRig(t, func(h *Handler) { h.PerIP = 1000 })
	g.h.lim = rl.New(256) // 64 shards x 4 keys
	for i := range 5000 {
		a := attempt{
			ip:   fmt.Sprintf("10.%d.%d.%d", i/65536, i/256%256, i%256),
			user: fmt.Sprintf("user-%d", i), ua: fmt.Sprintf("ua-%d", i), pass: "bad",
		}
		g.do(a)
	}
	assert.LessOrEqual(t, g.h.lim.Len(), 256, "the counters never outgrow their cap")
	assert.NotZero(t, g.h.lim.Len())
}

func TestNonLoginRequestsAllocateNothing(t *testing.T) {
	g := newRig(t, nil)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://bank.test/products", http.NoBody)
	d := policy.NewDecision("e", "bank", policy.ModeBlock, netip.MustParseAddr("203.0.113.1"))
	r = r.WithContext(policy.WithDecision(r.Context(), d))
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	w := httptest.NewRecorder()
	allocs := testing.AllocsPerRun(200, func() { _ = g.h.ServeHTTP(w, r, next) })
	assert.Zero(t, allocs, "the module adds nothing to the other 99.9% of requests")
}

func TestValidation(t *testing.T) {
	ok := func() *Handler {
		return &Handler{
			SiteID: "s", Action: "block", Window: "10m", PerIP: 1, PerUsername: 1, PerDevice: 1,
			Endpoints: []Endpoint{{Path: "/l", Method: "POST", UsernameField: "u"}},
		}
	}
	for name, mutate := range map[string]func(*Handler){
		"no site":        func(h *Handler) { h.SiteID = "" },
		"bad action":     func(h *Handler) { h.Action = "nuke" },
		"no endpoints":   func(h *Handler) { h.Endpoints = nil },
		"relative path":  func(h *Handler) { h.Endpoints[0].Path = "l" },
		"no field":       func(h *Handler) { h.Endpoints[0].UsernameField = "" },
		"zero threshold": func(h *Handler) { h.PerUsername = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			h := ok()
			mutate(h)
			assert.Error(t, h.Validate())
		})
	}
	h := ok()
	require.NoError(t, h.Provision(caddy.Context{}))
	require.NoError(t, h.Validate())
	h = ok()
	h.Window = "soon"
	assert.Error(t, h.Provision(caddy.Context{}))
}

func BenchmarkNonLoginRequest(b *testing.B) {
	g := newRig(b, nil)
	r := httptest.NewRequestWithContext(b.Context(), http.MethodGet, "http://bank.test/products", http.NoBody)
	d := policy.NewDecision("e", "bank", policy.ModeBlock, netip.MustParseAddr("203.0.113.1"))
	r = r.WithContext(policy.WithDecision(r.Context(), d))
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	w := httptest.NewRecorder()
	b.ReportAllocs()
	for b.Loop() {
		_ = g.h.ServeHTTP(w, r, next)
	}
}

func BenchmarkLoginAttempt(b *testing.B) {
	g := newRig(b, func(h *Handler) { h.PerIP, h.PerUsername, h.PerDevice = 1<<30, 1<<30, 1<<30 })
	body := "email=ada%40bank.test&password=bad"
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	})
	b.ReportAllocs()
	for b.Loop() {
		r := httptest.NewRequestWithContext(b.Context(), http.MethodPost, "http://bank.test/api/login", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("User-Agent", "Mozilla/5.0 bench")
		d := policy.NewDecision("e", "bank", policy.ModeBlock, netip.MustParseAddr("203.0.113.1"))
		r = r.WithContext(policy.WithDecision(r.Context(), d))
		_ = g.h.ServeHTTP(httptest.NewRecorder(), r, next)
	}
}
