package bot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
	"github.com/skylarng89/sherlock-waf/internal/netx"
	"github.com/skylarng89/sherlock-waf/internal/policy"
	"github.com/skylarng89/sherlock-waf/internal/policy/ipset"
)

const browserUA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"

func newHandler(t *testing.T, h Handler) *Handler {
	t.Helper()
	if h.SiteID == "" {
		h.SiteID = "shop"
	}
	if h.Challenge == "" {
		h.Challenge = config.ChallengePoW
	}
	if h.Difficulty == 0 {
		h.Difficulty = 2 // fast in tests; the production default is 4
	}
	if h.TTL == "" {
		h.TTL = "30m"
	}
	if h.VerifiedBots == "" {
		h.VerifiedBots = "allow"
	}
	require.NoError(t, h.Provision(caddy.Context{}))
	require.NoError(t, h.Validate())
	return &h
}

type resp struct {
	status  int
	body    string
	header  http.Header
	reached bool
	d       *policy.Decision
}

type reqOpts struct {
	method, target, ip, ua string
	accept                 string
	cookie                 string
	form                   url.Values
	mutate                 func(*policy.Decision)
}

func send(t *testing.T, h *Handler, o reqOpts) resp {
	t.Helper()
	if o.method == "" {
		o.method = http.MethodGet
	}
	if o.target == "" {
		o.target = "/"
	}
	if o.ip == "" {
		o.ip = "203.0.113.10"
	}
	if o.ua == "" {
		o.ua = browserUA
	}
	var body *strings.Reader
	if o.form != nil {
		body = strings.NewReader(o.form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequestWithContext(t.Context(), o.method, "http://shop.example.test"+o.target, body)
	if o.form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.Header.Set("User-Agent", o.ua)
	if o.accept != "" {
		r.Header.Set("Accept", o.accept)
	}
	if o.cookie != "" {
		r.AddCookie(&http.Cookie{Name: Cookie, Value: o.cookie}) //nolint:gosec // a request cookie in a test
	}
	d := policy.NewDecision("01TESTEVENT000000000000000", "shop", policy.ModeDetect, netip.MustParseAddr(o.ip))
	if o.mutate != nil {
		o.mutate(d)
	}
	r = r.WithContext(policy.WithDecision(r.Context(), d))
	rec := httptest.NewRecorder()
	out := resp{d: d}
	require.NoError(t, h.ServeHTTP(rec, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		out.reached = true
		w.WriteHeader(http.StatusOK)
		return nil
	})))
	out.status, out.body, out.header = rec.Code, rec.Body.String(), rec.Header()
	return out
}

const html = "text/html,application/xhtml+xml"

func challengeRule() []Rule { return []Rule{{Paths: []string{"/checkout/*"}, Action: "challenge"}} }

func tokenFrom(t *testing.T, page string) string {
	t.Helper()
	const marker = `data-token="`
	_, rest, found := strings.Cut(page, marker)
	require.True(t, found, page)
	token, _, _ := strings.Cut(rest, `"`)
	return token
}

func cookieFrom(t *testing.T, r resp) string {
	t.Helper()
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Name == Cookie {
			return c.Value
		}
	}
	t.Fatalf("no clearance cookie; status %d body %s", r.status, r.body)
	return ""
}

// solveChallenge fetches a challenge for a path and completes it, returning the cookie.
func solveChallenge(t *testing.T, h *Handler, target, ip, ua string) string {
	t.Helper()
	page := send(t, h, reqOpts{target: target, ip: ip, ua: ua, accept: html})
	require.Equal(t, 403, page.status)
	token := tokenFrom(t, page.body)
	counter := solve(token, h.Difficulty)
	done := send(t, h, reqOpts{method: "POST", target: verifyURL, ip: ip, ua: ua, form: url.Values{
		"challenge": {token}, "counter": {fmt.Sprint(counter)}, "return": {target},
	}})
	require.Equal(t, 303, done.status, done.body)
	assert.Equal(t, target, done.header.Get("Location"))
	return cookieFrom(t, done)
}

func TestChallengePageThenClearanceThenPass(t *testing.T) {
	h := newHandler(t, Handler{Rules: challengeRule()})

	open := send(t, h, reqOpts{target: "/about", accept: html})
	assert.True(t, open.reached, "paths outside the rules are not challenged")

	page := send(t, h, reqOpts{target: "/checkout/pay", accept: html})
	assert.Equal(t, 403, page.status)
	assert.False(t, page.reached)
	assert.Contains(t, page.body, "Checking your browser")
	assert.Contains(t, page.body, "<noscript>")
	assert.Contains(t, page.body, `role="status"`, "progress is announced")
	assert.Equal(t, policy.ActionChallenge, page.d.Action())
	assert.Contains(t, page.header.Get("Content-Security-Policy"), "script-src 'self'")
	assert.NotContains(t, page.header.Get("Content-Security-Policy"), "unsafe-inline'; script", "no inline scripts")
	assert.Equal(t, "no-store", page.header.Get("Cache-Control"))

	cookie := solveChallenge(t, h, "/checkout/pay", "203.0.113.10", browserUA)
	again := send(t, h, reqOpts{target: "/checkout/pay", accept: html, cookie: cookie})
	assert.True(t, again.reached, "a valid clearance passes")
}

func TestCurlAndAPIClientsAreNeverShownHTML(t *testing.T) {
	h := newHandler(t, Handler{Rules: challengeRule()})
	for name, o := range map[string]reqOpts{
		"curl":        {target: "/checkout/x", ua: "curl/8.5.0"},
		"json client": {target: "/checkout/x", accept: "application/json"},
		"wildcard":    {target: "/checkout/x", accept: "*/*"},
		"api post":    {method: "POST", target: "/checkout/x", accept: "application/json"},
	} {
		r := send(t, h, o)
		assert.Equal(t, 403, r.status, name)
		assert.NotContains(t, r.body, "<html", name)
		assert.Equal(t, "application/problem+json", r.header.Get("Content-Type"), name)
		assert.Contains(t, r.body, "event_id", name)
		assert.False(t, r.reached, name)
	}
}

func TestClearanceCannotBeForgedStolenOrReused(t *testing.T) {
	h := newHandler(t, Handler{Rules: challengeRule()})
	cookie := solveChallenge(t, h, "/checkout/a", "203.0.113.10", browserUA)
	pass := func(c, ip, ua string) bool {
		return send(t, h, reqOpts{target: "/checkout/a", accept: html, cookie: c, ip: ip, ua: ua}).reached
	}
	assert.True(t, pass(cookie, "203.0.113.10", browserUA))
	assert.True(t, pass(cookie, "203.0.113.200", browserUA), "the same /24 is the same network")
	assert.False(t, pass(cookie, "198.51.100.5", browserUA), "a cookie copied to another network prefix is rejected")
	assert.False(t, pass(cookie, "203.0.113.10", "Different/1.0"), "or to another browser")
	assert.False(t, pass(cookie[:len(cookie)-2]+"AA", "203.0.113.10", browserUA), "a tampered cookie fails")
	assert.False(t, pass("", "203.0.113.10", browserUA))
	assert.False(t, pass("not-base64!!", "203.0.113.10", browserUA))

	other := newHandler(t, Handler{SiteID: "other", Rules: challengeRule()})
	assert.False(t, send(t, other, reqOpts{target: "/checkout/a", accept: html, cookie: cookie}).reached, "a clearance is bound to its site")

	// IPv6 clients are grouped by /48.
	c6 := solveChallenge(t, h, "/checkout/a", "2001:db8:1:2::5", browserUA)
	assert.True(t, pass(c6, "2001:db8:1:ffff::9", browserUA))
	assert.False(t, pass(c6, "2001:db8:2::1", browserUA))
}

func TestClearanceExpiresAndSurvivesOneKeyRotation(t *testing.T) {
	h := newHandler(t, Handler{Rules: challengeRule(), TTL: "2h"})
	cookie := solveChallenge(t, h, "/checkout/a", "203.0.113.10", browserUA)
	b := bindingFor(netip.MustParseAddr("203.0.113.10"), browserUA, "shop")

	now := time.Now()
	assert.True(t, validClearance(b, now.Add(time.Hour), cookie))
	assert.False(t, validClearance(b, now.Add(3*time.Hour), cookie), "expired")

	// After 24 h the key rotates; the previous key still verifies for one more period.
	ring.mu.Lock()
	ring.born = now.Add(-25 * time.Hour)
	ring.mu.Unlock()
	fresh, _ := issueClearance(b, now, time.Hour) // triggers the rotation
	assert.True(t, validClearance(b, now, fresh))
	assert.True(t, validClearance(b, now, cookie), "a clearance signed with the previous key is still accepted")

	ring.mu.Lock()
	ring.born = now.Add(-25 * time.Hour)
	ring.mu.Unlock()
	_, _ = issueClearance(b, now, time.Hour) // second rotation drops the first key
	assert.False(t, validClearance(b, now, cookie), "after two rotations the old key is gone")
}

func TestProofOfWorkIsBoundSingleUseAndVerified(t *testing.T) {
	h := newHandler(t, Handler{Rules: challengeRule(), Difficulty: 3})
	page := send(t, h, reqOpts{target: "/checkout/a", accept: html})
	token := tokenFrom(t, page.body)
	counter := solve(token, 3)
	form := func(tok string, c uint64) url.Values {
		return url.Values{"challenge": {tok}, "counter": {fmt.Sprint(c)}, "return": {"/checkout/a"}}
	}
	post := func(ip, ua string, f url.Values) resp {
		return send(t, h, reqOpts{method: "POST", target: verifyURL, ip: ip, ua: ua, form: f})
	}

	assert.Equal(t, 403, post("203.0.113.10", browserUA, form(token, counter+1)).status, "a wrong counter fails")
	assert.Equal(t, 403, post("198.51.100.1", browserUA, form(token, counter)).status, "a challenge solved from another network fails")
	assert.Equal(t, 403, post("203.0.113.10", "Other/1", form(token, counter)).status, "or from another browser")
	assert.Equal(t, 403, post("203.0.113.10", browserUA, form(token[:len(token)-3]+"AAA", counter)).status, "a forged challenge fails")
	assert.Equal(t, 403, post("203.0.113.10", browserUA, url.Values{"challenge": {token}, "counter": {"x"}}).status)

	assert.Equal(t, 303, post("203.0.113.10", browserUA, form(token, counter)).status, "the genuine solution works")
	assert.Equal(t, 403, post("203.0.113.10", browserUA, form(token, counter)).status, "but only once: a replay is refused")

	// An expired challenge fails even with a correct solution.
	expired := issueChallenge(bindingFor(netip.MustParseAddr("203.0.113.10"), browserUA, "shop"), time.Now().Add(-time.Hour), 3)
	assert.Equal(t, 403, post("203.0.113.10", browserUA, form(expired, solve(expired, 3))).status)
}

func TestDifficultyIsInTheSignedChallenge(t *testing.T) {
	easy := newHandler(t, Handler{Rules: challengeRule(), Difficulty: 1})
	hard := newHandler(t, Handler{Rules: challengeRule(), Difficulty: 4})
	token := tokenFrom(t, send(t, easy, reqOpts{target: "/checkout/a", accept: html}).body)
	easyCounter := solve(token, 1)
	// Presenting an easy solution to a hard handler cannot lower the bar: the difficulty is inside the MAC.
	r := send(t, hard, reqOpts{method: "POST", target: verifyURL, form: url.Values{"challenge": {token}, "counter": {fmt.Sprint(easyCounter)}}})
	assert.Equal(t, 303, r.status, "the signed difficulty (1) is what counts, not the handler's")
	b := bindingFor(netip.MustParseAddr("203.0.113.10"), browserUA, "shop")
	tok2 := issueChallenge(b, time.Now(), 4)
	var c uint64
	for leadingZeroHex(tok2, c, 4) == false && c < 3 { // a tiny counter is overwhelmingly unlikely to solve difficulty 4
		c++
	}
	assert.False(t, leadingZeroHex(tok2, 0, 4) && leadingZeroHex(tok2, 1, 4) && leadingZeroHex(tok2, 2, 4))
}

func TestReturnTargetIsSameSiteOnly(t *testing.T) {
	for in, want := range map[string]string{
		"/checkout/a?x=1":             "/checkout/a?x=1",
		"":                            "/",
		"https://evil.example/":       "/",
		"//evil.example/x":            "/",
		"/\\evil.example":             "/",
		"/ok\r\nSet-Cookie: a=b":      "/",
		"javascript:alert(1)":         "/",
		"/.sherlock/challenge/verify": "/",
		"relative":                    "/",
	} {
		assert.Equal(t, want, safeReturn(in), in)
	}
}

func TestAllowlistedClientsAreNeverChallenged(t *testing.T) {
	h := newHandler(t, Handler{Rules: challengeRule()})
	r := send(t, h, reqOpts{target: "/checkout/a", accept: html, mutate: func(d *policy.Decision) { d.Allowlisted = true }})
	assert.True(t, r.reached)
}

func TestRuleActionsAndMatching(t *testing.T) {
	acl.SetGeo(fakeGeo{"203.0.113.10": "KP"})
	s, err := ipset.Parse([]string{"203.0.113.77"})
	require.NoError(t, err)
	acl.SetReputation(s)
	t.Cleanup(func() { acl.SetGeo(nil); acl.SetReputation(nil) })

	h := newHandler(t, Handler{Rules: []Rule{
		{Paths: []string{"/admin/*"}, Action: "block"},
		{Paths: []string{"/open/*"}, Action: "allow"},
		{Countries: []string{"KP"}, Paths: []string{"/c/*"}, Action: "challenge"},
		{Reputation: true, Methods: []string{"POST"}, Action: "challenge"},
	}})
	assert.Equal(t, 403, send(t, h, reqOpts{target: "/admin/x", accept: html}).status)
	assert.Equal(t, policy.ActionBlock, send(t, h, reqOpts{target: "/admin/x", accept: html}).d.Action())
	assert.True(t, send(t, h, reqOpts{target: "/open/x", accept: html}).reached)
	assert.Contains(t, send(t, h, reqOpts{target: "/c/x", accept: html}).body, "Checking your browser", "country rule")
	assert.True(t, send(t, h, reqOpts{target: "/c/x", accept: html, ip: "203.0.113.11"}).reached, "other countries pass")
	assert.Equal(t, 403, send(t, h, reqOpts{method: "POST", target: "/p", ip: "203.0.113.77"}).status, "reputation + method rule")
	assert.True(t, send(t, h, reqOpts{method: "GET", target: "/p", ip: "203.0.113.77", accept: html}).reached, "every field of a rule must match")
}

type fakeGeo map[string]string

func (g fakeGeo) Country(ip netip.Addr) (string, bool) { c, ok := g[ip.String()]; return c, ok }

func TestRateLimitHandoff(t *testing.T) {
	h := newHandler(t, Handler{})
	r := send(t, h, reqOpts{target: "/", accept: html, mutate: func(d *policy.Decision) { d.ChallengeRequested = true }})
	assert.Equal(t, 403, r.status)
	assert.Contains(t, r.body, "Checking your browser")
	assert.Equal(t, "ratelimit", r.d.Findings()[0].RuleID)
	assert.True(t, send(t, h, reqOpts{target: "/", accept: html}).reached, "without a request for it nothing is challenged")
}

type fakeDNS struct {
	mu   sync.Mutex
	ptr  map[string][]string
	fwd  map[string][]string
	hits int
}

func (f *fakeDNS) LookupAddr(_ context.Context, a string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	if v, ok := f.ptr[a]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("no ptr")
}

func (f *fakeDNS) LookupHost(_ context.Context, n string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.fwd[n]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("no host")
}

const googleUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

func TestVerifiedBotsUseReverseAndForwardDNSWithoutBlockingTheRequest(t *testing.T) {
	dns := &fakeDNS{
		ptr: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}, "203.0.113.50": {"evil.example.net."}, "203.0.113.51": {"crawl.googlebot.com."}},
		fwd: map[string][]string{"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}, "crawl.googlebot.com": {"192.0.2.99"}},
	}
	v := newVerifier(dns)
	h := newHandler(t, Handler{})
	h.dns = v

	do := func(ip string) resp { return send(t, h, reqOpts{target: "/", ip: ip, ua: googleUA, accept: html}) }

	first := do("66.249.66.1")
	assert.Equal(t, 403, first.status, "the first request from an unchecked claimant is treated as unverified (no DNS on the request path)")
	require.Eventually(t, func() bool { return do("66.249.66.1").reached }, 3*time.Second, 10*time.Millisecond, "after the background check the genuine crawler passes")

	for _, ip := range []string{"203.0.113.50", "203.0.113.51", "203.0.113.52"} { // wrong domain / forward mismatch / no PTR
		do(ip)
		require.Eventually(t, func() bool {
			v.mu.Lock()
			defer v.mu.Unlock()
			c, ok := v.cache[key(netip.MustParseAddr(ip), crawlers[0])]
			return ok && c.v == unverified
		}, 3*time.Second, 10*time.Millisecond, ip)
		r := do(ip)
		assert.Equal(t, 403, r.status, "a Googlebot UA from a non-Google address is unverified: "+ip)
		assert.False(t, r.reached, ip)
	}

	dns.mu.Lock()
	hits := dns.hits
	dns.mu.Unlock()
	do("66.249.66.1")
	do("66.249.66.1")
	dns.mu.Lock()
	assert.Equal(t, hits, dns.hits, "verdicts are cached")
	dns.mu.Unlock()
}

func TestVerifiedBotPolicyBlockAndChallenge(t *testing.T) {
	dns := &fakeDNS{ptr: map[string][]string{"66.249.66.1": {"x.googlebot.com"}}, fwd: map[string][]string{"x.googlebot.com": {"66.249.66.1"}}}
	for policyName, wantStatus := range map[string]int{"block": 403, "challenge": 403, "allow": 200} {
		h := newHandler(t, Handler{VerifiedBots: policyName})
		h.dns = newVerifier(dns)
		var last resp
		require.Eventually(t, func() bool {
			last = send(t, h, reqOpts{ip: "66.249.66.1", ua: googleUA, accept: html})
			return h.dns.check(netip.MustParseAddr("66.249.66.1"), crawlers[0]) == verified
		}, 3*time.Second, 10*time.Millisecond)
		last = send(t, h, reqOpts{ip: "66.249.66.1", ua: googleUA, accept: html})
		got := last.status
		if last.reached {
			got = 200
		}
		assert.Equal(t, wantStatus, got, policyName)
	}
}

func TestClaimedCrawlerDetection(t *testing.T) {
	for ua, want := range map[string]string{googleUA: "googlebot", "Mozilla/5.0 (compatible; bingbot/2.0)": "bingbot", "Applebot/0.1": "applebot", browserUA: "", "curl/8": ""} {
		c, ok := claimedCrawler(ua)
		assert.Equal(t, want != "", ok, ua)
		assert.Equal(t, want, c.name, ua)
	}
}

func TestProviderChallengesVerifyServerSide(t *testing.T) {
	var gotSecret, gotResponse, gotIP string
	ok := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotSecret, gotResponse, gotIP = r.PostForm.Get("secret"), r.PostForm.Get("response"), r.PostForm.Get("remoteip")
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": ok})
	}))
	defer srv.Close()
	prevURL, prevClient := turnstileVerifyURL, verifyClient
	turnstileVerifyURL, verifyClient = srv.URL, netx.NewClient(netx.Options{AllowPrivate: true})
	t.Cleanup(func() { turnstileVerifyURL, verifyClient = prevURL, prevClient })
	t.Setenv(EnvTurnstileSecret, "s3cret")

	h := newHandler(t, Handler{Challenge: "turnstile", SiteKey: "0xAAAA", Rules: challengeRule()})
	page := send(t, h, reqOpts{target: "/checkout/a", accept: html})
	assert.Contains(t, page.body, `data-sitekey="0xAAAA"`)
	assert.Contains(t, page.body, "challenges.cloudflare.com")
	assert.Contains(t, page.header.Get("Content-Security-Policy"), "https://challenges.cloudflare.com")
	assert.NotContains(t, page.body, "s3cret")
	token := tokenFrom(t, page.body)

	post := func(tok, widget string) resp {
		return send(t, h, reqOpts{method: "POST", target: verifyURL, form: url.Values{"challenge": {tok}, "cf-turnstile-response": {widget}, "return": {"/checkout/a"}}})
	}
	assert.Equal(t, 303, post(token, "widget-token").status)
	assert.Equal(t, "s3cret", gotSecret)
	assert.Equal(t, "widget-token", gotResponse)
	assert.Equal(t, "203.0.113.10", gotIP)

	ok = false
	assert.Equal(t, 403, post(token, "widget-token").status, "the provider says no")
	ok = true
	assert.Equal(t, 403, post(token+"x", "widget-token").status, "an unsealed token is refused before the provider is asked")
	assert.Equal(t, 403, post(token, "").status, "no widget response")

	t.Setenv(EnvTurnstileSecret, "")
	assert.Equal(t, 403, post(token, "widget-token").status, "no secret configured: fail closed")
	_ = os.Getenv
}

func TestProviderOutageFailsClosed(t *testing.T) {
	prev := turnstileVerifyURL
	turnstileVerifyURL = "http://127.0.0.1:1/siteverify"
	t.Cleanup(func() { turnstileVerifyURL = prev })
	t.Setenv(EnvTurnstileSecret, "s")
	h := newHandler(t, Handler{Challenge: "turnstile", SiteKey: "k", Rules: challengeRule()})
	token := tokenFrom(t, send(t, h, reqOpts{target: "/checkout/a", accept: html}).body)
	r := send(t, h, reqOpts{method: "POST", target: verifyURL, form: url.Values{"challenge": {token}, "cf-turnstile-response": {"w"}}})
	assert.Equal(t, 403, r.status, "a provider outage must not let clients through")
}

func TestInternalPathsAndScript(t *testing.T) {
	h := newHandler(t, Handler{})
	js := send(t, h, reqOpts{target: scriptURL})
	assert.Equal(t, 200, js.status)
	assert.Contains(t, js.header.Get("Content-Type"), "javascript")
	assert.NotContains(t, js.body, "eval(", "the solver uses no eval")
	assert.Contains(t, js.body, "data-token")
	assert.Equal(t, 404, send(t, h, reqOpts{target: Prefix + "nothing"}).status)
	assert.Equal(t, 404, send(t, h, reqOpts{method: "POST", target: scriptURL}).status)
	assert.Equal(t, 404, send(t, h, reqOpts{target: verifyURL}).status, "verify only answers POST")
	assert.True(t, send(t, h, reqOpts{target: "/.sherlockx/a"}).reached, "only the reserved prefix is intercepted")
}

func TestValidation(t *testing.T) {
	for name, h := range map[string]Handler{
		"no site":          {Challenge: "pow", Difficulty: 4, TTL: "30m"},
		"bad challenge":    {SiteID: "s", Challenge: "captcha", Difficulty: 4, TTL: "30m"},
		"turnstile no key": {SiteID: "s", Challenge: "turnstile", Difficulty: 4, TTL: "30m"},
		"difficulty":       {SiteID: "s", Challenge: "pow", Difficulty: 9, TTL: "30m"},
	} {
		assert.Error(t, h.Validate(), name)
	}
	bad := Handler{SiteID: "s", Challenge: "pow", Difficulty: 4, TTL: "soon"}
	assert.Error(t, bad.Provision(caddy.Context{}))
}

func TestBrowserPostIsRefusedWithoutAChallengePage(t *testing.T) {
	h := newHandler(t, Handler{Rules: challengeRule()})
	r := send(t, h, reqOpts{method: "POST", target: "/checkout/x", accept: html})
	assert.Equal(t, 403, r.status)
	assert.NotContains(t, r.body, "Checking your browser", "a POST body cannot be replayed after a challenge, so no challenge page is shown for it")
	assert.Equal(t, policy.ActionChallenge, r.d.Action())
}
