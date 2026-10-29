package bot

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/netx"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

const (
	moduleName = "sherlock_bot"
	// Prefix is reserved on every protected site for the challenge endpoints.
	Prefix    = "/.sherlock/"
	scriptURL = Prefix + "challenge.js"
	verifyURL = Prefix + "challenge/verify"
)

//go:embed assets/challenge.js
var challengeJS []byte

//go:embed assets/challenge.html.tmpl
var pageSource string

var pageTemplate = template.Must(template.New("challenge").Parse(pageSource))

func init() { caddy.RegisterModule(&Handler{}) }

// Siteverify endpoints, variables so tests can point them at a local server.
var (
	turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	hcaptchaVerifyURL  = "https://api.hcaptcha.com/siteverify"
	verifyClient       = netx.NewClient(netx.Options{Timeout: 10 * time.Second})
)

// Environment variables holding the provider secrets.
const (
	EnvTurnstileSecret = "SHERLOCK_TURNSTILE_SECRET" //nolint:gosec // the name of an environment variable, not a credential
	EnvHCaptchaSecret  = "SHERLOCK_HCAPTCHA_SECRET"  //nolint:gosec // the name of an environment variable, not a credential
)

// Rule is one compiled bot rule.
type Rule struct {
	Paths      []string `json:"paths,omitempty"`
	Methods    []string `json:"methods,omitempty"`
	Countries  []string `json:"countries,omitempty"`
	Reputation bool     `json:"reputation,omitempty"`
	Action     string   `json:"action"`
}

// Handler is the sherlock_bot Caddy handler.
type Handler struct {
	SiteID       string `json:"site_id"`
	Challenge    string `json:"challenge"`
	Difficulty   int    `json:"difficulty"`
	TTL          string `json:"clearance_ttl"`
	SiteKey      string `json:"site_key,omitempty"`
	VerifiedBots string `json:"verified_bots"`
	Rules        []Rule `json:"rules,omitempty"`
	ClientTTL    int    `json:"-"`
	ttl          time.Duration
	now          func() time.Time
	dns          *verifier
}

// CaddyModule implements caddy.Module.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers." + moduleName, New: func() caddy.Module { return new(Handler) }}
}

// Provision implements caddy.Provisioner.
func (h *Handler) Provision(caddy.Context) error {
	var err error
	if h.ttl, err = time.ParseDuration(h.TTL); err != nil || h.ttl < time.Minute {
		return fmt.Errorf("sherlock_bot site %q: invalid clearance_ttl %q", h.SiteID, h.TTL)
	}
	h.now = time.Now
	if h.dns == nil {
		h.dns = defaultVerifier
	}
	return nil
}

// Validate implements caddy.Validator.
func (h *Handler) Validate() error {
	if h.SiteID == "" {
		return errors.New("sherlock_bot: site_id is required")
	}
	switch h.Challenge {
	case config.ChallengePoW:
	case config.ChallengeTurnstile, config.ChallengeHCaptcha:
		if h.SiteKey == "" {
			return fmt.Errorf("sherlock_bot site %q: %s needs a site_key", h.SiteID, h.Challenge)
		}
	default:
		return fmt.Errorf("sherlock_bot: invalid challenge %q", h.Challenge)
	}
	if h.Difficulty < 1 || h.Difficulty > 6 {
		return fmt.Errorf("sherlock_bot: difficulty %d out of range", h.Difficulty)
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	d := policy.DecisionFrom(r.Context())
	if d == nil || !d.ClientIP.IsValid() {
		return next.ServeHTTP(w, r)
	}
	if strings.HasPrefix(r.URL.Path, Prefix) {
		h.serveInternal(w, r, d)
		return nil
	}
	if d.Allowlisted { // an allow-listed client is never challenged
		return next.ServeHTTP(w, r)
	}
	now := h.now()
	b := bindingFor(d.ClientIP, r.UserAgent(), h.SiteID)
	if c, err := r.Cookie(Cookie); err == nil && validClearance(b, now, c.Value) {
		return next.ServeHTTP(w, r)
	}

	action, why := h.decide(r, d) //nolint:contextcheck // the DNS check runs in a detached background worker by design
	switch action {
	case "":
		return next.ServeHTTP(w, r)
	case config.BotActionAllow:
		return next.ServeHTTP(w, r)
	case config.ActionBlock:
		d.AddFinding(policy.Finding{Module: "bot", RuleID: why, Severity: policy.SeverityWarning, Message: "request blocked by a bot rule"})
		d.Terminate("bot", policy.ActionBlock)
		blockpage.Write(w, r, http.StatusForbidden, d.EventID)
		return nil
	}
	return h.challenge(w, r, d, b, now, why)
}

// decide returns what to do with a request that has no valid clearance: "" for
// nothing, or allow, block, challenge, with the reason.
func (h *Handler) decide(r *http.Request, d *policy.Decision) (action, why string) {
	if c, claims := claimedCrawler(r.UserAgent()); claims {
		switch h.dns.check(d.ClientIP, c) {
		case verified:
			if h.VerifiedBots != "" && h.VerifiedBots != config.BotActionAllow {
				return h.VerifiedBots, "verified-bot:" + c.name
			}
			return config.BotActionAllow, "verified-bot:" + c.name
		case unknown, unverified:
			// An unverified (or not yet verified) claim gets no special treatment
			// and, being a likely impersonation, is challenged.
			d.AddFinding(policy.Finding{Module: "bot", RuleID: "unverified-bot:" + c.name, Severity: policy.SeverityNotice, Message: "user agent claims to be " + c.name + " but the address is not verified"})
			return config.ActionChallenge, "unverified-bot:" + c.name
		}
	}
	for _, rule := range h.Rules {
		if rule.matches(r, d.ClientIP) {
			return rule.Action, "rule"
		}
	}
	if d.ChallengeRequested {
		return config.ActionChallenge, "ratelimit"
	}
	return "", ""
}

func (r Rule) matches(req *http.Request, ip netip.Addr) bool {
	if len(r.Methods) > 0 && !slices.Contains(r.Methods, req.Method) {
		return false
	}
	if len(r.Paths) > 0 && !slices.ContainsFunc(r.Paths, func(p string) bool { return pathMatches(p, req.URL.Path) }) {
		return false
	}
	if len(r.Countries) > 0 {
		code, ok := acl.CountryOf(ip)
		if !ok || !slices.Contains(r.Countries, code) {
			return false
		}
	}
	if r.Reputation && !acl.Listed(ip) {
		return false
	}
	return true
}

func pathMatches(pattern, p string) bool {
	if ok, err := path.Match(pattern, p); err == nil && ok {
		return true
	}
	pre, ok := strings.CutSuffix(pattern, "/*")
	return ok && strings.HasPrefix(p, pre+"/")
}

// challenge answers with the challenge page, or with a JSON 403 for requests a
// page cannot be shown to (API clients, non-navigations): HTML must never be
// returned to a client that did not ask for it, and a POST body cannot be replayed.
func (h *Handler) challenge(w http.ResponseWriter, r *http.Request, d *policy.Decision, b binding, now time.Time, why string) error {
	d.AddFinding(policy.Finding{Module: "bot", RuleID: why, Severity: policy.SeverityNotice, Message: "client must complete a challenge"})
	d.Terminate("bot", policy.ActionChallenge)
	if !wantsHTML(r) || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		blockpage.Write(w, r, http.StatusForbidden, d.EventID)
		return nil
	}
	data := struct {
		Token, Return, Action, Provider, SiteKey, EventID, ScriptURL string
		Difficulty                                                   int
	}{
		Return: r.URL.RequestURI(), Action: verifyURL, Provider: h.Challenge, SiteKey: h.SiteKey, EventID: d.EventID,
		ScriptURL: scriptURL, Difficulty: h.Difficulty,
	}
	if h.Challenge == config.ChallengePoW {
		data.Token = issueChallenge(b, now, h.Difficulty)
	} else {
		cur, _, _ := ring.keys(now)
		data.Token = b.seal(cur, "ext", make([]byte, 8)) // binds the widget submission to this client
	}
	var buf bytes.Buffer
	if err := pageTemplate.Execute(&buf, data); err != nil {
		slog.Error("rendering the challenge page failed", "error", err)
		blockpage.Write(w, r, http.StatusForbidden, d.EventID)
		return nil
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set(blockpage.EventIDHeader, d.EventID)
	hd.Set("Content-Security-Policy", pageCSP(h.Challenge))
	w.WriteHeader(http.StatusForbidden)
	if r.Method == http.MethodGet {
		_, _ = w.Write(buf.Bytes())
	}
	return nil
}

func pageCSP(provider string) string {
	switch provider {
	case config.ChallengeTurnstile:
		return "default-src 'none'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src https://challenges.cloudflare.com; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
	case config.ChallengeHCaptcha:
		return "default-src 'none'; script-src 'self' https://js.hcaptcha.com https://*.hcaptcha.com; frame-src https://*.hcaptcha.com; connect-src https://*.hcaptcha.com; style-src 'unsafe-inline' https://*.hcaptcha.com; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
	}
	return "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
}

func wantsHTML(r *http.Request) bool {
	for _, v := range r.Header.Values("Accept") {
		for part := range strings.SplitSeq(v, ",") {
			mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil || mt != "text/html" {
				continue
			}
			if q, ok := params["q"]; ok {
				if f, err := strconv.ParseFloat(q, 64); err != nil || f <= 0 {
					continue
				}
			}
			return true
		}
	}
	return false
}

// serveInternal handles the reserved /.sherlock/ paths.
func (h *Handler) serveInternal(w http.ResponseWriter, r *http.Request, d *policy.Decision) {
	switch {
	case r.URL.Path == scriptURL && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		hd := w.Header()
		hd.Set("Content-Type", "text/javascript; charset=utf-8")
		hd.Set("Cache-Control", "public, max-age=3600")
		hd.Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodGet {
			_, _ = w.Write(challengeJS)
		}
	case r.URL.Path == verifyURL && r.Method == http.MethodPost:
		h.verify(w, r, d)
	default:
		http.NotFound(w, r)
	}
}

// verify checks a submitted solution and, if it holds, sets the clearance cookie
// and sends the client back where it was going.
func (h *Handler) verify(w http.ResponseWriter, r *http.Request, d *policy.Decision) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	now := h.now()
	b := bindingFor(d.ClientIP, r.UserAgent(), h.SiteID)
	token := r.PostForm.Get("challenge")
	ok := false
	switch h.Challenge {
	case config.ChallengePoW:
		counter, err := strconv.ParseUint(r.PostForm.Get("counter"), 10, 64)
		ok = err == nil && solved(b, now, token, counter)
	default:
		_, sealed := b.open(now, "ext", token, 8)
		ok = sealed && h.verifyProvider(r.Context(), r, d.ClientIP)
	}
	if !ok {
		d.AddFinding(policy.Finding{Module: "bot", RuleID: "challenge-failed", Severity: policy.SeverityWarning, Message: "challenge solution rejected"})
		d.Terminate("bot", policy.ActionBlock)
		blockpage.Write(w, r, http.StatusForbidden, d.EventID)
		return
	}
	value, exp := issueClearance(b, now, h.ttl)
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure follows the transport; a plain-HTTP site could never store a Secure cookie
		Name: Cookie, Value: value, Path: "/", Expires: exp, MaxAge: int(h.ttl.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	d.AddFinding(policy.Finding{Module: "bot", RuleID: "challenge-passed", Severity: policy.SeverityInfo, Message: "challenge completed"})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, safeReturn(r.PostForm.Get("return")), http.StatusSeeOther) //nolint:gosec // G710: safeReturn only yields a path on this site
}

// safeReturn only ever returns a path on this site: an open redirect would turn
// the challenge into a phishing helper.
func safeReturn(p string) string {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") || strings.HasPrefix(p, Prefix) {
		return "/"
	}
	if u, err := url.Parse(p); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return p
}

// verifyProvider confirms a Turnstile or hCaptcha response with the provider.
func (h *Handler) verifyProvider(ctx context.Context, r *http.Request, ip netip.Addr) bool {
	endpoint, secretEnv, field := turnstileVerifyURL, EnvTurnstileSecret, "cf-turnstile-response" //nolint:gosec // form field and variable names, not credentials
	if h.Challenge == config.ChallengeHCaptcha {
		endpoint, secretEnv, field = hcaptchaVerifyURL, EnvHCaptchaSecret, "h-captcha-response" //nolint:gosec // form field and variable names, not credentials
	}
	secret, response := os.Getenv(secretEnv), r.PostForm.Get(field)
	if secret == "" || response == "" || len(response) > 4096 {
		return false
	}
	form := url.Values{"secret": {secret}, "response": {response}, "remoteip": {ip.String()}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := verifyClient.Do(req)
	if err != nil {
		slog.Warn("challenge provider verification failed", "provider", h.Challenge)
		return false // fail closed: a provider outage must not let clients through
	}
	defer func() { _ = res.Body.Close() }()
	var out struct {
		Success bool `json:"success"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&out) != nil {
		return false
	}
	return out.Success
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
