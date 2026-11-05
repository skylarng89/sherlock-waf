// Package ratelimit is the sherlock_ratelimit Caddy module: named rate limits
// per site or endpoint, and the auto-ban that turns repeated blocks into a
// temporary ban. It runs after the ACL (an allow-listed client is exempt) and
// before the WAF so a flood never reaches Coraza.
package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/policy"
	rl "github.com/skylarng89/sherlock-waf/internal/policy/ratelimit"
)

const moduleName = "sherlock_ratelimit"

// maxKeys bounds the limiter's memory: roughly 150 bytes per key.
const maxKeys = 1 << 20

var (
	limiter = rl.New(maxKeys)

	autoMu       sync.RWMutex
	autoSettings = map[string]*AutoBan{}
)

func init() {
	caddy.RegisterModule(&Handler{})
	policy.SetBlockObserver(observeBlock)
}

// Rule is one compiled rate limit.
type Rule struct {
	Name    string   `json:"name"`
	Paths   []string `json:"paths,omitempty"`
	Methods []string `json:"methods,omitempty"`
	Key     string   `json:"key"`
	Limit   int      `json:"limit"`
	Window  string   `json:"window"`
	Action  string   `json:"action"`

	window time.Duration
	header string
	claim  string
	apiKey string
}

// AutoBan is the per-site auto-ban setting.
type AutoBan struct {
	Threshold int    `json:"blocks_threshold"`
	Window    string `json:"window"`
	Duration  string `json:"ban_duration"`

	window, duration time.Duration
}

// Handler is the sherlock_ratelimit Caddy handler.
type Handler struct {
	SiteID  string   `json:"site_id"`
	Rules   []Rule   `json:"rules,omitempty"`
	AutoBan *AutoBan `json:"auto_ban,omitempty"`
	// Handoff passes "challenge" rules to the bot module instead of blocking.
	// The compiler sets it only when the site's bot policy is enabled.
	Handoff bool `json:"challenge_handoff,omitempty"`

	now func() time.Time
}

// CaddyModule implements caddy.Module.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers." + moduleName, New: func() caddy.Module { return new(Handler) }}
}

// Provision implements caddy.Provisioner.
func (h *Handler) Provision(caddy.Context) error {
	h.now = time.Now
	for i := range h.Rules {
		r := &h.Rules[i]
		w, err := time.ParseDuration(r.Window)
		if err != nil || w < time.Second {
			return fmt.Errorf("sherlock_ratelimit rule %q: invalid window %q", r.Name, r.Window)
		}
		r.window = w
		if after, ok := strings.CutPrefix(r.Key, config.KeyHeaderPrefix); ok {
			r.header = after
		}
		if after, ok := strings.CutPrefix(r.Key, config.KeyJWTPrefix); ok {
			r.claim = after
		}
		if after, ok := strings.CutPrefix(r.Key, config.KeyAPIKeyPrefix); ok {
			r.apiKey = after
		}
	}
	if a := h.AutoBan; a != nil {
		var err error
		if a.window, err = time.ParseDuration(a.Window); err != nil {
			return fmt.Errorf("sherlock_ratelimit auto_ban window: %w", err)
		}
		if a.duration, err = time.ParseDuration(a.Duration); err != nil {
			return fmt.Errorf("sherlock_ratelimit auto_ban ban_duration: %w", err)
		}
		autoMu.Lock()
		autoSettings[h.SiteID] = a
		autoMu.Unlock()
	}
	return nil
}

// Cleanup implements caddy.CleanerUpper: forget this site's auto-ban setting
// unless a newer configuration already replaced it.
func (h *Handler) Cleanup() error {
	if h.AutoBan == nil {
		return nil
	}
	autoMu.Lock()
	defer autoMu.Unlock()
	if autoSettings[h.SiteID] == h.AutoBan {
		delete(autoSettings, h.SiteID)
	}
	return nil
}

// Validate implements caddy.Validator.
func (h *Handler) Validate() error {
	if h.SiteID == "" {
		return errors.New("sherlock_ratelimit: site_id is required")
	}
	for _, r := range h.Rules {
		if r.Limit < 1 {
			return fmt.Errorf("sherlock_ratelimit rule %q: limit must be positive", r.Name)
		}
		if !slices.Contains([]string{config.ActionBlock, config.ActionChallenge, config.ActionLog}, r.Action) {
			return fmt.Errorf("sherlock_ratelimit rule %q: invalid action %q", r.Name, r.Action)
		}
	}
	return nil
}

func (r *Rule) matches(req *http.Request) bool {
	if len(r.Methods) > 0 && !slices.Contains(r.Methods, req.Method) {
		return false
	}
	if len(r.Paths) == 0 {
		return true
	}
	for _, p := range r.Paths {
		if ok, err := path.Match(p, req.URL.Path); err == nil && ok {
			return true
		}
		// "/api/*" is meant to cover everything below it, not one segment.
		if pre, ok := strings.CutSuffix(p, "/*"); ok && strings.HasPrefix(req.URL.Path, pre+"/") {
			return true
		}
	}
	return false
}

// keyFor derives the bucket key. A key that cannot be derived (no header, no
// verified token, no client certificate) falls back to the address rather than
// sharing one bucket among every anonymous client.
func (r *Rule) keyFor(req *http.Request, d *policy.Decision, ip string) string {
	switch {
	case r.header != "":
		if v := req.Header.Get(r.header); v != "" {
			return "h:" + v
		}
	case r.claim != "":
		// Only claims of a token the API module verified are used: an
		// unverified claim is attacker-chosen and would let a client pick its bucket.
		if v, ok := d.Claim(r.claim); ok {
			return "c:" + v
		}
	case r.apiKey != "":
		if v := req.Header.Get(r.apiKey); v != "" {
			sum := sha256.Sum256([]byte(v)) // the key itself must not sit in memory or logs
			return "k:" + hex.EncodeToString(sum[:12])
		}
	case r.Key == config.KeyClientCertSubject:
		if v := d.ClientCertSubject(); v != "" {
			return "m:" + v
		}
	}
	return "ip:" + ip
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	d := policy.DecisionFrom(r.Context())
	if d == nil || !d.ClientIP.IsValid() || d.Allowlisted {
		return next.ServeHTTP(w, r)
	}
	ip := d.ClientIP.String()
	now := h.now()
	for i := range h.Rules {
		rule := &h.Rules[i]
		if !rule.matches(r) {
			continue
		}
		res := limiter.AllowAt(h.SiteID+"|"+rule.Name+"|"+rule.keyFor(r, d, ip), rule.Limit, rule.window, now)
		if res.Allowed {
			continue
		}
		msg := fmt.Sprintf("rate limit %q exceeded (%d per %s)", rule.Name, rule.Limit, rule.Window)
		d.AddFinding(policy.Finding{Module: "ratelimit", RuleID: rule.Name, Severity: policy.SeverityWarning, Message: msg})
		if rule.Action == config.ActionLog {
			continue
		}
		if rule.Action == config.ActionChallenge && h.Handoff {
			d.ChallengeRequested = true // the bot module serves the challenge
			continue
		}
		// Without a bot module for this site a "challenge" rule is enforced as a
		// block, the safe reading of the rule.
		d.Terminate("ratelimit", policy.ActionRateLimit)
		w.Header().Set("Retry-After", fmt.Sprint(int(res.RetryAfter.Seconds())+1))
		blockpage.Write(w, r, http.StatusTooManyRequests, d.EventID)
		return nil
	}
	return next.ServeHTTP(w, r)
}

// observeBlock counts a block towards the site's auto-ban and bans the client
// when the threshold is passed.
func observeBlock(d *policy.Decision) {
	if d.Allowlisted || !d.ClientIP.IsValid() || d.Terminated() == "acl" {
		return // allow-listed clients are exempt; ACL denials and bans are not new evidence
	}
	autoMu.RLock()
	a := autoSettings[d.SiteID]
	autoMu.RUnlock()
	if a == nil || a.Threshold < 1 {
		return
	}
	now := time.Now()
	if _, banned := acl.Bans.Active(d.ClientIP, d.SiteID, now); banned {
		return
	}
	if res := limiter.AllowAt("autoban|"+d.SiteID+"|"+d.ClientIP.String(), a.Threshold, a.window, now); res.Allowed {
		return
	}
	acl.AddAutoBan(acl.Ban{
		IP: d.ClientIP, Until: now.Add(a.duration), Source: "auto", SiteID: d.SiteID, CreatedAt: now,
		Reason: fmt.Sprintf("more than %d blocked requests in %s", a.Threshold, a.Window),
	})
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
