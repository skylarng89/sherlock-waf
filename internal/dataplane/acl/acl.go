package acl

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/policy"
	"github.com/skylarng89/sherlock-waf/internal/policy/ratelimit"
)

const moduleName = "sherlock_acl"

func init() { caddy.RegisterModule(&Handler{}) }

// Handler is the sherlock_acl Caddy handler. Its JSON is produced by the
// compiler from the effective policy of one site or endpoint.
//
// Precedence, first match wins: temporary ban, explicit deny list, allow list
// (which exempts the client from country and reputation rules, the password gate,
// rate limits and bot checks, but not from the WAF unless AllowBypassWAF is
// set), country rule, reputation, password gate.
type Handler struct {
	SiteID           string   `json:"site_id"`
	AllowLists       []string `json:"allow_lists,omitempty"`
	DenyLists        []string `json:"deny_lists,omitempty"`
	CountryMode      string   `json:"country_mode,omitempty"`
	Countries        []string `json:"countries,omitempty"`
	Reputation       bool     `json:"reputation,omitempty"`
	ReputationAction string   `json:"reputation_action,omitempty"`
	GateUsername     string   `json:"gate_username,omitempty"`
	GateHash         string   `json:"gate_hash,omitempty"`
	AllowBypassWAF   bool     `json:"allow_bypass_waf,omitempty"`

	countrySet map[string]struct{}
	gate       *gate
	tries      *ratelimit.Limiter
	now        func() time.Time
}

// CaddyModule implements caddy.Module.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers." + moduleName, New: func() caddy.Module { return new(Handler) }}
}

// Provision implements caddy.Provisioner.
func (h *Handler) Provision(caddy.Context) error {
	h.now = time.Now
	h.countrySet = make(map[string]struct{}, len(h.Countries))
	for _, c := range h.Countries {
		h.countrySet[strings.ToUpper(c)] = struct{}{}
	}
	if h.GateHash != "" {
		g, err := newGate(h.GateUsername, h.GateHash)
		if err != nil {
			return fmt.Errorf("sherlock_acl site %q: %w", h.SiteID, err)
		}
		h.gate = g
		h.tries = ratelimit.New(4096)
	}
	return nil
}

// Validate implements caddy.Validator.
func (h *Handler) Validate() error {
	if h.SiteID == "" {
		return errors.New("sherlock_acl: site_id is required")
	}
	switch h.CountryMode {
	case "", config.CountryOff, config.CountryAllow, config.CountryDeny:
	default:
		return fmt.Errorf("sherlock_acl: invalid country_mode %q", h.CountryMode)
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	d := policy.DecisionFrom(r.Context())
	if d == nil || !d.ClientIP.IsValid() {
		return next.ServeHTTP(w, r) // core could not identify the client; nothing to evaluate
	}
	ip := d.ClientIP
	now := h.now()

	if b, ok := Bans.Active(ip, h.SiteID, now); ok {
		return h.deny(w, r, d, policy.ActionBan, "ban:"+b.Source, "client is temporarily banned ("+b.Source+")")
	}
	for _, name := range h.DenyLists {
		if list(name).Contains(ip) {
			return h.deny(w, r, d, policy.ActionBlock, name, "client is on deny list "+name)
		}
	}
	for _, name := range h.AllowLists {
		if list(name).Contains(ip) {
			d.Allowlisted, d.SkipWAF = true, h.AllowBypassWAF
			return next.ServeHTTP(w, r)
		}
	}
	if blocked, rule, msg := h.countryDenied(ip); blocked {
		return h.deny(w, r, d, policy.ActionBlock, rule, msg)
	}
	if h.Reputation && reputation.Load().Contains(ip) {
		if h.ReputationAction == config.ActionLog {
			d.AddFinding(policy.Finding{Module: "acl", RuleID: "reputation", Severity: policy.SeverityWarning, Message: "client is on a reputation list (log only)"})
		} else {
			return h.deny(w, r, d, policy.ActionBlock, "reputation", "client is on a reputation list")
		}
	}
	if h.gate != nil {
		if handled := h.checkGate(w, r, d, ip, now); handled {
			return nil
		}
	}
	return next.ServeHTTP(w, r)
}

func (h *Handler) deny(w http.ResponseWriter, r *http.Request, d *policy.Decision, a policy.Action, rule, msg string) error {
	d.AddFinding(policy.Finding{Module: "acl", RuleID: rule, Severity: policy.SeverityWarning, Message: msg})
	d.Terminate("acl", a)
	blockpage.Write(w, r, http.StatusForbidden, d.EventID)
	return nil
}

// countryDenied applies the country rule. An address with no known country (a
// private network, or no database loaded yet) is never denied by it: locking
// out internal clients, or everyone while a database downloads, is worse than
// the rule being silent; GET /system/info and the dashboard report feed status.
func (h *Handler) countryDenied(ip netip.Addr) (bool, string, string) {
	if h.CountryMode == "" || h.CountryMode == config.CountryOff || len(h.countrySet) == 0 && h.CountryMode == config.CountryDeny {
		return false, "", ""
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false, "", ""
	}
	code, ok := country(ip)
	if !ok {
		return false, "", ""
	}
	_, listed := h.countrySet[code]
	switch {
	case h.CountryMode == config.CountryDeny && listed:
		return true, "country:" + code, "country " + code + " is denied"
	case h.CountryMode == config.CountryAllow && !listed:
		return true, "country:" + code, "country " + code + " is not in the allowed list"
	}
	return false, "", ""
}

// checkGate enforces HTTP Basic authentication. It reports whether it already
// answered the request.
func (h *Handler) checkGate(w http.ResponseWriter, r *http.Request, d *policy.Decision, ip netip.Addr, now time.Time) bool {
	user, pass, ok := basicAuth(r)
	if ok {
		if res := h.tries.AllowAt(ip.String(), 20, time.Minute, now); !res.Allowed {
			d.AddFinding(policy.Finding{Module: "acl", RuleID: "password_gate", Severity: policy.SeverityWarning, Message: "too many password attempts"})
			d.Terminate("acl", policy.ActionRateLimit)
			w.Header().Set("Retry-After", fmt.Sprint(int(res.RetryAfter.Seconds())+1))
			blockpage.Write(w, r, http.StatusTooManyRequests, d.EventID)
			return true
		}
		if h.gate.check(user, pass) {
			return false
		}
	}
	d.AddFinding(policy.Finding{Module: "acl", RuleID: "password_gate", Severity: policy.SeverityNotice, Message: "password required"})
	d.Terminate("acl", policy.ActionChallenge)
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	blockpage.Write(w, r, http.StatusUnauthorized, d.EventID)
	return true
}

// basicAuth parses an Authorization: Basic header without allocating a Request copy.
func basicAuth(r *http.Request) (user, pass string, ok bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Basic "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(h[len(prefix):])
	if err != nil {
		return "", "", false
	}
	user, pass, found := strings.Cut(string(raw), ":")
	return user, pass, found
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
