package config

import (
	"slices"
	"strings"
	"time"
)

// EffectiveACL is the resolved access-control policy.
type EffectiveACL struct {
	AllowLists     []string `json:"allow_lists"`
	DenyLists      []string `json:"deny_lists"`
	CountryMode    string   `json:"country_mode"`
	Countries      []string `json:"countries"`
	Reputation     bool     `json:"reputation"`
	ReputationAct  string   `json:"reputation_action"`
	PasswordGate   bool     `json:"password_gate"`
	GateUsername   string   `json:"password_gate_username,omitempty"`
	GateHash       string   `json:"-"` // never leaves the node through the API
	AllowBypassWAF bool     `json:"allow_bypass_waf"`
}

// EffectiveAutoBan is the resolved auto-ban policy.
type EffectiveAutoBan struct {
	Enabled         bool          `json:"enabled"`
	BlocksThreshold int           `json:"blocks_threshold"`
	Window          time.Duration `json:"window"`
	BanDuration     time.Duration `json:"ban_duration"`
}

func newEffectiveACL() EffectiveACL {
	return EffectiveACL{AllowLists: []string{}, DenyLists: []string{}, Countries: []string{}, CountryMode: CountryOff, ReputationAct: ActionBlock}
}

// optOutPrefix is the form of an opt_out entry for a rate limit.
const optOutPrefix = "rate_limits:"

// OptOutNames returns the rate-limit names an opt_out list removes.
func OptOutNames(optOut []string) []string {
	var out []string
	for _, o := range optOut {
		if n, ok := strings.CutPrefix(o, optOutPrefix); ok {
			out = append(out, n)
		}
	}
	return out
}

// applyAccess merges one layer's ACL, rate limits and auto-ban into e.
func (e *EffectivePolicy) applyAccess(p *Policy, src string) {
	set := func(field string) { e.Sources[field] = src }

	if a := p.ACL; a != nil {
		if a.AllowLists != nil {
			e.ACL.AllowLists = a.AllowLists.Apply(e.ACL.AllowLists)
			set("acl.allow_lists")
		}
		if a.DenyLists != nil {
			e.ACL.DenyLists = a.DenyLists.Apply(e.ACL.DenyLists)
			set("acl.deny_lists")
		}
		if c := a.Countries; c != nil {
			if c.Mode != "" {
				e.ACL.CountryMode = c.Mode
				set("acl.countries.mode")
			}
			if c.List != nil {
				e.ACL.Countries = slices.Clone(c.List)
				set("acl.countries.list")
			}
		}
		if r := a.Reputation; r != nil {
			e.ACL.Reputation = r.Enabled == nil || *r.Enabled
			if r.Action != "" {
				e.ACL.ReputationAct = r.Action
			}
			set("acl.reputation")
		}
		if g := a.PasswordGate; g != nil {
			e.ACL.PasswordGate = g.Enabled == nil || *g.Enabled
			if g.Username != "" {
				e.ACL.GateUsername = g.Username
			}
			if g.PasswordHash != "" {
				e.ACL.GateHash = g.PasswordHash
			}
			set("acl.password_gate")
		}
		if a.AllowBypassWAF != nil {
			e.ACL.AllowBypassWAF = *a.AllowBypassWAF
			set("acl.allow_bypass_waf")
		}
	}

	// Opt-outs act on what was inherited; this layer's own items are added after.
	for _, name := range OptOutNames(p.OptOut) {
		e.RateLimits = slices.DeleteFunc(e.RateLimits, func(rl RateLimit) bool { return rl.Name == name })
		delete(e.Sources, "rate_limits."+name)
	}
	for _, rl := range p.RateLimits {
		if i := slices.IndexFunc(e.RateLimits, func(x RateLimit) bool { return x.Name == rl.Name }); i >= 0 {
			e.RateLimits[i] = rl
		} else {
			e.RateLimits = append(e.RateLimits, rl)
		}
		set("rate_limits." + rl.Name)
	}

	if b := p.AutoBan; b != nil {
		e.AutoBan.Enabled = b.Enabled == nil || *b.Enabled
		if b.BlocksThreshold != 0 {
			e.AutoBan.BlocksThreshold = b.BlocksThreshold
		}
		if b.Window != 0 {
			e.AutoBan.Window = b.Window.Std()
		}
		if b.BanDuration != 0 {
			e.AutoBan.BanDuration = b.BanDuration.Std()
		}
		set("auto_ban")
	}
}

// sortRateLimits makes the resolved list deterministic (compiled output and
// goldens must not depend on declaration order across layers).
func (e *EffectivePolicy) sortRateLimits() {
	slices.SortStableFunc(e.RateLimits, func(a, b RateLimit) int { return strings.Compare(a.Name, b.Name) })
}
