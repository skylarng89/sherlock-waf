package config

import (
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

// Limits that keep a configuration (and the compiled data-plane state) bounded.
const (
	maxIPLists        = 1000
	maxListEntries    = 1_000_000
	maxRateLimits     = 50
	maxMatchPatterns  = 50
	maxRateLimitValue = 1_000_000
)

var (
	listNameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	countryRE    = regexp.MustCompile(`^[A-Z]{2}$`)
	envNameRE    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	jwtClaimRE   = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	headerNameRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$")
)

func (r *Root) validateAccess(errs *Errors) {
	lists := r.validateGlobalAccess(errs)
	r.Global.Defaults.validateAccess("/global/defaults", lists, nil, true, errs)
	for i := range r.Sites {
		s := &r.Sites[i]
		sp := "/sites/" + strconv.Itoa(i)
		inheritedSite := namesOf(r.Global.Defaults.RateLimits)
		s.Policy.validateAccess(sp+"/policy", lists, inheritedSite, false, errs)
		for j := range s.Endpoints {
			inherited := slices.Concat(inheritedSite, namesOf(s.Policy.RateLimits))
			s.Endpoints[j].Policy.validateAccess(sp+"/endpoints/"+strconv.Itoa(j)+"/policy", lists, inherited, false, errs)
		}
	}
}

func namesOf(rls []RateLimit) []string {
	out := make([]string, len(rls))
	for i, rl := range rls {
		out[i] = rl.Name
	}
	return out
}

// validateGlobalAccess checks ip_lists and feeds and returns the list names.
func (r *Root) validateGlobalAccess(errs *Errors) map[string]bool {
	g := &r.Global
	names := map[string]bool{}
	if len(g.IPLists) > maxIPLists {
		errs.add("/global/ip_lists", CodeOutOfRange, "at most %d lists", maxIPLists)
	}
	total := 0
	for i, l := range g.IPLists {
		p := "/global/ip_lists/" + strconv.Itoa(i)
		switch {
		case !listNameRE.MatchString(l.Name):
			errs.add(p+"/name", CodeInvalid, "must be lowercase letters, digits, '-' or '_' (max 63)")
		case names[l.Name]:
			errs.add(p+"/name", CodeDuplicate, "list %q already defined", l.Name)
		}
		names[l.Name] = true
		total += len(l.CIDRs)
		for j, c := range l.CIDRs {
			if _, err := policy.ParsePrefix(c); err != nil {
				errs.add(p+"/cidrs/"+strconv.Itoa(j), CodeInvalid, "%v", err)
				break // one bad entry per list is enough to act on; keeps error output bounded
			}
		}
	}
	if total > maxListEntries {
		errs.add("/global/ip_lists", CodeOutOfRange, "at most %d entries in total", maxListEntries)
	}

	f := &g.Feeds
	switch f.GeoIP.Provider {
	case "", GeoDBIPLite, GeoMaxMind:
	default:
		errs.add("/global/feeds/geoip/provider", CodeInvalid, "must be %s or %s", GeoDBIPLite, GeoMaxMind)
	}
	for i, l := range f.ReputationLists {
		if !slices.Contains([]string{ListFireHOLLevel1, ListSpamhausDROP}, l) {
			errs.add("/global/feeds/reputation_lists/"+strconv.Itoa(i), CodeInvalid, "unknown list %q (known: %s, %s)", l, ListFireHOLLevel1, ListSpamhausDROP)
		}
	}
	if f.CrowdSec.Enabled {
		if u := f.CrowdSec.LAPIURL; !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			errs.add("/global/feeds/crowdsec/lapi_url", CodeInvalid, "must be an http(s) URL")
		}
	}
	return names
}

func (p *Policy) validateAccess(path string, lists map[string]bool, inherited []string, isGlobal bool, errs *Errors) {
	p.validateBot(path+"/bot", errs)
	p.validateAPI(path+"/api", errs)
	if a := p.ACL; a != nil {
		a.validate(path+"/acl", lists, errs)
	}
	if len(p.RateLimits) > maxRateLimits {
		errs.add(path+"/rate_limits", CodeOutOfRange, "at most %d rate limits per level", maxRateLimits)
	}
	own := map[string]bool{}
	for i, rl := range p.RateLimits {
		rp := path + "/rate_limits/" + strconv.Itoa(i)
		rl.validate(rp, errs)
		if own[rl.Name] {
			errs.add(rp+"/name", CodeDuplicate, "rate limit %q listed twice at this level", rl.Name)
		}
		own[rl.Name] = true
	}
	if b := p.AutoBan; b != nil {
		b.validate(path+"/auto_ban", errs)
	}
	for i, o := range p.OptOut {
		op := path + "/opt_out/" + strconv.Itoa(i)
		if rest, other := strings.CutPrefix(o, optOutExclusions); other || strings.HasPrefix(o, optOutVirtualPatches) {
			switch {
			case isGlobal:
				errs.add(op, CodeInvalid, "the global defaults have nothing to opt out of")
			case other && !slugRE.MatchString(rest):
				errs.add(op, CodeInvalid, "%q is not a valid exclusion id", rest)
			case !other && !vpatchIDRE.MatchString(strings.TrimPrefix(o, optOutVirtualPatches)):
				errs.add(op, CodeInvalid, "%q is not a valid virtual patch id", strings.TrimPrefix(o, optOutVirtualPatches))
			}
			continue
		}
		name, ok := strings.CutPrefix(o, optOutPrefix)
		switch {
		case !ok:
			errs.add(op, CodeInvalid, "must look like %q", optOutPrefix+"<name>")
		case isGlobal:
			errs.add(op, CodeInvalid, "the global defaults have nothing to opt out of")
		case own[name]:
			errs.add(op, CodeInvalid, "%q is both defined and opted out at this level", name)
		case !slices.Contains(inherited, name):
			errs.add(op, CodeNotFound, "no inherited rate limit named %q to opt out of", name)
		}
	}
}

func (a *ACLPolicy) validate(path string, lists map[string]bool, errs *Errors) {
	check := func(field string, l *NameList) {
		if l == nil {
			return
		}
		for i, n := range l.Names() {
			if !lists[n] {
				errs.add(path+"/"+field+"/"+strconv.Itoa(i), CodeNotFound, "no ip_lists entry named %q", n)
			}
		}
	}
	check("allow_lists", a.AllowLists)
	check("deny_lists", a.DenyLists)
	if c := a.Countries; c != nil {
		if !slices.Contains([]string{"", CountryOff, CountryAllow, CountryDeny}, c.Mode) {
			errs.add(path+"/countries/mode", CodeInvalid, "must be off, allow or deny")
		}
		seen := map[string]bool{}
		for i, cc := range c.List {
			cp := path + "/countries/list/" + strconv.Itoa(i)
			if !countryRE.MatchString(cc) {
				errs.add(cp, CodeInvalid, "%q is not an ISO 3166-1 alpha-2 code in capitals", cc)
			}
			if seen[cc] {
				errs.add(cp, CodeDuplicate, "%q listed twice", cc)
			}
			seen[cc] = true
		}
		if c.Mode == CountryAllow && c.List != nil && len(c.List) == 0 {
			errs.add(path+"/countries/list", CodeInvalid, "an empty allow list would block every country")
		}
	}
	if r := a.Reputation; r != nil && !slices.Contains([]string{"", ActionBlock, ActionLog}, r.Action) {
		errs.add(path+"/reputation/action", CodeInvalid, "must be block or log")
	}
	if g := a.PasswordGate; g != nil {
		on := g.Enabled == nil || *g.Enabled
		if on && (g.Username == "" || g.PasswordHash == "") {
			errs.add(path+"/password_gate", CodeRequired, "username and password_hash are required while the gate is enabled")
		}
		if strings.ContainsAny(g.Username, ":\r\n") || len(g.Username) > 64 {
			errs.add(path+"/password_gate/username", CodeInvalid, "must be at most 64 characters without ':' or line breaks")
		}
		if g.PasswordHash != "" && !strings.HasPrefix(g.PasswordHash, "$argon2id$") {
			errs.add(path+"/password_gate/password_hash", CodeInvalid, "must be an argon2id hash (generate one with `sherlock hash-password`)")
		}
	}
}

func (rl *RateLimit) validate(p string, errs *Errors) {
	if !listNameRE.MatchString(rl.Name) {
		errs.add(p+"/name", CodeInvalid, "must be lowercase letters, digits, '-' or '_' (max 63)")
	}
	if rl.Limit < 1 || rl.Limit > maxRateLimitValue {
		errs.add(p+"/limit", CodeOutOfRange, "must be between 1 and %d", maxRateLimitValue)
	}
	if w := rl.Window.Std(); w < time.Second || w > 24*time.Hour {
		errs.add(p+"/window", CodeOutOfRange, "must be between 1s and 24h")
	}
	if !slices.Contains([]string{"", ActionBlock, ActionChallenge, ActionLog}, rl.Action) {
		errs.add(p+"/action", CodeInvalid, "must be block, challenge or log")
	}
	switch k := rl.Key; {
	case k == "" || k == KeyIP:
	case strings.HasPrefix(k, KeyHeaderPrefix):
		if !headerNameRE.MatchString(strings.TrimPrefix(k, KeyHeaderPrefix)) {
			errs.add(p+"/key", CodeInvalid, "header name is not valid")
		}
	case strings.HasPrefix(k, KeyJWTPrefix):
		if !jwtClaimRE.MatchString(strings.TrimPrefix(k, KeyJWTPrefix)) {
			errs.add(p+"/key", CodeInvalid, "claim name is not valid")
		}
	case strings.HasPrefix(k, KeyAPIKeyPrefix):
		if !headerNameRE.MatchString(strings.TrimPrefix(k, KeyAPIKeyPrefix)) {
			errs.add(p+"/key", CodeInvalid, "header name is not valid")
		}
	case k == KeyClientCertSubject:
	default:
		errs.add(p+"/key", CodeInvalid, "must be ip, header:<name>, jwt:<claim>, api_key:<header> or mtls_subject")
	}
	if len(rl.Match.Paths) > maxMatchPatterns || len(rl.Match.Methods) > len(validVerbs) {
		errs.add(p+"/match", CodeOutOfRange, "too many patterns")
	}
	for i, pat := range rl.Match.Paths {
		if !strings.HasPrefix(pat, "/") {
			errs.add(p+"/match/paths/"+strconv.Itoa(i), CodeInvalid, "must start with '/'")
		} else if _, err := path.Match(pat, "/"); err != nil {
			errs.add(p+"/match/paths/"+strconv.Itoa(i), CodeInvalid, "invalid glob: %v", err)
		}
	}
	for i, m := range rl.Match.Methods {
		if !slices.Contains(validVerbs, m) {
			errs.add(p+"/match/methods/"+strconv.Itoa(i), CodeInvalid, "%q is not an HTTP method", m)
		}
	}
}

func (b *AutoBan) validate(p string, errs *Errors) {
	if b.BlocksThreshold < 0 || b.BlocksThreshold > maxRateLimitValue {
		errs.add(p+"/blocks_threshold", CodeOutOfRange, "must be between 1 and %d", maxRateLimitValue)
	}
	if w := b.Window.Std(); w != 0 && (w < time.Second || w > 24*time.Hour) {
		errs.add(p+"/window", CodeOutOfRange, "must be between 1s and 24h")
	}
	if d := b.BanDuration.Std(); d != 0 && (d < time.Minute || d > 30*24*time.Hour) {
		errs.add(p+"/ban_duration", CodeOutOfRange, "must be between 1m and 30d")
	}
}
