package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const accessGlobal = `
schema_version: 1
global:
  ip_lists:
    - { name: office, cidrs: ["203.0.113.0/24", "2001:db8::/32"] }
    - { name: known-bad, cidrs: ["198.51.100.7"] }
    - { name: partners, cidrs: ["192.0.2.0/28"] }
  defaults:
    acl:
      deny_lists: [known-bad]
      countries: { mode: deny, list: [KP] }
    rate_limits:
      - { name: global-per-ip, limit: 600, window: 1m }
      - { name: noisy, limit: 5, window: 10s, action: log }
    auto_ban: { blocks_threshold: 10 }
`

func access(site string) string {
	return accessGlobal + `
sites:
  - id: shop
    hosts: [shop.example.test]
    tls: { mode: none }
    upstreams: { targets: ["h:1"] }
` + site
}

func parseAccess(t *testing.T, site string) *Root {
	t.Helper()
	r, err := Parse([]byte(access(site)))
	require.NoError(t, err)
	return r
}

func TestAccessDefaultsAndGlobalInheritance(t *testing.T) {
	r := parseAccess(t, "")
	eff := r.EffectivePolicy(&r.Sites[0], nil)

	assert.Equal(t, []string{"known-bad"}, eff.ACL.DenyLists)
	assert.Equal(t, "deny", eff.ACL.CountryMode)
	assert.Equal(t, []string{"KP"}, eff.ACL.Countries)
	require.Len(t, eff.RateLimits, 2)
	assert.Equal(t, "global-per-ip", eff.RateLimits[0].Name)
	assert.Equal(t, "ip", eff.RateLimits[0].Key, "key defaults to ip")
	assert.Equal(t, "block", eff.RateLimits[0].Action, "action defaults to block")
	assert.Equal(t, []string{"/*"}, eff.RateLimits[0].Match.Paths)
	assert.Equal(t, "global", eff.Sources["rate_limits.global-per-ip"])
	assert.True(t, eff.AutoBan.Enabled, "a present block without enabled means on")
	assert.Equal(t, 10, eff.AutoBan.BlocksThreshold)
	assert.Equal(t, 5*time.Minute, eff.AutoBan.Window, "unset fields get the documented defaults")
	assert.Equal(t, 30*time.Minute, eff.AutoBan.BanDuration)
	assert.False(t, eff.ACL.AllowBypassWAF, "an allow list does not skip the WAF unless asked")
}

func TestNamedListsUnionReplaceAndOptOut(t *testing.T) {
	r := parseAccess(t, `    policy:
      rate_limits:
        - { name: global-per-ip, limit: 60, window: 1m, action: challenge }   # replaces the global item
        - { name: site-login, limit: 10, window: 1m }
      opt_out: ["rate_limits:noisy"]
    endpoints:
      - id: health
        match: { path: /healthz }
        policy:
          opt_out: ["rate_limits:global-per-ip", "rate_limits:site-login"]
`)
	site := r.EffectivePolicy(&r.Sites[0], nil)
	names := func(e EffectivePolicy) []string {
		out := []string{}
		for _, rl := range e.RateLimits {
			out = append(out, rl.Name)
		}
		return out
	}
	assert.Equal(t, []string{"global-per-ip", "site-login"}, names(site), "noisy was opted out, site-login added")
	assert.Equal(t, 60, site.RateLimits[0].Limit, "a lower level replaces an item of the same name")
	assert.Equal(t, "site", site.Sources["rate_limits.global-per-ip"])
	assert.NotContains(t, site.Sources, "rate_limits.noisy")

	ep := r.EffectivePolicy(&r.Sites[0], &r.Sites[0].Endpoints[0])
	assert.Empty(t, ep.RateLimits, "an endpoint can opt out of global and site items")
}

func TestListReferencesReplaceOrEdit(t *testing.T) {
	r := parseAccess(t, `    policy:
      acl:
        allow_lists: [office]
        deny_lists: { add: [partners], remove: [known-bad] }
    endpoints:
      - id: admin
        match: { path_prefix: /admin }
        policy:
          acl: { allow_lists: { add: [partners] }, deny_lists: [] }
`)
	site := r.EffectivePolicy(&r.Sites[0], nil)
	assert.Equal(t, []string{"office"}, site.ACL.AllowLists)
	assert.Equal(t, []string{"partners"}, site.ACL.DenyLists, "edit: remove inherited, add new")
	assert.Equal(t, "site", site.Sources["acl.deny_lists"])

	ep := r.EffectivePolicy(&r.Sites[0], &r.Sites[0].Endpoints[0])
	assert.Equal(t, []string{"office", "partners"}, ep.ACL.AllowLists, "edit adds to the inherited list")
	assert.Empty(t, ep.ACL.DenyLists, "a sequence replaces; an empty one clears")
	assert.Equal(t, "endpoint:admin", ep.Sources["acl.allow_lists"])
}

func TestPasswordGateHashIsNeverInTheJSONForm(t *testing.T) {
	r := parseAccess(t, `    policy:
      acl: { password_gate: { username: ada, password_hash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA" } }
`)
	eff := r.EffectivePolicy(&r.Sites[0], nil)
	assert.True(t, eff.ACL.PasswordGate)
	assert.Equal(t, "ada", eff.ACL.GateUsername)
	assert.NotEmpty(t, eff.ACL.GateHash)
	b, err := jsonOf(eff)
	require.NoError(t, err)
	assert.NotContains(t, b, "argon2id", "the effective-policy API must not return the hash")
}

func TestAccessValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		site, path string
		code       string
	}{
		"unknown allow list": {"    policy: { acl: { allow_lists: [nope] } }\n", "/sites/0/policy/acl/allow_lists/0", CodeNotFound},
		"unknown add":        {"    policy: { acl: { deny_lists: { add: [nope] } } }\n", "/sites/0/policy/acl/deny_lists/0", CodeNotFound},
		"bad country":        {"    policy: { acl: { countries: { mode: deny, list: [kp] } } }\n", "/sites/0/policy/acl/countries/list/0", CodeInvalid},
		"country mode":       {"    policy: { acl: { countries: { mode: maybe } } }\n", "/sites/0/policy/acl/countries/mode", CodeInvalid},
		"empty allow set":    {"    policy: { acl: { countries: { mode: allow, list: [] } } }\n", "/sites/0/policy/acl/countries/list", CodeInvalid},
		"gate needs creds":   {"    policy: { acl: { password_gate: { enabled: true } } }\n", "/sites/0/policy/acl/password_gate", CodeRequired},
		"gate plaintext":     {"    policy: { acl: { password_gate: { username: a, password_hash: secret } } }\n", "/sites/0/policy/acl/password_gate/password_hash", CodeInvalid},
		"rl limit":           {"    policy: { rate_limits: [{ name: a, limit: 0, window: 1m }] }\n", "/sites/0/policy/rate_limits/0/limit", CodeOutOfRange},
		"rl window":          {"    policy: { rate_limits: [{ name: a, limit: 1, window: 25h }] }\n", "/sites/0/policy/rate_limits/0/window", CodeOutOfRange},
		"rl key":             {"    policy: { rate_limits: [{ name: a, limit: 1, window: 1m, key: cookie }] }\n", "/sites/0/policy/rate_limits/0/key", CodeInvalid},
		"rl header":          {"    policy: { rate_limits: [{ name: a, limit: 1, window: 1m, key: \"header:bad name\" }] }\n", "/sites/0/policy/rate_limits/0/key", CodeInvalid},
		"rl action":          {"    policy: { rate_limits: [{ name: a, limit: 1, window: 1m, action: ban }] }\n", "/sites/0/policy/rate_limits/0/action", CodeInvalid},
		"rl glob":            {"    policy: { rate_limits: [{ name: a, limit: 1, window: 1m, match: { paths: [\"/[x\"] } }] }\n", "/sites/0/policy/rate_limits/0/match/paths/0", CodeInvalid},
		"rl path":            {"    policy: { rate_limits: [{ name: a, limit: 1, window: 1m, match: { paths: [x] } }] }\n", "/sites/0/policy/rate_limits/0/match/paths/0", CodeInvalid},
		"rl method":          {"    policy: { rate_limits: [{ name: a, limit: 1, window: 1m, match: { methods: [FETCH] } }] }\n", "/sites/0/policy/rate_limits/0/match/methods/0", CodeInvalid},
		"rl duplicate":       {"    policy: { rate_limits: [{ name: a, limit: 1, window: 1m }, { name: a, limit: 2, window: 1m }] }\n", "/sites/0/policy/rate_limits/1/name", CodeDuplicate},
		"autoban duration":   {"    policy: { auto_ban: { ban_duration: 1s } }\n", "/sites/0/policy/auto_ban/ban_duration", CodeOutOfRange},
		"opt out shape":      {"    policy: { opt_out: [noisy] }\n", "/sites/0/policy/opt_out/0", CodeInvalid},
		"opt out nothing":    {"    policy: { opt_out: [\"rate_limits:ghost\"] }\n", "/sites/0/policy/opt_out/0", CodeNotFound},
		"opt out and define": {"    policy: { rate_limits: [{ name: noisy, limit: 1, window: 1m }], opt_out: [\"rate_limits:noisy\"] }\n", "/sites/0/policy/opt_out/0", CodeInvalid},
	} {
		_, err := Parse([]byte(access(tc.site)))
		var errs Errors
		require.ErrorAs(t, err, &errs, name)
		assert.NotEmpty(t, findMsg(errs, tc.path, tc.code), "%s: got %v", name, errs)
	}
}

func TestGlobalAccessValidation(t *testing.T) {
	for name, tc := range map[string]struct{ global, path, code string }{
		"list name":      {"  ip_lists: [{ name: Bad Name, cidrs: [] }]", "/global/ip_lists/0/name", CodeInvalid},
		"duplicate":      {"  ip_lists: [{ name: a, cidrs: [] }, { name: a, cidrs: [] }]", "/global/ip_lists/1/name", CodeDuplicate},
		"bad cidr":       {"  ip_lists: [{ name: a, cidrs: [\"10.0.0.0/33\"] }]", "/global/ip_lists/0/cidrs/0", CodeInvalid},
		"geo provider":   {"  feeds: { geoip: { provider: ipinfo } }", "/global/feeds/geoip/provider", CodeInvalid},
		"rep list":       {"  feeds: { reputation_lists: [mystery] }", "/global/feeds/reputation_lists/0", CodeInvalid},
		"crowdsec url":   {"  feeds: { crowdsec: { enabled: true, lapi_url: \"ftp://x\" } }", "/global/feeds/crowdsec/lapi_url", CodeInvalid},
		"global opt out": {"  defaults: { opt_out: [\"rate_limits:x\"] }", "/global/defaults/opt_out/0", CodeInvalid},
	} {
		y := "schema_version: 1\nglobal:\n" + tc.global + "\nsites:\n  - { id: a, hosts: [a.example.test], upstreams: { targets: [\"h:1\"] } }\n"
		_, err := Parse([]byte(y))
		var errs Errors
		require.ErrorAs(t, err, &errs, name)
		assert.NotEmpty(t, findMsg(errs, tc.path, tc.code), "%s: got %v", name, errs)
	}
}

func TestAccessConfigRoundTripsThroughYAMLAndJSON(t *testing.T) {
	r := parseAccess(t, `    policy:
      acl:
        allow_lists: [office]
        deny_lists: { add: [partners], remove: [known-bad] }
      rate_limits: [{ name: login, limit: 10, window: 1m, key: "header:X-Api-Key", action: challenge }]
      opt_out: ["rate_limits:noisy"]
`)
	y, err := MarshalYAML(r)
	require.NoError(t, err)
	back, err := Parse(y)
	require.NoError(t, err, string(y))
	a, _ := Snapshot(r)
	b, _ := Snapshot(back)
	assert.JSONEq(t, string(a), string(b))
	assert.True(t, strings.Contains(string(y), "add:"), "edit form is preserved in export")

	snap, err := FromSnapshot(a)
	require.NoError(t, err)
	c, _ := Snapshot(snap)
	assert.JSONEq(t, string(a), string(c), "the stored snapshot form decodes back to the same configuration")
}

func jsonOf(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

func TestBotPolicyDefaultsMergeAndValidation(t *testing.T) {
	r := parseAccess(t, `    policy:
      bot:
        challenge: pow
        rules:
          - { match: { paths: ["/checkout/*"], methods: [POST] } }
          - { match: { countries: [KP] }, action: block }
    endpoints:
      - id: login
        match: { path: /login }
        policy: { bot: { difficulty: 5, verified_bots: challenge } }
`)
	site := r.EffectivePolicy(&r.Sites[0], nil)
	assert.True(t, site.Bot.Enabled, "a bot block without enabled means on")
	assert.Equal(t, 4, site.Bot.Difficulty)
	assert.Equal(t, 30*time.Minute, site.Bot.ClearanceTTL)
	assert.Equal(t, "allow", site.Bot.VerifiedBots)
	require.Len(t, site.Bot.Rules, 2)
	assert.Equal(t, "challenge", site.Bot.Rules[0].Action, "rule action defaults to challenge")

	ep := r.EffectivePolicy(&r.Sites[0], &r.Sites[0].Endpoints[0])
	assert.Equal(t, 5, ep.Bot.Difficulty)
	assert.Equal(t, "challenge", ep.Bot.VerifiedBots)
	assert.Len(t, ep.Bot.Rules, 2, "rules are inherited when the endpoint sets none")
	assert.Equal(t, "site", ep.Sources["bot.rules"])
	assert.Equal(t, "endpoint:login", ep.Sources["bot.difficulty"])

	none := parseAccess(t, "")
	assert.False(t, none.EffectivePolicy(&none.Sites[0], nil).Bot.Enabled, "bot defence is opt-in")

	for name, tc := range map[string]struct{ site, path string }{
		"challenge type": {"    policy: { bot: { challenge: captcha } }\n", "/sites/0/policy/bot/challenge"},
		"difficulty":     {"    policy: { bot: { difficulty: 9 } }\n", "/sites/0/policy/bot/difficulty"},
		"ttl":            {"    policy: { bot: { clearance_ttl: 1s } }\n", "/sites/0/policy/bot/clearance_ttl"},
		"verified bots":  {"    policy: { bot: { verified_bots: maybe } }\n", "/sites/0/policy/bot/verified_bots"},
		"site key":       {"    policy: { bot: { site_key: \"a b\" } }\n", "/sites/0/policy/bot/site_key"},
		"rule action":    {"    policy: { bot: { rules: [{ action: ban }] } }\n", "/sites/0/policy/bot/rules/0/action"},
		"rule glob":      {"    policy: { bot: { rules: [{ match: { paths: [x] } }] } }\n", "/sites/0/policy/bot/rules/0/match/paths/0"},
		"rule country":   {"    policy: { bot: { rules: [{ match: { countries: [kp] } }] } }\n", "/sites/0/policy/bot/rules/0/match/countries/0"},
	} {
		_, err := Parse([]byte(access(tc.site)))
		var errs Errors
		require.ErrorAs(t, err, &errs, name)
		assert.NotEmpty(t, findMsg(errs, tc.path, CodeInvalid)+findMsg(errs, tc.path, CodeOutOfRange), "%s: %v", name, errs)
	}
}
