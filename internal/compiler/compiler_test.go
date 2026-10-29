package compiler

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
)

var update = flag.Bool("update", false, "rewrite golden files")

// testdata reads fixtures through os.Root so names cannot escape the directory.
func testdata(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot("testdata")
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func compileFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := testdata(t).ReadFile(name + ".yaml")
	require.NoError(t, err)
	root, err := config.Parse(data)
	require.NoError(t, err)
	out, err := Compile(root, Options{})
	require.NoError(t, err)
	return out
}

func TestGolden(t *testing.T) {
	files, err := filepath.Glob("testdata/*.yaml")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".yaml")
		t.Run(name, func(t *testing.T) {
			got := compileFixture(t, name)
			golden := name + ".golden.json"
			if *update {
				require.NoError(t, testdata(t).WriteFile(golden, got, 0o600))
			}
			want, err := testdata(t).ReadFile(golden)
			require.NoError(t, err, "run go test ./internal/compiler -update to create it")
			assert.Equal(t, string(want), string(got))
		})
	}
}

func TestDeterministic(t *testing.T) {
	a := compileFixture(t, "two-sites")
	for range 20 {
		require.Equal(t, string(a), string(compileFixture(t, "two-sites")))
	}
}

func TestAdminDisabledAndValidJSON(t *testing.T) {
	for _, name := range []string{"one-site", "two-sites", "path-prefix", "tls-file", "acme", "endpoint-override"} {
		var cfg map[string]any
		require.NoError(t, json.Unmarshal(compileFixture(t, name), &cfg), name)
		assert.Equal(t, map[string]any{"disabled": true, "config": map[string]any{"persist": false}}, cfg["admin"], name)
	}
}

// route digs into the compiled JSON to assert structure without brittle paths.
func chainsFor(t *testing.T, name, server string) [][]string {
	t.Helper()
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Handle []struct {
							Handler string `json:"handler"`
							Routes  []struct {
								Handle []map[string]any `json:"handle"`
							} `json:"routes"`
						} `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	require.NoError(t, json.Unmarshal(compileFixture(t, name), &cfg))
	var out [][]string
	for _, r := range cfg.Apps.HTTP.Servers[server].Routes {
		for _, h := range r.Handle {
			if h.Handler != "subroute" {
				continue
			}
			for _, sr := range h.Routes {
				var chain []string
				for _, hh := range sr.Handle {
					chain = append(chain, hh["handler"].(string))
				}
				out = append(out, chain)
			}
		}
	}
	return out
}

func TestHandlerOrderIsFixed(t *testing.T) {
	chains := chainsFor(t, "one-site", "sherlock_http")
	require.Len(t, chains, 1)
	assert.Equal(t, []string{"sherlock_core", "sherlock_acl", "sherlock_waf", "headers", "reverse_proxy"}, chains[0])
}

func TestEndpointSubroutesOrderedAndOffOmitsWAF(t *testing.T) {
	chains := chainsFor(t, "endpoint-override", "sherlock_http")
	// health(path exact, off), login(exact+method), uploads(prefix), default
	require.Len(t, chains, 4)
	assert.Equal(t, []string{"sherlock_core", "sherlock_acl", "headers", "reverse_proxy"}, chains[0], "mode off drops sherlock_waf")
	for _, c := range chains[1:] {
		assert.Equal(t, []string{"sherlock_core", "sherlock_acl", "sherlock_waf", "headers", "reverse_proxy"}, c)
	}
}

func TestEndpointPolicyReachesCompiledWAF(t *testing.T) {
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(compileFixture(t, "endpoint-override"), &cfg))
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	s := string(raw)
	assert.Contains(t, s, `"paranoia_level":2`)
	assert.Contains(t, s, `"max_body_bytes":52428800`)
	assert.Equal(t, 2, strings.Count(s, `"paranoia_level":1`), "default subroute and uploads keep PL1")
}

func TestTLSScenarios(t *testing.T) {
	file := string(compileFixture(t, "tls-file"))
	assert.Contains(t, file, `"load_files"`)
	assert.Contains(t, file, `"skip_certificates"`)
	assert.Contains(t, file, `"protocol_min": "tls1.3"`)
	assert.Contains(t, file, "max-age=63072000; includeSubDomains")
	assert.Contains(t, file, `"status_code": 308`)

	acme := string(compileFixture(t, "acme"))
	assert.Contains(t, acme, `"module": "acme"`)
	assert.Contains(t, acme, "acme-staging-v02")
	assert.NotContains(t, acme, "legacy.example.com\"],\n          \"issuers\"")

	plain := string(compileFixture(t, "one-site"))
	assert.NotContains(t, plain, sherlockHTTPS, "no TLS sites means no HTTPS listener")
	assert.NotContains(t, plain, "Strict-Transport-Security")
}

const sherlockHTTPS = "sherlock_https"

func TestUnknownHostGets421(t *testing.T) {
	assert.Contains(t, string(compileFixture(t, "two-sites")), `"status_code": 421`)
}

func TestSiteOrdering(t *testing.T) {
	out := string(compileFixture(t, "path-prefix"))
	api := strings.Index(out, `"/api"`)
	web := strings.Index(out, "10.0.1.10:8080")
	assert.Greater(t, web, api, "path-scoped site must precede the catch-all site on the same host")

	two := string(compileFixture(t, "two-sites"))
	assert.Less(t, strings.Index(two, "shop.example.com"), strings.Index(two, "*.blog.example.com"), "wildcard hosts sort last")
}

func TestCustomPortsAndDataDir(t *testing.T) {
	data, err := testdata(t).ReadFile("acme.yaml")
	require.NoError(t, err)
	root, err := config.Parse(data)
	require.NoError(t, err)
	out, err := Compile(root, Options{HTTPPort: 8080, HTTPSPort: 8443, DataDir: "/var/lib/sherlock"})
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, `":8080"`)
	assert.Contains(t, s, `":8443"`)
	assert.Contains(t, s, "https://{http.request.host}:8443{http.request.uri}")
	assert.Contains(t, s, `"root": "/var/lib/sherlock"`)
}

func TestCompileErrors(t *testing.T) {
	_, err := Compile(nil, Options{})
	require.Error(t, err)
}

const proxyOptionsYAML = `
schema_version: 1
sites:
  - id: secure
    hosts: [secure.example.test]
    tls: { mode: file, cert_id: CERT1 }
    upstreams:
      targets: ["origin.internal:443"]
      tls: { enabled: true, client_cert_id: CLIENT1 }
      http_version: "2"
      websockets: false
    policy: { block_page: { template_id: corp-403 } }
  - id: grpc
    hosts: [grpc.example.test]
    tls: { mode: none }
    upstreams: { targets: ["origin.internal:50051"], http_version: h2c }
`

func compileProxyOptions(t *testing.T, opts Options) ([]byte, error) {
	t.Helper()
	root, err := config.Parse([]byte(proxyOptionsYAML))
	require.NoError(t, err)
	return Compile(root, opts)
}

func TestUploadedCertificatesAndProxyOptionsReachTheCompiledConfig(t *testing.T) {
	resolved := map[string]bool{}
	out, err := compileProxyOptions(t, Options{CertFiles: func(id string) (string, string, error) {
		resolved[id] = true
		return "/data/certs/" + id + ".crt", "/data/certs/" + id + ".key", nil
	}})
	require.NoError(t, err)
	got := string(out)

	assert.True(t, resolved["CERT1"] && resolved["CLIENT1"], "both the site and the upstream client certificate are resolved")
	assert.Contains(t, got, `"certificate": "/data/certs/CERT1.crt"`)
	assert.Contains(t, got, `"client_certificate_file": "/data/certs/CLIENT1.crt"`)
	assert.Contains(t, got, `"client_certificate_key_file": "/data/certs/CLIENT1.key"`)
	assert.Contains(t, got, `"block_websockets": true`)
	assert.Contains(t, got, `"block_page_id": "corp-403"`)
	assert.Contains(t, got, `"versions": [`)
	assert.Contains(t, got, `"h2c"`)
	assert.NotContains(t, got, "BEGIN", "key material never appears in the compiled config, only file paths")
}

func TestCertificateReferencesFailClosedWhenUnavailable(t *testing.T) {
	_, err := compileProxyOptions(t, Options{})
	require.ErrorContains(t, err, "is not available on this node")

	_, err = compileProxyOptions(t, Options{CertFiles: func(id string) (string, string, error) {
		if id == "CLIENT1" {
			return "", "", os.ErrNotExist
		}
		return "/c", "/k", nil
	}})
	require.ErrorContains(t, err, "upstream client")
	require.ErrorContains(t, err, "CLIENT1")
}

func TestProxyOptionsAreOmittedWhenUnset(t *testing.T) {
	out := string(compileFixture(t, "one-site"))
	for _, s := range []string{"block_websockets", "block_page_id", "versions", "client_certificate_file"} {
		assert.NotContains(t, out, s)
	}
}

const accessYAML = `
schema_version: 1
global:
  ip_lists:
    - { name: office, cidrs: ["203.0.113.0/24"] }
    - { name: bad, cidrs: ["198.51.100.7"] }
  defaults:
    acl: { deny_lists: [bad], reputation: { enabled: true } }
    rate_limits: [{ name: per-ip, limit: 600, window: 1m }]
    auto_ban: { blocks_threshold: 7, window: 10m, ban_duration: 1h }
sites:
  - id: shop
    hosts: [shop.example.test]
    tls: { mode: none }
    upstreams: { targets: ["h:1"] }
    policy:
      acl: { allow_lists: [office], countries: { mode: deny, list: [KP] } }
    endpoints:
      - id: login
        match: { path: /login, methods: [POST] }
        policy:
          rate_limits: [{ name: login, limit: 10, window: 1m, action: challenge }]
          opt_out: ["rate_limits:per-ip"]
          auto_ban: { blocks_threshold: 2 }
`

func handlersOf(t *testing.T, out []byte) [][]map[string]any {
	t.Helper()
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(out, &cfg))
	var chains [][]map[string]any
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if h, ok := x["handle"].([]any); ok {
				var chain []map[string]any
				for _, e := range h {
					if m, ok := e.(map[string]any); ok {
						chain = append(chain, m)
					}
				}
				if len(chain) > 0 && chain[0]["handler"] == "sherlock_core" {
					chains = append(chains, chain)
				}
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(cfg)
	return chains
}

func TestAccessPolicyReachesTheCompiledChain(t *testing.T) {
	root, err := config.Parse([]byte(accessYAML))
	require.NoError(t, err)
	out, err := Compile(root, Options{})
	require.NoError(t, err)
	chains := handlersOf(t, out)
	require.Len(t, chains, 2, "login endpoint and the site default")

	names := func(c []map[string]any) []string {
		var n []string
		for _, h := range c {
			n = append(n, h["handler"].(string))
		}
		return n
	}
	login, site := chains[0], chains[1]
	want := []string{"sherlock_core", "sherlock_acl", "sherlock_ratelimit", "sherlock_waf", "headers", "reverse_proxy"}
	assert.Equal(t, want, names(site), "order: core, acl, ratelimit, waf")
	assert.Equal(t, want, names(login))

	acl := site[1]
	assert.Equal(t, []any{"office"}, acl["allow_lists"])
	assert.Equal(t, []any{"bad"}, acl["deny_lists"], "global deny list is inherited")
	assert.Equal(t, "deny", acl["country_mode"])
	assert.Equal(t, true, acl["reputation"])

	rules := site[2]["rules"].([]any)
	require.Len(t, rules, 1)
	assert.Equal(t, "per-ip", rules[0].(map[string]any)["name"])
	assert.Equal(t, "1m0s", rules[0].(map[string]any)["window"])

	loginRules := login[2]["rules"].([]any)
	require.Len(t, loginRules, 1, "the endpoint opted out of the global limit and added its own")
	assert.Equal(t, "login", loginRules[0].(map[string]any)["name"])
	assert.Equal(t, "challenge", loginRules[0].(map[string]any)["action"])

	// Auto-ban is per site, from the site-level policy, in every route's module.
	for _, c := range chains {
		ab := c[2]["auto_ban"].(map[string]any)
		assert.EqualValues(t, 7, ab["blocks_threshold"], "the endpoint's own auto_ban does not change the site's")
		assert.Equal(t, "1h0m0s", ab["ban_duration"])
	}
}

func TestBareACLModuleIsAlwaysPresentForBans(t *testing.T) {
	out := compileFixture(t, "one-site")
	chains := handlersOf(t, out)
	require.Len(t, chains, 1)
	assert.Equal(t, "sherlock_acl", chains[0][1]["handler"])
	assert.Len(t, chains[0][1], 2, "with no policy it carries only the handler name and site id")
}

func TestPasswordGateHashReachesTheModuleButNotAnythingElse(t *testing.T) {
	root, err := config.Parse([]byte(`
schema_version: 1
sites:
  - id: private
    hosts: [private.example.test]
    tls: { mode: none }
    upstreams: { targets: ["h:1"] }
    policy: { acl: { password_gate: { username: ada, password_hash: "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA" } } }
`))
	require.NoError(t, err)
	out, err := Compile(root, Options{})
	require.NoError(t, err)
	chains := handlersOf(t, out)
	assert.Equal(t, "ada", chains[0][1]["gate_username"])
	assert.Contains(t, chains[0][1]["gate_hash"], "$argon2id$")
}

func TestBotPolicyReachesTheChainAndEnablesHandoff(t *testing.T) {
	root, err := config.Parse([]byte(`
schema_version: 1
sites:
  - id: shop
    hosts: [shop.example.test]
    tls: { mode: none }
    upstreams: { targets: ["h:1"] }
    policy:
      rate_limits: [{ name: login, limit: 5, window: 1m, action: challenge }]
      bot:
        challenge: turnstile
        site_key: 0x4AAAA
        difficulty: 3
        verified_bots: challenge
        rules: [{ match: { paths: ["/checkout/*"], countries: [KP], reputation: true }, action: challenge }]
  - id: plain
    hosts: [plain.example.test]
    tls: { mode: none }
    upstreams: { targets: ["h:1"] }
`))
	require.NoError(t, err)
	out, err := Compile(root, Options{})
	require.NoError(t, err)
	chains := handlersOf(t, out)
	require.Len(t, chains, 2)
	var shop, plain []map[string]any
	for _, c := range chains {
		if c[0]["site_id"] == "shop" {
			shop = c
		} else {
			plain = c
		}
	}
	order := func(c []map[string]any) []string {
		var n []string
		for _, h := range c {
			n = append(n, h["handler"].(string))
		}
		return n
	}
	assert.Equal(t, []string{"sherlock_core", "sherlock_acl", "sherlock_ratelimit", "sherlock_bot", "sherlock_waf", "headers", "reverse_proxy"}, order(shop))
	assert.NotContains(t, order(plain), "sherlock_bot", "bot defence is opt-in")

	assert.Equal(t, true, shop[2]["challenge_handoff"], "rate limits hand challenges to the bot module when it is on")
	bot := shop[3]
	assert.Equal(t, "turnstile", bot["challenge"])
	assert.Equal(t, "0x4AAAA", bot["site_key"])
	assert.EqualValues(t, 3, bot["difficulty"])
	assert.Equal(t, "30m0s", bot["clearance_ttl"])
	assert.Equal(t, "challenge", bot["verified_bots"])
	rule := bot["rules"].([]any)[0].(map[string]any)
	assert.Equal(t, []any{"KP"}, rule["countries"])
	assert.Equal(t, true, rule["reputation"])
}
