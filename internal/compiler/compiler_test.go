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
	assert.Equal(t, []string{"sherlock_core", "sherlock_waf", "headers", "reverse_proxy"}, chains[0])
}

func TestEndpointSubroutesOrderedAndOffOmitsWAF(t *testing.T) {
	chains := chainsFor(t, "endpoint-override", "sherlock_http")
	// health(path exact, off), login(exact+method), uploads(prefix), default
	require.Len(t, chains, 4)
	assert.Equal(t, []string{"sherlock_core", "headers", "reverse_proxy"}, chains[0], "mode off drops sherlock_waf")
	for _, c := range chains[1:] {
		assert.Equal(t, []string{"sherlock_core", "sherlock_waf", "headers", "reverse_proxy"}, c)
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
