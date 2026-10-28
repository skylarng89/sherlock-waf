package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const minimalYAML = `
schema_version: 1
sites:
  - id: shop
    hosts: ["Shop.Example.com"]
    upstreams:
      targets: ["10.0.1.10:8080"]
`

func TestParseAppliesDefaults(t *testing.T) {
	r, err := Parse([]byte(minimalYAML))
	require.NoError(t, err)
	s := r.Sites[0]
	assert.Equal(t, []string{"shop.example.com"}, s.Hosts)
	assert.Equal(t, TLSACME, s.TLS.Mode)
	assert.Equal(t, "1.2", s.TLS.MinVersion)
	assert.True(t, *s.TLS.HSTS.Enabled)
	assert.Equal(t, LBRoundRobin, s.Upstreams.LBPolicy)
	assert.Equal(t, 5*time.Second, s.Upstreams.Timeouts.Dial.Std())
	assert.True(t, *s.Headers.SecurityHeaders)
}

func TestParseFullSubset(t *testing.T) {
	_, err := Parse([]byte(`
schema_version: 1
global:
  trusted_proxies: ["10.0.0.0/8"]
  acme: { email: ops@example.com, ca: "https://acme-v02.api.letsencrypt.org/directory" }
  defaults:
    mode: detect
    waf: { paranoia_level: 1 }
sites:
  - id: shop
    name: Shop
    hosts: ["shop.example.com"]
    path_prefix: /app
    tls: { mode: file, cert_file: /c.pem, key_file: /k.pem, min_version: "1.3" }
    upstreams:
      targets: ["10.0.1.10:8080", "[::1]:9000"]
      lb_policy: least_conn
      health_check: { path: /healthz, interval: 10s, timeout: 2s }
      tls: { enabled: true }
      timeouts: { dial: 3s, read: 30s, write: 30s }
    headers: { security_headers: true }
    policy:
      mode: block
      block_page: { template_id: default }
      waf: { blocking_paranoia_level: 1, skip_inspection_extensions: [".css"] }
    endpoints:
      - id: login
        match: { path: /login, methods: [POST] }
        policy: { waf: { paranoia_level: 2 } }
`))
	require.NoError(t, err)
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantPath string
		wantCode string
	}{
		{"empty", "", "", CodeSyntax},
		{"bad syntax", "a: [", "", CodeSyntax},
		{"multi doc", minimalYAML + "---\nschema_version: 1\n", "", CodeSyntax},
		{"unknown top-level", minimalYAML + "bogus: 1\n", "/bogus", CodeUnknownField},
		{"unknown nested", `
schema_version: 1
sites:
  - id: a
    hosts: [a.example.com]
    upstreams: { targets: ["h:1"], typo: 1 }
`, "/sites/0/upstreams/typo", CodeUnknownField},
		{"unsupported later-milestone field", `
schema_version: 1
sites:
  - id: a
    hosts: [a.example.com]
    upstreams: { targets: ["h:1"] }
    policy: { rate_limits: [] }
`, "/sites/0/policy/rate_limits", CodeUnknownField},
		{"wrong version", "schema_version: 2\nsites: []\n", "/schema_version", CodeInvalid},
		{"no sites", "schema_version: 1\n", "/sites", CodeRequired},
		{"alias", "schema_version: 1\nx: &a 1\nsites: *a\n", "/sites", CodeSyntax},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			var errs Errors
			require.ErrorAs(t, err, &errs)
			assert.Contains(t, errs, Error{Path: tc.wantPath, Code: tc.wantCode, Message: findMsg(errs, tc.wantPath, tc.wantCode)})
		})
	}
}

func findMsg(errs Errors, path, code string) string {
	for _, e := range errs {
		if e.Path == path && e.Code == code {
			return e.Message
		}
	}
	return ""
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sherlock.yaml")
	require.NoError(t, os.WriteFile(p, []byte(minimalYAML), 0o600))
	r, err := Load(p)
	require.NoError(t, err)
	assert.Len(t, r.Sites, 1)

	_, err = Load(filepath.Join(dir, "missing.yaml"))
	require.Error(t, err)
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(minimalYAML))
	f.Add([]byte("schema_version: 1\nsites: [{id: a, hosts: [a.b], upstreams: {targets: [\"h:1\"]}, endpoints: [{id: e, match: {path_glob: \"/[\"}}]}]\n"))
	f.Add([]byte("{}"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		r, err := Parse(data)
		if err != nil {
			return
		}
		// Anything that validates must resolve without panicking.
		for i := range r.Sites {
			_ = r.EffectivePolicy(&r.Sites[i], nil)
			_ = r.Sites[i].OrderedEndpoints()
		}
	})
}
