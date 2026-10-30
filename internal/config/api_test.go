package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func apiConfig(api string) string {
	return `
schema_version: 1
sites:
  - id: bank
    hosts: [api.example.com]
    upstreams: { targets: ["h:1"] }
    policy:
      api:
` + api
}

func TestAPIPolicyValidation(t *testing.T) {
	tests := []struct {
		name string
		api  string
		path string // JSON pointer of the expected error; empty = valid
	}{
		{"valid", `
        enabled: true
        openapi_doc_id: pay
        unknown_path_action: block
        schema_violation_action: log
        jwt:
          - { match: { paths: ["/api/*"] }, jwks_url: "https://auth.example.com/jwks.json", issuer: "https://auth.example.com/", audiences: [shop] }
        mtls: { required_paths: ["/ob/*"], ca_cert_id: ca1 }`, ""},
		{"bad action", "        unknown_path_action: nuke", "/sites/0/policy/api/unknown_path_action"},
		{"http jwks", `
        jwt: [{ jwks_url: "http://auth.example.com/jwks.json", issuer: i }]`, "/sites/0/policy/api/jwt/0/jwks_url"},
		{"metadata address", `
        jwt: [{ jwks_url: "https://169.254.169.254/latest/meta-data", issuer: i }]`, "/sites/0/policy/api/jwt/0/jwks_url"},
		{"loopback", `
        jwt: [{ jwks_url: "https://127.0.0.1/jwks.json", issuer: i }]`, "/sites/0/policy/api/jwt/0/jwks_url"},
		{"private", `
        jwt: [{ jwks_url: "https://10.1.2.3/jwks.json", issuer: i }]`, "/sites/0/policy/api/jwt/0/jwks_url"},
		{"localhost", `
        jwt: [{ jwks_url: "https://localhost/jwks.json", issuer: i }]`, "/sites/0/policy/api/jwt/0/jwks_url"},
		{"credentials in url", `
        jwt: [{ jwks_url: "https://u:p@auth.example.com/jwks.json", issuer: i }]`, "/sites/0/policy/api/jwt/0/jwks_url"},
		{"two key sources", `
        jwt: [{ jwks_url: "https://a.example.com/j", hmac_secret_env: SECRET, issuer: i }]`, "/sites/0/policy/api/jwt/0"},
		{"no key source", `
        jwt: [{ issuer: i }]`, "/sites/0/policy/api/jwt/0"},
		{"no issuer or audience", `
        jwt: [{ jwks_url: "https://a.example.com/j" }]`, "/sites/0/policy/api/jwt/0"},
		{"bad env name", `
        jwt: [{ hmac_secret_env: "not valid", issuer: i }]`, "/sites/0/policy/api/jwt/0/hmac_secret_env"},
		{"skew too large", `
        jwt: [{ jwks_url: "https://a.example.com/j", issuer: i, clock_skew: 1h }]`, "/sites/0/policy/api/jwt/0/clock_skew"},
		{"bad path", `
        jwt: [{ jwks_url: "https://a.example.com/j", issuer: i, match: { paths: ["api"] } }]`, "/sites/0/policy/api/jwt/0/match/paths/0"},
		{"bad mtls path", `
        mtls: { required_paths: ["x"] }`, "/sites/0/policy/api/mtls/required_paths/0"},
		{"body limit", "        max_body_bytes: 999999999", "/sites/0/policy/api/max_body_bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(apiConfig(tt.api)))
			if tt.path == "" {
				require.NoError(t, err)
				return
			}
			var errs Errors
			require.ErrorAs(t, err, &errs)
			var paths []string
			for _, e := range errs {
				paths = append(paths, e.Path)
			}
			assert.Contains(t, paths, tt.path)
		})
	}
}

func TestRateLimitKeysForAPIs(t *testing.T) {
	for key, ok := range map[string]bool{
		"jwt:client_id": true, "jwt:sub": true, "api_key:X-Api-Key": true, "mtls_subject": true, "header:X-Id": true,
		"jwt:": false, "jwt:bad claim": false, "api_key:bad header": false, "cookie:x": false,
	} {
		cfg := `
schema_version: 1
sites:
  - id: bank
    hosts: [api.example.com]
    upstreams: { targets: ["h:1"] }
    policy:
      rate_limits: [{ name: r, key: "` + key + `", limit: 5, window: 1m }]
`
		_, err := Parse([]byte(cfg))
		if ok {
			assert.NoError(t, err, key)
		} else {
			assert.Error(t, err, key)
		}
	}
}

func TestAPIEffectiveInheritance(t *testing.T) {
	cfg := `
schema_version: 1
global:
  defaults:
    api:
      unknown_path_action: block
      jwt: [{ jwks_url: "https://a.example.com/j", issuer: i }]
sites:
  - id: bank
    hosts: [api.example.com]
    upstreams: { targets: ["h:1"] }
    policy:
      api: { enabled: true, openapi_doc_id: pay, mtls: { ca_cert_id: ca1 } }
    endpoints:
      - id: open
        match: { path_prefix: /ob }
        policy:
          api: { mtls: { required_paths: ["/ob/*"] }, schema_violation_action: block }
`
	root, err := Parse([]byte(cfg))
	require.NoError(t, err)
	site := &root.Sites[0]
	site0 := root.EffectivePolicy(site, nil).API
	assert.True(t, site0.Enabled)
	assert.Equal(t, "pay", site0.OpenAPIDocID)
	assert.Equal(t, "block", site0.UnknownPathAction, "inherited from global")
	assert.Equal(t, "log", site0.SchemaViolationAction, "default")
	require.Len(t, site0.JWT, 1)
	assert.Equal(t, "block", site0.JWT[0].Action, "default action")
	assert.Equal(t, []string{"/*"}, site0.JWT[0].Match.Paths)

	ep := root.EffectivePolicy(site, &site.Endpoints[0]).API
	assert.Equal(t, "block", ep.SchemaViolationAction)
	assert.Equal(t, "ca1", ep.MTLS.CACertID, "objects merge field by field")
	assert.Equal(t, []string{"/ob/*"}, ep.MTLS.RequiredPaths)

	refs := root.References()
	assert.Equal(t, []string{"/sites/0/policy/api/openapi_doc_id"}, refs.OpenAPIDocs["pay"])
	assert.Equal(t, []string{"/sites/0/policy/api/mtls/ca_cert_id"}, refs.CACerts["ca1"])
	assert.False(t, strings.Contains(site0.OpenAPIDocID, " "))
}
