package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func financeConfig(policy string) string {
	return `
schema_version: 1
sites:
  - id: bank
    hosts: [bank.example.com]
    upstreams: { targets: ["h:1"] }
    policy:
` + policy
}

func TestLoginPolicyValidation(t *testing.T) {
	const ok = `{ path: /api/login, username_field: email }`
	tests := []struct {
		name   string
		policy string
		path   string // JSON pointer of the expected error; empty = valid
	}{
		{"valid", "      login_protection: { enabled: true, endpoints: [" + ok + "], thresholds: { per_ip: 20, per_username: 5, window: 10m }, action: challenge }", ""},
		{"json pointer username", `      login_protection: { endpoints: [{ path: /login, username_field: /user/email, failure_statuses: [401, 422] }] }`, ""},
		{"bad action", "      login_protection: { action: nuke }", "/sites/0/policy/login_protection/action"},
		{"path without slash", `      login_protection: { endpoints: [{ path: login, username_field: u }] }`, "/sites/0/policy/login_protection/endpoints/0/path"},
		{"bad glob", `      login_protection: { endpoints: [{ path: "/a[", username_field: u }] }`, "/sites/0/policy/login_protection/endpoints/0/path"},
		{"bad method", `      login_protection: { endpoints: [{ path: /l, method: FETCH, username_field: u }] }`, "/sites/0/policy/login_protection/endpoints/0/method"},
		{"missing username field", `      login_protection: { endpoints: [{ path: /l }] }`, "/sites/0/policy/login_protection/endpoints/0/username_field"},
		{"status out of range", `      login_protection: { endpoints: [{ path: /l, username_field: u, failure_statuses: [99] }] }`, "/sites/0/policy/login_protection/endpoints/0/failure_statuses/0"},
		{"threshold too large", `      login_protection: { thresholds: { per_ip: 1000000 } }`, "/sites/0/policy/login_protection/thresholds/per_ip"},
		{"negative threshold", `      login_protection: { thresholds: { per_username: -1 } }`, "/sites/0/policy/login_protection/thresholds/per_username"},
		{"window too short", `      login_protection: { thresholds: { window: 10s } }`, "/sites/0/policy/login_protection/thresholds/window"},
		{"unknown field", `      login_protection: { passwords: yes }`, "login_protection"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(financeConfig(tc.policy)))
			if tc.path == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.path)
		})
	}
}

func TestLoginPolicyDefaultsAndInheritance(t *testing.T) {
	cfg := `
schema_version: 1
global:
  defaults:
    login_protection:
      thresholds: { per_username: 3, window: 30m }
      action: block
sites:
  - id: bank
    hosts: [bank.example.com]
    upstreams: { targets: ["h:1"] }
    policy:
      login_protection:
        enabled: true
        endpoints: [{ path: /api/login, username_field: email }]
        thresholds: { per_ip: 50 }
`
	root, err := Parse([]byte(cfg))
	require.NoError(t, err)
	l := root.EffectivePolicy(&root.Sites[0], nil).Login
	assert.True(t, l.Active())
	assert.Equal(t, 50, l.PerIP, "site value")
	assert.Equal(t, 3, l.PerUser, "inherited from global")
	assert.Equal(t, DefaultLoginPerDevice, l.PerDevice, "default")
	assert.Equal(t, "30m0s", l.Window.String())
	assert.Equal(t, ActionBlock, l.Action)
	require.Len(t, l.Endpoints, 1)
	assert.Equal(t, "POST", l.Endpoints[0].Method, "method defaults to POST")
	assert.Equal(t, []int{401, 403}, l.Endpoints[0].FailureStatuses, "failure statuses default")

	eff := root.EffectivePolicy(&root.Sites[0], nil)
	assert.Equal(t, SourceGlobal, eff.Sources["login_protection.thresholds.per_username"])
	assert.Equal(t, SourceSite, eff.Sources["login_protection.thresholds.per_ip"])
}

func TestLoginIsInactiveWithoutEndpoints(t *testing.T) {
	root, err := Parse([]byte(financeConfig("      login_protection: { enabled: true }")))
	require.NoError(t, err)
	assert.False(t, root.EffectivePolicy(&root.Sites[0], nil).Login.Active(), "nothing to watch until an endpoint is declared")
	root, err = Parse([]byte(financeConfig("      mode: detect")))
	require.NoError(t, err)
	assert.False(t, root.EffectivePolicy(&root.Sites[0], nil).Login.Enabled, "off unless configured")
}

func TestDLPPolicyValidation(t *testing.T) {
	long := strings.Repeat("a", maxDLPPatternLen+1)
	tests := []struct {
		name   string
		policy string
		path   string
	}{
		{"valid", `      dlp: { enabled: true, detect: [pan, iban, "custom:nin"], custom_patterns: [{ name: nin, pattern: "\\b[A-Z]{2}[0-9]{6}\\b" }], action: mask, max_body_bytes: 2097152 }`, ""},
		{"defaults only", "      dlp: { enabled: true }", ""},
		{"bad action", "      dlp: { action: delete }", "/sites/0/policy/dlp/action"},
		{"bad detect", "      dlp: { detect: [ssn] }", "/sites/0/policy/dlp/detect/0"},
		{"undeclared custom here", `      dlp: { detect: ["custom:x"], custom_patterns: [{ name: y, pattern: "z+" }] }`, "/sites/0/policy/dlp/detect/0"},
		{"bad name", `      dlp: { custom_patterns: [{ name: "Bad Name", pattern: "z+" }] }`, "/sites/0/policy/dlp/custom_patterns/0/name"},
		{"duplicate name", `      dlp: { custom_patterns: [{ name: a, pattern: "z+" }, { name: a, pattern: "y+" }] }`, "/sites/0/policy/dlp/custom_patterns/1/name"},
		{"empty pattern", `      dlp: { custom_patterns: [{ name: a }] }`, "/sites/0/policy/dlp/custom_patterns/0/pattern"},
		{"invalid regexp", `      dlp: { custom_patterns: [{ name: a, pattern: "(" }] }`, "/sites/0/policy/dlp/custom_patterns/0/pattern"},
		{"lookahead is not RE2", `      dlp: { custom_patterns: [{ name: a, pattern: "a(?=b)" }] }`, "/sites/0/policy/dlp/custom_patterns/0/pattern"},
		{"matches empty", `      dlp: { custom_patterns: [{ name: a, pattern: "x*" }] }`, "/sites/0/policy/dlp/custom_patterns/0/pattern"},
		{"pattern too long", fmt.Sprintf(`      dlp: { custom_patterns: [{ name: a, pattern: "%s" }] }`, long), "/sites/0/policy/dlp/custom_patterns/0/pattern"},
		{"body too small", "      dlp: { max_body_bytes: 10 }", "/sites/0/policy/dlp/max_body_bytes"},
		{"body too large", "      dlp: { max_body_bytes: 1073741824 }", "/sites/0/policy/dlp/max_body_bytes"},
		{"bad content type", `      dlp: { content_types: ["Not A Type"] }`, "/sites/0/policy/dlp/content_types/0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(financeConfig(tc.policy)))
			if tc.path == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.path)
		})
	}
}

func TestDLPTooManyPatternsAndDefaults(t *testing.T) {
	var b strings.Builder
	b.WriteString("      dlp:\n        custom_patterns:\n")
	for i := range maxDLPPatterns + 1 {
		fmt.Fprintf(&b, "          - { name: p%d, pattern: \"x%d\" }\n", i, i)
	}
	_, err := Parse([]byte(financeConfig(b.String())))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/sites/0/policy/dlp/custom_patterns")

	root, err := Parse([]byte(financeConfig("      dlp: { enabled: true }")))
	require.NoError(t, err)
	d := root.EffectivePolicy(&root.Sites[0], nil).DLP
	assert.True(t, d.Active())
	assert.Equal(t, []string{DLPDetectPAN}, d.Detect)
	assert.Equal(t, DLPActionMask, d.Action)
	assert.Equal(t, DefaultDLPMaxBodyBytes, d.MaxBodyBytes)
	assert.Contains(t, d.ContentTypes, "application/json")
}

func TestDLPInheritsPatternsFromAHigherLevel(t *testing.T) {
	cfg := `
schema_version: 1
global:
  defaults:
    dlp:
      custom_patterns: [{ name: nin, pattern: "[A-Z]{2}[0-9]{6}" }]
sites:
  - id: bank
    hosts: [bank.example.com]
    upstreams: { targets: ["h:1"] }
    policy:
      dlp: { enabled: true, detect: ["custom:nin"], action: block }
`
	root, err := Parse([]byte(cfg))
	require.NoError(t, err, "a level that declares no patterns may refer to inherited ones")
	d := root.EffectivePolicy(&root.Sites[0], nil).DLP
	assert.Equal(t, []string{"custom:nin"}, d.Detect)
	require.Len(t, d.Custom, 1)
	assert.Equal(t, SourceGlobal, root.EffectivePolicy(&root.Sites[0], nil).Sources["dlp.custom_patterns"])
	assert.Equal(t, "block", d.Action)
}
