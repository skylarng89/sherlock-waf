package compiler

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
)

func compiledHandlers(t *testing.T, yaml string) ([]string, map[string]map[string]any, error) {
	t.Helper()
	root, err := config.Parse([]byte(yaml))
	require.NoError(t, err)
	out, err := Compile(root, Options{})
	if err != nil {
		return nil, nil, err
	}
	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	var order []string
	byName := map[string]map[string]any{}
	var find func(any)
	find = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if h, ok := x["handler"].(string); ok && len(h) > 9 && h[:9] == "sherlock_" {
				order = append(order, h)
				byName[h] = x
			}
			for _, c := range x {
				find(c)
			}
		case []any:
			for _, c := range x {
				find(c)
			}
		}
	}
	find(doc["apps"])
	return order, byName, nil
}

func financeYAML(policy string) string {
	return `
schema_version: 1
sites:
  - id: bank
    hosts: [bank.test]
    tls: { mode: none }
    upstreams: { targets: ["origin.internal:8080"] }
    policy:
` + policy
}

func TestLoginAndDLPHandlersSitInThePipelineSlots(t *testing.T) {
	order, h, err := compiledHandlers(t, financeYAML(`
      mode: block
      bot: { enabled: true }
      login_protection:
        enabled: true
        endpoints: [{ path: /api/login, username_field: email }]
        thresholds: { per_ip: 30 }
        action: challenge
      dlp:
        enabled: true
        detect: [pan, "custom:nin"]
        custom_patterns: [{ name: nin, pattern: "[A-Z]{2}[0-9]{6}" }]
        action: mask
`))
	require.NoError(t, err)
	// request-pipeline.md: bot (5), login (6), waf (7), dlp (8), then the proxy.
	assert.Equal(t, []string{"sherlock_core", "sherlock_acl", "sherlock_bot", "sherlock_login", "sherlock_waf", "sherlock_dlp"}, order[:6])

	login := h["sherlock_login"]
	assert.Equal(t, "block", login["mode"])
	assert.Equal(t, "challenge", login["action"])
	assert.EqualValues(t, 30, login["per_ip"])
	assert.EqualValues(t, 5, login["per_username"])
	assert.Equal(t, "10m0s", login["window"])
	assert.Equal(t, true, login["challenge_handoff"], "the bot module serves the challenge")
	ep := login["endpoints"].([]any)[0].(map[string]any)
	assert.Equal(t, "/api/login", ep["path"])
	assert.Equal(t, "POST", ep["method"])
	assert.Equal(t, "email", ep["username_field"])
	assert.Equal(t, []any{float64(401), float64(403)}, ep["failure_statuses"])

	dlp := h["sherlock_dlp"]
	assert.Equal(t, "mask", dlp["action"])
	assert.Equal(t, []any{"pan", "custom:nin"}, dlp["detect"])
	assert.Contains(t, dlp["content_types"], "application/json")
	assert.EqualValues(t, config.DefaultDLPMaxBodyBytes, dlp["max_body_bytes"])
	assert.Equal(t, "nin", dlp["custom_patterns"].([]any)[0].(map[string]any)["name"])
}

func TestFinanceHandlersAreOmittedWhenOffOrNotConfigured(t *testing.T) {
	for name, policy := range map[string]string{
		"not configured":    "      mode: block",
		"login no endpoint": "      mode: block\n      login_protection: { enabled: true }",
		"login disabled":    "      mode: block\n      login_protection: { enabled: false, endpoints: [{ path: /l, username_field: u }] }",
		"dlp disabled":      "      mode: block\n      dlp: { enabled: false }",
		"mode off":          "      mode: \"off\"\n      login_protection: { enabled: true, endpoints: [{ path: /l, username_field: u }] }\n      dlp: { enabled: true }",
	} {
		t.Run(name, func(t *testing.T) {
			order, _, err := compiledHandlers(t, financeYAML(policy))
			require.NoError(t, err)
			assert.NotContains(t, order, "sherlock_login")
			assert.NotContains(t, order, "sherlock_dlp")
		})
	}
}

func TestLoginWithoutBotHasNoChallengeHandoff(t *testing.T) {
	_, h, err := compiledHandlers(t, financeYAML("      login_protection: { enabled: true, endpoints: [{ path: /l, username_field: u }] }"))
	require.NoError(t, err)
	assert.NotContains(t, h["sherlock_login"], "challenge_handoff")
	assert.Equal(t, "detect", h["sherlock_login"]["mode"], "the default mode is detect, so nothing is enforced")
}

func TestDLPRefusesAnUnresolvedCustomPattern(t *testing.T) {
	root, err := config.Parse([]byte(financeYAML(`      dlp: { enabled: true, detect: ["custom:missing"] }`)))
	require.NoError(t, err, "a level without patterns may inherit them, so validation cannot tell")
	_, err = Compile(root, Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "custom:missing")
}
