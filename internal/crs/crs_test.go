package crs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
)

func TestCatalogueIsParsedFromTheEmbeddedRules(t *testing.T) {
	all, err := Rules()
	require.NoError(t, err)
	assert.Greater(t, len(all), 300)

	r, ok := Get(942100)
	require.True(t, ok)
	assert.Equal(t, "request", r.Direction)
	assert.Equal(t, "attack-sqli", r.Category)
	assert.Equal(t, 1, r.ParanoiaLevel)
	assert.Contains(t, r.Message, "SQL Injection")
	assert.Equal(t, 2, r.Phase)
	assert.Equal(t, "critical", r.Severity)

	r2, ok := Get(942260)
	require.True(t, ok)
	assert.Equal(t, 2, r2.ParanoiaLevel)

	r3, ok := Get(951230)
	require.True(t, ok)
	assert.Equal(t, "response", r3.Direction)

	for i := 1; i < len(all); i++ {
		require.Less(t, all[i-1].ID, all[i].ID, "ids are unique and sorted")
	}
}

func TestSearch(t *testing.T) {
	r, _ := Get(942100)
	assert.True(t, r.Match(""))
	assert.True(t, r.Match("942"))
	assert.True(t, r.Match("sql injection"))
	assert.True(t, r.Match("attack-sqli"))
	assert.False(t, r.Match("xss"))
}

func eff(mut func(*config.EffectivePolicy)) config.EffectivePolicy {
	e := config.EffectivePolicy{Mode: config.ModeBlock}
	e.WAF.Enabled = true
	e.WAF.ParanoiaLevel = 1
	e.WAF.BlockingParanoiaLevel = 1
	if mut != nil {
		mut(&e)
	}
	return e
}

func TestStateFor(t *testing.T) {
	pl1, _ := Get(942100)
	pl2, _ := Get(942260)
	resp, _ := Get(951230)
	tests := []struct {
		name string
		rule Rule
		eff  config.EffectivePolicy
		want State
		by   []string
	}{
		{"pl1 enforcing", pl1, eff(nil), Enforcing, nil},
		{"pl2 rule below detection level", pl2, eff(nil), Inactive, nil},
		{"pl2 rule above blocking level", pl2, eff(func(e *config.EffectivePolicy) { e.WAF.ParanoiaLevel = 2 }), DetectOnly, nil},
		{"pl2 rule enforcing", pl2, eff(func(e *config.EffectivePolicy) { e.WAF.ParanoiaLevel, e.WAF.BlockingParanoiaLevel = 2, 2 }), Enforcing, nil},
		{"response rule without outbound inspection", resp, eff(nil), Inactive, nil},
		{"response rule with outbound inspection", resp, eff(func(e *config.EffectivePolicy) { e.WAF.OutboundInspection = true }), Enforcing, nil},
		{"waf off", pl1, eff(func(e *config.EffectivePolicy) { e.Mode = config.ModeOff }), Inactive, nil},
		{"removed everywhere by id", pl1, eff(func(e *config.EffectivePolicy) {
			e.WAF.Exclusions = []config.Exclusion{{ID: "x", RemoveRuleIDs: []string{"942000-942199"}}}
		}), Disabled, []string{"x"}},
		{"removed everywhere by tag", pl1, eff(func(e *config.EffectivePolicy) {
			e.WAF.Exclusions = []config.Exclusion{{ID: "t", RemoveTags: []string{"attack-sqli"}}}
		}), Disabled, []string{"t"}},
		{"removed on one path", pl1, eff(func(e *config.EffectivePolicy) {
			e.WAF.Exclusions = []config.Exclusion{{ID: "p", Match: config.ExclusionMatch{Paths: []string{"/search"}}, RemoveRuleIDs: []string{"942100"}}}
		}), PartlyExcluded, []string{"p"}},
		{"target removal keeps the rule enforcing", pl1, eff(func(e *config.EffectivePolicy) {
			e.WAF.Exclusions = []config.Exclusion{{ID: "q", RemoveTargets: []config.ExclusionTarget{{RuleIDs: []string{"942100"}, Target: "ARGS:q"}}}}
		}), Enforcing, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := StateFor(tc.rule, tc.eff)
			assert.Equal(t, tc.want, st.State, "%+v", st)
			assert.Equal(t, tc.by, st.By)
		})
	}
}
