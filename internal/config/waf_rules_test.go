package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutboundInspectionIsAccepted(t *testing.T) {
	root, err := Parse([]byte(siteYAML("    policy: { waf: { outbound_inspection: true, outbound_max_body_bytes: 65536, outbound_content_types: [text/html, application/json] } }\n")))
	require.NoError(t, err)
	eff := root.EffectivePolicy(&root.Sites[0], nil)
	assert.True(t, eff.WAF.OutboundInspection)
	assert.Equal(t, int64(65536), eff.WAF.OutboundMaxBodyBytes)
	assert.Equal(t, []string{"text/html", "application/json"}, eff.WAF.OutboundContentTypes)
}

func TestRuleTuningErrors(t *testing.T) {
	tests := []struct {
		name, policy, path, code string
	}{
		{"empty exclusion", `waf: { exclusions: [{ id: x }] }`, "/sites/0/policy/waf/exclusions/0", CodeRequired},
		{"bad exclusion id", `waf: { exclusions: [{ id: "X Y", remove_rule_ids: ["942100"] }] }`, "/sites/0/policy/waf/exclusions/0/id", CodeInvalid},
		{"non numeric rule", `waf: { exclusions: [{ id: x, remove_rule_ids: ["abc"] }] }`, "/sites/0/policy/waf/exclusions/0/remove_rule_ids/0", CodeInvalid},
		{"engine rule", `waf: { exclusions: [{ id: x, remove_rule_ids: ["200002"] }] }`, "/sites/0/policy/waf/exclusions/0/remove_rule_ids/0", CodeInvalid},
		{"virtual patch rule", `waf: { exclusions: [{ id: x, remove_rule_ids: ["9500001"] }] }`, "/sites/0/policy/waf/exclusions/0/remove_rule_ids/0", CodeInvalid},
		{"reversed range", `waf: { exclusions: [{ id: x, remove_rule_ids: ["942200-942100"] }] }`, "/sites/0/policy/waf/exclusions/0/remove_rule_ids/0", CodeInvalid},
		{"target injection", `waf: { exclusions: [{ id: x, remove_targets: [{ rule_ids: ["942100"], target: "ARGS:q;ctl:ruleEngine=Off" }] }] }`, "/sites/0/policy/waf/exclusions/0/remove_targets/0/target", CodeInvalid},
		{"target without rule", `waf: { exclusions: [{ id: x, remove_targets: [{ target: "ARGS:q" }] }] }`, "/sites/0/policy/waf/exclusions/0/remove_targets/0", CodeRequired},
		{"relative path", `waf: { exclusions: [{ id: x, match: { paths: ["search"] }, remove_rule_ids: ["942100"] }] }`, "/sites/0/policy/waf/exclusions/0/match/paths/0", CodeInvalid},
		{"lowercase method", `waf: { exclusions: [{ id: x, match: { methods: ["get"] }, remove_rule_ids: ["942100"] }] }`, "/sites/0/policy/waf/exclusions/0/match/methods/0", CodeInvalid},
		{"duplicate exclusion", `waf: { exclusions: [{ id: x, remove_rule_ids: ["942100"] }, { id: x, remove_rule_ids: ["942101"] }] }`, "/sites/0/policy/waf/exclusions/1/id", CodeDuplicate},
		{"custom rule exec", `waf: { custom_rules: "SecRule ARGS \"@rx x\" \"id:10001,phase:2,pass,exec:/bin/id\"" }`, "/sites/0/policy/waf/custom_rules", "forbidden_action"},
		{"custom rule id", `waf: { custom_rules: "SecAction \"id:5,phase:1,pass\"" }`, "/sites/0/policy/waf/custom_rules", "id_range"},
		{"bad stack", `stacks: ["Word Press"]`, "/sites/0/policy/stacks/0", CodeInvalid},
		{"bad patch id", `virtual_patches: { disabled: ["CVE-1"] }`, "/sites/0/policy/virtual_patches/disabled/0", CodeInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(siteYAML("    policy: { " + tc.policy + " }\n")))
			var errs Errors
			require.ErrorAs(t, err, &errs)
			assert.NotEmpty(t, findMsg(errs, tc.path, tc.code), "got %v", errs)
		})
	}
}

func TestExclusionsAndPatchesMergeAcrossLevels(t *testing.T) {
	root, err := Parse([]byte(`schema_version: 1
global:
  defaults:
    waf:
      exclusions:
        - { id: global-one, remove_rule_ids: ["920350"] }
        - { id: shared, remove_rule_ids: ["920360"] }
    virtual_patches: { enabled: true, disabled: ["SV-2021-0001"] }
sites:
  - id: shop
    hosts: [shop.example.com]
    upstreams: { targets: ["h:1"] }
    policy:
      stacks: [wordpress, php]
      waf:
        exclusions:
          - { id: shared, remove_rule_ids: ["920370"] }
          - { id: site-one, match: { paths: ["/search"] }, remove_targets: [{ rule_ids: ["942100"], target: "ARGS:q" }] }
    endpoints:
      - id: login
        match: { path: /wp-login.php }
        policy:
          stacks: { add: [apache], remove: [php] }
          virtual_patches: { disabled: ["SV-2022-0002"] }
          opt_out: ["exclusions:global-one"]
`))
	require.NoError(t, err)
	site := &root.Sites[0]

	siteEff := root.EffectivePolicy(site, nil)
	ids := []string{}
	for _, e := range siteEff.WAF.Exclusions {
		ids = append(ids, e.ID)
	}
	assert.Equal(t, []string{"global-one", "shared", "site-one"}, ids)
	assert.Equal(t, []string{"920370"}, siteEff.WAF.Exclusions[1].RemoveRuleIDs, "the lower level replaces an item with the same id")
	assert.Equal(t, []string{"wordpress", "php"}, siteEff.Stacks)
	assert.Equal(t, []string{"SV-2021-0001"}, siteEff.VirtualPatches.Disabled)
	assert.Equal(t, SourceSite, siteEff.Sources["waf.exclusions.site-one"])
	assert.Equal(t, SourceGlobal, siteEff.Sources["waf.exclusions.global-one"])

	epEff := root.EffectivePolicy(site, &site.Endpoints[0])
	ids = ids[:0]
	for _, e := range epEff.WAF.Exclusions {
		ids = append(ids, e.ID)
	}
	assert.Equal(t, []string{"shared", "site-one"}, ids, "opt_out drops an inherited exclusion")
	assert.Equal(t, []string{"wordpress", "apache"}, epEff.Stacks)
	assert.Equal(t, []string{"SV-2021-0001", "SV-2022-0002"}, epEff.VirtualPatches.Disabled)
}

func TestVirtualPatchDefaults(t *testing.T) {
	root, err := Parse([]byte(siteYAML("")))
	require.NoError(t, err)
	eff := root.EffectivePolicy(&root.Sites[0], nil)
	assert.True(t, eff.VirtualPatches.Enabled)
	assert.Empty(t, eff.Stacks)
}
