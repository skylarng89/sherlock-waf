package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParse(t *testing.T, y string) *Root {
	t.Helper()
	r, err := Parse([]byte(y))
	require.NoError(t, err)
	return r
}

func TestEffectiveDefaults(t *testing.T) {
	r := mustParse(t, siteYAML(""))
	eff := r.EffectivePolicy(&r.Sites[0], nil)
	assert.Equal(t, ModeDetect, eff.Mode)
	assert.Equal(t, FailOpen, eff.FailMode)
	assert.Equal(t, 1, eff.WAF.ParanoiaLevel)
	assert.Equal(t, 1, eff.WAF.BlockingParanoiaLevel)
	assert.Equal(t, 5, eff.WAF.InboundThreshold)
	assert.Equal(t, int64(10<<20), eff.WAF.MaxBodyBytes)
	assert.Equal(t, SourceDefault, eff.Sources["mode"])
	assert.Equal(t, SourceDerived, eff.Sources["fail_mode"])
}

// TestEffectiveMergeTable covers the scalar and object merge rules: the
// lowest layer that sets a field wins and unrelated fields are untouched.
func TestEffectiveMergeTable(t *testing.T) {
	const base = `
schema_version: 1
global:
  defaults: %s
sites:
  - id: s
    hosts: [s.example.com]
    upstreams: { targets: ["h:1"] }
    policy: %s
    endpoints:
      - id: e
        match: { path: /login, methods: [POST] }
        policy: %s
`
	tests := []struct {
		name               string
		global, site, endp string
		check              func(t *testing.T, site, endpoint EffectivePolicy)
	}{
		{
			name:   "global only",
			global: "{ mode: block, waf: { paranoia_level: 2, inbound_threshold: 7 } }",
			site:   "{}", endp: "{}",
			check: func(t *testing.T, site, endpoint EffectivePolicy) {
				for _, e := range []EffectivePolicy{site, endpoint} {
					assert.Equal(t, ModeBlock, e.Mode)
					assert.Equal(t, 2, e.WAF.ParanoiaLevel)
					assert.Equal(t, 2, e.WAF.BlockingParanoiaLevel) // derived
					assert.Equal(t, 7, e.WAF.InboundThreshold)
					assert.Equal(t, FailClosed, e.FailMode)
					assert.Equal(t, SourceGlobal, e.Sources["mode"])
				}
			},
		},
		{
			name:   "site overrides global scalar, objects merge field by field",
			global: "{ mode: detect, waf: { paranoia_level: 1, inbound_threshold: 7 } }",
			site:   "{ mode: block, waf: { inbound_threshold: 9 } }",
			endp:   "{}",
			check: func(t *testing.T, site, _ EffectivePolicy) {
				assert.Equal(t, ModeBlock, site.Mode)
				assert.Equal(t, 1, site.WAF.ParanoiaLevel)
				assert.Equal(t, 9, site.WAF.InboundThreshold)
				assert.Equal(t, SourceSite, site.Sources["mode"])
				assert.Equal(t, SourceGlobal, site.Sources["waf.paranoia_level"])
				assert.Equal(t, SourceSite, site.Sources["waf.inbound_threshold"])
			},
		},
		{
			name:   "endpoint override applies only to endpoint (AC5)",
			global: "{ waf: { paranoia_level: 1 } }",
			site:   "{ mode: block }",
			endp:   "{ waf: { paranoia_level: 2 } }",
			check: func(t *testing.T, site, endpoint EffectivePolicy) {
				assert.Equal(t, 1, site.WAF.ParanoiaLevel)
				assert.Equal(t, 2, endpoint.WAF.ParanoiaLevel)
				assert.Equal(t, 2, endpoint.WAF.BlockingParanoiaLevel)
				assert.Equal(t, ModeBlock, endpoint.Mode)
				assert.Equal(t, "endpoint:e", endpoint.Sources["waf.paranoia_level"])
				assert.Equal(t, SourceSite, endpoint.Sources["mode"])
			},
		},
		{
			name:   "explicit fail_mode beats the mode-derived default",
			global: "{}", site: "{ mode: block, fail_mode: open }", endp: "{}",
			check: func(t *testing.T, site, _ EffectivePolicy) {
				assert.Equal(t, FailOpen, site.FailMode)
				assert.Equal(t, SourceSite, site.Sources["fail_mode"])
			},
		},
		{
			name:   "endpoint mode off",
			global: "{}", site: "{ mode: block }", endp: "{ mode: off }",
			check: func(t *testing.T, site, endpoint EffectivePolicy) {
				assert.Equal(t, ModeBlock, site.Mode)
				assert.Equal(t, ModeOff, endpoint.Mode)
				assert.Equal(t, FailOpen, endpoint.FailMode)
			},
		},
		{
			name:   "list of values is replaced wholesale",
			global: "{ waf: { skip_inspection_extensions: [\".css\", \".js\"] } }",
			site:   "{ waf: { skip_inspection_extensions: [\".png\"] } }", endp: "{}",
			check: func(t *testing.T, site, _ EffectivePolicy) {
				assert.Equal(t, []string{".png"}, site.WAF.SkipInspectionExtensions)
			},
		},
		{
			name:   "explicit blocking level survives paranoia change below",
			global: "{ waf: { paranoia_level: 2, blocking_paranoia_level: 1 } }",
			site:   "{}", endp: "{ waf: { paranoia_level: 3 } }",
			check: func(t *testing.T, site, endpoint EffectivePolicy) {
				assert.Equal(t, 1, site.WAF.BlockingParanoiaLevel)
				assert.Equal(t, 1, endpoint.WAF.BlockingParanoiaLevel)
				assert.Equal(t, 3, endpoint.WAF.ParanoiaLevel)
			},
		},
		{
			name:   "body limit and block page",
			global: "{ block_page: { template_id: default } }",
			site:   "{ waf: { max_body_bytes: 100 } }", endp: "{ waf: { max_body_bytes: 200 } }",
			check: func(t *testing.T, site, endpoint EffectivePolicy) {
				assert.Equal(t, int64(100), site.WAF.MaxBodyBytes)
				assert.Equal(t, int64(200), endpoint.WAF.MaxBodyBytes)
				assert.Equal(t, "default", endpoint.BlockPage.TemplateID)
			},
		},
		{
			name:   "waf disabled at endpoint",
			global: "{}", site: "{}", endp: "{ waf: { enabled: false } }",
			check: func(t *testing.T, site, endpoint EffectivePolicy) {
				assert.True(t, site.WAF.Enabled)
				assert.False(t, endpoint.WAF.Enabled)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			y := sprintf(base, tc.global, tc.site, tc.endp)
			r := mustParse(t, y)
			s := &r.Sites[0]
			tc.check(t, r.EffectivePolicy(s, nil), r.EffectivePolicy(s, &s.Endpoints[0]))
		})
	}
}

func TestEffectiveDoesNotAliasConfig(t *testing.T) {
	r := mustParse(t, siteYAML("    policy: { waf: { skip_inspection_extensions: [\".css\"] } }\n"))
	eff := r.EffectivePolicy(&r.Sites[0], nil)
	eff.WAF.SkipInspectionExtensions[0] = ".evil"
	assert.Equal(t, ".css", r.Sites[0].Policy.WAF.SkipInspectionExtensions[0])
}

func TestOrderedEndpoints(t *testing.T) {
	r := mustParse(t, endpointYAML(
		ep("any-prefix", "path_prefix: /a"),
		ep("glob", `path_glob: "/a/*/xy"`),
		ep("long-prefix", "path_prefix: /a/bcd"),
		ep("exact", "path: /a"),
		ep("prefix-post", "path_prefix: /a, methods: [POST]"),
		ep("exact-post", "path: /a, methods: [POST]"),
	))
	var ids []string
	for _, e := range r.Sites[0].OrderedEndpoints() {
		ids = append(ids, e.ID)
	}
	assert.Equal(t, []string{"exact-post", "exact", "glob", "long-prefix", "prefix-post", "any-prefix"}, ids)
	// the original declaration order is untouched
	assert.Equal(t, "any-prefix", r.Sites[0].Endpoints[0].ID)
}

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }
