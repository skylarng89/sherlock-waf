package vpatch

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedPackIsValid(t *testing.T) {
	all, err := All()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(all), 15, "the initial pack has 15-25 rules")
	assert.LessOrEqual(t, len(all), 25)
	for _, p := range all {
		assert.True(t, p.KEV, "%s: the pack covers exploited CVEs only", p.ID)
		assert.NotEmpty(t, p.Tests.Positive, p.ID)
		assert.NotEmpty(t, p.Tests.Negative, p.ID)
	}
	covered, err := Covered()
	require.NoError(t, err)
	assert.NotEmpty(t, covered)
}

func TestNoCVEIsBothPatchedAndCovered(t *testing.T) {
	all, _ := All()
	covered, _ := Covered()
	patched := map[string]string{}
	for _, p := range all {
		for _, c := range p.CVEs {
			patched[c] = p.ID
		}
	}
	for _, c := range covered {
		assert.NotContains(t, patched, c.CVE, "%s is covered by CRS and also has a rule", c.CVE)
	}
}

func TestActivation(t *testing.T) {
	generic := Patch{ID: "SV-2024-0001"}
	wp := Patch{ID: "SV-2024-0002", Stacks: []string{"wordpress", "php"}}
	tests := []struct {
		name     string
		patch    Patch
		enabled  bool
		disabled []string
		declared []string
		want     bool
	}{
		{"generic needs no stack", generic, true, nil, nil, true},
		{"product rule without stack", wp, true, nil, nil, false},
		{"product rule with another stack", wp, true, nil, []string{"drupal"}, false},
		{"product rule with its stack", wp, true, nil, []string{"wordpress"}, true},
		{"product rule matched by any of its stacks", wp, true, nil, []string{"drupal", "php"}, true},
		{"pack disabled", generic, false, nil, nil, false},
		{"patch disabled", wp, true, []string{"SV-2024-0002"}, []string{"wordpress"}, false},
		{"other patch disabled", wp, true, []string{"SV-2024-0001"}, []string{"wordpress"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.patch.Active(tc.enabled, tc.disabled, tc.declared))
		})
	}
}

func TestSelectOnlyActivatesDeclaredStacks(t *testing.T) {
	none, err := Select(true, nil, nil)
	require.NoError(t, err)
	all, _ := All()
	for _, id := range none {
		p, _ := Get(id)
		assert.True(t, p.Generic(), "%s is product-specific but active without a declared stack", id)
	}
	wp, err := Select(true, nil, []string{"wordpress"})
	require.NoError(t, err)
	assert.Contains(t, wp, "SV-2020-0001")
	assert.NotContains(t, wp, "SV-2018-0001", "the Drupal rule stays off on a WordPress site")
	assert.Len(t, none, 0, "the shipped pack has no generic rules")
	assert.NotEmpty(t, all)
}

func TestDirectivesAreOrderedAndSkipUnknownIDs(t *testing.T) {
	out, err := Directives([]string{"SV-2020-0001", "SV-9999-0001", "SV-2018-0001", "SV-2020-0001"})
	require.NoError(t, err)
	assert.Less(t, strings.Index(out, "# SV-2018-0001\n"), strings.Index(out, "# SV-2020-0001\n"))
	assert.Equal(t, 1, strings.Count(out, "# SV-2020-0001\n"), "duplicates are rendered once")
}

func TestParseRejectsBrokenPatches(t *testing.T) {
	meta := func(mod string) string {
		return `id: SV-2024-0001
title: t
cves: [CVE-2024-0001]
vendor: v
product: p
versions: "1"
severity: high
cvss: 7.5
kev: true
stacks: [x]
references: [https://example.com]
false_positive_notes: none
verification: synthetic
added_in: "2026.10.1"
rule_ids: [9500001]
` + mod
	}
	rule := `SecRule REQUEST_FILENAME "@streq /x" "id:9500001,phase:1,deny"`
	tests := []struct {
		name string
		yaml string
		conf string
		want string
	}{
		{"unknown field", meta("bogus: 1\n"), rule, "bogus"},
		{"rule id outside range", meta(""), `SecRule REQUEST_FILENAME "@streq /x" "id:12345,phase:1,deny"`, "outside the reserved range"},
		{"rule not listed", meta(""), rule + "\n" + `SecRule REQUEST_FILENAME "@streq /y" "id:9500002,phase:1,deny"`, "not listed"},
		{"listed but missing", meta(""), `SecAction "id:9500009,phase:1,pass"`, "not listed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"d/SV-2024-0001.yaml":       {Data: []byte(tc.yaml)},
				"d/SV-2024-0001.conf":       {Data: []byte(tc.conf)},
				"d/SV-2024-0001.tests.yaml": {Data: []byte("positive: [{name: a, method: GET, path: /x}]\nnegative: [{name: b, method: GET, path: /y}]\n")},
			}
			_, err := parse(fsys, "d")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestParseRequiresTests(t *testing.T) {
	fsys := fstest.MapFS{
		"d/SV-2024-0001.yaml": {Data: []byte("id: SV-2024-0001\n")},
		"d/SV-2024-0001.conf": {Data: []byte("")},
	}
	_, err := parse(fsys, "d")
	require.Error(t, err)
}
