package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindPANsIsTheStrictVariant(t *testing.T) {
	const visa = "4111" + "1111" + "1111" + "1111"
	for name, tc := range map[string]struct {
		in   string
		want []PANSpan
	}{
		"plain":            {"x " + visa + " y", []PANSpan{{From: 2, To: 18, Last4: "1111"}}},
		"grouped":          {"4111 1111 1111 1111", []PANSpan{{From: 0, To: 19, Last4: "1111"}}},
		"glued to letters": {"a" + visa, nil},
		"glued to digits":  {"7777" + visa, nil},
		"not a card":       {"4111 1111 1111 1112", nil},
		"none":             {"hello", nil},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, FindPANs(tc.in))
		})
	}
	// Redaction of Sherlock's own events keeps the looser rule: over-masking is harmless there.
	assert.Equal(t, "[PAN:****1111]", maskPANs(visa))
	assert.Contains(t, maskPANs("7777"+visa), "[PAN:****1111]")
}
