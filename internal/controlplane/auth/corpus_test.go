package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCorpusIsFilteredToThePolicyMinimum(t *testing.T) {
	require.Greater(t, len(commonPasswords), 20_000, "the embedded list was loaded")
	for entry := range commonPasswords {
		if len(entry) < MinPasswordLength {
			t.Fatalf("entry %q is shorter than the policy minimum and can never match", entry)
		}
		if entry != strings.ToLower(entry) {
			t.Fatalf("entry %q is not lower-cased", entry)
		}
	}
}

func TestCommonPasswordMatchesThroughNoiseAndLeetspeak(t *testing.T) {
	// "iloveyou1234" is a corpus entry; these are the variants a policy-minded user writes.
	for _, p := range []string{
		"iloveyou1234",
		"ILoveYou1234",
		"iloveyou1234!",
		"iloveyou1234!!!",
		"iloveyou1234!@#",
		"Iloveyou1234!",
	} {
		assert.True(t, isCommonPassword(p), p)
	}
	assert.True(t, isCommonPassword("p@ssw0rd1234!"), "leetspeak decodes to a corpus entry after trailing noise is removed")
}

func TestCommonPasswordDoesNotMatchUnrelatedPassphrases(t *testing.T) {
	for _, p := range []string{
		"vH4-Lq9xm2TcWd",
		"the quick brown fox 42",
		"kettle-orbit-marble-7",
	} {
		assert.False(t, isCommonPassword(p), p)
	}
}

func TestNormalisedCandidatesStripOnlyTrailingNoise(t *testing.T) {
	got := normalisedCandidates("abc123!")
	assert.Contains(t, got, "abc123!")
	assert.Contains(t, got, "abc")
	assert.NotContains(t, normalisedCandidates("ab1c"), "ab", "a digit in the middle is not trailing noise")
}

// FuzzCommonPasswordNormaliser checks the properties the policy relies on:
// the normaliser never panics, and appending a noise character to a password
// never makes a common password look uncommon.
func FuzzCommonPasswordNormaliser(f *testing.F) {
	for _, seed := range []string{"iloveyou1234", "P@ssw0rd!!", "", "a", "1234567890123", "ÄÖÜ-pass", "\x00\xff", "     "} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, p string) {
		_ = normalisedCandidates(p)
		common := isCommonPassword(p)
		if common && isASCII(p) {
			assert.True(t, isCommonPassword(p+"!"), "noise must not hide a match: %q", p)
		}
	})
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
