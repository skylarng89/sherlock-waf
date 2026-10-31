package auth

import (
	_ "embed"
	"strings"
)

// commonPasswordData is the SecLists list filtered to 12+ character entries
// (see the header of the file and NOTICE). The policy minimum is 12, so
// shorter entries could never match and are not shipped.
//
//go:embed data/common-passwords.txt
var commonPasswordData string

var commonPasswords = parseCorpus(commonPasswordData)

// parseCorpus reads one lower-case entry per line. Lines starting with '#' are
// comments; entries are trimmed and empty lines are skipped.
func parseCorpus(data string) map[string]struct{} {
	set := make(map[string]struct{}, 32_768)
	for line := range strings.SplitSeq(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[line] = struct{}{}
	}
	return set
}

// leetSubstitutions maps the letter-for-symbol swaps people make in common
// words. Digits that are usually part of a number ('1', '2') and '!' are left
// alone: they are handled by the trailing-noise rule instead.
var leetSubstitutions = strings.NewReplacer("0", "o", "3", "e", "4", "a", "5", "s", "7", "t", "@", "a", "$", "s")

// isNoise reports a character that people append to a common word to get past
// a policy: a digit or a symbol.
func isNoise(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= '!' && c <= '/') || (c >= ':' && c <= '@') || (c >= '[' && c <= '`') || (c >= '{' && c <= '~')
}

// normalisedCandidates returns every spelling of p that the corpus should be
// checked against: each prefix of the lower-cased password once its trailing
// digits and symbols are removed, plus a leetspeak-decoded form of each.
func normalisedCandidates(p string) []string {
	lower := strings.ToLower(p)
	var out []string
	for i := len(lower); i > 0; i-- {
		prefix := lower[:i]
		out = append(out, prefix, leetSubstitutions.Replace(prefix))
		if !isNoise(lower[i-1]) {
			break
		}
	}
	return out
}

// isCommonPassword reports whether p, or a spelling of p that drops its
// trailing digits and symbols or decodes leetspeak, is on the corpus or the
// curated short list.
func isCommonPassword(p string) bool {
	for _, c := range normalisedCandidates(p) {
		_, inCorpus := commonPasswords[c]
		_, inCurated := curatedPasswords[c]
		if inCorpus || inCurated {
			return true
		}
	}
	return false
}
