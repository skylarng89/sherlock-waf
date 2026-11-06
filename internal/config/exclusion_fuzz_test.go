package config

import (
	"regexp"
	"strings"
	"testing"
)

// FuzzPathsRegexp checks what the exclusion compiler relies on: a glob either
// is refused or becomes a valid regular expression that cannot break out of the
// quoted SecRule operand it is written into.
func FuzzPathsRegexp(f *testing.F) {
	for _, s := range []string{"/a/*", "/api/**", "/v?/x", "/[ab]/c", "/", "", "/a\"b", "/a\nb", "/a[\"]", "/[", "/\\", "/**", "[a-z]*"} {
		f.Add(s, "/a/b")
	}
	f.Fuzz(func(t *testing.T, glob, p string) {
		expr, err := PathsRegexp([]string{glob})
		if err != nil {
			return
		}
		if strings.ContainsAny(expr, "\"\x00\r\n") {
			t.Fatalf("glob %q produced an expression %q that can escape its directive", glob, expr)
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			t.Fatalf("glob %q produced an invalid expression %q: %v", glob, expr, err)
		}
		_ = re.MatchString(p)
		m := ExclusionMatch{Paths: []string{glob}, Methods: []string{"GET"}}
		match, err := m.Matcher()
		if err != nil {
			t.Fatalf("Matcher refused a glob PathsRegexp accepted: %v", err)
		}
		_ = match(p, "get")
	})
}
