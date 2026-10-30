package config

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

// PathsRegexp turns path globs into one anchored regular expression. "*" and
// "?" stay inside a path segment (path.Match semantics); a trailing "/**"
// matches the prefix and everything below it.
func PathsRegexp(globs []string) (string, error) {
	if len(globs) == 0 {
		return "", nil
	}
	parts := make([]string, len(globs))
	for i, g := range globs {
		deep := strings.HasSuffix(g, "/**")
		g = strings.TrimSuffix(g, "/**")
		if _, err := path.Match(g, ""); err != nil {
			return "", fmt.Errorf("invalid path glob %q: %w", g, err)
		}
		var re strings.Builder
		for j := 0; j < len(g); j++ {
			switch c := g[j]; c {
			case '*':
				re.WriteString("[^/]*")
			case '?':
				re.WriteString("[^/]")
			case '[':
				end := strings.IndexByte(g[j:], ']')
				if end < 0 {
					return "", fmt.Errorf("invalid path glob %q", g)
				}
				class := strings.ReplaceAll(g[j+1:j+end], `\`, `\\`)
				re.WriteString("[" + class + "]")
				j += end
			default:
				re.WriteString(regexp.QuoteMeta(string(c)))
			}
		}
		if deep {
			re.WriteString("(?:/.*)?")
		}
		parts[i] = re.String()
	}
	out := "^(?:" + strings.Join(parts, "|") + ")$"
	if strings.ContainsAny(out, "\"\x00\r\n") {
		// QuoteMeta never emits a quote, but a hand-built Settings might carry one.
		out = strings.ReplaceAll(out, `"`, `\x22`)
	}
	return out, nil
}

// Matcher compiles the scope once for repeated use (impact previews scan many
// events). It uses the same translation as the compiled rule, so previews
// agree with enforcement.
func (m ExclusionMatch) Matcher() (func(reqPath, method string) bool, error) {
	var re *regexp.Regexp
	if len(m.Paths) > 0 {
		expr, err := PathsRegexp(m.Paths)
		if err != nil {
			return nil, err
		}
		if re, err = regexp.Compile(expr); err != nil {
			return nil, fmt.Errorf("compiling exclusion path scope: %w", err)
		}
	}
	return func(reqPath, method string) bool {
		if len(m.Methods) > 0 && !slices.Contains(m.Methods, strings.ToUpper(method)) {
			return false
		}
		return re == nil || re.MatchString(reqPath)
	}, nil
}
