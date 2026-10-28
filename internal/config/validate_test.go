package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func siteYAML(extra string) string {
	return `
schema_version: 1
sites:
  - id: shop
    hosts: [shop.example.com]
    upstreams: { targets: ["10.0.0.1:80"] }
` + extra
}

func withUpstreams(u string) string {
	return strings.Replace(siteYAML(""), `{ targets: ["10.0.0.1:80"] }`, u, 1)
}

func TestValidateSiteErrors(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantPath string
		wantCode string
	}{
		{"bad id", strings.Replace(siteYAML(""), "id: shop", "id: Shop_1", 1), "/sites/0/id", CodeInvalid},
		{"bad host", strings.Replace(siteYAML(""), "shop.example.com", "bad_host", 1), "/sites/0/hosts/0", CodeInvalid},
		{"bad target", strings.Replace(siteYAML(""), "10.0.0.1:80", "nohost", 1), "/sites/0/upstreams/targets/0", CodeInvalid},
		{"port range", strings.Replace(siteYAML(""), "10.0.0.1:80", "h:70000", 1), "/sites/0/upstreams/targets/0", CodeInvalid},
		{"bad tls mode", siteYAML("    tls: { mode: weird }\n"), "/sites/0/tls/mode", CodeInvalid},
		{"file tls needs files", siteYAML("    tls: { mode: file }\n"), "/sites/0/tls/cert_file", CodeRequired},
		{"files without file mode", siteYAML("    tls: { mode: acme, cert_file: /x }\n"), "/sites/0/tls", CodeInvalid},
		{"bad min tls", siteYAML("    tls: { min_version: \"1.0\" }\n"), "/sites/0/tls/min_version", CodeInvalid},
		{"bad mode", siteYAML("    policy: { mode: nope }\n"), "/sites/0/policy/mode", CodeInvalid},
		{"pl range", siteYAML("    policy: { waf: { paranoia_level: 5 } }\n"), "/sites/0/policy/waf/paranoia_level", CodeOutOfRange},
		{"blocking above pl", siteYAML("    policy: { waf: { blocking_paranoia_level: 3 } }\n"), "/sites/0/policy/waf/blocking_paranoia_level", CodeInvalid},
		{"outbound unsupported", siteYAML("    policy: { waf: { outbound_inspection: true } }\n"), "/sites/0/policy/waf/outbound_inspection", CodeUnsupported},
		{"body limit", siteYAML("    policy: { waf: { max_body_bytes: 0 } }\n"), "/sites/0/policy/waf/max_body_bytes", CodeOutOfRange},
		{"bad ext", siteYAML("    policy: { waf: { skip_inspection_extensions: [css] } }\n"), "/sites/0/policy/waf/skip_inspection_extensions/0", CodeInvalid},
		{"template", siteYAML("    policy: { block_page: { template_id: fancy } }\n"), "/sites/0/policy/block_page/template_id", CodeUnsupported},
		{"client cert", withUpstreams(`{ targets: ["h:1"], tls: { client_cert_id: c } }`), "/sites/0/upstreams/tls/client_cert_id", CodeUnsupported},
		{"health timeout > interval", withUpstreams(`{ targets: ["h:1"], health_check: { path: /h, interval: 1s, timeout: 5s } }`), "/sites/0/upstreams/health_check/timeout", CodeOutOfRange},
		{"path prefix", siteYAML("    path_prefix: app\n"), "/sites/0/path_prefix", CodeInvalid},
		{"global proxy cidr", "schema_version: 1\nglobal: { trusted_proxies: [\"10.0.0.0/40\"] }\nsites:\n  - {id: a, hosts: [a.b], upstreams: {targets: [\"h:1\"]}}\n", "/global/trusted_proxies", CodeInvalid},
		{"acme ca", "schema_version: 1\nglobal: { acme: { ca: \"http://x\" } }\nsites:\n  - {id: a, hosts: [a.b], upstreams: {targets: [\"h:1\"]}}\n", "/global/acme/ca", CodeInvalid},
		{"duplicate site", siteYAML("  - id: shop\n    hosts: [other.example.com]\n    upstreams: { targets: [\"h:1\"] }\n"), "/sites/1/id", CodeDuplicate},
		{"duplicate host", siteYAML("  - id: other\n    hosts: [shop.example.com]\n    upstreams: { targets: [\"h:1\"] }\n"), "/sites/1/hosts/0", CodeDuplicate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			var errs Errors
			require.ErrorAs(t, err, &errs)
			assert.NotEmpty(t, findMsg(errs, tc.wantPath, tc.wantCode), "got %v", errs)
		})
	}
}

func TestSameHostDifferentPrefixAllowed(t *testing.T) {
	_, err := Parse([]byte(siteYAML(`  - id: api
    hosts: [shop.example.com]
    path_prefix: /api
    upstreams: { targets: ["h:1"] }
`)))
	require.NoError(t, err)
}

func endpointYAML(eps ...string) string {
	return siteYAML("    endpoints:\n" + strings.Join(eps, ""))
}

func ep(id, match string) string {
	return fmt.Sprintf("      - { id: %s, match: { %s } }\n", id, match)
}

func TestEndpointValidation(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantPath string
		wantCode string
	}{
		{"no matcher", endpointYAML(ep("a", "methods: [GET]")), "/sites/0/endpoints/0/match", CodeInvalid},
		{"two matchers", endpointYAML(ep("a", "path: /x, path_prefix: /y")), "/sites/0/endpoints/0/match", CodeInvalid},
		{"relative path", endpointYAML(ep("a", "path: x")), "/sites/0/endpoints/0/match/path", CodeInvalid},
		{"traversal", endpointYAML(ep("a", "path_prefix: /a/../b")), "/sites/0/endpoints/0/match/path_prefix", CodeInvalid},
		{"bad glob", endpointYAML(ep("a", `path_glob: "/[x"`)), "/sites/0/endpoints/0/match/path_glob", CodeInvalid},
		{"bad method", endpointYAML(ep("a", "path: /x, methods: [get]")), "/sites/0/endpoints/0/match/methods/0", CodeInvalid},
		{"dup method", endpointYAML(ep("a", "path: /x, methods: [GET, GET]")), "/sites/0/endpoints/0/match/methods/1", CodeDuplicate},
		{"dup id", endpointYAML(ep("a", "path: /x"), ep("a", "path: /y")), "/sites/0/endpoints/1/id", CodeDuplicate},
		{"identical exact", endpointYAML(ep("a", "path: /x"), ep("b", "path: /x")), "/sites/0/endpoints/1/match", CodeAmbiguous},
		{"identical exact overlapping methods", endpointYAML(ep("a", "path: /x, methods: [GET, POST]"), ep("b", "path: /x, methods: [POST]")), "/sites/0/endpoints/1/match", CodeAmbiguous},
		{"identical prefix", endpointYAML(ep("a", "path_prefix: /x"), ep("b", "path_prefix: /x")), "/sites/0/endpoints/1/match", CodeAmbiguous},
		{"glob overlapping heads same length", endpointYAML(ep("a", `path_glob: "/ab*"`), ep("b", `path_glob: "/a*c"`)), "/sites/0/endpoints/1/match", CodeAmbiguous},
		{"prefix vs glob same length", endpointYAML(ep("a", "path_prefix: /abcd"), ep("b", `path_glob: "/ab*d"`)), "/sites/0/endpoints/1/match", CodeAmbiguous},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			var errs Errors
			require.ErrorAs(t, err, &errs)
			assert.NotEmpty(t, findMsg(errs, tc.wantPath, tc.wantCode), "got %v", errs)
		})
	}
}

func TestEndpointsNotAmbiguous(t *testing.T) {
	tests := map[string]string{
		"different exact":            endpointYAML(ep("a", "path: /x"), ep("b", "path: /y")),
		"method-specific vs any":     endpointYAML(ep("a", "path: /x"), ep("b", "path: /x, methods: [POST]")),
		"disjoint methods":           endpointYAML(ep("a", "path: /x, methods: [GET]"), ep("b", "path: /x, methods: [POST]")),
		"different prefix lengths":   endpointYAML(ep("a", "path_prefix: /x"), ep("b", "path_prefix: /xy")),
		"disjoint prefixes":          endpointYAML(ep("a", "path_prefix: /ab"), ep("b", "path_prefix: /cd")),
		"exact vs prefix same text":  endpointYAML(ep("a", "path: /x"), ep("b", "path_prefix: /x")),
		"disjoint globs same length": endpointYAML(ep("a", `path_glob: "/a*"`), ep("b", `path_glob: "/b*"`)),
	}
	for name, y := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(y))
			require.NoError(t, err)
		})
	}
}

func TestEndpointCap(t *testing.T) {
	var b strings.Builder
	for i := range MaxEndpointsPerSite + 1 {
		b.WriteString(ep(fmt.Sprintf("e%d", i), fmt.Sprintf("path: /p%d", i)))
	}
	_, err := Parse([]byte(endpointYAML(b.String())))
	var errs Errors
	require.ErrorAs(t, err, &errs)
	assert.NotEmpty(t, findMsg(errs, "/sites/0/endpoints", CodeOutOfRange))
}

func TestErrorsString(t *testing.T) {
	e := Errors{{Path: "/a", Code: CodeInvalid, Message: "bad"}, {Code: CodeSyntax, Message: "oops"}}
	assert.Equal(t, "invalid configuration: /a: bad (invalid); /: oops (syntax)", e.Error())
}
