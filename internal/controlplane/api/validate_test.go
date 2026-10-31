package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
)

// specOperation is one documented operation that carries a body or a
// constrained parameter, the only operations the validator can reject on schema
// grounds.
type specOperation struct {
	method, template string
	op               *openapi3.Operation
	// params are every query and path parameter; only the constrained ones are
	// mutated, the others are sent so that required parameters are present.
	params []*openapi3.Parameter
}

func constrainedOperations(t *testing.T) []specOperation {
	t.Helper()
	spec, err := apigen.GetSpec()
	require.NoError(t, err)
	var out []specOperation
	paths := spec.Paths.Map()
	tmpls := make([]string, 0, len(paths))
	for p := range paths {
		tmpls = append(tmpls, p)
	}
	sort.Strings(tmpls)
	for _, tmpl := range tmpls {
		item := paths[tmpl]
		for _, method := range sortedKeys(item.Operations()) {
			op := item.Operations()[method]
			var params []*openapi3.Parameter
			hasConstrained := false
			for _, ref := range append(slices.Clone(item.Parameters), op.Parameters...) {
				p := ref.Value
				if p == nil || (p.In != "query" && p.In != "path") || p.Schema == nil {
					continue
				}
				params = append(params, p)
				hasConstrained = hasConstrained || hasConstraint(p.Schema.Value)
			}
			if op.RequestBody != nil || hasConstrained {
				out = append(out, specOperation{method: method, template: BasePath + tmpl, op: op, params: params})
			}
		}
	}
	require.NotEmpty(t, out)
	return out
}

func sortedKeys(m map[string]*openapi3.Operation) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func hasConstraint(s *openapi3.Schema) bool {
	return s != nil && (len(s.Enum) > 0 || s.Pattern != "" || s.MinLength > 0 || s.MaxLength != nil ||
		s.Min != nil || s.Max != nil || s.Format == "date-time")
}

// jsonBody returns the schema of the operation's JSON (or merge-patch) body.
func jsonBody(op *openapi3.Operation) (string, *openapi3.Schema) {
	if op.RequestBody == nil || op.RequestBody.Value == nil {
		return "", nil
	}
	for _, mt := range []string{"application/json", "application/merge-patch+json"} {
		if mtv := op.RequestBody.Value.Content.Get(mt); mtv != nil && mtv.Schema != nil {
			return mt, mtv.Schema.Value
		}
	}
	return "", nil
}

// validCandidates are strings that satisfy the usual identifier, code and
// address patterns in api/openapi.yaml. A pattern no candidate matches fails the
// test, so a new pattern forces a sample here instead of silently passing.
var validCandidates = []string{"abc", "SV-1234-5678", "NL", "123456", "a1", "ab-1", "ABC", "a.b_c-d", "203.0.113.0/24", "2026-01-01T00:00:00Z", "01ARZ3NDEKTSV4RRFFQ69G5FAV"}

// invalidCandidates are strings that break typical patterns.
var invalidCandidates = []string{"BAD!", "!", " ", "9"}

func firstMatching(t *testing.T, pattern string, want bool, candidates []string) string {
	t.Helper()
	re := regexp.MustCompile(pattern)
	for _, c := range candidates {
		if re.MatchString(c) == want {
			return c
		}
	}
	t.Fatalf("no candidate is %v for pattern %q: add one to the table", map[bool]string{true: "valid", false: "invalid"}[want], pattern)
	return ""
}

// sampleValue builds a minimal value that satisfies the schema.
func sampleValue(t *testing.T, s *openapi3.Schema) any {
	t.Helper()
	switch {
	case len(s.Enum) > 0:
		return s.Enum[0]
	case len(s.OneOf) > 0:
		return sampleValue(t, s.OneOf[0].Value)
	case len(s.AllOf) > 0:
		merged := map[string]any{}
		for _, member := range s.AllOf {
			if m, ok := sampleValue(t, member.Value).(map[string]any); ok {
				for k, v := range m {
					merged[k] = v
				}
			}
		}
		return merged
	}
	typ := ""
	if s.Type != nil && len(s.Type.Slice()) > 0 {
		typ = s.Type.Slice()[0]
	} else if len(s.Properties) > 0 {
		typ = "object"
	}
	switch typ {
	case "object":
		m := map[string]any{}
		for _, name := range s.Required {
			m[name] = sampleValue(t, s.Properties[name].Value)
		}
		return m
	case "array":
		var items []any
		for i := uint64(0); i < s.MinItems; i++ {
			items = append(items, sampleValue(t, s.Items.Value))
		}
		if items == nil {
			items = []any{}
		}
		return items
	case "integer", "number":
		if s.Min != nil {
			return *s.Min
		}
		if s.Max != nil && *s.Max < 1 {
			return *s.Max
		}
		return 1
	case "boolean":
		return false
	case "string":
		if s.Format == "date-time" {
			return "2026-01-01T00:00:00Z"
		}
		if s.Pattern != "" {
			return firstMatching(t, s.Pattern, true, validCandidates)
		}
		return strings.Repeat("a", length(max(s.MinLength, 1)))
	}
	return map[string]any{}
}

type mutation struct {
	name  string
	value any
}

// mutations returns one invalid value per constraint the schema declares.
func mutations(t *testing.T, s *openapi3.Schema) []mutation {
	t.Helper()
	var out []mutation
	if len(s.Enum) > 0 {
		out = append(out, mutation{"enum", "__not_in_enum__"})
	}
	if s.MinLength > 0 {
		out = append(out, mutation{"minLength", strings.Repeat("a", length(s.MinLength-1))})
	}
	if s.MaxLength != nil {
		out = append(out, mutation{"maxLength", strings.Repeat("a", length(*s.MaxLength+1))})
	}
	if s.Pattern != "" {
		out = append(out, mutation{"pattern", firstMatching(t, s.Pattern, false, invalidCandidates)})
	}
	if s.Format == "date-time" {
		out = append(out, mutation{"format", "not-a-time"})
	}
	if s.Min != nil {
		out = append(out, mutation{"minimum", *s.Min - 1})
	}
	if s.Max != nil {
		out = append(out, mutation{"maximum", *s.Max + 1})
	}
	return out
}

// spec-driven table: every operation with a body or constrained parameter is
// exercised with a valid sample, then with one mutation per constraint, each of
// which must be refused with a problem naming the offending JSON pointer.
func TestValidationFollowsTheSpec(t *testing.T) {
	srv, err := New(Deps{})
	require.NoError(t, err)
	ops := constrainedOperations(t)
	checked := 0

	for _, so := range ops {
		t.Run(so.method+" "+so.template, func(t *testing.T) {
			ct, bodySchema := jsonBody(so.op)
			base := map[string]any{}
			if bodySchema != nil {
				base, _ = sampleValue(t, bodySchema).(map[string]any)
			}
			query := url.Values{}
			path := so.template
			for _, p := range so.params {
				if p.Required || p.In == "path" {
					setParam(&path, &query, p, fmt.Sprint(sampleValue(t, p.Schema.Value)))
				}
			}
			// Valid sample: a request built from the document must pass.
			valid := newSpecRequest(t, so.method, path, query, base, ct)
			require.NoError(t, srv.validateRequest(valid), "valid sample must pass")
			checked++

			if bodySchema != nil {
				for _, name := range sortedSchemaNames(bodySchema) {
					for _, m := range mutations(t, bodySchema.Properties[name].Value) {
						body := clone(base)
						body[name] = m.value
						req := newSpecRequest(t, so.method, path, query, body, ct)
						if req.ContentLength > maxBodyBytes {
							// Over the 4 MiB cap the request is refused as too large
							// before any schema check; the cap has its own test.
							continue
						}
						assertRefused(t, srv, req, "/"+name, m.name)
						checked++
					}
				}
				for _, ct := range []string{"text/plain", ""} {
					req := newSpecRequest(t, so.method, path, query, base, ct)
					assertUnsupportedMediaType(t, srv, req, ct)
					checked++
				}
			}
			for _, p := range so.params {
				for _, m := range mutations(t, p.Schema.Value) {
					q := url.Values{}
					pp := so.template
					for k, vs := range query {
						q[k] = vs
					}
					setParam(&pp, &q, p, fmt.Sprint(m.value))
					req := newSpecRequest(t, so.method, pp, q, base, ct)
					assertRefused(t, srv, req, "/"+p.In+"/"+p.Name, m.name)
					checked++
				}
			}
		})
	}
	assert.GreaterOrEqual(t, checked, 100, "the table must exercise every constraint, not a sample of them")
}

func sortedSchemaNames(s *openapi3.Schema) []string {
	names := make([]string, 0, len(s.Properties))
	for n := range s.Properties {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// length bounds generated strings. Anything past the body cap is still longer
// than the schema allows, so capping just above it keeps the mutation invalid.
func length(n uint64) int {
	const limit = maxBodyBytes + 1
	if n > limit {
		return limit
	}
	return int(n)
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// setParam writes a path parameter into the template, or a query parameter.
func setParam(path *string, q *url.Values, p *openapi3.Parameter, v string) {
	if p.In == "path" {
		*path = strings.ReplaceAll(*path, "{"+p.Name+"}", url.PathEscape(v))
		return
	}
	q.Set(p.Name, v)
}

func newSpecRequest(t *testing.T, method, path string, query url.Values, body any, contentType string) *http.Request {
	t.Helper()
	target := path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		rd = bytes.NewReader(raw)
	}
	var req *http.Request
	if rd != nil {
		req = httptest.NewRequestWithContext(t.Context(), method, target, rd)
	} else {
		req = httptest.NewRequestWithContext(t.Context(), method, target, nil)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

func assertRefused(t *testing.T, srv *Server, req *http.Request, pointer, constraint string) {
	t.Helper()
	err := srv.validateRequest(req)
	var p *problem
	require.True(t, errors.As(err, &p), "%s at %s: expected a problem, got %v", constraint, pointer, err)
	assert.Equal(t, http.StatusUnprocessableEntity, p.Status, "%s at %s", constraint, pointer)
	paths := make([]string, 0, len(p.Errors))
	for _, e := range p.Errors {
		paths = append(paths, e.Path)
	}
	assert.Contains(t, paths, pointer, "%s must name its JSON pointer", constraint)
}

func assertUnsupportedMediaType(t *testing.T, srv *Server, req *http.Request, ct string) {
	t.Helper()
	var p *problem
	err := srv.validateRequest(req)
	require.True(t, errors.As(err, &p), "content type %q must be refused", ct)
	assert.Equal(t, http.StatusUnsupportedMediaType, p.Status, "content type %q", ct)
}

// Passwords and tokens must never be echoed back in a validation response.
func TestValidationNeverEchoesSecrets(t *testing.T) {
	srv, err := New(Deps{})
	require.NoError(t, err)
	const marker = "PW-MARKER-7f3a"
	req := newSpecRequest(t, http.MethodPost, BasePath+"/setup/admin", nil, map[string]any{
		"setup_token": "tok", "username": "ada", "password": marker + strings.Repeat("x", 1100),
	}, "application/json")
	err = srv.validateRequest(req)
	var p *problem
	require.True(t, errors.As(err, &p))
	assert.Equal(t, http.StatusUnprocessableEntity, p.Status)
	raw, err := json.Marshal(p.Errors)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), marker)
}

// Documents the config bodies the server itself produces and the ones the CLI
// and the dashboard send must keep passing the schema.
func TestConfigBodiesFromTheConfigPackageConform(t *testing.T) {
	srv, err := New(Deps{})
	require.NoError(t, err)
	files, err := filepath.Glob("../../compiler/testdata/*.yaml")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		raw, err := os.ReadFile(f) //nolint:gosec // fixtures named by a fixed glob, not user input
		require.NoError(t, err)
		root, err := config.Parse(raw)
		require.NoError(t, err, f)
		body, err := json.Marshal(root)
		require.NoError(t, err)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, BasePath+"/config", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		assert.NoError(t, srv.validateRequest(req), "PUT /config from %s", filepath.Base(f))
	}
}

func TestMediaTypeAndBodyRules(t *testing.T) {
	srv, err := New(Deps{})
	require.NoError(t, err)
	tests := []struct {
		name, method, path, ct, body string
		want                         int
	}{
		{"json accepted with charset", http.MethodPost, "/setup/admin", "application/json; charset=utf-8", `{"setup_token":"t","username":"ada","password":"correct horse battery"}`, 0},
		{"form refused", http.MethodPost, "/setup/admin", "application/x-www-form-urlencoded", "username=ada", http.StatusUnsupportedMediaType},
		{"missing content type with body", http.MethodPost, "/setup/admin", "", `{}`, http.StatusUnsupportedMediaType},
		{"merge patch on a patch operation", http.MethodPatch, "/sites/shop", "application/merge-patch+json", `{}`, 0},
		{"plain json on a merge patch operation", http.MethodPatch, "/sites/shop", "application/json", `{}`, http.StatusUnsupportedMediaType},
		{"empty body on a required body", http.MethodPost, "/tokens", "application/json", "", http.StatusBadRequest},
		{"malformed json", http.MethodPost, "/tokens", "application/json", `{"name":`, http.StatusBadRequest},
		{"wrong type is a schema violation", http.MethodPost, "/tokens", "application/json", `{"name":1,"scopes":"read"}`, http.StatusUnprocessableEntity},
		{"unknown config key is a schema violation", http.MethodPut, "/config", "application/json", `{"schema_version":1,"sites":[],"zzz":1}`, http.StatusUnprocessableEntity},
		{"no body and no content type is fine", http.MethodGet, "/sites", "", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), tt.method, BasePath+tt.path, strings.NewReader(tt.body))
			if tt.ct != "" {
				req.Header.Set("Content-Type", tt.ct)
			}
			err := srv.validateRequest(req)
			if tt.want == 0 {
				assert.NoError(t, err)
				return
			}
			var p *problem
			require.True(t, errors.As(err, &p), "expected a problem, got %v", err)
			assert.Equal(t, tt.want, p.Status)
		})
	}
}

// Validation runs after authentication: an anonymous caller gets the same 401
// whatever the body, so the response reveals nothing about the schema.
func TestAnonymousCallersLearnNothingFromValidation(t *testing.T) {
	h := newHarness(t)
	anon := h.anon()
	for _, body := range []string{`{"name":1}`, `not json`, ``} {
		r := anon.do("POST", "/tokens", body)
		assert.Equal(t, http.StatusUnauthorized, r.Status, body)
	}
	r := anon.do("POST", "/tokens", "x")
	assert.Equal(t, http.StatusUnauthorized, r.Status)
	assert.NotContains(t, string(r.Body), "schema")
}

func BenchmarkValidateRequest(b *testing.B) {
	srv, err := New(Deps{})
	require.NoError(b, err)
	body := []byte(`{"id":"shop","hosts":["shop.example.com"],"tls":{"mode":"none"},"policy":{"mode":"block","waf":{"paranoia_level":2}},"upstreams":{"targets":["10.0.1.10:8080"]}}`)
	b.ReportAllocs()
	for b.Loop() {
		req := httptest.NewRequestWithContext(b.Context(), http.MethodPost, BasePath+"/sites", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if err := srv.validateRequest(req); err != nil {
			b.Fatal(err)
		}
	}
}
