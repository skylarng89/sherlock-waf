package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
)

// MaxSpecBytes bounds an uploaded OpenAPI document.
const MaxSpecBytes = 4 << 20

// maxViolations bounds the findings one request can produce.
const maxViolations = 10

// Endpoint is one documented operation.
type Endpoint struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Summary string `json:"summary,omitempty"`
}

// Spec is a compiled OpenAPI document: a router plus the request validators.
// It is immutable and shared by every request.
type Spec struct {
	Version   string // "3.0" or "3.1"
	Endpoints []Endpoint

	doc    *openapi3.T
	router routers.Router
	schema []openapi3.SchemaValidationOption
}

// CompileSpec parses, validates and compiles an OpenAPI 3.0 or 3.1 document
// (JSON or YAML). External references are never followed: a document is
// untrusted input and must not make the node read files or call out.
func CompileSpec(ctx context.Context, raw []byte) (*Spec, error) {
	if len(raw) == 0 || len(raw) > MaxSpecBytes {
		return nil, fmt.Errorf("document must be between 1 byte and %d bytes", MaxSpecBytes)
	}
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	doc, err := loader.LoadFromData(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing OpenAPI document: %w", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.0") && !strings.HasPrefix(doc.OpenAPI, "3.1") {
		return nil, fmt.Errorf("unsupported OpenAPI version %q: use 3.0.x or 3.1.x", doc.OpenAPI)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("invalid OpenAPI document: %w", err)
	}
	if doc.Paths == nil || doc.Paths.Len() == 0 {
		return nil, errors.New("the document describes no paths")
	}
	doc.Servers = pathOnlyServers(doc.Servers)
	router, err := legacy.NewRouter(doc)
	if err != nil {
		return nil, fmt.Errorf("building router: %w", err)
	}
	s := &Spec{doc: doc, router: router, Version: doc.OpenAPI[:3]}
	if doc.IsOpenAPI31OrLater() {
		s.schema = []openapi3.SchemaValidationOption{openapi3.EnableJSONSchema2020()}
	}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			s.Endpoints = append(s.Endpoints, Endpoint{Method: method, Path: path, Summary: op.Summary})
		}
	}
	slices.SortFunc(s.Endpoints, func(a, b Endpoint) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return strings.Compare(a.Method, b.Method)
	})
	return s, nil
}

// pathOnlyServers keeps only the path of each server URL. The WAF sits in
// front of the API under whatever host the site serves, so the document's
// host is irrelevant, but its base path ("/v1") is not.
func pathOnlyServers(in openapi3.Servers) openapi3.Servers {
	seen := map[string]bool{}
	var out openapi3.Servers
	for _, sv := range in {
		base, err := sv.BasePath()
		if err != nil {
			continue
		}
		if u, err := url.Parse(base); err == nil && u.Path != "" {
			base = u.Path
		}
		if base == "" || !strings.HasPrefix(base, "/") {
			base = "/"
		}
		if !seen[base] {
			seen[base] = true
			out = append(out, &openapi3.Server{URL: base})
		}
	}
	if len(out) == 0 {
		out = openapi3.Servers{{URL: "/"}}
	}
	return out
}

// Violation is one way a request breaks the document.
type Violation struct {
	// Pointer locates the problem: /query/limit, /header/x-id, /path/id,
	// /body, /body/amount/currency.
	Pointer string
	Message string
}

// Outcome of checking one request.
type Outcome int

// Check outcomes.
const (
	// Conforms: the request is documented and valid.
	Conforms Outcome = iota
	// UnknownPath: no documented path matches.
	UnknownPath
	// UnknownMethod: the path exists but not for this method.
	UnknownMethod
	// Invalid: documented, but parameters or body break the schema.
	Invalid
)

// Check validates r. The body is read up to maxBody and restored for the
// upstream; a larger body is not validated and the second result says so.
func (s *Spec) Check(r *http.Request, maxBody int64) (out Outcome, vs []Violation, bodySkipped bool) {
	route, pathParams, err := s.router.FindRoute(r)
	if err != nil {
		var re *routers.RouteError
		if errors.As(err, &re) && re.Error() == routers.ErrMethodNotAllowed.Error() {
			return UnknownMethod, nil, false
		}
		return UnknownPath, nil, false
	}
	opts := &openapi3filter.Options{
		AuthenticationFunc:      openapi3filter.NoopAuthenticationFunc, // authentication is the JWT module's job
		SkipSettingDefaults:     true,
		MultiError:              true,
		SchemaValidationOptions: s.schema,
	}
	body, skipped, err := readBody(r, maxBody)
	if err != nil {
		return Invalid, []Violation{{Pointer: "/body", Message: "request body could not be read"}}, false
	}
	if skipped {
		opts.ExcludeRequestBody = true
	}
	in := &openapi3filter.RequestValidationInput{Request: r, PathParams: pathParams, Route: route, Options: opts}
	verr := openapi3filter.ValidateRequest(r.Context(), in)
	restoreBody(r, body)
	if verr == nil {
		return Conforms, nil, skipped
	}
	vs = violations(verr)
	if len(vs) == 0 {
		vs = []Violation{{Pointer: "/", Message: "request does not conform to the OpenAPI document"}}
	}
	return Invalid, vs, skipped
}

// readBody buffers up to max bytes. When the body is larger it is left
// untouched for the upstream (skipped == true) and nothing is validated.
func readBody(r *http.Request, max int64) (buf []byte, skipped bool, err error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, false, nil
	}
	if r.ContentLength > max {
		return nil, true, nil
	}
	buf, err = io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > max {
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
		return nil, true, nil
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(buf))
	return buf, false, nil
}

func restoreBody(r *http.Request, buf []byte) {
	if buf != nil {
		r.Body = io.NopCloser(bytes.NewReader(buf))
	}
}

func violations(err error) []Violation {
	var out []Violation
	var walk func(error)
	walk = func(e error) {
		if e == nil || len(out) >= maxViolations {
			return
		}
		// Direct type checks, not errors.As: a RequestError wraps a MultiError,
		// and unwrapping it here would skip the parameter or body it names.
		switch x := e.(type) {
		case openapi3.MultiError:
			for _, sub := range x {
				walk(sub)
			}
		case *openapi3filter.RequestError:
			out = append(out, requestViolation(x))
		case *openapi3filter.SecurityRequirementsError:
		default:
			out = append(out, Violation{Pointer: "/", Message: "request does not conform to the OpenAPI document"})
		}
	}
	walk(err)
	return out
}

func requestViolation(re *openapi3filter.RequestError) Violation {
	base := "/body"
	if p := re.Parameter; p != nil {
		base = "/" + p.In + "/" + p.Name
	}
	if se := firstSchemaError(re.Err); se != nil {
		// Reason never contains the offending value, so no payload data
		// (account numbers, tokens) ends up in events.
		return Violation{Pointer: base + toPointer(se.JSONPointer()), Message: se.Reason}
	}
	var pe *openapi3filter.ParseError
	if errors.As(re.Err, &pe) {
		return Violation{Pointer: base, Message: pe.Reason}
	}
	msg := re.Reason
	if msg == "" {
		msg = "invalid"
	}
	return Violation{Pointer: base, Message: msg}
}

func firstSchemaError(err error) *openapi3.SchemaError {
	if me, ok := err.(openapi3.MultiError); ok {
		for _, e := range me {
			if se := firstSchemaError(e); se != nil {
				return se
			}
		}
		return nil
	}
	var se *openapi3.SchemaError
	if errors.As(err, &se) {
		return se
	}
	return nil
}

func toPointer(parts []string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteByte('/')
		b.WriteString(strings.NewReplacer("~", "~0", "/", "~1").Replace(p))
	}
	return b.String()
}

// SpecRegistry holds the compiled documents by id. Readers never block:
// updates replace a copy-on-write map.
type SpecRegistry struct {
	mu    sync.Mutex
	specs atomic.Pointer[map[string]*Spec]
}

// Specs is the process-wide registry.
var Specs = &SpecRegistry{}

// Get returns the compiled document, or nil.
func (g *SpecRegistry) Get(id string) *Spec {
	if m := g.specs.Load(); m != nil {
		return (*m)[id]
	}
	return nil
}

// Set compiles raw and publishes it under id. On error the previous
// document, if any, stays live.
func (g *SpecRegistry) Set(ctx context.Context, id string, raw []byte) (*Spec, error) {
	s, err := CompileSpec(ctx, raw)
	if err != nil {
		return nil, err
	}
	g.put(id, s)
	return s, nil
}

func (g *SpecRegistry) put(id string, s *Spec) {
	g.mu.Lock()
	defer g.mu.Unlock()
	next := map[string]*Spec{}
	if m := g.specs.Load(); m != nil {
		for k, v := range *m {
			next[k] = v
		}
	}
	if s == nil {
		delete(next, id)
	} else {
		next[id] = s
	}
	g.specs.Store(&next)
}

// Delete forgets a document.
func (g *SpecRegistry) Delete(id string) { g.put(id, nil) }

// Template maps a concrete request line to the documented path it belongs to
// ("/accounts/{id}/balance"), so counts group by endpoint instead of by id.
func (s *Spec) Template(ctx context.Context, method, requestPath string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, method, requestPath, nil)
	if err != nil {
		return "", false
	}
	route, _, err := s.router.FindRoute(req)
	if err != nil {
		return "", false
	}
	return route.Path, true
}
