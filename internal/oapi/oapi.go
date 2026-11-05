// Package oapi checks HTTP requests against a compiled OpenAPI document:
// route matching, parameters, media type and body schema. It is shared by the
// data plane (API protection) and the control plane (request validation).
// Authentication and authorisation are never done here.
package oapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
)

// maxViolations bounds the findings one request can produce.
const maxViolations = 10

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

// Violation is one way a request breaks the document.
type Violation struct {
	// Pointer locates the problem: /query/limit, /header/x-id, /path/id,
	// /body, /body/amount/currency.
	Pointer string
	Message string
	// Malformed marks a request that cannot be parsed at all (bad JSON or
	// number syntax, a missing required body or parameter, an unreadable body).
	// Everything else is a schema violation on a parsed value.
	Malformed bool
}

// Validator is an immutable request checker built from one document.
type Validator struct {
	router routers.Router
	schema []openapi3.SchemaValidationOption
}

// NewValidator builds a validator for doc. Server URLs are reduced to their
// base path: a WAF sits in front of the API under whatever host the site
// serves, so the host is irrelevant but "/v1" or "/api/v1" is not. doc is
// modified in place.
func NewValidator(doc *openapi3.T) (*Validator, error) {
	if doc == nil || doc.Paths == nil || doc.Paths.Len() == 0 {
		return nil, errors.New("the document describes no paths")
	}
	doc.Servers = PathOnlyServers(doc.Servers)
	router, err := legacy.NewRouter(doc)
	if err != nil {
		return nil, fmt.Errorf("building router: %w", err)
	}
	v := &Validator{router: router}
	if doc.IsOpenAPI31OrLater() {
		v.schema = []openapi3.SchemaValidationOption{openapi3.EnableJSONSchema2020()}
	}
	return v, nil
}

// PathOnlyServers keeps only the path of each server URL.
func PathOnlyServers(in openapi3.Servers) openapi3.Servers {
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

// Route returns the documented operation that r matches and its path
// parameters. It reports UnknownMethod separately from UnknownPath.
func (v *Validator) Route(r *http.Request) (*routers.Route, map[string]string, Outcome) {
	route, params, err := v.router.FindRoute(r)
	if err != nil {
		var re *routers.RouteError
		if errors.As(err, &re) && re.Error() == routers.ErrMethodNotAllowed.Error() {
			return nil, nil, UnknownMethod
		}
		return nil, nil, UnknownPath
	}
	return route, params, Conforms
}

// Template maps a concrete request line to the documented path it belongs to
// ("/accounts/{id}/balance"), so counts group by endpoint instead of by id.
func (v *Validator) Template(ctx context.Context, method, requestPath string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, method, requestPath, nil)
	if err != nil {
		return "", false
	}
	route, _, out := v.Route(req)
	if out != Conforms {
		return "", false
	}
	return route.Path, true
}

// Check validates r. The body is read up to maxBody and restored for the
// next handler; a larger body is not validated and bodySkipped says so.
func (v *Validator) Check(r *http.Request, maxBody int64) (out Outcome, vs []Violation, bodySkipped bool) {
	route, pathParams, out := v.Route(r)
	if out != Conforms {
		return out, nil, false
	}
	opts := &openapi3filter.Options{
		AuthenticationFunc:      openapi3filter.NoopAuthenticationFunc, // authentication is the caller's job
		SkipSettingDefaults:     true,
		MultiError:              true,
		SchemaValidationOptions: v.schema,
	}
	body, skipped, err := readBody(r, maxBody)
	if err != nil {
		return Invalid, []Violation{{Pointer: "/body", Message: "request body could not be read", Malformed: true}}, false
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
// untouched for the next handler (skipped == true) and nothing is validated.
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
		// (account numbers, tokens) ends up in events or responses.
		return Violation{Pointer: base + toPointer(se.JSONPointer()), Message: se.Reason}
	}
	var pe *openapi3filter.ParseError
	if errors.As(re.Err, &pe) {
		return Violation{Pointer: base, Message: pe.Reason, Malformed: true}
	}
	if errors.Is(re.Err, openapi3filter.ErrInvalidRequired) {
		return Violation{Pointer: base, Message: "a value is required", Malformed: true}
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
