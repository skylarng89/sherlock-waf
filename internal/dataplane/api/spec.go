package api

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/skylarng89/sherlock-waf/internal/oapi"
)

// MaxSpecBytes bounds an uploaded OpenAPI document.
const MaxSpecBytes = 4 << 20

// Endpoint is one documented operation.
type Endpoint struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Summary string `json:"summary,omitempty"`
}

// Outcome of checking one request.
type Outcome = oapi.Outcome

// Check outcomes.
const (
	Conforms      = oapi.Conforms
	UnknownPath   = oapi.UnknownPath
	UnknownMethod = oapi.UnknownMethod
	Invalid       = oapi.Invalid
)

// Violation is one way a request breaks the document.
type Violation = oapi.Violation

// Spec is a compiled OpenAPI document: a validator plus the operation list.
// It is immutable and shared by every request.
type Spec struct {
	Version   string // "3.0" or "3.1"
	Endpoints []Endpoint

	validator *oapi.Validator
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
	v, err := oapi.NewValidator(doc)
	if err != nil {
		return nil, err
	}
	s := &Spec{Version: doc.OpenAPI[:3], validator: v}
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

// Check validates r. See oapi.Validator.Check.
func (s *Spec) Check(r *http.Request, maxBody int64) (Outcome, []Violation, bool) {
	return s.validator.Check(r, maxBody)
}

// Template maps a concrete request line to the documented path it belongs to.
func (s *Spec) Template(ctx context.Context, method, requestPath string) (string, bool) {
	return s.validator.Template(ctx, method, requestPath)
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
