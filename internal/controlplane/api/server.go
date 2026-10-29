// Package api serves the control-plane REST API (api/openapi.yaml). Every
// request passes one middleware chain: request id, size limit, authentication,
// CSRF for cookie sessions, and authorisation from the route's
// x-sherlock-permission. A route the spec does not declare a permission for is
// refused at start-up, and an unknown permission name denies.
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/certstore"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
	"github.com/skylarng89/sherlock-waf/internal/policy"
	"github.com/skylarng89/sherlock-waf/internal/secrets"
	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

const (
	// BasePath is where the API is mounted.
	BasePath = "/api/v1"

	// SessionCookie holds the session token. Both cookies use the __Host-
	// prefix: the browser then guarantees Secure, Path=/ and no Domain, so a
	// sibling host cannot set them.
	SessionCookie = "__Host-sherlock_session"
	// CSRFCookie carries the double-submit CSRF token the dashboard echoes.
	CSRFCookie = "__Host-sherlock_csrf"
	// CSRFHeader is where the dashboard sends it on non-GET requests.
	CSRFHeader = "X-CSRF-Token"

	maxBodyBytes = 4 << 20
	permHeader   = "x-sherlock-permission"
)

// Info is static build information reported by /system/info.
type Info struct {
	Version    string
	Commit     string
	CRSVersion string
	Features   []string
}

// Deps are the services the API is built on.
type Deps struct {
	Store  store.Store
	Config *configsvc.Service
	Auth   *auth.Service
	Audit  *audit.Service
	Hasher *auth.Hasher
	Info   Info
	// Authorizer, when set, replaces the built-in role check for authenticated
	// principals (the Enterprise extension point). Authentication, CSRF and the
	// public/session rules above it are not replaceable.
	Authorizer extension.Authorizer
	Logger     *slog.Logger
	Now        func() time.Time

	// Secrets seals uploaded private keys.
	Secrets *secrets.Service
	// Certs materialises uploaded certificates for the data plane; the API
	// removes a certificate's files when it is deleted.
	Certs *certstore.Files
	// Setup guards first-run administrator creation; nil once users exist.
	Setup *SetupGate
	// EventStats reports the event pipeline counters for GET /system/status.
	EventStats func() (published, dropped uint64)
	// Feeds reports feed health for GET /feeds/status (nil: no feeds configured).
	Feeds func() []FeedStatus
	// DataDir is where Caddy keeps the certificates it obtains (ACME status).
	DataDir string
}

// Server is the HTTP API.
type Server struct {
	Deps
	log   *slog.Logger
	perms map[string]string // "METHOD /api/v1/path/{param}" -> permission
}

// New builds the server and verifies that every operation declares a permission.
func New(d Deps) (*Server, error) {
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Hasher == nil {
		d.Hasher = auth.NewHasher(4)
	}
	perms, err := permissionTable()
	if err != nil {
		return nil, err
	}
	return &Server{Deps: d, log: d.Logger, perms: perms}, nil
}

// permissionTable reads x-sherlock-permission from the embedded spec. A missing
// or unknown value is a start-up error: no route may exist without a decision.
func permissionTable() (map[string]string, error) {
	spec, err := apigen.GetSpec()
	if err != nil {
		return nil, fmt.Errorf("loading embedded openapi spec: %w", err)
	}
	known := map[string]bool{
		auth.PermPublic: true, auth.PermAuthenticated: true, auth.PermSessionAny: true, auth.PermSessionPart: true,
		auth.PermConfigRead: true, auth.PermConfigWrite: true, auth.PermEventsRead: true, auth.PermUsersManage: true,
		auth.PermTokensOwn: true, auth.PermAuditRead: true, auth.PermSystemRead: true,
	}
	table := map[string]string{}
	for p, item := range spec.Paths.Map() {
		for method, op := range item.Operations() {
			var perm string
			switch v := op.Extensions[permHeader].(type) {
			case string:
				perm = v
			case json.RawMessage:
				_ = json.Unmarshal(v, &perm)
			}
			if perm == "" {
				return nil, fmt.Errorf("operation %s %s has no %s", method, p, permHeader)
			}
			if !known[perm] {
				return nil, fmt.Errorf("operation %s %s declares unknown permission %q", method, p, perm)
			}
			table[method+" "+BasePath+p] = perm
		}
	}
	return table, nil
}

// Handler returns the API handler to mount (it includes BasePath).
func (s *Server) Handler() http.Handler {
	strict := apigen.NewStrictHandlerWithOptions(&handlers{s: s}, nil, apigen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  s.badRequestHandler,
		ResponseErrorHandlerFunc: s.errorHandler,
	})
	mux := http.NewServeMux()
	apigen.HandlerWithOptions(strict, apigen.StdHTTPServerOptions{
		BaseURL:          BasePath,
		BaseRouter:       mux,
		ErrorHandlerFunc: s.badRequestHandler,
	})
	// Anything the spec does not declare is a problem document, not Go's plain 404/405.
	mux.HandleFunc(BasePath+"/", func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, errNotFound("this route"), requestIDFrom(r.Context()))
	})
	return s.outer(s.guard(mux))
}

type ctxKey int

const (
	keyPrincipal ctxKey = iota
	keyWriter
	keyIP
	keyRequestID
	keyUserAgent
)

func requestIDFrom(ctx context.Context) string { s, _ := ctx.Value(keyRequestID).(string); return s }

func principalFrom(ctx context.Context) auth.Principal {
	p, _ := ctx.Value(keyPrincipal).(auth.Principal)
	return p
}

func ipFrom(ctx context.Context) string { s, _ := ctx.Value(keyIP).(string); return s }

func writerFrom(ctx context.Context) http.ResponseWriter {
	w, _ := ctx.Value(keyWriter).(http.ResponseWriter)
	return w
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// outer applies headers and limits that hold for every response, including 404s.
func (s *Server) outer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		h := w.Header()
		h.Set("X-Request-Id", id)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")

		ip := ""
		if a, err := policy.ParseRemoteAddr(r.RemoteAddr); err == nil {
			ip = a.String()
		}
		ctx := context.WithValue(r.Context(), keyRequestID, id)
		ctx = context.WithValue(ctx, keyIP, ip)
		ctx = context.WithValue(ctx, keyWriter, w)
		ctx = context.WithValue(ctx, keyUserAgent, r.UserAgent())
		r = r.WithContext(ctx)
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// guard authenticates and authorises before the router dispatches. It must run
// outside the generated handlers: they bind and validate parameters before any
// middleware they are given, so a guard installed there would let anonymous
// callers probe parameter validation. The matched pattern comes from the mux.
func (s *Server) guard(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		perm, declared := s.perms[pattern]
		if !declared { // only the not-found fallback is registered without a permission
			mux.ServeHTTP(w, r)
			return
		}
		if perm == auth.PermPublic {
			if err := strictBody(r, pattern); err != nil {
				s.errorHandler(w, r, err)
				return
			}
			mux.ServeHTTP(w, r)
			return
		}

		p, bySession, err := s.authenticate(r)
		if err != nil {
			s.errorHandler(w, r, err)
			return
		}
		if err := s.authorise(r, p, pattern, perm, bySession); err != nil {
			s.errorHandler(w, r, err)
			return
		}
		if err := strictBody(r, pattern); err != nil {
			s.errorHandler(w, r, err)
			return
		}
		mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyPrincipal, p)))
	})
}

func (s *Server) authenticate(r *http.Request) (p auth.Principal, bySession bool, err error) {
	ctx := r.Context()
	if h := r.Header.Get("Authorization"); h != "" {
		token, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			return p, false, auth.ErrUnauthenticated
		}
		ip, _ := netip.ParseAddr(ipFrom(ctx))
		p, err = s.Auth.AuthenticateToken(ctx, strings.TrimSpace(token), ip)
		return p, false, err
	}
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return p, false, auth.ErrUnauthenticated
	}
	p, err = s.Auth.AuthenticateSession(ctx, c.Value)
	return p, true, err
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func (s *Server) authorise(r *http.Request, p auth.Principal, pattern, perm string, bySession bool) error {
	if bySession && !safeMethod(r.Method) && !auth.CheckCSRF(p, r.Header.Get(CSRFHeader)) {
		return errForbidden("Missing or invalid CSRF token.")
	}
	partial := p.Stage != "" && p.Stage != store.StageFull
	switch perm {
	case auth.PermSessionAny:
		if !bySession {
			return errForbidden("This operation needs a browser session.")
		}
		return nil
	case auth.PermSessionPart:
		if !bySession || !partial {
			return errForbidden("This step is only available during sign-in.")
		}
		return nil
	}
	if partial {
		return errForbidden("Finish signing in first.")
	}
	if perm == auth.PermAuthenticated {
		return nil
	}
	if s.Authorizer != nil {
		d, err := s.Authorizer.Authorize(r.Context(), extension.AuthzRequest{Principal: extPrincipal(p), Permission: extension.Permission(perm)})
		if err != nil {
			return fmt.Errorf("authorizer: %w", err) // fail closed: a broken authoriser is a 500, never an allow
		}
		if !d.Allow {
			s.recordDenied(r, p, pattern, perm, d.Reason)
			return errForbidden("You do not have permission for this operation.")
		}
		return nil
	}
	if !auth.Has(p.Permissions, perm) {
		s.recordDenied(r, p, pattern, perm, "role or scope lacks permission")
		return errForbidden("You do not have permission for this operation.")
	}
	return nil
}

func extPrincipal(p auth.Principal) extension.Principal {
	ep := extension.Principal{Type: "user", ID: p.UserID, Username: p.Username, Role: p.Role}
	if p.IsToken() {
		ep.Type = "token"
		ep.ID = p.TokenID
	}
	return ep
}

func (s *Server) recordDenied(r *http.Request, p auth.Principal, pattern, perm, reason string) {
	actor := audit.ActorUser
	id := p.UserID
	if p.IsToken() {
		actor, id = audit.ActorToken, p.TokenID
	}
	err := s.Audit.Record(r.Context(), s.Store, audit.Input{
		ActorType: actor, ActorID: id, IP: ipFrom(r.Context()), Action: "auth.denied",
		ObjectType: "route", ObjectID: pattern, Details: map[string]any{"permission": perm, "reason": reason},
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		s.log.Error("recording denial failed", "error", err)
	}
}

// strictBodyTargets lists the operations whose JSON body is a configuration
// object. The generated decoder ignores unknown fields; for configuration a
// typo must be an error (as it is in the YAML file), not a silent no-op.
var strictBodyTargets = map[string]func() any{
	"PUT " + BasePath + "/config":                  func() any { return new(config.Root) },
	"POST " + BasePath + "/config/validate":        func() any { return new(config.Root) },
	"PUT " + BasePath + "/defaults":                func() any { return new(config.Policy) },
	"POST " + BasePath + "/sites":                  func() any { return new(config.Site) },
	"POST " + BasePath + "/sites/{site}/endpoints": func() any { return new(config.Endpoint) },
}

func strictBody(r *http.Request, pattern string) error {
	mk, ok := strictBodyTargets[pattern]
	if !ok || r.Body == nil {
		return nil
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return errBadRequest("The request body could not be read (limit is 4 MiB).")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(mk()); err != nil && len(raw) > 0 {
		return errBadRequest("Invalid configuration document: " + err.Error())
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return nil
}

// FeedStatus is the health of one background feed.
type FeedStatus struct {
	Name        string
	State       string // disabled | never_loaded | ok | stale | failed
	LastSuccess time.Time
	LastError   string
	Entries     int
}
