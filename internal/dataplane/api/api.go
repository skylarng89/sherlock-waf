// Package api is the sherlock_api Caddy module: OpenAPI conformance, JWT
// validation and client-certificate requirements for JSON APIs. It runs after
// the ACL and before rate limiting, so a limit can key on a verified token
// claim or certificate subject. It never makes a network call: key sets are
// fetched by background jobs and documents are compiled when uploaded.
package api

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

const moduleName = "sherlock_api"

// jwksWarmup bounds how long provisioning waits for the first key fetch, so a
// fresh start does not reject every token while the set is still loading.
const jwksWarmup = 3 * time.Second

func init() { caddy.RegisterModule(&Handler{}) }

// JWTRule is one compiled JWT rule.
type JWTRule struct {
	Paths           []string `json:"paths,omitempty"`
	Methods         []string `json:"methods,omitempty"`
	JWKSURL         string   `json:"jwks_url,omitempty"`
	PublicKeyPEM    string   `json:"public_key_pem,omitempty"`
	HMACSecretEnv   string   `json:"hmac_secret_env,omitempty"`
	Issuer          string   `json:"issuer,omitempty"`
	Audiences       []string `json:"audiences,omitempty"`
	ClockSkew       string   `json:"clock_skew,omitempty"`
	RefreshInterval string   `json:"refresh_interval,omitempty"`
	Optional        bool     `json:"optional,omitempty"`
	Action          string   `json:"action"`

	verifier *Verifier
}

// Handler is the sherlock_api Caddy handler.
type Handler struct {
	SiteID                string      `json:"site_id"`
	Mode                  config.Mode `json:"mode"`
	OpenAPIDocID          string      `json:"openapi_doc_id,omitempty"`
	UnknownPathAction     string      `json:"unknown_path_action,omitempty"`
	SchemaViolationAction string      `json:"schema_violation_action,omitempty"`
	MaxBodyBytes          int64       `json:"max_body_bytes,omitempty"`
	JWT                   []JWTRule   `json:"jwt,omitempty"`
	MTLSRequiredPaths     []string    `json:"mtls_required_paths,omitempty"`

	now      func() time.Time
	released []string
}

// CaddyModule implements caddy.Module.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers." + moduleName, New: func() caddy.Module { return new(Handler) }}
}

// Provision implements caddy.Provisioner.
func (h *Handler) Provision(caddy.Context) error {
	h.now = time.Now
	for i := range h.JWT {
		r := &h.JWT[i]
		skew, err := parseDur(r.ClockSkew, config.DefaultJWTClockSkew)
		if err != nil {
			return fmt.Errorf("sherlock_api jwt rule %d clock_skew: %w", i, err)
		}
		refresh, err := parseDur(r.RefreshInterval, config.DefaultJWKSRefresh)
		if err != nil {
			return fmt.Errorf("sherlock_api jwt rule %d refresh_interval: %w", i, err)
		}
		v := &Verifier{Issuer: r.Issuer, Audiences: r.Audiences, Skew: skew, Now: func() time.Time { return h.now() }}
		switch {
		case r.JWKSURL != "":
			src := JWKS.Acquire(r.JWKSURL, refresh)
			h.released = append(h.released, r.JWKSURL)
			v.Keys = src
			waitReady(src)
		case r.PublicKeyPEM != "":
			k, err := ParsePublicKeyPEM(r.PublicKeyPEM)
			if err != nil {
				return fmt.Errorf("sherlock_api jwt rule %d public_key_pem: %w", i, err)
			}
			v.Keys = StaticKeys{k}
		case r.HMACSecretEnv != "":
			secret := os.Getenv(r.HMACSecretEnv)
			if len(secret) < 32 {
				return fmt.Errorf("sherlock_api jwt rule %d: environment variable %s must hold a secret of at least 32 bytes", i, r.HMACSecretEnv)
			}
			v.Keys, v.AllowHMAC = StaticKeys{{Secret: []byte(secret)}}, true
		default:
			return fmt.Errorf("sherlock_api jwt rule %d has no key source", i)
		}
		r.verifier = v
	}
	return nil
}

func parseDur(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	return time.ParseDuration(s)
}

func waitReady(s *JWKSSource) {
	deadline := time.Now().Add(jwksWarmup)
	for !s.Ready() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
}

// Cleanup implements caddy.CleanerUpper.
func (h *Handler) Cleanup() error {
	for _, u := range h.released {
		JWKS.Release(u)
	}
	h.released = nil
	return nil
}

// Validate implements caddy.Validator.
func (h *Handler) Validate() error {
	if h.SiteID == "" {
		return errors.New("sherlock_api: site_id is required")
	}
	for _, a := range []string{h.UnknownPathAction, h.SchemaViolationAction} {
		if !slices.Contains([]string{"", config.ActionLog, config.ActionBlock}, a) {
			return fmt.Errorf("sherlock_api: invalid action %q", a)
		}
	}
	for i, r := range h.JWT {
		if !slices.Contains([]string{config.ActionLog, config.ActionBlock}, r.Action) {
			return fmt.Errorf("sherlock_api jwt rule %d: invalid action %q", i, r.Action)
		}
	}
	return nil
}

// enforcing reports whether a block action really blocks: in detect mode every
// block becomes a finding, like the WAF.
func (h *Handler) enforcing(action string) bool {
	return action == config.ActionBlock && h.Mode == config.ModeBlock
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	d := policy.DecisionFrom(r.Context())
	if d == nil || h.Mode == config.ModeOff {
		return next.ServeHTTP(w, r)
	}
	if h.checkMTLS(w, r, d) || h.checkJWT(w, r, d) || h.checkSpec(w, r, d) {
		return nil
	}
	return next.ServeHTTP(w, r)
}

func (h *Handler) finding(d *policy.Decision, rule string, sev policy.Severity, target, msg string) {
	d.AddFinding(policy.Finding{Module: "api", RuleID: rule, Severity: sev, Target: target, Message: msg})
}

func (h *Handler) deny(w http.ResponseWriter, r *http.Request, d *policy.Decision, status int) bool {
	d.Terminate("api", policy.ActionBlock)
	blockpage.Write(w, r, status, d.EventID)
	return true
}

// checkMTLS records the verified client certificate and enforces the paths that
// require one. It reports whether it answered the request.
func (h *Handler) checkMTLS(w http.ResponseWriter, r *http.Request, d *policy.Decision) bool {
	var cert *x509.Certificate
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
		cert = r.TLS.VerifiedChains[0][0]
		d.SetClientCert(cert.Subject.String())
	}
	if cert != nil || len(h.MTLSRequiredPaths) == 0 || !pathMatches(h.MTLSRequiredPaths, r.URL.Path) {
		return false
	}
	h.finding(d, "api.mtls", policy.SeverityWarning, "", "a verified client certificate is required for this path")
	return h.enforcing(config.ActionBlock) && h.deny(w, r, d, http.StatusForbidden)
}

// checkJWT validates the bearer token of the first matching rule.
func (h *Handler) checkJWT(w http.ResponseWriter, r *http.Request, d *policy.Decision) bool {
	rule := h.jwtRuleFor(r)
	if rule == nil {
		return false
	}
	tok, present := bearer(r)
	if !present && rule.Optional {
		return false
	}
	var reason string
	if !present {
		reason = "bearer token required"
	} else {
		claims, err := rule.verifier.Verify(tok)
		if err == nil {
			d.SetClaims(claims)
			return false
		}
		reason = "token rejected: " + err.Error()
	}
	h.finding(d, "api.jwt", policy.SeverityWarning, "/header/authorization", reason)
	if !h.enforcing(rule.Action) {
		return false
	}
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	return h.deny(w, r, d, http.StatusUnauthorized)
}

func (h *Handler) jwtRuleFor(r *http.Request) *JWTRule {
	for i := range h.JWT {
		j := &h.JWT[i]
		if len(j.Methods) > 0 && !slices.Contains(j.Methods, r.Method) {
			continue
		}
		if pathMatches(j.Paths, r.URL.Path) {
			return j
		}
	}
	return nil
}

func bearer(r *http.Request) (string, bool) {
	v := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(v) > len(p) && strings.EqualFold(v[:len(p)], p) {
		return strings.TrimSpace(v[len(p):]), true
	}
	return "", false
}

// checkSpec validates the request against the OpenAPI document.
func (h *Handler) checkSpec(w http.ResponseWriter, r *http.Request, d *policy.Decision) bool {
	if h.OpenAPIDocID == "" {
		return false
	}
	spec := Specs.Get(h.OpenAPIDocID)
	if spec == nil {
		h.finding(d, "api.document_missing", policy.SeverityNotice, "", "the OpenAPI document is not loaded; requests are not checked")
		return false
	}
	max := h.MaxBodyBytes
	if max <= 0 {
		max = config.DefaultAPIMaxBodyBytes
	}
	out, vs, skipped := spec.Check(r, max)
	if skipped {
		h.finding(d, "api.body_not_validated", policy.SeverityNotice, "/body", "body larger than the validation limit; not validated")
	}
	switch out {
	case Conforms:
		return false
	case Invalid:
		// handled below
	case UnknownPath, UnknownMethod:
		msg := "path is not in the OpenAPI document"
		if out == UnknownMethod {
			msg = "method is not documented for this path"
		}
		h.finding(d, "api.unknown_endpoint", policy.SeverityWarning, "", msg)
		return h.enforcing(h.UnknownPathAction) && h.deny(w, r, d, http.StatusForbidden)
	}
	for _, v := range vs {
		h.finding(d, "api.schema", policy.SeverityWarning, v.Pointer, v.Message)
	}
	return h.enforcing(h.SchemaViolationAction) && h.deny(w, r, d, http.StatusBadRequest)
}

// pathMatches reports whether p matches any glob; "/api/*" covers everything below.
func pathMatches(globs []string, p string) bool {
	if len(globs) == 0 {
		return true
	}
	for _, g := range globs {
		if ok, err := path.Match(g, p); err == nil && ok {
			return true
		}
		if pre, ok := strings.CutSuffix(g, "/*"); ok && strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
