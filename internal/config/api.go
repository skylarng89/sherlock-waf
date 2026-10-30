package config

import (
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/netx"
)

// APIPolicy configures the API module: OpenAPI conformance, JWT validation and
// mutual TLS. Every field is optional and inherits like the rest of a policy.
type APIPolicy struct {
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// OpenAPIDocID refers to an uploaded OpenAPI document (3.0 or 3.1).
	OpenAPIDocID string `yaml:"openapi_doc_id,omitempty" json:"openapi_doc_id,omitempty"`
	// UnknownPathAction applies to requests the document does not describe
	// (path or method); SchemaViolationAction to documented requests whose
	// parameters or body break the schema. Both are log (default) or block.
	UnknownPathAction     string `yaml:"unknown_path_action,omitempty" json:"unknown_path_action,omitempty"`
	SchemaViolationAction string `yaml:"schema_violation_action,omitempty" json:"schema_violation_action,omitempty"`
	// MaxBodyBytes bounds the request body read for schema validation; larger
	// bodies are not validated (the finding says so).
	MaxBodyBytes *int64 `yaml:"max_body_bytes,omitempty" json:"max_body_bytes,omitempty"`
	// JWT rules are a list: a lower level replaces the whole list.
	JWT  []JWTRule   `yaml:"jwt,omitempty" json:"jwt,omitempty"`
	MTLS *MTLSPolicy `yaml:"mtls,omitempty" json:"mtls,omitempty"`
}

// JWTRule validates bearer tokens on the requests it matches. Keys come from
// exactly one of JWKSURL (fetched by a background job, never on the request
// path), PublicKeyPEM or HMACSecretEnv.
type JWTRule struct {
	Match APIMatch `yaml:"match,omitempty" json:"match"`
	// JWKSURL must be https and may not point at a private, loopback or
	// link-local address (SSRF, threat T13).
	JWKSURL string `yaml:"jwks_url,omitempty" json:"jwks_url,omitempty"`
	// PublicKeyPEM is a static RSA, ECDSA or Ed25519 public key.
	PublicKeyPEM string `yaml:"public_key_pem,omitempty" json:"public_key_pem,omitempty"`
	// HMACSecretEnv names the environment variable holding a shared secret.
	// It is the only way to accept HS256/384/512 tokens.
	HMACSecretEnv string   `yaml:"hmac_secret_env,omitempty" json:"hmac_secret_env,omitempty"`
	Issuer        string   `yaml:"issuer,omitempty" json:"issuer,omitempty"`
	Audiences     []string `yaml:"audiences,omitempty" json:"audiences,omitempty"`
	// ClockSkew tolerates small clock differences in exp/nbf (default 30s).
	ClockSkew Duration `yaml:"clock_skew,omitempty" json:"clock_skew,omitempty"`
	// RefreshInterval is how often the JWKS is refetched (default 15m).
	RefreshInterval Duration `yaml:"refresh_interval,omitempty" json:"refresh_interval,omitempty"`
	// Optional lets requests without a token through; a token that is present
	// must still be valid.
	Optional bool `yaml:"optional,omitempty" json:"optional,omitempty"`
	// Action for a missing or invalid token: block (default) or log.
	Action string `yaml:"action,omitempty" json:"action,omitempty"`
}

// APIMatch selects requests by path glob and method.
type APIMatch struct {
	Paths   []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
}

// MTLSPolicy requires a verified client certificate on the listed paths. The
// CA is an uploaded CA bundle; the site's TLS listener asks for a certificate
// (without insisting) and the API module enforces the paths.
type MTLSPolicy struct {
	RequiredPaths []string `yaml:"required_paths,omitempty" json:"required_paths,omitempty"`
	CACertID      string   `yaml:"ca_cert_id,omitempty" json:"ca_cert_id,omitempty"`
}

// API defaults and bounds.
const (
	DefaultAPIMaxBodyBytes int64 = 1 << 20
	DefaultJWTClockSkew          = 30 * time.Second
	DefaultJWKSRefresh           = 15 * time.Minute
	KeyJWTPrefix                 = "jwt:"
	KeyAPIKeyPrefix              = "api_key:"
	KeyClientCertSubject         = "mtls_subject"
	maxJWTRules                  = 20
	maxAPIBodyBytesLimit   int64 = 16 << 20
)

// EffectiveAPI is the resolved API policy.
type EffectiveAPI struct {
	Enabled               bool       `json:"enabled"`
	OpenAPIDocID          string     `json:"openapi_doc_id,omitempty"`
	UnknownPathAction     string     `json:"unknown_path_action"`
	SchemaViolationAction string     `json:"schema_violation_action"`
	MaxBodyBytes          int64      `json:"max_body_bytes"`
	JWT                   []JWTRule  `json:"jwt"`
	MTLS                  MTLSPolicy `json:"mtls"`
}

func newEffectiveAPI() EffectiveAPI {
	return EffectiveAPI{
		UnknownPathAction: ActionLog, SchemaViolationAction: ActionLog,
		MaxBodyBytes: DefaultAPIMaxBodyBytes, JWT: []JWTRule{}, MTLS: MTLSPolicy{RequiredPaths: []string{}},
	}
}

func (e *EffectivePolicy) applyAPI(p *Policy, src string) {
	a := p.API
	if a == nil {
		return
	}
	set := func(f string) { e.Sources["api."+f] = src }
	e.API.Enabled = a.Enabled == nil || *a.Enabled
	set("enabled")
	if a.OpenAPIDocID != "" {
		e.API.OpenAPIDocID = a.OpenAPIDocID
		set("openapi_doc_id")
	}
	if a.UnknownPathAction != "" {
		e.API.UnknownPathAction = a.UnknownPathAction
		set("unknown_path_action")
	}
	if a.SchemaViolationAction != "" {
		e.API.SchemaViolationAction = a.SchemaViolationAction
		set("schema_violation_action")
	}
	if a.MaxBodyBytes != nil {
		e.API.MaxBodyBytes = *a.MaxBodyBytes
		set("max_body_bytes")
	}
	if a.JWT != nil {
		e.API.JWT = slices.Clone(a.JWT)
		set("jwt")
	}
	if m := a.MTLS; m != nil {
		if m.RequiredPaths != nil {
			e.API.MTLS.RequiredPaths = slices.Clone(m.RequiredPaths)
			set("mtls.required_paths")
		}
		if m.CACertID != "" {
			e.API.MTLS.CACertID = m.CACertID
			set("mtls.ca_cert_id")
		}
	}
}

func (p *Policy) applyAPIDefaults() {
	if p.API == nil {
		return
	}
	for i := range p.API.JWT {
		j := &p.API.JWT[i]
		if j.Action == "" {
			j.Action = ActionBlock
		}
		if len(j.Match.Paths) == 0 {
			j.Match.Paths = []string{"/*"}
		}
		if j.ClockSkew == 0 {
			j.ClockSkew = Duration(DefaultJWTClockSkew)
		}
		if j.RefreshInterval == 0 {
			j.RefreshInterval = Duration(DefaultJWKSRefresh)
		}
	}
}

func (p *Policy) validateAPI(pth string, errs *Errors) {
	a := p.API
	if a == nil {
		return
	}
	for _, f := range []struct{ name, v string }{
		{"unknown_path_action", a.UnknownPathAction}, {"schema_violation_action", a.SchemaViolationAction},
	} {
		if !slices.Contains([]string{"", ActionLog, ActionBlock}, f.v) {
			errs.add(pth+"/"+f.name, CodeInvalid, "must be log or block")
		}
	}
	if a.MaxBodyBytes != nil && (*a.MaxBodyBytes < 1 || *a.MaxBodyBytes > maxAPIBodyBytesLimit) {
		errs.add(pth+"/max_body_bytes", CodeOutOfRange, "must be between 1 and %d", maxAPIBodyBytesLimit)
	}
	if len(a.JWT) > maxJWTRules {
		errs.add(pth+"/jwt", CodeOutOfRange, "at most %d rules", maxJWTRules)
	}
	for i, j := range a.JWT {
		j.validate(pth+"/jwt/"+strconv.Itoa(i), errs)
	}
	if m := a.MTLS; m != nil {
		for i, pat := range m.RequiredPaths {
			validatePathGlob(pth+"/mtls/required_paths/"+strconv.Itoa(i), pat, errs)
		}
		if len(m.RequiredPaths) > maxMatchPatterns {
			errs.add(pth+"/mtls/required_paths", CodeOutOfRange, "too many patterns")
		}
	}
}

func validatePathGlob(p, pat string, errs *Errors) {
	if !strings.HasPrefix(pat, "/") {
		errs.add(p, CodeInvalid, "must start with '/'")
	} else if _, err := path.Match(pat, "/"); err != nil {
		errs.add(p, CodeInvalid, "invalid glob: %v", err)
	}
}

func (j JWTRule) validate(p string, errs *Errors) {
	sources := 0
	for _, s := range []string{j.JWKSURL, j.PublicKeyPEM, j.HMACSecretEnv} {
		if s != "" {
			sources++
		}
	}
	if sources != 1 {
		errs.add(p, CodeInvalid, "set exactly one of jwks_url, public_key_pem or hmac_secret_env")
	}
	if j.JWKSURL != "" {
		u, err := url.Parse(j.JWKSURL)
		switch {
		case err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil:
			errs.add(p+"/jwks_url", CodeInvalid, "must be an https URL without credentials")
		case internalHost(u.Hostname()):
			// Names are checked again when connecting (netx refuses internal
			// addresses after DNS resolution); this catches the obvious cases early.
			errs.add(p+"/jwks_url", CodeInvalid, "must not point at a loopback, private or link-local address")
		}
	}
	if j.HMACSecretEnv != "" && !envNameRE.MatchString(j.HMACSecretEnv) {
		errs.add(p+"/hmac_secret_env", CodeInvalid, "must be an environment variable name")
	}
	if j.Issuer == "" && len(j.Audiences) == 0 {
		errs.add(p, CodeInvalid, "set issuer or audiences: a token from any issuer for any audience proves little")
	}
	if len(j.Audiences) > 20 {
		errs.add(p+"/audiences", CodeOutOfRange, "at most 20 audiences")
	}
	if !slices.Contains([]string{"", ActionLog, ActionBlock}, j.Action) {
		errs.add(p+"/action", CodeInvalid, "must be block or log")
	}
	if s := j.ClockSkew.Std(); s < 0 || s > 5*time.Minute {
		errs.add(p+"/clock_skew", CodeOutOfRange, "must be between 0 and 5m")
	}
	if r := j.RefreshInterval.Std(); r != 0 && (r < time.Minute || r > 24*time.Hour) {
		errs.add(p+"/refresh_interval", CodeOutOfRange, "must be between 1m and 24h")
	}
	for i, pat := range j.Match.Paths {
		validatePathGlob(p+"/match/paths/"+strconv.Itoa(i), pat, errs)
	}
	for i, m := range j.Match.Methods {
		if !slices.Contains(validVerbs, m) {
			errs.add(p+"/match/methods/"+strconv.Itoa(i), CodeInvalid, "%q is not an HTTP method", m)
		}
	}
}

// internalHost reports literal addresses and names that are never a public key server.
func internalHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && netx.Blocked(ip, false)
}
