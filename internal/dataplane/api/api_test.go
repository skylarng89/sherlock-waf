package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

type outcome struct {
	status  int
	reached bool
	d       *policy.Decision
	header  http.Header
}

func newHandler(t *testing.T, h Handler) *Handler {
	t.Helper()
	h.SiteID = "bank"
	if h.Mode == "" {
		h.Mode = config.ModeBlock
	}
	require.NoError(t, h.Provision(caddy.Context{}))
	require.NoError(t, h.Validate())
	t.Cleanup(func() { _ = h.Cleanup() })
	return &h
}

func serve(t *testing.T, h *Handler, r *http.Request) outcome {
	t.Helper()
	d := policy.NewDecision("01TESTEVENT000000000000000", "bank", policy.Mode(h.Mode), netip.MustParseAddr("192.0.2.1"))
	r = r.WithContext(policy.WithDecision(r.Context(), d))
	rec := httptest.NewRecorder()
	out := outcome{d: d}
	require.NoError(t, h.ServeHTTP(rec, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		out.reached = true
		w.WriteHeader(http.StatusOK)
		return nil
	})))
	out.status, out.header = rec.Code, rec.Header()
	return out
}

func rules(o outcome) []string {
	var out []string
	for _, f := range o.d.Findings() {
		out = append(out, f.RuleID)
	}
	return out
}

func installBank(t *testing.T) {
	t.Helper()
	_, err := Specs.Set(t.Context(), "bank", []byte(bankSpec30))
	require.NoError(t, err)
	t.Cleanup(func() { Specs.Delete("bank") })
}

func TestSpecActionsBlockInBlockModeAndOnlyLogInDetect(t *testing.T) {
	installBank(t)
	for _, tt := range []struct {
		name        string
		mode        config.Mode
		unknown     string
		schema      string
		r           func() *http.Request
		wantStatus  int
		wantReached bool
		wantRule    string
	}{
		{"unknown path blocked", config.ModeBlock, "block", "log", func() *http.Request { return req("GET", "/v1/secret", "") }, 403, false, "api.unknown_endpoint"},
		{"unknown path logged", config.ModeBlock, "log", "log", func() *http.Request { return req("GET", "/v1/secret", "") }, 200, true, "api.unknown_endpoint"},
		{"unknown path in detect mode", config.ModeDetect, "block", "block", func() *http.Request { return req("GET", "/v1/secret", "") }, 200, true, "api.unknown_endpoint"},
		{"schema violation blocked", config.ModeBlock, "log", "block", func() *http.Request { return req("POST", "/v1/payments", `{"amount":-1,"currency":"EUR"}`) }, 400, false, "api.schema"},
		{"schema violation in detect mode", config.ModeDetect, "log", "block", func() *http.Request { return req("POST", "/v1/payments", `{"amount":-1,"currency":"EUR"}`) }, 200, true, "api.schema"},
		{"conforming request passes", config.ModeBlock, "block", "block", func() *http.Request { return req("POST", "/v1/payments", `{"amount":5,"currency":"USD"}`) }, 200, true, ""},
		{"mode off checks nothing", config.ModeOff, "block", "block", func() *http.Request { return req("GET", "/v1/secret", "") }, 200, true, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandler(t, Handler{Mode: tt.mode, OpenAPIDocID: "bank", UnknownPathAction: tt.unknown, SchemaViolationAction: tt.schema})
			o := serve(t, h, tt.r())
			assert.Equal(t, tt.wantStatus, o.status)
			assert.Equal(t, tt.wantReached, o.reached)
			if tt.wantRule == "" {
				assert.Empty(t, rules(o))
				return
			}
			assert.Contains(t, rules(o), tt.wantRule)
			if !tt.wantReached {
				assert.Equal(t, policy.ActionBlock, o.d.Action())
				assert.Equal(t, "api", o.d.Terminated())
			}
		})
	}
}

func TestSchemaFindingCarriesJSONPointer(t *testing.T) {
	installBank(t)
	h := newHandler(t, Handler{OpenAPIDocID: "bank", SchemaViolationAction: "log"})
	o := serve(t, h, req("POST", "/v1/payments", `{"amount":"x","currency":"EUR"}`))
	require.Len(t, o.d.Findings(), 1)
	assert.Equal(t, "/body/amount", o.d.Findings()[0].Target)
}

func TestMissingDocumentDoesNotBlock(t *testing.T) {
	h := newHandler(t, Handler{OpenAPIDocID: "gone", UnknownPathAction: "block", SchemaViolationAction: "block"})
	o := serve(t, h, req("GET", "/anything", ""))
	assert.True(t, o.reached)
	assert.Equal(t, []string{"api.document_missing"}, rules(o))
}

func TestOversizeBodyIsReportedNotBlocked(t *testing.T) {
	installBank(t)
	h := newHandler(t, Handler{OpenAPIDocID: "bank", SchemaViolationAction: "block", MaxBodyBytes: 16})
	o := serve(t, h, req("POST", "/v1/payments", `{"amount":"x","currency":"EUR","pad":"aaaaaaaaaaaaaaaa"}`))
	assert.True(t, o.reached)
	assert.Equal(t, []string{"api.body_not_validated"}, rules(o))
}

func TestJWTRules(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der := mustPKIX(t, &key.PublicKey)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	now := time.Now()
	claims := func(mut func(map[string]any)) string {
		c := map[string]any{"iss": "https://auth.example.com/", "aud": "shop-api", "client_id": "app-7", "exp": now.Add(time.Hour).Unix()}
		if mut != nil {
			mut(c)
		}
		return sign(t, "ES256", "", c, ecSigner(t, key))
	}
	rule := JWTRule{
		Paths: []string{"/api/*"}, PublicKeyPEM: pemKey, Issuer: "https://auth.example.com/", Audiences: []string{"shop-api"},
		Action: config.ActionBlock,
	}
	h := newHandler(t, Handler{JWT: []JWTRule{rule}})
	bearerReq := func(path, tok string) *http.Request {
		r := req("GET", path, "")
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		return r
	}
	t.Run("valid token passes and exposes verified claims", func(t *testing.T) {
		o := serve(t, h, bearerReq("/api/x", claims(nil)))
		assert.True(t, o.reached)
		got, ok := o.d.Claim("client_id")
		assert.True(t, ok)
		assert.Equal(t, "app-7", got)
	})
	for name, tok := range map[string]string{
		"expired":        claims(func(c map[string]any) { c["exp"] = now.Add(-time.Hour).Unix() }),
		"wrong audience": claims(func(c map[string]any) { c["aud"] = "other" }),
		"wrong issuer":   claims(func(c map[string]any) { c["iss"] = "https://evil/" }),
		"alg none":       enc(map[string]any{"alg": "none"}) + "." + enc(map[string]any{"exp": now.Add(time.Hour).Unix(), "iss": "https://auth.example.com/", "aud": "shop-api"}) + ".",
		"bad signature":  claims(nil)[:len(claims(nil))-4] + "AAAA",
		"missing":        "",
	} {
		t.Run(name, func(t *testing.T) {
			o := serve(t, h, bearerReq("/api/x", tok))
			assert.Equal(t, 401, o.status)
			assert.False(t, o.reached)
			assert.Contains(t, o.header.Get("WWW-Authenticate"), "Bearer")
			assert.Equal(t, []string{"api.jwt"}, rules(o))
			_, ok := o.d.Claim("client_id")
			assert.False(t, ok, "claims of a rejected token are never exposed")
		})
	}
	t.Run("paths outside the rule are not checked", func(t *testing.T) {
		assert.True(t, serve(t, h, bearerReq("/public", "")).reached)
	})
	t.Run("detect mode only logs", func(t *testing.T) {
		d := newHandler(t, Handler{Mode: config.ModeDetect, JWT: []JWTRule{rule}})
		o := serve(t, d, bearerReq("/api/x", ""))
		assert.True(t, o.reached)
		assert.Equal(t, []string{"api.jwt"}, rules(o))
	})
	t.Run("optional lets anonymous through but not bad tokens", func(t *testing.T) {
		opt := rule
		opt.Optional = true
		oh := newHandler(t, Handler{JWT: []JWTRule{opt}})
		assert.True(t, serve(t, oh, bearerReq("/api/x", "")).reached)
		assert.Equal(t, 401, serve(t, oh, bearerReq("/api/x", "junk.junk.junk")).status)
	})
	t.Run("method scoped rule", func(t *testing.T) {
		m := rule
		m.Methods = []string{"POST"}
		mh := newHandler(t, Handler{JWT: []JWTRule{m}})
		assert.True(t, serve(t, mh, bearerReq("/api/x", "")).reached, "GET is not covered")
		pr := req("POST", "/api/x", "")
		assert.Equal(t, 401, serve(t, mh, pr).status)
	})
}

func TestHMACSecretFromEnvironment(t *testing.T) {
	t.Setenv("TEST_JWT_SECRET", strings.Repeat("k", 40))
	h := newHandler(t, Handler{JWT: []JWTRule{{Paths: []string{"/*"}, HMACSecretEnv: "TEST_JWT_SECRET", Issuer: "i", Action: "block"}}})
	tok := sign(t, "HS256", "", map[string]any{"iss": "i", "exp": time.Now().Add(time.Hour).Unix()}, hmacSigner([]byte(strings.Repeat("k", 40))))
	r := req("GET", "/x", "")
	r.Header.Set("Authorization", "Bearer "+tok)
	assert.True(t, serve(t, h, r).reached)

	//nolint:gosec // an environment variable name in a test, not a credential
	bad := Handler{SiteID: "bank", Mode: "block", JWT: []JWTRule{{Paths: []string{"/*"}, HMACSecretEnv: "UNSET_SECRET_VAR", Action: "block"}}}
	assert.Error(t, bad.Provision(caddy.Context{}), "a missing or short secret fails the reload instead of accepting everything")
}

func TestMTLS(t *testing.T) {
	h := newHandler(t, Handler{MTLSRequiredPaths: []string{"/open-banking/*"}})
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "tpp-42"}}
	withCert := func(path string) *http.Request {
		r := req("GET", path, "")
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
		return r
	}
	t.Run("required path without a certificate", func(t *testing.T) {
		o := serve(t, h, req("GET", "/open-banking/accounts", ""))
		assert.Equal(t, 403, o.status)
		assert.Equal(t, []string{"api.mtls"}, rules(o))
	})
	t.Run("unverified certificate does not count", func(t *testing.T) {
		r := req("GET", "/open-banking/accounts", "")
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		assert.Equal(t, 403, serve(t, h, r).status)
	})
	t.Run("verified certificate passes and exposes its subject", func(t *testing.T) {
		o := serve(t, h, withCert("/open-banking/accounts"))
		assert.True(t, o.reached)
		assert.Equal(t, cert.Subject.String(), o.d.ClientCertSubject())
	})
	t.Run("other paths do not need one", func(t *testing.T) {
		assert.True(t, serve(t, h, req("GET", "/health", "")).reached)
	})
}

func TestValidate(t *testing.T) {
	assert.Error(t, (&Handler{}).Validate())
	assert.Error(t, (&Handler{SiteID: "a", UnknownPathAction: "nuke"}).Validate())
	assert.Error(t, (&Handler{SiteID: "a", JWT: []JWTRule{{Action: "nuke"}}}).Validate())
}

func mustPKIX(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return der
}
