package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dpapi "github.com/skylarng89/sherlock-waf/internal/dataplane/api"
)

const openBankingSpec = `
openapi: 3.0.3
info: { title: Open banking mock, version: "1" }
paths:
  /accounts/{id}/balance:
    get:
      parameters: [{ name: id, in: path, required: true, schema: { type: string, pattern: "^[0-9]{1,10}$" } }]
      responses: { "200": { description: ok } }
  /payments:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [amount, currency]
              additionalProperties: false
              properties:
                amount: { type: integer, minimum: 1 }
                currency: { type: string, enum: [EUR, USD] }
      responses: { "201": { description: created } }
`

const apiLiveConfig = `
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
sites:
  - id: bank
    hosts: [bank.localhost]
    tls: { mode: none }
    upstreams: { targets: ["%s"] }
    policy:
      mode: block
      rate_limits:
        - { name: per-client, key: "jwt:client_id", limit: 3, window: 1m, match: { paths: ["/accounts/*"] } }
      api:
        enabled: true
        openapi_doc_id: live-bank
        unknown_path_action: block
        schema_violation_action: block
        jwt:
          - match: { paths: ["/accounts/*", "/payments"] }
            public_key_pem: |
%s
            issuer: https://auth.bank.test/
            audiences: [open-banking]
`

func b64json(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// TestAPIProtectionLive covers M9 acceptance criteria 1-3 against a mock
// open-banking upstream behind the real data plane.
func TestAPIProtectionLive(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pemKey := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	indented := "              " + strings.ReplaceAll(pemKey, "\n", "\n              ")

	_, err = dpapi.Specs.Set(t.Context(), "live-bank", []byte(openBankingSpec))
	require.NoError(t, err)
	t.Cleanup(func() { dpapi.Specs.Delete("live-bank") })

	var upstreamHits int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		b, _ := io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(map[string]string{"upstream": r.Method + " " + r.URL.Path, "body": string(b)})
	}))
	t.Cleanup(up.Close)
	port := launch(t, fmt.Sprintf(apiLiveConfig, strings.TrimPrefix(up.URL, "http://"), indented))

	token := func(signer *ecdsa.PrivateKey, mut func(map[string]any)) string {
		c := map[string]any{"iss": "https://auth.bank.test/", "aud": "open-banking", "client_id": "tpp-1", "exp": time.Now().Add(time.Hour).Unix()}
		if mut != nil {
			mut(c)
		}
		signed := b64json(map[string]any{"alg": "ES256", "typ": "JWT"}) + "." + b64json(c)
		d := sha256.Sum256([]byte(signed))
		r, s, err := ecdsa.Sign(rand.Reader, signer, d[:])
		require.NoError(t, err)
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	call := func(method, target, body, tok string) (int, string) {
		req, err := http.NewRequestWithContext(t.Context(), method, fmt.Sprintf("http://127.0.0.1:%d%s", port, target), strings.NewReader(body))
		require.NoError(t, err)
		req.Host = "bank.localhost"
		req.Header.Set("Accept", "application/json")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	good := token(key, nil)

	t.Run("documented request with a valid token reaches the upstream with its body", func(t *testing.T) {
		code, body := call("POST", "/payments", `{"amount":10,"currency":"EUR"}`, good)
		assert.Equal(t, 200, code)
		var got map[string]string
		require.NoError(t, json.Unmarshal([]byte(body), &got))
		assert.Equal(t, "POST /payments", got["upstream"])
		assert.JSONEq(t, `{"amount":10,"currency":"EUR"}`, got["body"])
	})

	t.Run("JWTs that must be rejected", func(t *testing.T) {
		none := b64json(map[string]any{"alg": "none"}) + "." + b64json(map[string]any{"iss": "https://auth.bank.test/", "aud": "open-banking", "exp": time.Now().Add(time.Hour).Unix()}) + "."
		for name, tok := range map[string]string{
			"expired":        token(key, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }),
			"wrong audience": token(key, func(c map[string]any) { c["aud"] = "other-api" }),
			"wrong issuer":   token(key, func(c map[string]any) { c["iss"] = "https://evil/" }),
			"wrong signer":   token(other, nil),
			"alg none":       none,
			"missing":        "",
		} {
			before := upstreamHits
			code, _ := call("GET", "/accounts/7/balance", "", tok)
			assert.Equal(t, 401, code, name)
			assert.Equal(t, before, upstreamHits, "%s must not reach the upstream", name)
		}
	})

	t.Run("undocumented endpoints are blocked", func(t *testing.T) {
		before := upstreamHits
		for _, c := range []struct{ method, path string }{{"GET", "/admin/export"}, {"DELETE", "/payments"}, {"GET", "/accounts"}} {
			code, _ := call(c.method, c.path, "", good)
			assert.Equal(t, 403, code, "%s %s", c.method, c.path)
		}
		assert.Equal(t, before, upstreamHits)
	})

	t.Run("schema violations and BOLA-style id probing are blocked", func(t *testing.T) {
		before := upstreamHits
		for _, body := range []string{`{"amount":-5,"currency":"EUR"}`, `{"amount":5,"currency":"EUR","is_admin":true}`, `{"amount":5}`, `not json`} {
			code, _ := call("POST", "/payments", body, good)
			assert.Equal(t, 400, code, body)
		}
		for _, id := range []string{"1%27%20OR%20%271%27=%271", "..%2F..%2Fetc%2Fpasswd", "7;DROP"} {
			code, _ := call("GET", "/accounts/"+id+"/balance", "", good)
			assert.Contains(t, []int{400, 403}, code, id)
		}
		assert.Equal(t, before, upstreamHits)
	})

	t.Run("rate limit per JWT client id, not per address", func(t *testing.T) {
		a := token(key, func(c map[string]any) { c["client_id"] = "tpp-a" })
		b := token(key, func(c map[string]any) { c["client_id"] = "tpp-b" })
		for i := range 3 {
			code, _ := call("GET", fmt.Sprintf("/accounts/%d/balance", i+1), "", a)
			assert.Equal(t, 200, code, "tpp-a request %d", i+1)
		}
		code, _ := call("GET", "/accounts/1/balance", "", a)
		assert.Equal(t, 429, code, "tpp-a is over its limit")
		code, _ = call("GET", "/accounts/1/balance", "", b)
		assert.Equal(t, 200, code, "tpp-b shares the address but not the bucket")
	})
}
