package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bankSpec30 = `
openapi: 3.0.3
info: { title: Bank, version: "1" }
servers: [{ url: "https://api.bank.example/v1" }]
paths:
  /accounts/{id}/balance:
    get:
      summary: Balance
      parameters:
        - { name: id, in: path, required: true, schema: { type: string, pattern: "^[0-9]{1,10}$" } }
        - { name: currency, in: query, schema: { type: string, enum: [EUR, USD] } }
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
                amount: { type: integer, minimum: 1, maximum: 1000000 }
                currency: { type: string, enum: [EUR, USD] }
                creditor: { type: object, properties: { iban: { type: string, maxLength: 34 } } }
      responses: { "201": { description: created } }
      security: [{ bearer: [] }]
components:
  securitySchemes: { bearer: { type: http, scheme: bearer } }
`

const bankSpec31 = `
openapi: 3.1.0
info: { title: Bank, version: "1" }
paths:
  /payments:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [amount]
              properties:
                amount: { type: integer, exclusiveMinimum: 0 }
                memo: { type: [string, "null"] }
      responses: { "201": { description: created } }
`

func compile(t *testing.T, doc string) *Spec {
	t.Helper()
	s, err := CompileSpec(t.Context(), []byte(doc))
	require.NoError(t, err)
	return s
}

func req(method, target, body string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

func TestCompileSpecVersionsAndEndpoints(t *testing.T) {
	s30 := compile(t, bankSpec30)
	assert.Equal(t, "3.0", s30.Version)
	assert.Equal(t, []Endpoint{
		{Method: "GET", Path: "/accounts/{id}/balance", Summary: "Balance"},
		{Method: "POST", Path: "/payments"},
	}, s30.Endpoints)
	assert.Equal(t, "3.1", compile(t, bankSpec31).Version)
}

func TestCompileSpecRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":        "",
		"not openapi":  "hello: world",
		"swagger 2":    `{"swagger":"2.0","info":{"title":"x","version":"1"},"paths":{}}`,
		"no paths":     "openapi: 3.0.3\ninfo: {title: x, version: '1'}\npaths: {}\n",
		"bad schema":   "openapi: 3.0.3\ninfo: {title: x, version: '1'}\npaths:\n  /a:\n    get:\n      responses: {'200': {description: ok}}\n      parameters: [{name: q, in: query, schema: {type: nonsense}}]\n",
		"external ref": "openapi: 3.0.3\ninfo: {title: x, version: '1'}\npaths:\n  /a:\n    get:\n      responses:\n        '200': {$ref: 'file:///etc/passwd'}\n",
		"remote ref":   "openapi: 3.0.3\ninfo: {title: x, version: '1'}\npaths:\n  /a:\n    get:\n      responses:\n        '200': {$ref: 'http://169.254.169.254/x.yaml#/a'}\n",
		"oversize":     strings.Repeat("a", MaxSpecBytes+1),
		"future 4.0":   "openapi: 4.0.0\ninfo: {title: x, version: '1'}\npaths: {'/a': {get: {responses: {'200': {description: ok}}}}}\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CompileSpec(t.Context(), []byte(doc))
			assert.Error(t, err)
		})
	}
}

func TestCheck(t *testing.T) {
	s30, s31 := compile(t, bankSpec30), compile(t, bankSpec31)
	tests := []struct {
		name    string
		spec    *Spec
		r       *http.Request
		want    Outcome
		pointer string // first violation, when Invalid
	}{
		{"documented GET under the server base path", s30, req("GET", "/v1/accounts/42/balance?currency=EUR", ""), Conforms, ""},
		{"valid payment", s30, req("POST", "/v1/payments", `{"amount":10,"currency":"EUR"}`), Conforms, ""},
		{"unknown path", s30, req("GET", "/v1/admin/export", ""), UnknownPath, ""},
		{"outside the base path", s30, req("GET", "/accounts/42/balance", ""), UnknownPath, ""},
		{"unknown method", s30, req("DELETE", "/v1/payments", ""), UnknownMethod, ""},
		{"path parameter pattern (BOLA-style id probing)", s30, req("GET", "/v1/accounts/1%20OR%201=1/balance", ""), Invalid, "/path/id"},
		{"path parameter pattern, traversal", s30, req("GET", "/v1/accounts/..%2F..%2Fetc/balance", ""), Invalid, ""},
		{"enum violation in query", s30, req("GET", "/v1/accounts/42/balance?currency=BTC", ""), Invalid, "/query/currency"},
		{"missing required body field", s30, req("POST", "/v1/payments", `{"amount":10}`), Invalid, "/body/currency"},
		{"wrong type", s30, req("POST", "/v1/payments", `{"amount":"10","currency":"EUR"}`), Invalid, "/body/amount"},
		{"nested pointer", s30, req("POST", "/v1/payments", `{"amount":10,"currency":"EUR","creditor":{"iban":"`+strings.Repeat("X", 40)+`"}}`), Invalid, "/body/creditor/iban"},
		{"mass assignment: extra property", s30, req("POST", "/v1/payments", `{"amount":10,"currency":"EUR","is_admin":true}`), Invalid, "/body"},
		{"out of range", s30, req("POST", "/v1/payments", `{"amount":99999999,"currency":"EUR"}`), Invalid, "/body/amount"},
		{"not json", s30, req("POST", "/v1/payments", `{"amount":`), Invalid, "/body"},
		{"missing required body", s30, req("POST", "/v1/payments", ``), Invalid, "/body"},
		{"3.1 valid with null type array", s31, req("POST", "/payments", `{"amount":5,"memo":null}`), Conforms, ""},
		{"3.1 exclusiveMinimum", s31, req("POST", "/payments", `{"amount":0}`), Invalid, "/body/amount"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, vs, _ := tt.spec.Check(tt.r, 1<<20)
			assert.Equal(t, tt.want, got)
			if tt.want == Invalid {
				require.NotEmpty(t, vs)
				if tt.pointer != "" {
					assert.Equal(t, tt.pointer, vs[0].Pointer)
				}
			}
		})
	}
}

func TestViolationMessagesDoNotEchoValues(t *testing.T) {
	s := compile(t, bankSpec30)
	_, vs, _ := s.Check(req("POST", "/v1/payments", `{"amount":10,"currency":"4111111111111111"}`), 1<<20)
	require.NotEmpty(t, vs)
	for _, v := range vs {
		assert.NotContains(t, v.Message, "4111111111111111", "payloads must not leak into events")
	}
}

func TestCheckRestoresBodyForUpstream(t *testing.T) {
	s := compile(t, bankSpec30)
	const body = `{"amount":10,"currency":"EUR"}`
	r := req("POST", "/v1/payments", body)
	out, _, _ := s.Check(r, 1<<20)
	require.Equal(t, Conforms, out)
	got, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	assert.Equal(t, body, string(got))
}

func TestOversizeBodyIsNotValidatedButStillForwarded(t *testing.T) {
	s := compile(t, bankSpec30)
	big := `{"amount":"bad","pad":"` + strings.Repeat("a", 200) + `"}`
	for _, chunked := range []bool{false, true} {
		r := req("POST", "/v1/payments", big)
		if chunked {
			r.ContentLength = -1
		}
		out, _, skipped := s.Check(r, 64)
		assert.True(t, skipped, "chunked=%v", chunked)
		assert.Equal(t, Conforms, out, "the body is skipped, not guessed at")
		got, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, big, string(got), "the upstream still receives the whole body")
	}
}

func TestSpecTemplate(t *testing.T) {
	s := compile(t, bankSpec30)
	p, ok := s.Template(t.Context(), "GET", "/v1/accounts/777/balance")
	assert.True(t, ok)
	assert.Equal(t, "/accounts/{id}/balance", p)
	_, ok = s.Template(t.Context(), "GET", "/nope")
	assert.False(t, ok)
}

func TestRegistryKeepsOldDocumentWhenReplacementFails(t *testing.T) {
	g := &SpecRegistry{}
	_, err := g.Set(t.Context(), "bank", []byte(bankSpec30))
	require.NoError(t, err)
	_, err = g.Set(t.Context(), "bank", []byte("garbage"))
	require.Error(t, err)
	require.NotNil(t, g.Get("bank"))
	g.Delete("bank")
	assert.Nil(t, g.Get("bank"))
}

func BenchmarkCheckTypicalPayment(b *testing.B) {
	s, err := CompileSpec(b.Context(), []byte(bankSpec30))
	require.NoError(b, err)
	const body = `{"amount":1500,"currency":"EUR","creditor":{"iban":"NL91ABNA0417164300"}}`
	b.ReportAllocs()
	for b.Loop() {
		r := httptest.NewRequestWithContext(b.Context(), "POST", "/v1/payments", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if out, _, _ := s.Check(r, 1<<20); out != Conforms {
			b.Fatal(out)
		}
	}
}
