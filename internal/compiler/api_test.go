package compiler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
)

const apiYAML = `
schema_version: 1
sites:
  - id: bank
    hosts: [api.bank.test]
    tls: { mode: file, cert_id: CERT1 }
    upstreams: { targets: ["origin.internal:8080"] }
    policy:
      mode: block
      rate_limits: [{ name: per-client, key: "jwt:client_id", limit: 10, window: 1m }]
      api:
        enabled: true
        openapi_doc_id: pay
        unknown_path_action: block
        jwt: [{ match: { paths: ["/v1/*"] }, jwks_url: "https://auth.bank.test/jwks.json", issuer: "https://auth.bank.test/", audiences: [bank] }]
        mtls: { required_paths: ["/ob/*"], ca_cert_id: ca1 }
`

func testCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Bank Root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func apiOpts(t *testing.T) (Options, string) {
	ca := testCA(t)
	return Options{
		CertFiles: func(string) (string, string, error) { return "/c.crt", "/c.key", nil },
		CABundles: func(string) (string, error) { return ca, nil },
	}, ca
}

func TestAPIHandlerIsBetweenACLAndRateLimitAndCarriesTheRules(t *testing.T) {
	root, err := config.Parse([]byte(apiYAML))
	require.NoError(t, err)
	opts, _ := apiOpts(t)
	out, err := Compile(root, opts)
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	var handlers []map[string]any
	var find func(any)
	find = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if h, ok := x["handler"].(string); ok && len(h) > 9 && h[:9] == "sherlock_" {
				handlers = append(handlers, x)
			}
			for _, c := range x {
				find(c)
			}
		case []any:
			for _, c := range x {
				find(c)
			}
		}
	}
	find(doc["apps"])
	var order []string
	var api map[string]any
	for _, h := range handlers {
		order = append(order, h["handler"].(string))
		if h["handler"] == "sherlock_api" {
			api = h
		}
	}
	// api before ratelimit: a limit keyed on a token claim needs the claim verified first.
	assert.Equal(t, []string{"sherlock_core", "sherlock_acl", "sherlock_api", "sherlock_ratelimit"}, order[:4])
	require.NotNil(t, api)
	assert.Equal(t, "pay", api["openapi_doc_id"])
	assert.Equal(t, "block", api["unknown_path_action"])
	assert.Equal(t, "block", api["mode"])
	assert.Equal(t, []any{"/ob/*"}, api["mtls_required_paths"])
	jwt := api["jwt"].([]any)[0].(map[string]any)
	assert.Equal(t, "https://auth.bank.test/jwks.json", jwt["jwks_url"])
	assert.Equal(t, "30s", jwt["clock_skew"])
}

func TestMTLSAsksForCertificatesWithoutInsistingAtTheHandshake(t *testing.T) {
	root, err := config.Parse([]byte(apiYAML))
	require.NoError(t, err)
	opts, ca := apiOpts(t)
	out, err := Compile(root, opts)
	require.NoError(t, err)

	blk, _ := pem.Decode([]byte(ca))
	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Policies []map[string]any `json:"tls_connection_policies"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	var ca1 map[string]any
	for _, p := range doc.Apps.HTTP.Servers[httpsServer].Policies {
		if a, ok := p["client_authentication"].(map[string]any); ok {
			ca1 = a
		}
	}
	require.NotNil(t, ca1)
	assert.Equal(t, "verify_if_given", ca1["mode"])
	assert.Equal(t, []any{base64.StdEncoding.EncodeToString(blk.Bytes)}, ca1["trusted_ca_certs"])
}

func TestAPICompileErrors(t *testing.T) {
	opts, _ := apiOpts(t)
	for name, yaml := range map[string]string{
		"block without a document": `
schema_version: 1
sites:
  - id: a
    hosts: [a.test]
    tls: { mode: none }
    upstreams: { targets: ["h:1"] }
    policy: { api: { enabled: true, unknown_path_action: block } }
`,
		"required paths without a CA": `
schema_version: 1
sites:
  - id: a
    hosts: [a.test]
    tls: { mode: none }
    upstreams: { targets: ["h:1"] }
    policy: { api: { enabled: true, mtls: { required_paths: ["/x/*"] } } }
`,
	} {
		t.Run(name, func(t *testing.T) {
			root, err := config.Parse([]byte(yaml))
			require.NoError(t, err)
			_, err = Compile(root, opts)
			assert.Error(t, err)
		})
	}
	t.Run("missing CA bundle", func(t *testing.T) {
		root, err := config.Parse([]byte(apiYAML))
		require.NoError(t, err)
		_, err = Compile(root, Options{CertFiles: opts.CertFiles})
		assert.Error(t, err)
	})
}

func TestAPIDisabledEmitsNothing(t *testing.T) {
	root, err := config.Parse([]byte(`
schema_version: 1
sites:
  - id: a
    hosts: [a.test]
    tls: { mode: none }
    upstreams: { targets: ["h:1"] }
`))
	require.NoError(t, err)
	out, err := Compile(root, Options{})
	require.NoError(t, err)
	assert.NotContains(t, string(out), "sherlock_api")
}
