package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dpapi "github.com/skylarng89/sherlock-waf/internal/dataplane/api"
)

const apiDocYAML = `
openapi: 3.1.0
info: { title: Pay, version: "1" }
paths:
  /accounts/{id}:
    get:
      summary: Account
      parameters: [{ name: id, in: path, required: true, schema: { type: string } }]
      responses: { "200": { description: ok } }
  /payments:
    post:
      responses: { "201": { description: created } }
`

func caPEM(t *testing.T, isCA bool, notAfter time.Time) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Bank Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAPIDocuments(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	t.Cleanup(func() { dpapi.Specs.Delete("pay") })
	put := func(id, content string) resp {
		return a.do("PUT", "/api-docs/"+id, map[string]string{"name": "Payments", "content": content})
	}

	assert.Equal(t, http.StatusUnprocessableEntity, put("pay", "not openapi").Status, "documents that do not compile are refused")
	assert.Equal(t, http.StatusBadRequest, put("Bad_Id", apiDocYAML).Status)
	assert.Nil(t, dpapi.Specs.Get("pay"), "nothing is loaded after a refusal")

	ok := put("pay", apiDocYAML)
	require.Equal(t, http.StatusOK, ok.Status, string(ok.Body))
	assert.Equal(t, "3.1", ok.JSON(t)["version"])
	assert.EqualValues(t, 2, ok.JSON(t)["endpoint_count"])
	require.NotNil(t, dpapi.Specs.Get("pay"), "the data plane serves the new document immediately")
	assert.Len(t, a.do("GET", "/api-docs", nil).JSON(t)["items"], 1)

	// A broken replacement keeps the working one.
	assert.Equal(t, http.StatusUnprocessableEntity, put("pay", "garbage").Status)
	assert.Len(t, dpapi.Specs.Get("pay").Endpoints, 2)

	eps := a.do("GET", "/api-docs/pay/endpoints?site=shop", nil)
	require.Equal(t, http.StatusOK, eps.Status, string(eps.Body))
	items := eps.JSON(t)["items"].([]any)
	require.Len(t, items, 2)
	assert.Equal(t, "/accounts/{id}", items[0].(map[string]any)["path"])
	assert.EqualValues(t, 0, items[0].(map[string]any)["schema_violations"])
	assert.Equal(t, http.StatusBadRequest, a.do("GET", "/api-docs/pay/endpoints", nil).Status, "site is required")
	assert.Equal(t, http.StatusNotFound, a.do("GET", "/api-docs/ghost/endpoints?site=shop", nil).Status)

	// In use by a site: cannot be deleted; unknown ids are refused at config time.
	tag := etagOf(t, a.do("GET", "/sites/shop", nil))
	r := a.do("PATCH", "/sites/shop", `{"policy":{"api":{"enabled":true,"openapi_doc_id":"pay"}}}`, "If-Match", tag, "Content-Type", "application/merge-patch+json")
	require.Equal(t, http.StatusOK, r.Status, string(r.Body))
	del := a.do("DELETE", "/api-docs/pay", nil)
	assert.Equal(t, http.StatusConflict, del.Status)
	assert.Contains(t, string(del.Body), "/sites/0/policy/api/openapi_doc_id")
	bad := a.do("PATCH", "/sites/shop", `{"policy":{"api":{"openapi_doc_id":"ghost"}}}`, "If-Match", etagOf(t, r), "Content-Type", "application/merge-patch+json")
	assert.Equal(t, http.StatusUnprocessableEntity, bad.Status)

	back := a.do("PATCH", "/sites/shop", `{"policy":{"api":null}}`, "If-Match", etagOf(t, r), "Content-Type", "application/merge-patch+json")
	require.Equal(t, http.StatusOK, back.Status, string(back.Body))
	assert.Equal(t, http.StatusNoContent, a.do("DELETE", "/api-docs/pay", nil).Status)
	assert.Nil(t, dpapi.Specs.Get("pay"))
	assert.Equal(t, http.StatusNotFound, a.do("DELETE", "/api-docs/pay", nil).Status)
}

func TestCABundles(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	up := func(pemData string) resp {
		return a.do("POST", "/ca-bundles", map[string]string{"name": "Bank CA", "certificates_pem": pemData})
	}
	good := caPEM(t, true, time.Now().Add(24*time.Hour))
	_, keyPEM := selfSigned(t, "x.test")

	assert.Equal(t, http.StatusBadRequest, up("nope").Status)
	assert.Equal(t, http.StatusBadRequest, up(good+keyPEM).Status, "a private key is refused outright")
	assert.Equal(t, http.StatusBadRequest, up(caPEM(t, false, time.Now().Add(time.Hour))).Status, "leaf certificates are not CAs")
	assert.Equal(t, http.StatusBadRequest, up(caPEM(t, true, time.Now().Add(-time.Minute))).Status, "expired")

	ok := up(good)
	require.Equal(t, http.StatusCreated, ok.Status, string(ok.Body))
	j := ok.JSON(t)
	assert.Equal(t, []any{"CN=Bank Root"}, j["subjects"])
	assert.NotContains(t, string(ok.Body), "BEGIN", "the response carries no PEM")
	id := j["id"].(string)
	assert.Len(t, a.do("GET", "/ca-bundles", nil).JSON(t)["items"], 1)

	// Referenced by a site: protected from deletion; unknown ids refused.
	tag := etagOf(t, a.do("GET", "/sites/shop", nil))
	r := a.do("PATCH", "/sites/shop", `{"policy":{"api":{"enabled":true,"mtls":{"ca_cert_id":"`+id+`","required_paths":["/ob/*"]}}}}`, "If-Match", tag, "Content-Type", "application/merge-patch+json")
	require.Equal(t, http.StatusOK, r.Status, string(r.Body))
	assert.Equal(t, http.StatusConflict, a.do("DELETE", "/ca-bundles/"+id, nil).Status)
	bad := a.do("PATCH", "/sites/shop", `{"policy":{"api":{"mtls":{"ca_cert_id":"ghost"}}}}`, "If-Match", etagOf(t, r), "Content-Type", "application/merge-patch+json")
	assert.Equal(t, http.StatusUnprocessableEntity, bad.Status)

	back := a.do("PATCH", "/sites/shop", `{"policy":{"api":null}}`, "If-Match", etagOf(t, r), "Content-Type", "application/merge-patch+json")
	require.Equal(t, http.StatusOK, back.Status)
	assert.Equal(t, http.StatusNoContent, a.do("DELETE", "/ca-bundles/"+id, nil).Status)
	assert.Equal(t, http.StatusNotFound, a.do("DELETE", "/ca-bundles/"+id, nil).Status)
}

func TestAPIAssetsNeedPermissions(t *testing.T) {
	h := newHarness(t)
	anon := h.anon()
	for _, c := range []struct{ m, p string }{{"GET", "/api-docs"}, {"PUT", "/api-docs/x"}, {"GET", "/ca-bundles"}, {"POST", "/ca-bundles"}} {
		got := anon.do(c.m, c.p, nil).Status
		assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, got, c.m+" "+c.p)
	}
}
