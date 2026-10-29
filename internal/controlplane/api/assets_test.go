package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/store"
)

func selfSigned(t *testing.T, dns ...string) (certPEM, keyPEM string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "t"}, DNSNames: dns,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(72 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	pk, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
}

func TestFirstRunSetup(t *testing.T) {
	h := newHarnessWith(t, harnessOpts{noUsers: true})
	c := h.anon()
	token, err := os.ReadFile(h.gate.Path())
	require.NoError(t, err)
	tok := strings.TrimSpace(string(token))

	info, err := os.Stat(h.gate.Path())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the token file is private")

	assert.Equal(t, true, c.do("GET", "/setup/status", nil).JSON(t)["setup_required"])

	body := func(token, user, pass string) map[string]string {
		return map[string]string{"setup_token": token, "username": user, "password": pass}
	}
	assert.Equal(t, http.StatusForbidden, c.do("POST", "/setup/admin", body("wrong", "ada", pw)).Status, "wrong token")
	assert.Equal(t, http.StatusBadRequest, c.do("POST", "/setup/admin", body(tok, "ab", pw)).Status, "bad username")
	assert.Equal(t, http.StatusBadRequest, c.do("POST", "/setup/admin", body(tok, "ada", "short")).Status, "weak password")
	assert.True(t, h.gate.Active(), "rejected input must not burn the token")

	made := c.do("POST", "/setup/admin", body(tok, "ada", pw))
	require.Equal(t, http.StatusCreated, made.Status, string(made.Body))
	assert.Equal(t, "admin", made.JSON(t)["role"])
	assert.NotContains(t, string(made.Body), "password")

	// The gate closes itself: the token is gone, reuse fails, status flips.
	_, err = os.Stat(h.gate.Path())
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Equal(t, http.StatusConflict, c.do("POST", "/setup/admin", body(tok, "mallory", pw)).Status)
	assert.Equal(t, false, c.do("GET", "/setup/status", nil).JSON(t)["setup_required"])

	// And the new admin can sign in (and is then forced to enrol MFA).
	login := c.do("POST", "/auth/login", map[string]string{"username": "ada", "password": pw})
	require.Equal(t, http.StatusOK, login.Status)
	assert.Equal(t, "mfa_enrol_required", login.JSON(t)["status"])
}

func TestSetupTokenIsThrottledAndConstantTime(t *testing.T) {
	h := newHarnessWith(t, harnessOpts{noUsers: true})
	c := h.anon()
	req := map[string]string{"setup_token": "nope", "username": "ada", "password": pw}
	for range 5 {
		assert.Equal(t, http.StatusForbidden, c.do("POST", "/setup/admin", req).Status)
	}
	r := c.do("POST", "/setup/admin", req)
	assert.Equal(t, http.StatusTooManyRequests, r.Status, "guessing is throttled process-wide")
	assert.NotEmpty(t, r.Header.Get("Retry-After"))

	tok, _ := os.ReadFile(h.gate.Path())
	req["setup_token"] = strings.TrimSpace(string(tok))
	assert.Equal(t, http.StatusTooManyRequests, c.do("POST", "/setup/admin", req).Status, "even the right token waits out the throttle")
}

func TestSetupIsClosedWhenUsersExist(t *testing.T) {
	h := newHarness(t) // has users and no gate
	c := h.anon()
	assert.Equal(t, false, c.do("GET", "/setup/status", nil).JSON(t)["setup_required"])
	r := c.do("POST", "/setup/admin", map[string]string{"setup_token": "x", "username": "mallory", "password": pw})
	assert.Equal(t, http.StatusConflict, r.Status)
}

func TestSetupAdminRaceNeverCreatesTwo(t *testing.T) {
	h := newHarnessWith(t, harnessOpts{noUsers: true})
	tok, _ := os.ReadFile(h.gate.Path())
	results := make(chan int, 8)
	for i := range 8 {
		go func() {
			name := fmt.Sprintf("admin%d", i)
			results <- h.anon().do("POST", "/setup/admin", map[string]string{"setup_token": strings.TrimSpace(string(tok)), "username": name, "password": pw}).Status
		}()
	}
	created := 0
	for range 8 {
		if <-results == http.StatusCreated {
			created++
		}
	}
	assert.Equal(t, 1, created, "the single-use token admits exactly one administrator")
	var n int
	require.NoError(t, h.st.Tx(t.Context(), func(ctx_ context.Context, tx store.Tx) (err error) { n, err = tx.CountUsers(ctx_); return err }))
	assert.Equal(t, 1, n)
}

func TestTestUpstream(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer ok.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	}))
	defer redirecting.Close()

	res := a.do("POST", "/system/test-upstream", map[string]any{"target": strings.TrimPrefix(ok.URL, "http://")}).JSON(t)
	assert.Equal(t, true, res["reachable"])
	assert.EqualValues(t, http.StatusTeapot, res["status"])

	res = a.do("POST", "/system/test-upstream", map[string]any{"target": strings.TrimPrefix(redirecting.URL, "http://")}).JSON(t)
	assert.Equal(t, true, res["reachable"])
	assert.EqualValues(t, http.StatusFound, res["status"], "redirects are reported, never followed")

	// A closed port is a failed check (200 with reachable=false), with a short class.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closed := ln.Addr().String()
	require.NoError(t, ln.Close())
	res = a.do("POST", "/system/test-upstream", map[string]any{"target": closed}).JSON(t)
	assert.Equal(t, false, res["reachable"])
	assert.Equal(t, "refused", res["error"])

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsSrv.Close()
	addr := strings.TrimPrefix(tlsSrv.URL, "https://")
	res = a.do("POST", "/system/test-upstream", map[string]any{"target": addr, "tls": true}).JSON(t)
	assert.Equal(t, false, res["reachable"], "an untrusted certificate fails verification")
	assert.Equal(t, "tls", res["error"])
	res = a.do("POST", "/system/test-upstream", map[string]any{"target": addr, "tls": true, "tls_skip_verify": true}).JSON(t)
	assert.Equal(t, true, res["reachable"])

	for _, bad := range []string{"", "nohost", "h:0", "h:99999", ":80", "h:port"} {
		assert.Equal(t, http.StatusBadRequest, a.do("POST", "/system/test-upstream", map[string]any{"target": bad}).Status, bad)
	}
	assert.NotContains(t, string(a.do("POST", "/system/test-upstream", map[string]any{"target": closed}).Body), "127.0.0.1", "errors are classes, not raw dial errors")
}

func TestTimeseries(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	base := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)
	require.NoError(t, h.st.Tx(t.Context(), func(ctx_ context.Context, tx store.Tx) error {
		for _, r := range []store.Rollup{
			{Bucket: base.Add(5 * time.Minute), SiteID: "shop", Action: "block", Count: 3},
			{Bucket: base.Add(20 * time.Minute), SiteID: "shop", Action: "block", Count: 4},
			{Bucket: base.Add(20 * time.Minute), SiteID: "shop", Action: "allow", Count: 100},
			{Bucket: base.Add(20 * time.Minute), SiteID: "docs", Action: "block", Count: 50},
			{Bucket: base.Add(time.Hour + time.Minute), SiteID: "shop", Action: "log", Count: 7},
		} {
			if err := tx.AddRollup(ctx_, r); err != nil {
				return err
			}
		}
		return nil
	}))
	q := func(extra string) map[string]any {
		return a.do("GET", "/stats/timeseries?from="+base.Format(time.RFC3339)+"&to="+base.Add(3*time.Hour).Format(time.RFC3339)+extra, nil).JSON(t)
	}
	hourly := q("&step=1h")["points"].([]any)
	require.Len(t, hourly, 3, "dense: one point per bucket, empty ones included")
	first := hourly[0].(map[string]any)["counts"].(map[string]any)
	assert.EqualValues(t, 57, first["block"], "3+4 from shop and 50 from docs share the first hour")
	assert.EqualValues(t, 100, first["allow"])
	assert.EqualValues(t, 7, hourly[1].(map[string]any)["counts"].(map[string]any)["log"])
	assert.Empty(t, hourly[2].(map[string]any)["counts"])

	only := q("&step=1h&site=shop")["points"].([]any)[0].(map[string]any)["counts"].(map[string]any)
	assert.EqualValues(t, 7, only["block"], "the site filter applies")

	for name, path := range map[string]string{
		"missing from":    "/stats/timeseries?to=2026-01-02T00:00:00Z",
		"inverted":        "/stats/timeseries?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z",
		"bad step":        "/stats/timeseries?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z&step=7m",
		"too many points": "/stats/timeseries?from=2020-01-01T00:00:00Z&to=2026-01-02T00:00:00Z&step=1m",
	} {
		assert.Equal(t, http.StatusBadRequest, a.do("GET", path, nil).Status, name)
	}
}

func TestCertificateLifecycle(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	cert, key := selfSigned(t, "secure.example.test")

	bad := a.do("POST", "/certificates", map[string]string{"name": "shop", "certificate_pem": cert, "private_key_pem": "nope"})
	assert.Equal(t, http.StatusBadRequest, bad.Status)
	assert.Contains(t, string(bad.Body), "no PEM private key")
	_, otherKey := selfSigned(t, "other.example.test")
	mismatch := a.do("POST", "/certificates", map[string]string{"name": "shop", "certificate_pem": cert, "private_key_pem": otherKey})
	assert.Equal(t, http.StatusBadRequest, mismatch.Status)
	assert.Contains(t, string(mismatch.Body), "does not match")

	made := a.do("POST", "/certificates", map[string]string{"name": "shop", "certificate_pem": cert, "private_key_pem": key})
	require.Equal(t, http.StatusCreated, made.Status, string(made.Body))
	assert.NotContains(t, string(made.Body), "PRIVATE KEY", "the key never comes back")
	id := made.JSON(t)["id"].(string)
	assert.Equal(t, []any{"secure.example.test"}, made.JSON(t)["hosts"])

	assert.Equal(t, http.StatusConflict, a.do("POST", "/certificates", map[string]string{"name": "shop", "certificate_pem": cert, "private_key_pem": key}).Status)
	list := a.do("GET", "/certificates", nil)
	assert.Len(t, list.JSON(t)["items"], 1)
	assert.NotContains(t, string(list.Body), "PRIVATE KEY")

	// A site can use it; the in-use certificate cannot be deleted.
	tag := etagOf(t, a.do("GET", "/config", nil))
	site := newSite("secure")
	site["tls"] = map[string]any{"mode": "file", "cert_id": id}
	site["hosts"] = []string{"secure.example.test"}
	r := a.do("POST", "/sites", site, "If-Match", tag)
	require.Equal(t, http.StatusCreated, r.Status, string(r.Body))
	del := a.do("DELETE", "/certificates/"+id, nil)
	assert.Equal(t, http.StatusConflict, del.Status)
	assert.Contains(t, string(del.Body), "/sites/1/tls/cert_id", "the conflict says where it is used")

	status := a.do("GET", "/certificates/acme-status", nil).JSON(t)["items"].([]any)
	var entry map[string]any
	for _, it := range status {
		if it.(map[string]any)["site"] == "secure" {
			entry = it.(map[string]any)
		}
	}
	require.NotNil(t, entry)
	assert.Equal(t, "issued", entry["state"])
	assert.NotEmpty(t, entry["not_after"])

	// Remove the site, then the certificate goes.
	tag = etagOf(t, r)
	require.Equal(t, http.StatusOK, a.do("DELETE", "/sites/secure", nil, "If-Match", tag).Status)
	assert.Equal(t, http.StatusNoContent, a.do("DELETE", "/certificates/"+id, nil).Status)
	assert.Equal(t, http.StatusNotFound, a.do("DELETE", "/certificates/"+id, nil).Status)
}

func TestConfigReferencingAMissingCertificateIsRefused(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	tag := etagOf(t, a.do("GET", "/config", nil))
	site := newSite("secure")
	site["tls"] = map[string]any{"mode": "file", "cert_id": "01NOSUCHCERT"}
	r := a.do("POST", "/sites", site, "If-Match", tag)
	require.Equal(t, http.StatusUnprocessableEntity, r.Status, string(r.Body))
	errs := r.JSON(t)["errors"].([]any)
	assert.Equal(t, "/sites/1/tls/cert_id", errs[0].(map[string]any)["path"])
	assert.Equal(t, "not_found", errs[0].(map[string]any)["code"])

	// The dry-run endpoint reports the same.
	v := a.do("POST", "/config/validate", map[string]any{"schema_version": 1, "sites": []any{site}})
	assert.Equal(t, false, v.JSON(t)["valid"])
}

func TestBlockPages(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	put := func(id, html string) resp { return a.do("PUT", "/block-pages/"+id, map[string]string{"html": html}) }

	assert.Equal(t, http.StatusUnprocessableEntity, put("corp", "{{.Nope}}").Status, "templates that fail to render are refused")
	assert.Equal(t, http.StatusUnprocessableEntity, put("corp", "{{.Status").Status)
	assert.Equal(t, http.StatusBadRequest, put("default", "<p>x</p>").Status, "the built-in page cannot be replaced")
	assert.Equal(t, http.StatusBadRequest, a.do("PUT", "/block-pages/Bad_Id", map[string]string{"html": "x"}).Status, "ids are slugs")

	ok := put("corp", "<h1>Blocked {{.Status}}</h1><p>{{.EventID}}</p>")
	require.Equal(t, http.StatusOK, ok.Status, string(ok.Body))
	assert.EqualValues(t, len("<h1>Blocked {{.Status}}</h1><p>{{.EventID}}</p>"), ok.JSON(t)["size_bytes"])
	assert.Len(t, a.do("GET", "/block-pages", nil).JSON(t)["items"], 1)

	// A policy may use it; then it cannot be deleted.
	tag := etagOf(t, a.do("GET", "/sites/shop", nil))
	r := a.do("PATCH", "/sites/shop", `{"policy":{"block_page":{"template_id":"corp"}}}`, "If-Match", tag, "Content-Type", "application/merge-patch+json")
	require.Equal(t, http.StatusOK, r.Status, string(r.Body))
	del := a.do("DELETE", "/block-pages/corp", nil)
	assert.Equal(t, http.StatusConflict, del.Status)
	assert.Contains(t, string(del.Body), "/sites/0/policy/block_page/template_id")

	// Unknown templates are refused at config time.
	tag = etagOf(t, r)
	bad := a.do("PATCH", "/sites/shop", `{"policy":{"block_page":{"template_id":"ghost"}}}`, "If-Match", tag, "Content-Type", "application/merge-patch+json")
	assert.Equal(t, http.StatusUnprocessableEntity, bad.Status)

	back := a.do("PATCH", "/sites/shop", `{"policy":{"block_page":{"template_id":"default"}}}`, "If-Match", tag, "Content-Type", "application/merge-patch+json")
	require.Equal(t, http.StatusOK, back.Status)
	assert.Equal(t, http.StatusNoContent, a.do("DELETE", "/block-pages/corp", nil).Status)
	assert.Equal(t, http.StatusNotFound, a.do("DELETE", "/block-pages/corp", nil).Status)
}

func TestRollbackToAVersionWithADeletedCertificateIsRefused(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	cert, key := selfSigned(t, "secure.example.test")
	id := a.do("POST", "/certificates", map[string]string{"name": "shop", "certificate_pem": cert, "private_key_pem": key}).JSON(t)["id"].(string)

	tag := etagOf(t, a.do("GET", "/config", nil))
	site := newSite("secure")
	site["tls"] = map[string]any{"mode": "file", "cert_id": id}
	site["hosts"] = []string{"secure.example.test"}
	withCert := a.do("POST", "/sites", site, "If-Match", tag)
	require.Equal(t, http.StatusCreated, withCert.Status)
	withCertID := withCert.JSON(t)["id"].(string)

	tag = etagOf(t, a.do("DELETE", "/sites/secure", nil, "If-Match", etagOf(t, withCert)))
	_ = tag
	require.Equal(t, http.StatusNoContent, a.do("DELETE", "/certificates/"+id, nil).Status)

	head := etagOf(t, a.do("GET", "/config", nil))
	rb := a.do("POST", "/config/versions/"+withCertID+"/rollback", nil, "If-Match", head)
	require.Equal(t, http.StatusUnprocessableEntity, rb.Status, string(rb.Body))
	assert.Contains(t, string(rb.Body), "does not exist")
	assert.Equal(t, head, a.do("GET", "/config", nil).Header.Get("ETag"), "nothing changed")
}

func TestUploadedCertificatesAreMaterialisedPrivately(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	cert, key := selfSigned(t, "shop.example.test")
	id := a.do("POST", "/certificates", map[string]string{"name": "shop", "certificate_pem": cert, "private_key_pem": key}).JSON(t)["id"].(string)

	certFile, keyFile, err := h.certs.Paths(id)
	require.NoError(t, err)
	info, err := os.Stat(keyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	assert.Equal(t, filepath.Join(h.dataDir, "certs"), filepath.Dir(certFile))

	require.Equal(t, http.StatusNoContent, a.do("DELETE", "/certificates/"+id, nil).Status)
	_, err = os.Stat(keyFile)
	assert.ErrorIs(t, err, os.ErrNotExist, "deleting a certificate removes its key file from disk")
}
