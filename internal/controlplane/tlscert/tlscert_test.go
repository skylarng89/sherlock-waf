package tlscert

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func dial(t *testing.T, addr string, cfg *tls.Config) (*tls.Conn, error) {
	t.Helper()
	c, err := (&tls.Dialer{Config: cfg}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	return c.(*tls.Conn), nil
}

func TestGeneratesSelfSignedP256WithExpectedNames(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Options{DataDir: dir, Hostnames: []string{"waf.example.test"}})
	require.NoError(t, err)

	leaf := s.leaf
	_, isP256 := leaf.PublicKey.(*ecdsa.PublicKey)
	assert.True(t, isP256)
	assert.Equal(t, "P-256", leaf.PublicKey.(*ecdsa.PublicKey).Curve.Params().Name)
	for _, h := range []string{"localhost", "127.0.0.1", "::1", "waf.example.test"} {
		assert.NoError(t, leaf.VerifyHostname(h), h)
	}
	assert.WithinDuration(t, time.Now().Add(validity), leaf.NotAfter, time.Hour)
	assert.Len(t, s.Fingerprint(), 64)

	info, err := os.Stat(filepath.Join(dir, keyFile))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "private key must not be group/world readable")
}

func TestReusesCertificateAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	a, err := New(Options{DataDir: dir})
	require.NoError(t, err)
	b, err := New(Options{DataDir: dir})
	require.NoError(t, err)
	assert.Equal(t, a.Fingerprint(), b.Fingerprint())
}

func TestRenewsInsideWindowAndWhenNamesChange(t *testing.T) {
	dir := t.TempDir()
	a, err := New(Options{DataDir: dir})
	require.NoError(t, err)

	later := time.Now().Add(validity - renewWindow + time.Hour)
	b, err := New(Options{DataDir: dir, Now: func() time.Time { return later }})
	require.NoError(t, err)
	assert.NotEqual(t, a.Fingerprint(), b.Fingerprint(), "expiring certificate must be replaced")

	c, err := New(Options{DataDir: dir, Now: func() time.Time { return later }, Hostnames: []string{"new.example.test"}})
	require.NoError(t, err)
	assert.NotEqual(t, b.Fingerprint(), c.Fingerprint(), "a new SAN needs a new certificate")
	assert.NoError(t, c.leaf.VerifyHostname("new.example.test"))
}

func TestRefreshSwapsTheServedCertificate(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	clock := &now
	s, err := New(Options{DataDir: dir, Now: func() time.Time { return *clock }})
	require.NoError(t, err)
	before := s.Fingerprint()

	*clock = now.Add(validity - renewWindow + time.Hour)
	require.NoError(t, s.refresh())
	assert.NotEqual(t, before, s.Fingerprint())

	got, err := s.Config().GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	assert.Equal(t, s.cert, got)
}

func TestServesHTTPSAndRefusesOldTLS(t *testing.T) {
	s, err := New(Options{DataDir: t.TempDir()})
	require.NoError(t, err)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	srv.TLS = s.Config()
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(s.leaf)
	addr := srv.Listener.Addr().String()
	conn, err := dial(t, addr, &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	_, err = dial(t, addr, &tls.Config{RootCAs: pool, ServerName: "localhost", MaxVersion: tls.VersionTLS11}) //nolint:gosec // proves old TLS is refused
	require.Error(t, err)

	_, port, _ := net.SplitHostPort(addr)
	_, err = dial(t, "127.0.0.1:"+port, &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "localhost", MinVersion: tls.VersionTLS12})
	require.Error(t, err, "unpinned self-signed certificate must not verify against an empty trust store")
}

func TestOperatorCertificateWinsAndMustComeAsAPair(t *testing.T) {
	gen, err := New(Options{DataDir: t.TempDir()})
	require.NoError(t, err)
	// Reuse a generated pair as the "operator" certificate.
	src := t.TempDir()
	first, err := New(Options{DataDir: src})
	require.NoError(t, err)

	op, err := New(Options{
		DataDir:  t.TempDir(),
		CertFile: filepath.Join(src, certFile),
		KeyFile:  filepath.Join(src, keyFile),
	})
	require.NoError(t, err)
	assert.Equal(t, first.Fingerprint(), op.Fingerprint())
	assert.NotEqual(t, gen.Fingerprint(), op.Fingerprint())

	_, err = New(Options{DataDir: t.TempDir(), CertFile: filepath.Join(src, certFile)})
	require.Error(t, err, "certificate without key must be refused")

	_, err = New(Options{DataDir: t.TempDir(), CertFile: "/nonexistent.crt", KeyFile: "/nonexistent.key"})
	require.Error(t, err, "a configured but unreadable certificate must fail closed, not fall back to self-signed")
}
