package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dpapi "github.com/skylarng89/sherlock-waf/internal/dataplane/api"
)

// jwksHost is a name that passes config validation (no loopback or private
// literal) but resolves to the test listener through the swapped JWKS client.
const jwksHost = "jwks.example.test"

const jwksConfig = `
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
      api:
        enabled: true
        jwt:
          - match: { paths: ["/payments"] }
            jwks_url: https://jwks.example.test/.well-known/jwks.json
            issuer: https://auth.bank.test/
            audiences: [open-banking]
`

// jwksServer serves a mutable key set over TLS and can be made to fail, which
// is how the live tests model key rotation and an identity provider outage.
type jwksServer struct {
	keys  atomic.Pointer[[]byte]
	fail  atomic.Bool
	hits  atomic.Int32
	inner *httptest.Server
}

// jwkEntry is one key in a served set, published under its kid.
type jwkEntry struct {
	kid string
	pub *ecdsa.PublicKey
}

func newJWKSServer(t *testing.T, keys ...jwkEntry) (*jwksServer, *x509.CertPool) {
	t.Helper()
	ca := newTestCA(t, "Sherlock test identity provider")
	leaf := ca.issue(t, "jwks", []string{jwksHost}, x509.ExtKeyUsageServerAuth)
	s := &jwksServer{}
	s.setKeys(t, keys...)
	s.inner = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		if s.fail.Load() {
			http.Error(w, "identity provider unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(*s.keys.Load())
	}))
	s.inner.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12} //nolint:gosec // test listener
	s.inner.StartTLS()
	t.Cleanup(s.inner.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return s, pool
}

// setKeys replaces the served key set.
func (s *jwksServer) setKeys(t *testing.T, keys ...jwkEntry) {
	t.Helper()
	set := struct {
		Keys []map[string]string `json:"keys"`
	}{}
	for _, k := range keys {
		point, err := k.pub.Bytes()
		require.NoError(t, err)
		set.Keys = append(set.Keys, map[string]string{
			"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": k.kid,
			"x": base64.RawURLEncoding.EncodeToString(point[1:33]),
			"y": base64.RawURLEncoding.EncodeToString(point[33:]),
		})
	}
	b, err := json.Marshal(set)
	require.NoError(t, err)
	s.keys.Store(&b)
}

// useJWKSServer routes jwksHost to the test listener for the rest of the test.
// The package-level client is restored after the app has stopped, because the
// cleanups run in reverse order of registration.
func useJWKSServer(t *testing.T, s *jwksServer, roots *x509.CertPool) {
	t.Helper()
	addr := s.inner.Listener.Addr().String()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, //nolint:gosec // MinVersion 1.2 is the product floor
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil || host != jwksHost {
				return nil, fmt.Errorf("unexpected JWKS dial to %q", address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	saved := dpapi.JWKS.Client
	dpapi.JWKS.Client = &http.Client{Transport: tr, Timeout: 10 * time.Second}
	t.Cleanup(func() { dpapi.JWKS.Client = saved })
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := b64json(map[string]any{"alg": "ES256", "typ": "JWT", "kid": kid})
	signed := header + "." + b64json(claims)
	d := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	require.NoError(t, err)
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jwksClaims() map[string]any {
	return map[string]any{"iss": "https://auth.bank.test/", "aud": "open-banking", "client_id": "tpp-1", "exp": time.Now().Add(time.Hour).Unix()}
}

func getWithToken(t *testing.T, port int, tok string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/payments", port), nil)
	require.NoError(t, err)
	req.Host = "bank.localhost"
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

// TestAPIJWKSLiveValidatesTokens checks that a token signed by a key from the
// remote JWKS passes, and that one with a wrong issuer or an unknown signer does not.
func TestAPIJWKSLiveValidatesTokens(t *testing.T) {
	signer, other := newP256(t), newP256(t)
	srv, roots := newJWKSServer(t, jwkEntry{"kid-0", &signer.PublicKey})
	useJWKSServer(t, srv, roots)
	port := launch(t, fmt.Sprintf(jwksConfig, upstreamServer(t)))

	good := signES256(t, signer, "kid-0", jwksClaims())
	require.Eventually(t, func() bool { return getWithToken(t, port, good) == http.StatusOK }, 20*time.Second, 50*time.Millisecond)

	wrongIssuer := jwksClaims()
	wrongIssuer["iss"] = "https://evil.test/"
	assert.Equal(t, http.StatusUnauthorized, getWithToken(t, port, signES256(t, signer, "kid-0", wrongIssuer)), "wrong issuer")
	assert.Equal(t, http.StatusUnauthorized, getWithToken(t, port, signES256(t, other, "kid-0", jwksClaims())), "signature from a key not in the set")
}

// TestAPIJWKSLiveRefetchesOnUnknownKid rotates the key set and expects a token
// signed by the new key to pass well before the 15 minute refresh interval.
// Only the early refetch triggered by the unknown kid can make that happen.
func TestAPIJWKSLiveRefetchesOnUnknownKid(t *testing.T) {
	oldKey, newKey := newP256(t), newP256(t)
	srv, roots := newJWKSServer(t, jwkEntry{"kid-old", &oldKey.PublicKey})
	useJWKSServer(t, srv, roots)
	port := launch(t, fmt.Sprintf(jwksConfig, upstreamServer(t)))

	require.Eventually(t, func() bool {
		return getWithToken(t, port, signES256(t, oldKey, "kid-old", jwksClaims())) == http.StatusOK
	}, 20*time.Second, 50*time.Millisecond)

	// Rotation publishes the new key under a new kid, as real identity providers do.
	srv.setKeys(t, jwkEntry{"kid-new", &newKey.PublicKey})
	before := srv.hits.Load()
	fresh := signES256(t, newKey, "kid-new", jwksClaims())
	require.Eventually(t, func() bool { return getWithToken(t, port, fresh) == http.StatusOK }, 15*time.Second, 50*time.Millisecond)
	assert.Greater(t, srv.hits.Load(), before, "the new key must come from a refetch")
}

// TestAPIJWKSLiveOutageKeepsOldKeys makes the identity provider fail. A token
// with an unknown kid triggers a refetch that fails, and tokens signed by the
// last good key must keep passing.
func TestAPIJWKSLiveOutageKeepsOldKeys(t *testing.T) {
	oldKey, unknownKey := newP256(t), newP256(t)
	srv, roots := newJWKSServer(t, jwkEntry{"kid-old", &oldKey.PublicKey})
	useJWKSServer(t, srv, roots)
	port := launch(t, fmt.Sprintf(jwksConfig, upstreamServer(t)))

	known := signES256(t, oldKey, "kid-old", jwksClaims())
	require.Eventually(t, func() bool { return getWithToken(t, port, known) == http.StatusOK }, 20*time.Second, 50*time.Millisecond)

	srv.fail.Store(true)
	before := srv.hits.Load()
	unknown := signES256(t, unknownKey, "kid-rotated", jwksClaims())
	assert.Equal(t, http.StatusUnauthorized, getWithToken(t, port, unknown), "an unknown kid is refused")
	require.Eventually(t, func() bool { return srv.hits.Load() > before }, 10*time.Second, 10*time.Millisecond, "the failing refetch must have been attempted")

	assert.Equal(t, http.StatusOK, getWithToken(t, port, known), "old keys survive a failed refresh")
}
