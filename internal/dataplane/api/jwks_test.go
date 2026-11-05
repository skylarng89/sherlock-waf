package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/netx"
)

func ecJWK(kid string, k *ecdsa.PublicKey) map[string]string {
	point, err := k.Bytes() // 0x04 || X || Y
	if err != nil {
		panic(err)
	}
	return map[string]string{
		"kty": "EC", "crv": "P-256", "kid": kid,
		"x": base64.RawURLEncoding.EncodeToString(point[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(point[33:]),
	}
}

func TestParseJWKSSkipsUnusableKeys(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	weak, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately weak: the parser must skip it
	require.NoError(t, err)
	bad := ecJWK("off-curve", &ec.PublicKey)
	bad["y"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	set, _ := json.Marshal(map[string]any{"keys": []any{
		ecJWK("good", &ec.PublicKey),
		bad,
		map[string]string{"kty": "oct", "k": "AAAA", "kid": "secret"},
		map[string]string{"kty": "EC", "use": "enc", "crv": "P-256", "kid": "enc"},
		map[string]string{
			"kty": "RSA", "kid": "weak",
			"n": base64.RawURLEncoding.EncodeToString(weak.N.Bytes()), "e": "AQAB",
		},
	}})
	keys, err := ParseJWKS(set)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "good", keys[0].ID)

	_, err = ParseJWKS([]byte(`{"keys":[]}`))
	assert.Error(t, err)
	_, err = ParseJWKS([]byte(`nope`))
	assert.Error(t, err)
}

func TestParsePublicKeyPEM(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	require.NoError(t, err)
	k, err := ParsePublicKeyPEM(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	require.NoError(t, err)
	assert.NotNil(t, k.Public)
	_, err = ParsePublicKeyPEM("not pem")
	assert.Error(t, err)
}

func TestJWKSRefusesInternalAddresses(t *testing.T) {
	// The default client is the one production uses: it must refuse loopback
	// and the cloud metadata address (acceptance criterion 4, threat T13).
	m := &JWKSManager{sources: map[string]*JWKSSource{}, Client: netx.NewClient(netx.Options{Timeout: 2 * time.Second})}
	for _, u := range []string{"https://169.254.169.254/latest/meta-data/", "https://127.0.0.1/jwks.json", "https://[::1]/jwks.json", "https://10.0.0.5/jwks.json"} {
		s := &JWKSSource{url: u, client: m.Client}
		err := s.fetch(t.Context())
		require.Error(t, err, u)
		assert.ErrorIs(t, err, netx.ErrBlockedAddress, u)
	}
}

func TestJWKSFetchRefreshAndRotation(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var rotated, hits atomic.Bool
	var fetches atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		hits.Store(true)
		keys := []any{ecJWK("k1", &k1.PublicKey)}
		if rotated.Load() {
			keys = []any{ecJWK("k2", &k2.PublicKey)}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	defer srv.Close()

	m := &JWKSManager{sources: map[string]*JWKSSource{}, Client: srv.Client()}
	src := m.Acquire(srv.URL, time.Hour)
	require.Eventually(t, src.Ready, 5*time.Second, 10*time.Millisecond)
	assert.Len(t, src.Keys("k1"), 1)

	// The provider rotates; a token with the new kid triggers an early refetch.
	rotated.Store(true)
	assert.Empty(t, src.Keys("k2"), "unknown kid is a miss on the request path, never a fetch")
	require.Eventually(t, func() bool { return len(src.Keys("k2")) == 1 }, 5*time.Second, 20*time.Millisecond)
	assert.Empty(t, src.Keys("k1"), "the retired key is gone")

	// A second acquire shares the fetcher; the last release stops it.
	assert.Same(t, src, m.Acquire(srv.URL, time.Hour))
	m.Release(srv.URL)
	m.Release(srv.URL)
	assert.Empty(t, m.sources)
	before := fetches.Load()
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, before, fetches.Load())
}

func TestJWKSKeepsKeysWhenRefreshFails(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var fail atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{ecJWK("k1", &k1.PublicKey)}})
	}))
	defer srv.Close()
	s := &JWKSSource{url: srv.URL, client: srv.Client()}
	require.NoError(t, s.fetch(t.Context()))
	fail.Store(true)
	require.Error(t, s.fetch(t.Context()))
	assert.Len(t, s.Keys("k1"), 1, "a failed refresh must not empty the key set")
}
