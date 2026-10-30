package api

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testNow = time.Unix(1_800_000_000, 0)

func enc(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sign(t *testing.T, alg, kid string, claims map[string]any, signer func(signed []byte) []byte) string {
	t.Helper()
	h := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		h["kid"] = kid
	}
	signed := enc(h) + "." + enc(claims)
	return signed + "." + base64.RawURLEncoding.EncodeToString(signer([]byte(signed)))
}

func validClaims() map[string]any {
	return map[string]any{
		"iss": "https://auth.example.com/", "aud": []string{"shop-api"}, "sub": "u1", "client_id": "app-7",
		"exp": testNow.Add(time.Hour).Unix(), "nbf": testNow.Add(-time.Minute).Unix(),
	}
}

func rsaSigner(t *testing.T, key *rsa.PrivateKey, pss bool) func([]byte) []byte {
	return func(b []byte) []byte {
		d := sha256.Sum256(b)
		var sig []byte
		var err error
		if pss {
			sig, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
		}
		require.NoError(t, err)
		return sig
	}
}

func ecSigner(t *testing.T, key *ecdsa.PrivateKey) func([]byte) []byte {
	return func(b []byte) []byte {
		d := sha256.Sum256(b)
		r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
		require.NoError(t, err)
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}
}

func hmacSigner(secret []byte) func([]byte) []byte {
	return func(b []byte) []byte {
		m := hmac.New(sha256.New, secret)
		m.Write(b)
		return m.Sum(nil)
	}
}

func newVerifier(keys ...Key) *Verifier {
	return &Verifier{
		Keys: StaticKeys(keys), Issuer: "https://auth.example.com/", Audiences: []string{"shop-api"},
		Skew: 30 * time.Second, Now: func() time.Time { return testNow },
	}
}

func TestVerifyAcceptsEveryAllowedAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	v := newVerifier(Key{ID: "r", Public: &rsaKey.PublicKey}, Key{ID: "e", Public: &ecKey.PublicKey}, Key{ID: "d", Public: edPub})

	tests := []struct {
		name string
		tok  string
	}{
		{"RS256", sign(t, "RS256", "r", validClaims(), rsaSigner(t, rsaKey, false))},
		{"PS256", sign(t, "PS256", "r", validClaims(), rsaSigner(t, rsaKey, true))},
		{"ES256", sign(t, "ES256", "e", validClaims(), ecSigner(t, ecKey))},
		{"EdDSA", sign(t, "EdDSA", "d", validClaims(), func(b []byte) []byte { return ed25519.Sign(edKey, b) })},
		{"aud as string", sign(t, "ES256", "e", func() map[string]any { c := validClaims(); c["aud"] = "shop-api"; return c }(), ecSigner(t, ecKey))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := v.Verify(tt.tok)
			require.NoError(t, err)
			got, ok := c.Claim("client_id")
			assert.True(t, ok)
			assert.Equal(t, "app-7", got)
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	v := newVerifier(Key{ID: "r", Public: &rsaKey.PublicKey}, Key{ID: "e", Public: &ecKey.PublicKey})
	good := func(mut func(map[string]any)) string {
		c := validClaims()
		mut(c)
		return sign(t, "RS256", "r", c, rsaSigner(t, rsaKey, false))
	}

	// "none" token, and an HS256 token signed with the PEM-less public modulus as
	// a secret: both must fail even though the structure is perfect.
	noneTok := enc(map[string]any{"alg": "none"}) + "." + enc(validClaims()) + "."
	noneTok2 := enc(map[string]any{"alg": "none"}) + "." + enc(validClaims()) + ".AAAA"
	confusion := sign(t, "HS256", "r", validClaims(), hmacSigner(rsaKey.N.Bytes()))

	tests := []struct {
		name string
		tok  string
		want error
	}{
		{"alg none, empty signature", noneTok, ErrAlgorithm},
		{"alg none, junk signature", noneTok2, ErrAlgorithm},
		{"alg confusion HS256 with a public key", confusion, ErrAlgorithm},
		{"alg None mixed case", enc(map[string]any{"alg": "None"}) + "." + enc(validClaims()) + ".AAAA", ErrAlgorithm},
		{"wrong signature", sign(t, "RS256", "r", validClaims(), rsaSigner(t, other, false)), ErrSignature},
		{"expired", good(func(c map[string]any) { c["exp"] = testNow.Add(-time.Hour).Unix() }), ErrExpired},
		{"expired within skew is fine; beyond is not", good(func(c map[string]any) { c["exp"] = testNow.Add(-31 * time.Second).Unix() }), ErrExpired},
		{"not yet valid", good(func(c map[string]any) { c["nbf"] = testNow.Add(time.Hour).Unix() }), ErrNotYet},
		{"no exp", good(func(c map[string]any) { delete(c, "exp") }), ErrMissingExp},
		{"exp as string", good(func(c map[string]any) { c["exp"] = "9999999999" }), ErrMissingExp},
		{"wrong audience", good(func(c map[string]any) { c["aud"] = []string{"other-api"} }), ErrAudience},
		{"no audience", good(func(c map[string]any) { delete(c, "aud") }), ErrAudience},
		{"wrong issuer", good(func(c map[string]any) { c["iss"] = "https://evil.example/" }), ErrIssuer},
		{"unknown kid", sign(t, "RS256", "zzz", validClaims(), rsaSigner(t, rsaKey, false)), ErrNoKey},
		{"RSA alg with EC key", sign(t, "RS256", "e", validClaims(), rsaSigner(t, rsaKey, false)), ErrSignature},
		{"crit header", func() string {
			s := enc(map[string]any{"alg": "RS256", "kid": "r", "crit": []string{"x"}}) + "." + enc(validClaims())
			return s + "." + base64.RawURLEncoding.EncodeToString([]byte("x"))
		}(), ErrMalformed},
		{"two segments", "a.b", ErrMalformed},
		{"four segments", "a.b.c.d", ErrMalformed},
		{"empty", "", ErrMalformed},
		{"oversize", strings.Repeat("a", maxTokenBytes+1), ErrMalformed},
		{"bad base64 header", "!!!." + enc(validClaims()) + ".AAAA", ErrMalformed},
		{"payload not an object", func() string {
			s := enc(map[string]any{"alg": "RS256", "kid": "r"}) + "." + base64.RawURLEncoding.EncodeToString([]byte("[1]"))
			return s + "." + base64.RawURLEncoding.EncodeToString(rsaSigner(t, rsaKey, false)([]byte(s)))
		}(), ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Verify(tt.tok)
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestSkewAllowsSlightlyExpiredTokens(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	v := newVerifier(Key{Public: &ecKey.PublicKey})
	c := validClaims()
	c["exp"] = testNow.Add(-10 * time.Second).Unix()
	_, err = v.Verify(sign(t, "ES256", "", c, ecSigner(t, ecKey)))
	assert.NoError(t, err, "10s past exp, 30s skew")
}

func TestHMACOnlyWithConfiguredSecret(t *testing.T) {
	secret := []byte(strings.Repeat("s3cret", 8))
	tok := sign(t, "HS256", "", validClaims(), hmacSigner(secret))

	v := newVerifier(Key{Secret: secret})
	_, err := v.Verify(tok)
	assert.ErrorIs(t, err, ErrAlgorithm, "HS* is refused unless the rule opted in")

	v.AllowHMAC = true
	_, err = v.Verify(tok)
	assert.NoError(t, err)

	_, err = v.Verify(sign(t, "HS256", "", validClaims(), hmacSigner([]byte("wrong"))))
	assert.ErrorIs(t, err, ErrSignature)

	// An RSA-only key set never verifies an HS token, even with HMAC allowed.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	v2 := newVerifier(Key{Public: &rsaKey.PublicKey})
	v2.AllowHMAC = true
	_, err = v2.Verify(sign(t, "HS256", "", validClaims(), hmacSigner(rsaKey.N.Bytes())))
	assert.ErrorIs(t, err, ErrSignature)
}

func TestECDSACurveMustMatchAlgorithm(t *testing.T) {
	k384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	v := newVerifier(Key{Public: &k384.PublicKey})
	// ES256 signature size (64) against a P-384 key.
	tok := sign(t, "ES256", "", validClaims(), func([]byte) []byte { return make([]byte, 64) })
	_, err = v.Verify(tok)
	assert.ErrorIs(t, err, ErrSignature)
}

func TestClaimKeys(t *testing.T) {
	c := Claims{"s": "abc", "n": json.Number("42"), "o": map[string]any{"a": 1}, "long": strings.Repeat("x", 300), "empty": ""}
	for name, want := range map[string]string{"s": "abc", "n": "42"} {
		got, ok := c.Claim(name)
		assert.True(t, ok)
		assert.Equal(t, want, got)
	}
	for _, name := range []string{"o", "long", "empty", "missing"} {
		_, ok := c.Claim(name)
		assert.False(t, ok, name)
	}
}

func FuzzVerify(f *testing.F) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := newVerifier(Key{Public: &ecKey.PublicKey})
	v.AllowHMAC = true
	seed := func(h, p string) string { return enc(map[string]any{"alg": h}) + "." + p + ".AAAA" }
	f.Add("a.b.c")
	f.Add(seed("ES256", enc(validClaims())))
	f.Add(seed("none", enc(validClaims())))
	f.Add(seed("HS256", "e30"))
	f.Add("..")
	f.Add(strings.Repeat(".", 50))
	f.Fuzz(func(t *testing.T, tok string) {
		c, err := v.Verify(tok)
		if err == nil {
			// The only way through is a signature made by the key, which a
			// fuzzer cannot produce; a pass means the parser is broken.
			t.Fatalf("accepted forged token %q (claims %v)", tok, c)
		}
	})
}
