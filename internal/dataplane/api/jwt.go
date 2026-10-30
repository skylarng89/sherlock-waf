package api

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	_ "crypto/sha256" // register hashes for crypto.Hash.New
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

// maxTokenBytes bounds what the parser looks at: bearer tokens above this are
// not real, and decoding them would hand an attacker free CPU and memory.
const maxTokenBytes = 8 << 10

// Errors a verification can return. They are reasons for the event log, not
// for the client, which only learns "invalid token".
var (
	ErrMalformed   = errors.New("malformed token")
	ErrAlgorithm   = errors.New("algorithm not allowed")
	ErrSignature   = errors.New("signature verification failed")
	ErrNoKey       = errors.New("no matching key")
	ErrExpired     = errors.New("token expired")
	ErrNotYet      = errors.New("token not valid yet")
	ErrIssuer      = errors.New("issuer mismatch")
	ErrAudience    = errors.New("audience mismatch")
	ErrMissingExp  = errors.New("token has no exp claim")
	ErrKeyMismatch = errors.New("key type does not fit the algorithm")
)

// Key is one verification key: exactly one of Public or Secret is set.
// Secret is a shared HMAC secret and is only used for HS* tokens; Public is
// only used for RS*/PS*/ES*/EdDSA tokens, so a public key can never be abused
// as an HMAC secret (the classic algorithm-confusion attack).
type Key struct {
	ID     string
	Alg    string // optional pin from the JWKS entry
	Public crypto.PublicKey
	Secret []byte
}

// KeySource supplies candidate keys for a token header. It must be cheap and
// must not block: it runs on the request path.
type KeySource interface {
	Keys(kid string) []Key
}

// StaticKeys is a fixed set of keys.
type StaticKeys []Key

// Keys implements KeySource.
func (s StaticKeys) Keys(kid string) []Key { return matchKeys(s, kid) }

func matchKeys(keys []Key, kid string) []Key {
	if kid != "" {
		var out []Key
		for _, k := range keys {
			if k.ID == kid {
				out = append(out, k)
			}
		}
		return out
	}
	// No kid in the token: only an unambiguous key set may be used.
	if len(keys) <= maxTryKeys {
		return keys
	}
	return nil
}

const maxTryKeys = 4

// Claims are the verified payload of a token.
type Claims map[string]any

// Verifier checks tokens against one rule.
type Verifier struct {
	Keys      KeySource
	Issuer    string
	Audiences []string
	Skew      time.Duration
	Now       func() time.Time
	// AllowHMAC accepts HS256/384/512, only ever with Secret keys. It is false
	// unless the rule configured a static secret.
	AllowHMAC bool
}

type header struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Crit []string `json:"crit"`
}

var algHashes = map[string]crypto.Hash{
	"RS256": crypto.SHA256, "RS384": crypto.SHA384, "RS512": crypto.SHA512,
	"PS256": crypto.SHA256, "PS384": crypto.SHA384, "PS512": crypto.SHA512,
	"ES256": crypto.SHA256, "ES384": crypto.SHA384, "ES512": crypto.SHA512,
	"HS256": crypto.SHA256, "HS384": crypto.SHA384, "HS512": crypto.SHA512,
	"EdDSA": 0,
}

// Verify parses and verifies token and returns its claims.
func (v *Verifier) Verify(token string) (Claims, error) {
	if len(token) == 0 || len(token) > maxTokenBytes {
		return nil, fmt.Errorf("%w: size", ErrMalformed)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected three segments", ErrMalformed)
	}
	rawHdr, err := b64(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	var h header
	if err := json.Unmarshal(rawHdr, &h); err != nil {
		return nil, fmt.Errorf("%w: header json", ErrMalformed)
	}
	if len(h.Crit) > 0 {
		return nil, fmt.Errorf("%w: crit header is not supported", ErrMalformed)
	}
	hash, known := algHashes[h.Alg]
	if !known { // includes "none", "" and anything exotic
		return nil, fmt.Errorf("%w: %q", ErrAlgorithm, h.Alg)
	}
	hmacAlg := strings.HasPrefix(h.Alg, "HS")
	if hmacAlg && !v.AllowHMAC {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithm, h.Alg)
	}
	sig, err := b64(parts[2])
	if err != nil || len(sig) == 0 {
		return nil, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	signed := []byte(parts[0] + "." + parts[1])

	cands := v.Keys.Keys(h.Kid)
	if len(cands) == 0 {
		return nil, ErrNoKey
	}
	verified := false
	for _, k := range cands {
		if k.Alg != "" && k.Alg != h.Alg {
			continue
		}
		if verifySig(h.Alg, hash, k, signed, sig) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, ErrSignature
	}

	rawPayload, err := b64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(rawPayload))
	dec.UseNumber()
	var c Claims
	if err := dec.Decode(&c); err != nil || c == nil {
		return nil, fmt.Errorf("%w: payload json", ErrMalformed)
	}
	return c, v.check(c)
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func verifySig(alg string, hash crypto.Hash, k Key, signed, sig []byte) error {
	switch {
	case strings.HasPrefix(alg, "HS"):
		if len(k.Secret) == 0 {
			return ErrKeyMismatch
		}
		m := hmac.New(hash.New, k.Secret)
		m.Write(signed)
		if !hmac.Equal(m.Sum(nil), sig) {
			return ErrSignature
		}
		return nil
	case k.Public == nil:
		return ErrKeyMismatch
	}
	switch pub := k.Public.(type) {
	case *rsa.PublicKey:
		d := digest(hash, signed)
		switch alg[:2] {
		case "RS":
			return rsa.VerifyPKCS1v15(pub, hash, d, sig)
		case "PS":
			return rsa.VerifyPSS(pub, hash, d, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
	case *ecdsa.PublicKey:
		if alg[:2] != "ES" || !curveMatches(alg, pub.Curve) {
			return ErrKeyMismatch
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return ErrSignature
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(pub, digest(hash, signed), r, s) {
			return ErrSignature
		}
		return nil
	case ed25519.PublicKey:
		if alg != "EdDSA" || len(pub) != ed25519.PublicKeySize {
			return ErrKeyMismatch
		}
		if !ed25519.Verify(pub, signed, sig) {
			return ErrSignature
		}
		return nil
	}
	return ErrKeyMismatch
}

func digest(h crypto.Hash, b []byte) []byte {
	m := h.New()
	m.Write(b)
	return m.Sum(nil)
}

func curveMatches(alg string, c elliptic.Curve) bool {
	switch alg {
	case "ES256":
		return c == elliptic.P256()
	case "ES384":
		return c == elliptic.P384()
	case "ES512":
		return c == elliptic.P521()
	}
	return false
}

func (v *Verifier) check(c Claims) error {
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	t := now()
	exp, ok := numericDate(c["exp"])
	if !ok {
		return ErrMissingExp
	}
	if !t.Before(exp.Add(v.Skew)) {
		return ErrExpired
	}
	if raw, present := c["nbf"]; present {
		nbf, ok := numericDate(raw)
		if !ok {
			return fmt.Errorf("%w: nbf", ErrMalformed)
		}
		if t.Add(v.Skew).Before(nbf) {
			return ErrNotYet
		}
	}
	if v.Issuer != "" {
		if iss, _ := c["iss"].(string); iss != v.Issuer {
			return ErrIssuer
		}
	}
	if len(v.Audiences) > 0 && !audienceOK(c["aud"], v.Audiences) {
		return ErrAudience
	}
	return nil
}

func numericDate(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil || f < 0 || f > 1<<40 {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

func audienceOK(aud any, want []string) bool {
	switch a := aud.(type) {
	case string:
		return slices.Contains(want, a)
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && slices.Contains(want, s) {
				return true
			}
		}
	}
	return false
}

// Claim returns a claim as a short string for use as a rate-limit key: strings
// and numbers only, bounded in length. Structured claims have no stable key.
func (c Claims) Claim(name string) (string, bool) {
	switch v := c[name].(type) {
	case string:
		if v != "" && len(v) <= 256 {
			return v, true
		}
	case json.Number:
		return v.String(), true
	}
	return "", false
}
