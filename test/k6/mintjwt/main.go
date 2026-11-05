// Command mintjwt prepares the API benchmark's JWT material: an ES256 key pair
// (created once in -dir) and one long-lived access token printed to stdout.
// The public key goes into the site's policy.api.jwt[].public_key_pem.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dir := flag.String("dir", "", "directory holding key.pem and pub.pem (created if missing)")
	issuer := flag.String("issuer", "https://auth.bench.test/", "iss claim")
	audience := flag.String("audience", "payments-bench", "aud claim")
	client := flag.String("client", "bench-tpp", "client_id claim")
	ttl := flag.Duration("ttl", 4*time.Hour, "token lifetime")
	flag.Parse()
	if *dir == "" {
		log.Fatal("mintjwt: -dir is required")
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		log.Fatalf("mintjwt: %v", err)
	}
	key, err := loadOrCreateKey(*dir)
	if err != nil {
		log.Fatalf("mintjwt: %v", err)
	}
	tok, err := sign(key, map[string]any{"alg": "ES256", "typ": "JWT"}, map[string]any{
		"iss": *issuer, "aud": *audience, "sub": *client, "client_id": *client,
		"iat": time.Now().Unix(), "exp": time.Now().Add(*ttl).Unix(),
	})
	if err != nil {
		log.Fatalf("mintjwt: %v", err)
	}
	fmt.Println(tok)
}

// loadOrCreateKey reuses an existing key so repeated runs against one data
// directory keep working; the public key is rewritten next to it either way.
func loadOrCreateKey(dir string) (*ecdsa.PrivateKey, error) {
	privPath := filepath.Join(dir, "key.pem")
	pubPath := filepath.Join(dir, "pub.pem")
	if raw, err := os.ReadFile(privPath); err == nil { //nolint:gosec // benchmark scratch directory
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("%s: not PEM", privPath)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func sign(key *ecdsa.PrivateKey, header, claims map[string]any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
