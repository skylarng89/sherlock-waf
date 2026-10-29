// Package certstore validates uploaded certificates, keeps their private keys
// in the encrypted secret store and materialises them as PEM files for Caddy.
package certstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/ids"
	"github.com/skylarng89/sherlock-waf/internal/secrets"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

const (
	// KeyPurpose is the secret purpose private keys are sealed under.
	KeyPurpose = "certificate_key"
	maxChain   = 10
	minRSABits = 2048
)

// ErrInvalid wraps every problem with an uploaded certificate or key, so the
// API can answer 400 with the reason.
var ErrInvalid = errors.New("invalid certificate")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Parsed is what Parse learned from an upload.
type Parsed struct {
	Hosts       []string
	NotBefore   time.Time
	NotAfter    time.Time
	Issuer      string
	Fingerprint string
	ChainPEM    string
	KeyPEM      []byte // PKCS#8, re-encoded so only one format is stored
}

// Parse validates a PEM certificate chain and its private key. It rejects an
// encrypted or mismatched key, weak keys, an expired or not-yet-valid leaf, and
// a leaf with no DNS names. now is the validation time.
func Parse(certPEM, keyPEM string, now time.Time) (Parsed, error) {
	var chain []*x509.Certificate
	var chainOut strings.Builder
	rest := []byte(certPEM)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return Parsed{}, invalid("unexpected %q block in the certificate chain", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return Parsed{}, invalid("unreadable certificate: %v", err)
		}
		chain = append(chain, c)
		if len(chain) > maxChain {
			return Parsed{}, invalid("more than %d certificates in the chain", maxChain)
		}
		if err := pem.Encode(&chainOut, blk); err != nil {
			return Parsed{}, fmt.Errorf("re-encoding certificate: %w", err)
		}
	}
	if len(chain) == 0 {
		return Parsed{}, invalid("no PEM certificate found")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return Parsed{}, invalid("unexpected data after the last certificate")
	}
	leaf := chain[0]
	if leaf.IsCA {
		return Parsed{}, invalid("the first certificate is a CA; put the server certificate first")
	}
	if now.Before(leaf.NotBefore) {
		return Parsed{}, invalid("the certificate is not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return Parsed{}, invalid("the certificate expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if len(leaf.DNSNames) == 0 {
		return Parsed{}, invalid("the certificate has no DNS names (subject alternative names)")
	}

	kb, _ := pem.Decode([]byte(keyPEM))
	if kb == nil {
		return Parsed{}, invalid("no PEM private key found")
	}
	if strings.Contains(kb.Type, "ENCRYPTED") || x509.IsEncryptedPEMBlock(kb) { //nolint:staticcheck // detection only; nothing is decrypted
		return Parsed{}, invalid("the private key is passphrase-protected; upload an unencrypted key")
	}
	key, err := parseKey(kb)
	if err != nil {
		return Parsed{}, err
	}
	if err := checkStrength(key); err != nil {
		return Parsed{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Parsed{}, fmt.Errorf("re-encoding private key: %w", err)
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if _, err := tls.X509KeyPair([]byte(chainOut.String()), keyOut); err != nil {
		return Parsed{}, invalid("the private key does not match the certificate")
	}

	sum := sha256.Sum256(leaf.Raw)
	hosts := slices.Clone(leaf.DNSNames)
	slices.Sort(hosts)
	return Parsed{
		Hosts: hosts, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Issuer: leaf.Issuer.String(),
		Fingerprint: hex.EncodeToString(sum[:]), ChainPEM: chainOut.String(), KeyPEM: keyOut,
	}, nil
}

func parseKey(b *pem.Block) (any, error) {
	switch b.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			return nil, invalid("unreadable private key: %v", err)
		}
		return k, nil
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
		if err != nil {
			return nil, invalid("unreadable private key: %v", err)
		}
		return k, nil
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(b.Bytes)
		if err != nil {
			return nil, invalid("unreadable private key: %v", err)
		}
		return k, nil
	}
	return nil, invalid("unsupported private key type %q", b.Type)
}

func checkStrength(key any) error {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < minRSABits {
			return invalid("RSA keys must be at least %d bits", minRSABits)
		}
	case *ecdsa.PrivateKey:
		if c := k.Curve; c != elliptic.P256() && c != elliptic.P384() && c != elliptic.P521() {
			return invalid("unsupported elliptic curve %s", c.Params().Name)
		}
	case ed25519.PrivateKey:
	default:
		return invalid("unsupported private key algorithm")
	}
	return nil
}

// Add validates and stores an upload. The key is sealed in the same
// transaction, so a certificate never exists without its key.
func Add(ctx context.Context, tx store.Tx, sec *secrets.Service, name, certPEM, keyPEM string, now time.Time) (store.Certificate, error) {
	p, err := Parse(certPEM, keyPEM, now)
	if err != nil {
		return store.Certificate{}, err
	}
	id, err := ids.New(now)
	if err != nil {
		return store.Certificate{}, err
	}
	keyID, err := sec.Seal(ctx, tx, KeyPurpose, p.KeyPEM)
	if err != nil {
		return store.Certificate{}, fmt.Errorf("sealing private key: %w", err)
	}
	c := store.Certificate{
		ID: id, Name: name, Hosts: p.Hosts, NotBefore: p.NotBefore, NotAfter: p.NotAfter, Issuer: p.Issuer,
		Fingerprint: p.Fingerprint, ChainPEM: p.ChainPEM, KeySecretID: keyID, CreatedAt: now.UTC().Truncate(time.Microsecond),
	}
	if err := tx.InsertCertificate(ctx, c); err != nil {
		return store.Certificate{}, err
	}
	return c, nil
}

// Remove deletes the certificate and its sealed key.
func Remove(ctx context.Context, tx store.Tx, id string) error {
	c, err := tx.GetCertificate(ctx, id)
	if err != nil {
		return err
	}
	if err := tx.DeleteCertificate(ctx, id); err != nil {
		return err
	}
	if err := tx.DeleteSecret(ctx, c.KeySecretID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// Files writes certificates to disk for Caddy, which loads them by path. The
// directory is private (0700) and the key files 0600; it sits next to node.key,
// which already guards every other secret on this node.
type Files struct {
	Store   store.Store
	Secrets *secrets.Service
	Dir     string
	Timeout time.Duration
}

// Paths materialises certificate id and returns its file paths. Files are
// rewritten only when their content changed, so a reload does not touch them.
func (f *Files) Paths(id string) (certFile, keyFile string, err error) {
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var chain string
	var key []byte
	err = f.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		c, err := tx.GetCertificate(ctx, id)
		if err != nil {
			return err
		}
		chain = c.ChainPEM
		key, err = f.Secrets.Open(ctx, tx, c.KeySecretID, KeyPurpose)
		return err
	})
	if err != nil {
		return "", "", fmt.Errorf("loading certificate: %w", err)
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return "", "", fmt.Errorf("creating certificate directory: %w", err)
	}
	root, err := os.OpenRoot(f.Dir)
	if err != nil {
		return "", "", fmt.Errorf("opening certificate directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	certName, keyName := safeName(id)+".crt", safeName(id)+".key"
	if err := writeIfChanged(root, certName, []byte(chain), 0o644); err != nil {
		return "", "", err
	}
	if err := writeIfChanged(root, keyName, key, 0o600); err != nil {
		return "", "", err
	}
	return filepath.Join(f.Dir, certName), filepath.Join(f.Dir, keyName), nil
}

// Delete removes the materialised files of id, if any.
func (f *Files) Delete(id string) {
	root, err := os.OpenRoot(f.Dir)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	_ = root.Remove(safeName(id) + ".crt")
	_ = root.Remove(safeName(id) + ".key")
}

// safeName keeps ids to filename-safe characters. Ids are ULIDs, but the value
// ultimately comes from a configuration document.
func safeName(id string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			return r
		}
		return '_'
	}, id)
}

func writeIfChanged(root *os.Root, name string, data []byte, mode os.FileMode) error {
	if cur, err := root.ReadFile(name); err == nil && string(cur) == string(data) {
		return nil
	}
	tmp := name + ".tmp"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("writing %s: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = root.Remove(tmp)
		return fmt.Errorf("writing %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("writing %s: %w", name, err)
	}
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("installing %s: %w", name, err)
	}
	return nil
}
