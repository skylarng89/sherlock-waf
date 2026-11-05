// Package tlscert provides the control-plane listener's TLS identity: an
// operator-supplied certificate when configured, otherwise a self-signed
// ECDSA P-256 certificate that is generated on first start and renewed before
// it expires. The certificate is configured from the environment, never from
// the database, so a bad database state cannot lock operators out.
package tlscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// EnvCert names an operator-supplied PEM certificate.
	EnvCert = "SHERLOCK_ADMIN_TLS_CERT"
	// EnvKey names the matching PEM private key.
	EnvKey = "SHERLOCK_ADMIN_TLS_KEY"

	validity    = 365 * 24 * time.Hour
	renewWindow = 30 * 24 * time.Hour

	certFile = "admin-tls.crt"
	keyFile  = "admin-tls.key"
)

// Options configures a Source.
type Options struct {
	DataDir string
	// CertFile and KeyFile, when both set, replace the self-signed identity.
	CertFile, KeyFile string
	// Hostnames are extra SANs; localhost, 127.0.0.1 and ::1 are always added.
	Hostnames []string
	Logger    *slog.Logger
	Now       func() time.Time
}

// Source serves the current certificate and swaps it on renewal.
type Source struct {
	opts Options

	mu   sync.RWMutex
	cert *tls.Certificate
	leaf *x509.Certificate
}

// New loads or creates the certificate.
func New(opts Options) (*Source, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if (opts.CertFile == "") != (opts.KeyFile == "") {
		return nil, errors.New("tlscert: certificate and key must be set together")
	}
	s := &Source{opts: opts}
	if err := s.refresh(); err != nil {
		return nil, err
	}
	return s, nil
}

// FromEnv builds Options fields from the environment.
func FromEnv(o Options) Options {
	o.CertFile, o.KeyFile = os.Getenv(EnvCert), os.Getenv(EnvKey)
	return o
}

// Config returns a TLS config that always presents the current certificate.
func (s *Source) Config() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			return s.cert, nil
		},
	}
}

// Fingerprint is the hex SHA-256 of the certificate's public key info, the
// value operators pin or compare when trusting a self-signed identity.
func (s *Source) Fingerprint() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return spki(s.leaf)
}

// NotAfter is the current certificate's expiry.
func (s *Source) NotAfter() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.leaf.NotAfter
}

// Run renews a self-signed certificate inside the renewal window. It returns
// when ctx ends. An operator-supplied certificate is re-read on each tick so
// that rotation on disk takes effect without a restart.
func (s *Source) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.refresh(); err != nil {
				s.opts.Logger.Error("admin tls refresh failed", "error", err)
			}
		}
	}
}

func (s *Source) refresh() error {
	if s.opts.CertFile != "" {
		return s.loadOperator()
	}
	return s.loadOrGenerate()
}

func (s *Source) loadOperator() error {
	pair, err := tls.LoadX509KeyPair(s.opts.CertFile, s.opts.KeyFile)
	if err != nil {
		return fmt.Errorf("tlscert: load operator certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("tlscert: parse operator certificate: %w", err)
	}
	s.set(&pair, leaf)
	return nil
}

func (s *Source) loadOrGenerate() error {
	certPath := filepath.Join(s.opts.DataDir, certFile)
	keyPath := filepath.Join(s.opts.DataDir, keyFile)
	if pair, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, perr := x509.ParseCertificate(pair.Certificate[0]); perr == nil && s.usable(leaf) {
			s.set(&pair, leaf)
			return nil
		}
	}
	return s.generate(certPath, keyPath)
}

// usable reports whether an existing self-signed certificate can stay: outside
// the renewal window and covering every wanted name.
func (s *Source) usable(leaf *x509.Certificate) bool {
	now := s.opts.Now()
	if now.Before(leaf.NotBefore) || now.Add(renewWindow).After(leaf.NotAfter) {
		return false
	}
	for _, name := range s.names() {
		if ip := net.ParseIP(name); ip != nil {
			if leaf.VerifyHostname(ip.String()) != nil {
				return false
			}
		} else if leaf.VerifyHostname(name) != nil {
			return false
		}
	}
	return true
}

func (s *Source) names() []string {
	names := []string{"localhost", "127.0.0.1", "::1"}
	if h, err := os.Hostname(); err == nil && h != "" {
		names = append(names, h)
	}
	return append(names, s.opts.Hostnames...)
}

func (s *Source) generate(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("tlscert: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return fmt.Errorf("tlscert: serial: %w", err)
	}
	now := s.opts.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Sherlock WAF control plane"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, n := range s.names() {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("tlscert: sign: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("tlscert: marshal key: %w", err)
	}
	if err := os.MkdirAll(s.opts.DataDir, 0o700); err != nil {
		return fmt.Errorf("tlscert: data dir: %w", err)
	}
	// Key first: a certificate without its key is useless, the reverse is
	// merely replaced on the next start.
	if err := writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := writeAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("tlscert: parse generated certificate: %w", err)
	}
	s.set(&tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf)
	s.opts.Logger.Info("generated self-signed admin certificate",
		"spki_sha256", spki(leaf), "not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

func (s *Source) set(c *tls.Certificate, leaf *x509.Certificate) {
	s.mu.Lock()
	changed := s.leaf == nil || spki(s.leaf) != spki(leaf)
	s.cert, s.leaf = c, leaf
	s.mu.Unlock()
	if changed {
		s.opts.Logger.Info("admin tls certificate active", "spki_sha256", spki(leaf))
	}
}

func spki(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("tlscert: write %s: %w", filepath.Base(path), err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("tlscert: chmod %s: %w", filepath.Base(path), err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("tlscert: write %s: %w", filepath.Base(path), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("tlscert: close %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("tlscert: install %s: %w", filepath.Base(path), err)
	}
	return nil
}
