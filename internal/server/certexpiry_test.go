package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/metrics"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

var errReadFailed = errors.New("database busy")

// writeACMECert stores a self-signed certificate where Caddy keeps ACME results.
func writeACMECert(t *testing.T, dataDir, host string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: notAfter.Add(-time.Hour), NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	dir := filepath.Join(dataDir, "certificates", "test-issuer", host)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, host+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
}

func expiryOf(snap []metrics.CertExpiry, site, host string) (time.Time, bool) {
	for _, e := range snap {
		if e.Site == site && e.Host == host {
			return e.NotAfter, true
		}
	}
	return time.Time{}, false
}

func noUploads(context.Context) (map[string]store.Certificate, error) { return nil, nil }

func TestCertExpiryCoversUploadedAndACMECertificates(t *testing.T) {
	dataDir := t.TempDir()
	acmeExp := time.Now().Add(40 * 24 * time.Hour).UTC().Truncate(time.Second)
	uploadedExp := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	writeACMECert(t, dataDir, "auto.example.test", acmeExp)

	uploads := func(context.Context) (map[string]store.Certificate, error) {
		return map[string]store.Certificate{
			"cert-1": {ID: "cert-1", Hosts: []string{"*.example.test"}, NotAfter: uploadedExp},
		}, nil
	}
	cfg := &fakeConfig{root: &config.Root{Sites: []config.Site{
		{ID: "auto", Hosts: []string{"auto.example.test", "*.acme.example.test"}, TLS: config.TLS{Mode: config.TLSACME}},
		{ID: "up", Hosts: []string{"up.example.test", "a.example.test", "other.test"}, TLS: config.TLS{Mode: config.TLSFile, CertID: "cert-1"}},
		{ID: "none", Hosts: []string{"none.example.test"}, TLS: config.TLS{Mode: config.TLSACME}},
	}}}
	w := newCertExpiryWatch(cfg, uploads, dataDir, discard())
	w.refresh(t.Context())
	snap := w.Snapshot()

	got, ok := expiryOf(snap, "auto", "auto.example.test")
	require.True(t, ok)
	assert.True(t, got.Equal(acmeExp), "ACME expiry is read from the stored certificate")

	got, ok = expiryOf(snap, "up", "up.example.test")
	require.True(t, ok)
	assert.True(t, got.Equal(uploadedExp), "uploaded expiry comes from the store and may already be negative")

	_, ok = expiryOf(snap, "up", "other.test")
	assert.False(t, ok, "a host the certificate does not cover gets no series")
	_, ok = expiryOf(snap, "auto", "*.acme.example.test")
	assert.False(t, ok, "wildcard ACME hosts are skipped: their storage name is not the host")
	_, ok = expiryOf(snap, "none", "none.example.test")
	assert.False(t, ok, "no certificate on disk yet means no series")
}

func TestCertExpiryIsCachedBetweenRefreshes(t *testing.T) {
	dataDir := t.TempDir()
	first := time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	writeACMECert(t, dataDir, "shop.example.test", first)
	cfg := &fakeConfig{root: &config.Root{Sites: []config.Site{
		{ID: "shop", Hosts: []string{"shop.example.test"}, TLS: config.TLS{Mode: config.TLSACME}},
	}}}
	w := newCertExpiryWatch(cfg, noUploads, dataDir, discard())
	w.refresh(t.Context())

	writeACMECert(t, dataDir, "shop.example.test", first.Add(time.Hour*24*90))
	got, _ := expiryOf(w.Snapshot(), "shop", "shop.example.test")
	assert.True(t, got.Equal(first), "scrapes read the snapshot, not the disk")

	w.refresh(t.Context())
	got, _ = expiryOf(w.Snapshot(), "shop", "shop.example.test")
	assert.False(t, got.Equal(first), "the next refresh picks up the renewed certificate")
}

func TestCertExpiryKeepsTheLastSnapshotWhenUploadsCannotBeListed(t *testing.T) {
	cfg := &fakeConfig{root: &config.Root{Sites: []config.Site{
		{ID: "up", Hosts: []string{"up.example.test"}, TLS: config.TLS{Mode: config.TLSFile, CertID: "cert-1"}},
	}}}
	fail := false
	uploads := func(context.Context) (map[string]store.Certificate, error) {
		if fail {
			return nil, errReadFailed
		}
		return map[string]store.Certificate{"cert-1": {ID: "cert-1", Hosts: []string{"up.example.test"}, NotAfter: time.Now().Add(time.Hour)}}, nil
	}
	w := newCertExpiryWatch(cfg, uploads, t.TempDir(), discard())
	w.refresh(t.Context())
	fail = true
	w.refresh(t.Context())
	_, ok := expiryOf(w.Snapshot(), "up", "up.example.test")
	assert.True(t, ok)
}

func TestWildcardCoversOnlyOneLabel(t *testing.T) {
	assert.True(t, wildcardCovers([]string{"*.example.test"}, "a.example.test"))
	assert.False(t, wildcardCovers([]string{"*.example.test"}, "a.b.example.test"))
	assert.False(t, wildcardCovers([]string{"*.example.test"}, "example.test"))
}

func TestCertExpiryBeforeAnyConfigurationReportsNothing(t *testing.T) {
	w := newCertExpiryWatch(&fakeConfig{err: configsvc.ErrNotFound}, noUploads, t.TempDir(), discard())
	w.refresh(t.Context())
	assert.Empty(t, w.Snapshot())
}
