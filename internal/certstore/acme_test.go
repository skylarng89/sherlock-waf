package certstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeACMECert(t *testing.T, dataDir, issuer, host string, notAfter time.Time) {
	t.Helper()
	iss := issue(t, spec{dns: []string{host}, notAfter: notAfter})
	dir := filepath.Join(dataDir, "certificates", issuer, host)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, host+".crt"), []byte(iss.certPEM), 0o600))
}

func TestACMEExpiryReadsTheCertificateCaddyStored(t *testing.T) {
	dataDir := t.TempDir()
	want := now.Add(30 * 24 * time.Hour)
	writeACMECert(t, dataDir, "acme-v02.api.letsencrypt.org-directory", "shop.example.test", want)

	got, ok := ACMEExpiry(dataDir, "shop.example.test")
	require.True(t, ok)
	assert.True(t, got.Equal(want), "got %s want %s", got, want)
}

func TestACMEExpiryPrefersTheLatestCopyAndReportsExpiredCertificates(t *testing.T) {
	dataDir := t.TempDir()
	writeACMECert(t, dataDir, "old-issuer", "shop.example.test", now.Add(-48*time.Hour))
	latest := now.Add(-time.Hour)
	writeACMECert(t, dataDir, "new-issuer", "shop.example.test", latest)

	got, ok := ACMEExpiry(dataDir, "shop.example.test")
	require.True(t, ok)
	assert.True(t, got.Equal(latest), "expired certificates are still reported so callers can see them lapse")
}

func TestACMEExpiryRejectsUnsafeOrMissingInput(t *testing.T) {
	dataDir := t.TempDir()
	writeACMECert(t, dataDir, "issuer", "shop.example.test", now.Add(time.Hour))

	cases := []struct {
		name, dataDir, host string
	}{
		{"no data dir", "", "shop.example.test"},
		{"empty host", dataDir, ""},
		{"traversal", dataDir, "../shop.example.test"},
		{"separator", dataDir, "a/b"},
		{"leading dot", dataDir, ".shop.example.test"},
		{"unknown host", dataDir, "other.example.test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := ACMEExpiry(tc.dataDir, tc.host)
			assert.False(t, ok)
		})
	}
}
