package certstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/secrets"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

var now = time.Now().UTC().Truncate(time.Second)

type issued struct {
	certPEM, keyPEM string
	key             any
}

type spec struct {
	dns       []string
	notBefore time.Time
	notAfter  time.Time
	ca        bool
	key       any
}

func issue(t *testing.T, s spec) issued {
	t.Helper()
	if s.key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		s.key = k
	}
	if s.notBefore.IsZero() {
		s.notBefore = now.Add(-time.Hour)
	}
	if s.notAfter.IsZero() {
		s.notAfter = now.Add(90 * 24 * time.Hour)
	}
	if s.dns == nil {
		s.dns = []string{"shop.example.test", "www.example.test"}
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "test"}, DNSNames: s.dns,
		NotBefore: s.notBefore, NotAfter: s.notAfter, IsCA: s.ca, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	pub := publicOf(s.key)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, s.key)
	require.NoError(t, err)
	pk, err := x509.MarshalPKCS8PrivateKey(s.key)
	require.NoError(t, err)
	return issued{
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})),
		key:     s.key,
	}
}

func publicOf(k any) any {
	switch v := k.(type) {
	case *ecdsa.PrivateKey:
		return &v.PublicKey
	case *rsa.PrivateKey:
		return &v.PublicKey
	}
	panic("unsupported test key")
}

func TestParseAcceptsAValidChainAndNormalisesTheKey(t *testing.T) {
	c := issue(t, spec{})
	p, err := Parse(c.certPEM, c.keyPEM, now)
	require.NoError(t, err)
	assert.Equal(t, []string{"shop.example.test", "www.example.test"}, p.Hosts)
	assert.Len(t, p.Fingerprint, 64)
	assert.Contains(t, string(p.KeyPEM), "BEGIN PRIVATE KEY")

	// SEC1 "EC PRIVATE KEY" input is accepted and stored as PKCS#8.
	ec := c.key.(*ecdsa.PrivateKey)
	sec1, err := x509.MarshalECPrivateKey(ec)
	require.NoError(t, err)
	p2, err := Parse(c.certPEM, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})), now)
	require.NoError(t, err)
	assert.Equal(t, string(p.KeyPEM), string(p2.KeyPEM))

	// An intermediate after the leaf is kept.
	inter := issue(t, spec{ca: true})
	chain, err := Parse(c.certPEM+inter.certPEM, c.keyPEM, now)
	require.NoError(t, err)
	assert.Equal(t, c.certPEM+inter.certPEM, chain.ChainPEM)
}

func TestParseRejections(t *testing.T) {
	good := issue(t, spec{})
	other := issue(t, spec{})
	weak, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately weak: proves it is refused
	require.NoError(t, err)
	weakCert := issue(t, spec{key: weak})
	encrypted := string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")}))
	dsaKey := func() string { // an unsupported private key type
		return string(pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("x")}))
	}()

	for name, tc := range map[string]struct {
		cert, key string
		want      string
	}{
		"no cert":         {"", good.keyPEM, "no PEM certificate"},
		"garbage":         {"not pem", good.keyPEM, "no PEM certificate"},
		"trailing data":   {good.certPEM + "junk", good.keyPEM, "unexpected data"},
		"wrong block":     {good.keyPEM, good.keyPEM, "unexpected \"PRIVATE KEY\" block"},
		"expired":         {issue(t, spec{notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Hour)}).certPEM, good.keyPEM, "expired"},
		"not yet valid":   {issue(t, spec{notBefore: now.Add(time.Hour)}).certPEM, good.keyPEM, "not valid until"},
		"ca first":        {issue(t, spec{ca: true}).certPEM, good.keyPEM, "is a CA"},
		"no dns names":    {issue(t, spec{dns: []string{}}).certPEM, good.keyPEM, "no DNS names"},
		"no key":          {good.certPEM, "", "no PEM private key"},
		"encrypted key":   {good.certPEM, encrypted, "passphrase-protected"},
		"unsupported key": {good.certPEM, dsaKey, "unsupported private key type"},
		"key mismatch":    {good.certPEM, other.keyPEM, "does not match"},
		"weak rsa":        {weakCert.certPEM, weakCert.keyPEM, "at least 2048 bits"},
		"too many in chain": {func() string {
			s := ""
			for range maxChain + 1 {
				s += good.certPEM
			}
			return s
		}(), good.keyPEM, "more than"},
	} {
		_, err := Parse(tc.cert, tc.key, now)
		require.ErrorIs(t, err, ErrInvalid, name)
		assert.ErrorContains(t, err, tc.want, name)
	}
}

func openStore(t *testing.T) (store.Store, *secrets.Service) {
	t.Helper()
	st, err := store.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "c.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	key, err := secrets.LoadKey(t.Context(), st, t.TempDir(), nil)
	require.NoError(t, err)
	return st, secrets.New(key)
}

func TestAddStoresTheKeyEncryptedAndRemoveDeletesIt(t *testing.T) {
	st, sec := openStore(t)
	c := issue(t, spec{})

	var added store.Certificate
	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
		added, err = Add(ctx, tx, sec, "shop", c.certPEM, c.keyPEM, now)
		return err
	}))

	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		raw, err := tx.GetSecret(ctx, added.KeySecretID)
		require.NoError(t, err)
		assert.NotContains(t, string(raw.Ciphertext), "PRIVATE KEY", "the key is stored encrypted")
		key, err := sec.Open(ctx, tx, added.KeySecretID, KeyPurpose)
		require.NoError(t, err)
		assert.Contains(t, string(key), "BEGIN PRIVATE KEY")
		_, err = sec.Open(ctx, tx, added.KeySecretID, "user_mfa_totp")
		assert.ErrorIs(t, err, secrets.ErrDecrypt, "a certificate key does not open under another purpose")
		return nil
	}))

	err := st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		_, err := Add(ctx, tx, sec, "shop", c.certPEM, c.keyPEM, now)
		return err
	})
	assert.ErrorIs(t, err, store.ErrConflict, "names are unique")

	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error { return Remove(ctx, tx, added.ID) }))
	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		_, err := tx.GetSecret(ctx, added.KeySecretID)
		assert.ErrorIs(t, err, store.ErrNotFound, "the sealed key goes with the certificate")
		return nil
	}))
}

func TestFilesAreWrittenPrivatelyAndOnlyWhenChanged(t *testing.T) {
	st, sec := openStore(t)
	c := issue(t, spec{})
	var added store.Certificate
	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
		added, err = Add(ctx, tx, sec, "shop", c.certPEM, c.keyPEM, now)
		return err
	}))

	dir := filepath.Join(t.TempDir(), "certs")
	f := &Files{Store: st, Secrets: sec, Dir: dir}
	certFile, keyFile, err := f.Paths(added.ID)
	require.NoError(t, err)

	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
	keyInfo, err := os.Stat(keyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm(), "the key file must not be group or world readable")
	got, err := os.ReadFile(certFile) //nolint:gosec // test path
	require.NoError(t, err)
	assert.Equal(t, c.certPEM, string(got))

	before, err := os.Stat(keyFile)
	require.NoError(t, err)
	_, _, err = f.Paths(added.ID)
	require.NoError(t, err)
	after, err := os.Stat(keyFile)
	require.NoError(t, err)
	assert.True(t, before.ModTime().Equal(after.ModTime()) && os.SameFile(before, after), "an unchanged certificate is not rewritten")

	_, _, err = f.Paths("missing")
	require.Error(t, err)

	// A hostile id cannot escape the directory.
	_, _, err = f.Paths("../../etc/passwd")
	require.Error(t, err)
	_, err = os.Stat(filepath.Join(dir, "..", "..", "etc"))
	assert.Error(t, err)

	f.Delete(added.ID)
	_, err = os.Stat(certFile)
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(keyFile)
	assert.ErrorIs(t, err, os.ErrNotExist)
}
