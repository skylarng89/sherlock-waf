package updater_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/updater"
)

const platformGOOS, platformGOARCH = "linux", "amd64"

type release struct {
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	manifest []byte
	sig      []byte
	archive  []byte
	name     string
}

func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}))
		_, err := tw.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// newRelease builds a signed release whose "binary" is a shell script that
// prints its version, so the default self-test runs for real.
func newRelease(t *testing.T, version, minFrom string) release {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return releaseWith(t, pub, priv, version, minFrom, []byte("#!/bin/sh\necho \"sherlock "+version+" (test)\"\n"))
}

func releaseWith(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, version, minFrom string, bin []byte) release {
	t.Helper()
	r := release{pub: pub, priv: priv, name: "sherlock_" + version + "_linux_amd64.tar.gz"}
	r.archive = tarGz(t, map[string][]byte{"LICENSE": []byte("x"), "sherlock": bin})
	sum := sha256.Sum256(r.archive)
	m, err := json.Marshal(updater.Manifest{Schema: 1, Version: version, CRSVersion: "4.0.0", MinUpgradeFrom: minFrom, Artefacts: map[string]string{r.name: hex.EncodeToString(sum[:])}})
	require.NoError(t, err)
	r.manifest, r.sig = m, updater.Sign(priv, m)
	return r
}

func (r release) bundle() updater.Bundle {
	return updater.Bundle{Manifest: r.manifest, Signature: r.sig, Archive: r.archive}
}

func newUpdater(t *testing.T, key ed25519.PublicKey, current, baseURL string) (*updater.Updater, string) {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "sherlock")
	require.NoError(t, os.WriteFile(exe, []byte("#!/bin/sh\necho old\n"), 0o755)) //nolint:gosec // test fixture
	u, err := updater.New(updater.Options{
		Key: key, CurrentVersion: current, ExePath: exe, DataDir: filepath.Join(dir, "data"),
		BaseURL: baseURL, AllowHTTP: true, GOOS: platformGOOS, GOARCH: platformGOARCH,
		HTTP: http.DefaultClient, // the httptest server is on loopback, which netx would refuse
	})
	require.NoError(t, err)
	return u, exe
}

func TestInstallVerifiedBundleAndRollback(t *testing.T) {
	r := newRelease(t, "0.5.0", "0.4.0")
	u, exe := newUpdater(t, r.pub, "0.4.0", "http://unused.invalid")

	v, err := u.VerifyBundle(r.bundle())
	require.NoError(t, err)
	res, err := u.Install(context.Background(), v)
	require.NoError(t, err)
	assert.Equal(t, "0.4.0", res.From)
	assert.Equal(t, "0.5.0", res.To)

	got, _ := os.ReadFile(exe) //nolint:gosec // test
	assert.Contains(t, string(got), "sherlock 0.5.0")
	assert.NoFileExists(t, exe+".new")
	old, _ := os.ReadFile(res.Backup) //nolint:gosec // test
	assert.Contains(t, string(old), "echo old")

	require.NoError(t, u.Rollback())
	got, _ = os.ReadFile(exe) //nolint:gosec // test
	assert.Contains(t, string(got), "echo old")
	assert.ErrorIs(t, u.Rollback(), updater.ErrNoBackup)
}

func TestRefusals(t *testing.T) {
	r := newRelease(t, "0.5.0", "0.4.0")
	cases := []struct {
		name    string
		mutate  func(b *updater.Bundle)
		current string
		key     func() ed25519.PublicKey
		want    error
	}{
		{name: "tampered archive", current: "0.4.0", want: updater.ErrChecksum, mutate: func(b *updater.Bundle) {
			b.Archive = append(append([]byte{}, b.Archive...), 0)
		}},
		{name: "truncated archive", current: "0.4.0", want: updater.ErrChecksum, mutate: func(b *updater.Bundle) {
			b.Archive = b.Archive[:len(b.Archive)/2]
		}},
		{name: "empty archive", current: "0.4.0", want: updater.ErrChecksum, mutate: func(b *updater.Bundle) { b.Archive = nil }},
		{name: "tampered manifest", current: "0.4.0", want: updater.ErrBadSignature, mutate: func(b *updater.Bundle) {
			b.Manifest = bytes.Replace(b.Manifest, []byte("0.5.0"), []byte("0.9.0"), 1)
		}},
		{name: "garbage signature", current: "0.4.0", want: updater.ErrBadSignature, mutate: func(b *updater.Bundle) { b.Signature = []byte("not base64!") }},
		{name: "missing signature", current: "0.4.0", want: updater.ErrBadSignature, mutate: func(b *updater.Bundle) { b.Signature = nil }},
		{name: "foreign key", current: "0.4.0", want: updater.ErrBadSignature, key: func() ed25519.PublicKey {
			p, _, _ := ed25519.GenerateKey(rand.Reader)
			return p
		}},
		{name: "downgrade", current: "0.6.0", want: updater.ErrDowngrade},
		{name: "same version", current: "0.5.0", want: updater.ErrUpToDate},
		{name: "too old to jump", current: "0.3.0", want: updater.ErrTooOld},
		{name: "dev build", current: "dev", want: updater.ErrUnknownCurrent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := r.pub
			if tc.key != nil {
				key = tc.key()
			}
			u, exe := newUpdater(t, key, tc.current, "http://unused.invalid")
			b := r.bundle()
			if tc.mutate != nil {
				tc.mutate(&b)
			}
			_, err := u.VerifyBundle(b)
			require.ErrorIs(t, err, tc.want)
			got, _ := os.ReadFile(exe) //nolint:gosec // test
			assert.Contains(t, string(got), "echo old", "a refused update leaves the binary alone")
		})
	}
}

func TestTamperedBinaryInsideSignedArchiveCannotInstall(t *testing.T) {
	// Replacing the binary inside the archive changes the archive hash.
	r := newRelease(t, "0.5.0", "")
	evil := tarGz(t, map[string][]byte{"sherlock": []byte("#!/bin/sh\necho evil\n")})
	b := r.bundle()
	b.Archive = evil
	u, _ := newUpdater(t, r.pub, "0.4.0", "http://unused.invalid")
	_, err := u.VerifyBundle(b)
	assert.ErrorIs(t, err, updater.ErrChecksum)
}

func TestSelfTestFailureKeepsOldBinary(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := releaseWith(t, pub, priv, "0.5.0", "", []byte("#!/bin/sh\necho \"sherlock 9.9.9\"\n")) // lies about its version
	u, exe := newUpdater(t, pub, "0.4.0", "http://unused.invalid")
	v, err := u.VerifyBundle(r.bundle())
	require.NoError(t, err)
	_, err = u.Install(context.Background(), v)
	require.ErrorContains(t, err, "self-test")
	got, _ := os.ReadFile(exe) //nolint:gosec // test
	assert.Contains(t, string(got), "echo old")
	assert.NoFileExists(t, exe+".new")
	assert.NoFileExists(t, exe+".bak")
}

func TestArchiveWithoutBinaryOrTruncatedGzip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for name, archive := range map[string][]byte{
		"no binary":      tarGz(t, map[string][]byte{"LICENSE": []byte("x")}),
		"not an archive": []byte("plain bytes"),
	} {
		t.Run(name, func(t *testing.T) {
			sum := sha256.Sum256(archive)
			m, _ := json.Marshal(updater.Manifest{Schema: 1, Version: "0.5.0", Artefacts: map[string]string{"sherlock_0.5.0_linux_amd64.tar.gz": hex.EncodeToString(sum[:])}})
			u, exe := newUpdater(t, pub, "0.4.0", "http://unused.invalid")
			v, err := u.VerifyBundle(updater.Bundle{Manifest: m, Signature: updater.Sign(priv, m), Archive: archive})
			require.NoError(t, err)
			_, err = u.Install(context.Background(), v)
			require.Error(t, err)
			got, _ := os.ReadFile(exe) //nolint:gosec // test
			assert.Contains(t, string(got), "echo old")
		})
	}
}

func TestOnlineDownloadAndCheck(t *testing.T) {
	r := newRelease(t, "0.5.0", "0.4.0")
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits[req.URL.Path]++
		switch req.URL.Path {
		case "/release-manifest.json":
			_, _ = w.Write(r.manifest)
		case "/release-manifest.json.sig":
			_, _ = w.Write(r.sig)
		case "/" + r.name:
			_, _ = w.Write(r.archive)
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(srv.Close)

	u, exe := newUpdater(t, r.pub, "0.4.0", srv.URL)
	st, err := u.Check(context.Background())
	require.NoError(t, err)
	assert.True(t, st.Available)
	assert.Equal(t, "0.5.0", st.Latest)
	assert.Zero(t, hits["/"+r.name], "a check does not download the archive")

	res, staged, err := u.Apply(context.Background())
	require.NoError(t, err)
	assert.False(t, staged)
	assert.Equal(t, "0.5.0", res.To)
	got, _ := os.ReadFile(exe) //nolint:gosec // test
	assert.Contains(t, string(got), "sherlock 0.5.0")

	u2, _ := newUpdater(t, r.pub, "0.5.0", srv.URL)
	st, err = u2.Check(context.Background())
	require.NoError(t, err)
	assert.False(t, st.Available)
}

func TestOnlineRefusesPlainHTTPAndBadSource(t *testing.T) {
	r := newRelease(t, "0.5.0", "")
	_, err := updater.New(updater.Options{Key: r.pub, CurrentVersion: "0.4.0", ExePath: "/x", BaseURL: "http://example.com"})
	require.ErrorContains(t, err, "https")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"schema":1,"version":"0.5.0"}`)) // unsigned
	}))
	t.Cleanup(srv.Close)
	u, _ := newUpdater(t, r.pub, "0.4.0", srv.URL)
	_, err = u.Check(context.Background())
	assert.ErrorIs(t, err, updater.ErrBadSignature)
}

func TestOnlineUsesSSRFSafeClientByDefault(t *testing.T) {
	r := newRelease(t, "0.5.0", "")
	srv := httptest.NewTLSServer(http.NotFoundHandler()) // loopback
	t.Cleanup(srv.Close)
	u, err := updater.New(updater.Options{Key: r.pub, CurrentVersion: "0.4.0", ExePath: "/x", BaseURL: srv.URL})
	require.NoError(t, err)
	_, err = u.Check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed", "the default client refuses loopback destinations")
}

func TestStageThenApplyStaged(t *testing.T) {
	r := newRelease(t, "0.5.0", "")
	u, exe := newUpdater(t, r.pub, "0.4.0", "http://unused.invalid")
	v, err := u.VerifyBundle(r.bundle())
	require.NoError(t, err)
	require.NoError(t, u.Stage(v))
	ver, ok := u.Staged()
	assert.True(t, ok)
	assert.Equal(t, "0.5.0", ver)

	res, had, err := u.ApplyStaged(context.Background())
	require.NoError(t, err)
	assert.True(t, had)
	assert.Equal(t, "0.5.0", res.To)
	got, _ := os.ReadFile(exe) //nolint:gosec // test
	assert.Contains(t, string(got), "sherlock 0.5.0")
	_, ok = u.Staged()
	assert.False(t, ok, "the staged update is consumed")

	_, had, err = u.ApplyStaged(context.Background())
	assert.NoError(t, err)
	assert.False(t, had)
}

func TestApplyStagedReverifiesTamperedStage(t *testing.T) {
	r := newRelease(t, "0.5.0", "")
	u, exe := newUpdater(t, r.pub, "0.4.0", "http://unused.invalid")
	v, err := u.VerifyBundle(r.bundle())
	require.NoError(t, err)
	require.NoError(t, u.Stage(v))

	// The service user can rewrite its data dir; the privileged apply must notice.
	staged := filepath.Join(filepath.Dir(exe), "data", "updates", "staged", r.name)
	require.NoError(t, os.WriteFile(staged, tarGz(t, map[string][]byte{"sherlock": []byte("#!/bin/sh\necho evil\n")}), 0o600))

	_, had, err := u.ApplyStaged(context.Background())
	require.ErrorIs(t, err, updater.ErrChecksum)
	assert.True(t, had)
	got, _ := os.ReadFile(exe) //nolint:gosec // test
	assert.Contains(t, string(got), "echo old")
	_, ok := u.Staged()
	assert.False(t, ok, "a tampered staged update is discarded")
}

func TestInstallIntoReadOnlyDirStages(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	r := newRelease(t, "0.5.0", "")
	_, exe := newUpdater(t, r.pub, "0.4.0", "http://unused.invalid")
	require.NoError(t, os.Chmod(filepath.Dir(exe), 0o500))       //nolint:gosec // test
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(exe), 0o700) }) //nolint:gosec // test
	// data lives inside that dir in this fixture, so stage elsewhere.
	u2, err := updater.New(updater.Options{Key: r.pub, CurrentVersion: "0.4.0", ExePath: exe, DataDir: t.TempDir(), BaseURL: "http://x", AllowHTTP: true, GOOS: platformGOOS, GOARCH: platformGOARCH})
	require.NoError(t, err)
	v, err := u2.VerifyBundle(r.bundle())
	require.NoError(t, err)
	_, staged, err := u2.InstallOrStage(context.Background(), v)
	require.NoError(t, err)
	assert.True(t, staged)
}

func TestNoReleaseKeyFailsClosed(t *testing.T) {
	_, err := updater.New(updater.Options{CurrentVersion: "0.4.0", ExePath: "/x"})
	assert.ErrorIs(t, err, updater.ErrNoReleaseKey, "a source build carries the UNSET placeholder")
}

func TestVersionOrdering(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"0.5.0", "0.4.9", 1}, {"1.0.0", "1.0.0", 0}, {"1.0.0-rc.1", "1.0.0", -1}, {"v1.2.3", "1.2.4", -1}, {"0.10.0", "0.9.0", 1},
	} {
		a, err := updater.ParseVersion(tc.a)
		require.NoError(t, err)
		b, err := updater.ParseVersion(tc.b)
		require.NoError(t, err)
		assert.Equal(t, tc.want, a.Compare(b), "%s vs %s", tc.a, tc.b)
	}
	for _, bad := range []string{"", "dev", "1.2", "1.2.x", "01.2.3"} {
		_, err := updater.ParseVersion(bad)
		assert.Error(t, err, bad)
	}
}
