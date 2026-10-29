package cli_test

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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/ops"
	"github.com/skylarng89/sherlock-waf/internal/updater"
	"github.com/skylarng89/sherlock-waf/pkg/cli"
)

func runWith(t *testing.T, info cli.BuildInfo, key ed25519.PublicKey, dir, stdin string, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := cli.NewRootCommand(info, cli.WithReleaseKey(key))
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(append([]string{"--data-dir", dir}, args...))
	err := cmd.ExecuteContext(context.Background())
	return result{out.String(), errOut.String(), err}
}

func writeRelease(t *testing.T, dir, version string, priv ed25519.PrivateKey, tamper bool) string {
	t.Helper()
	script := []byte("#!/bin/sh\necho \"sherlock " + version + "\"\n")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "sherlock", Mode: 0o755, Size: int64(len(script)), Typeflag: tar.TypeReg}))
	_, _ = tw.Write(script)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	name := "sherlock_" + version + "_" + goosarch() + ".tar.gz"
	sum := sha256.Sum256(buf.Bytes())
	m, _ := json.Marshal(updater.Manifest{Schema: 1, Version: version, Artefacts: map[string]string{name: hex.EncodeToString(sum[:])}})
	require.NoError(t, os.WriteFile(filepath.Join(dir, updater.ManifestName), m, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, updater.SignatureName), updater.Sign(priv, m), 0o600))
	archive := buf.Bytes()
	if tamper {
		archive = append(archive, 'x')
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), archive, 0o600))
	return filepath.Join(dir, name)
}

func TestUpdateBundleOffline(t *testing.T) {
	if updater.InContainer() {
		t.Skip("update refuses to run in a container")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	state := t.TempDir()
	run(t, state, pw+"\n", "user", "create", "ada", "--admin", "--password-stdin")
	bin := filepath.Join(t.TempDir(), "sherlock")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\necho old\n"), 0o755)) //nolint:gosec // test fixture
	info := cli.BuildInfo{Version: "0.4.0"}

	rel := t.TempDir()
	tampered := writeRelease(t, rel, "0.5.0", priv, true)
	r := runWith(t, info, pub, state, "", "update", "--bundle", tampered, "--binary", bin, "--no-restart")
	require.ErrorContains(t, r.err, "checksum")
	got, _ := os.ReadFile(bin) //nolint:gosec // test
	assert.Contains(t, string(got), "echo old", "AC3: a tampered bundle is refused and nothing changes")

	archive := writeRelease(t, rel, "0.5.0", priv, false)
	r = runWith(t, info, pub, state, "", "update", "--bundle", archive, "--binary", bin, "--no-restart")
	require.NoError(t, r.err, r.errOut)
	assert.Contains(t, r.out, "installed 0.4.0 -> 0.5.0")
	got, _ = os.ReadFile(bin) //nolint:gosec // test
	assert.Contains(t, string(got), "sherlock 0.5.0")
	backups, _ := filepath.Glob(filepath.Join(state, "backups", "sherlock-backup-*.tar.gz"))
	assert.Len(t, backups, 1, "the data is backed up before the swap")

	r = runWith(t, cli.BuildInfo{Version: "0.5.0"}, pub, state, "", "update", "--bundle", archive, "--binary", bin, "--no-restart")
	require.ErrorContains(t, r.err, "latest version")

	r = runWith(t, cli.BuildInfo{Version: "0.6.0"}, pub, state, "", "update", "--bundle", archive, "--binary", bin, "--no-restart")
	require.ErrorContains(t, r.err, "downgrades are refused")

	r = runWith(t, info, pub, state, "", "update", "--rollback", "--binary", bin, "--no-restart")
	require.NoError(t, r.err, r.errOut)
	got, _ = os.ReadFile(bin) //nolint:gosec // test
	assert.Contains(t, string(got), "echo old")
}

func TestUpdateFailsClosedWithoutKey(t *testing.T) {
	r := run(t, t.TempDir(), "", "update", "--check")
	require.ErrorIs(t, r.err, updater.ErrNoReleaseKey)
}

func TestBackupRestoreCommands(t *testing.T) {
	state := t.TempDir()
	require.NoError(t, run(t, state, pw+"\n", "user", "create", "ada", "--admin", "--password-stdin").err)

	out := filepath.Join(t.TempDir(), "b.tar.gz")
	r := run(t, state, "", "backup", "--output", out)
	require.NoError(t, r.err, r.errOut)
	assert.Contains(t, r.errOut, "node key is not in this backup")

	r = run(t, state, "", "backup", "verify", out)
	require.NoError(t, r.err, r.errOut)
	assert.Contains(t, r.out, "backup OK")

	// Restoring over a live node's state needs --force; a running server blocks it entirely.
	r = run(t, state, "", "restore", out)
	require.ErrorContains(t, r.err, "--force")
	release := holdLock(t, state)
	r = run(t, state, "", "restore", out, "--force")
	require.ErrorIs(t, r.err, ops.ErrLocked)
	release()

	fresh := t.TempDir()
	r = run(t, fresh, "", "restore", out)
	require.NoError(t, r.err, r.errOut)
	assert.FileExists(t, filepath.Join(fresh, "sherlock.db"))

	enc := filepath.Join(t.TempDir(), "k.tar.gz.enc")
	r = run(t, state, "pass phrase pass\n", "backup", "--output", enc, "--include-key", "--passphrase-stdin")
	require.NoError(t, r.err, r.errOut)
	assert.Error(t, run(t, state, "wrong wrong wrong\n", "backup", "verify", enc, "--passphrase-stdin").err)
	require.NoError(t, run(t, state, "pass phrase pass\n", "backup", "verify", enc, "--passphrase-stdin").err)
}

func goosarch() string { return runtime.GOOS + "_" + runtime.GOARCH }
