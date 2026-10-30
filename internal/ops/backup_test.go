package ops

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// seeded builds a node with a user, a configuration and some data-dir files.
func seeded(t *testing.T) *Env {
	t.Helper()
	e := open(t)
	_, err := e.CreateUser(t.Context(), "ada", pw, "admin")
	require.NoError(t, err)
	root, err := config.Parse([]byte(sample))
	require.NoError(t, err)
	_, _, err = e.ApplyConfig(t.Context(), root, ApplyOptions{Source: "import"})
	require.NoError(t, err)
	for name, body := range map[string]string{"certificates/a/cert.pem": "CERT", "certs/a/key.pem": "KEY", "access.jsonl": "log", "geoip/x": "cache", "locks/l": "l"} {
		p := filepath.Join(e.DataDir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	return e
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	e := seeded(t)
	info, err := e.Backup(t.Context(), BackupOptions{Version: "0.4.0"})
	require.NoError(t, err)
	assert.False(t, info.Encrypted)
	assert.FileExists(t, info.Path)

	vi, err := VerifyBackup(t.Context(), RestoreOptions{Archive: info.Path})
	require.NoError(t, err)
	assert.Equal(t, "sqlite", vi.Manifest.Database)
	assert.Contains(t, vi.Manifest.Files, "data/certificates/a/cert.pem")
	for _, skipped := range []string{"data/certs/a/key.pem", "data/access.jsonl", "data/geoip/x", "data/locks/l", "data/node.key", "data/sherlock.db"} {
		assert.NotContains(t, vi.Manifest.Files, skipped)
	}

	// A fresh host: restore reproduces users, config and certificate files.
	dst := t.TempDir()
	ri, err := Restore(t.Context(), RestoreOptions{DataDir: dst, Archive: info.Path})
	require.NoError(t, err)
	assert.Positive(t, ri.AuditEntries)
	got, err := os.ReadFile(filepath.Join(dst, "certificates/a/cert.pem")) //nolint:gosec // test
	require.NoError(t, err)
	assert.Equal(t, "CERT", string(got))
	assert.NoDirExists(t, filepath.Join(dst, ".restore-x"))
	entries, _ := os.ReadDir(dst)
	for _, en := range entries {
		assert.NotContains(t, en.Name(), ".restore-", "staging is removed")
	}

	st, err := store.OpenSQLite(t.Context(), filepath.Join(dst, "sherlock.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	var users int
	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
		users, err = tx.CountUsers(ctx)
		return err
	}))
	assert.Equal(t, 1, users)
	rep, err := audit.Verify(t.Context(), st)
	require.NoError(t, err)
	assert.Nil(t, rep.Problem, "the audit chain survives, including the restore entry")
}

func TestRestoreRefusesToOverwriteWithoutForce(t *testing.T) {
	e := seeded(t)
	info, err := e.Backup(t.Context(), BackupOptions{})
	require.NoError(t, err)

	other := seeded(t) // an existing node
	_, err = Restore(t.Context(), RestoreOptions{DataDir: other.DataDir, Archive: info.Path})
	require.ErrorContains(t, err, "--force")

	_, err = Restore(t.Context(), RestoreOptions{DataDir: other.DataDir, Archive: info.Path, Force: true, Now: func() time.Time { return time.Unix(1_800_000_000, 0) }})
	require.NoError(t, err)
	matches, _ := filepath.Glob(filepath.Join(other.DataDir, "pre-restore-*", "sherlock.db"))
	assert.Len(t, matches, 1, "the replaced database is kept")
}

func TestBackupCorruptionAndTruncationAreRefused(t *testing.T) {
	e := seeded(t)
	info, err := e.Backup(t.Context(), BackupOptions{})
	require.NoError(t, err)
	raw, err := os.ReadFile(info.Path)
	require.NoError(t, err)

	write := func(b []byte) string {
		p := filepath.Join(t.TempDir(), "b.tar.gz")
		require.NoError(t, os.WriteFile(p, b, 0o600)) //nolint:gosec // test temp path
		return p
	}
	bad := append([]byte{}, raw...)
	bad[len(bad)/2] ^= 0xff
	for name, p := range map[string]string{
		"truncated":   write(raw[:len(raw)/2]),
		"bit flipped": write(bad),
		"empty":       write(nil),
		"garbage":     write([]byte("not an archive")),
	} {
		t.Run(name, func(t *testing.T) {
			dst := t.TempDir()
			_, err := Restore(t.Context(), RestoreOptions{DataDir: dst, Archive: p})
			require.Error(t, err)
			assert.NoFileExists(t, filepath.Join(dst, "sherlock.db"), "a bad archive installs nothing")
		})
	}
}

func rewrite(t *testing.T, raw []byte, edit func(name string, body []byte) (string, []byte)) string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	var out bytes.Buffer
	ogz := gzip.NewWriter(&out)
	tw := tar.NewWriter(ogz)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		var body bytes.Buffer
		_, _ = body.ReadFrom(tr)
		name, b := edit(h.Name, body.Bytes())
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg}))
		_, _ = tw.Write(b)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, ogz.Close())
	p := filepath.Join(t.TempDir(), "x.tar.gz")
	require.NoError(t, os.WriteFile(p, out.Bytes(), 0o600))
	return p
}

func TestRestoreRejectsTamperedContentAndTraversal(t *testing.T) {
	e := seeded(t)
	info, err := e.Backup(t.Context(), BackupOptions{})
	require.NoError(t, err)
	raw, _ := os.ReadFile(info.Path) //nolint:gosec // test

	tampered := rewrite(t, raw, func(n string, b []byte) (string, []byte) {
		if n == "data/certificates/a/cert.pem" {
			return n, []byte("EVIL")
		}
		return n, b
	})
	_, err = Restore(t.Context(), RestoreOptions{DataDir: t.TempDir(), Archive: tampered})
	require.ErrorContains(t, err, "checksum")

	for _, evil := range []string{"data/../../etc/cron.d/x", "/etc/passwd", "data/../x", "other/file"} {
		p := rewrite(t, raw, func(n string, b []byte) (string, []byte) {
			if n == "data/certificates/a/cert.pem" {
				return evil, b
			}
			return n, b
		})
		dst := t.TempDir()
		_, err = Restore(t.Context(), RestoreOptions{DataDir: dst, Archive: p})
		require.ErrorContains(t, err, "unsafe entry", evil)
	}
}

func TestRestoreRejectsBrokenAuditChain(t *testing.T) {
	e := seeded(t)
	// Tamper with a stored audit row behind the application's back.
	raw, err := sql.Open("sqlite", "file:"+filepath.Join(e.DataDir, "sherlock.db"))
	require.NoError(t, err)
	_, err = raw.ExecContext(t.Context(), "UPDATE audit_log SET action = 'forged' WHERE seq = 1")
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	info, err := e.Backup(t.Context(), BackupOptions{})
	require.NoError(t, err)
	dst := t.TempDir()
	_, err = Restore(t.Context(), RestoreOptions{DataDir: dst, Archive: info.Path})
	require.ErrorContains(t, err, "audit chain is broken")
	assert.NoFileExists(t, filepath.Join(dst, "sherlock.db"))
}

func TestEncryptedBackupWithNodeKey(t *testing.T) {
	e := seeded(t)
	require.NoFileExists(t, filepath.Join(e.DataDir, "unused"))

	_, err := e.Backup(t.Context(), BackupOptions{IncludeKey: true})
	require.ErrorContains(t, err, "passphrase")

	info, err := e.Backup(t.Context(), BackupOptions{IncludeKey: true, Passphrase: "hunter2 hunter2"})
	require.NoError(t, err)
	assert.True(t, info.Encrypted)
	raw, _ := os.ReadFile(info.Path) //nolint:gosec // test
	assert.NotContains(t, string(raw), "SQLite format", "the archive is not readable without the passphrase")

	_, err = VerifyBackup(t.Context(), RestoreOptions{Archive: info.Path})
	require.ErrorContains(t, err, "passphrase")
	_, err = VerifyBackup(t.Context(), RestoreOptions{Archive: info.Path, Passphrase: "wrong wrong wrong"})
	require.ErrorIs(t, err, ErrWrongPassphrase)

	dst := t.TempDir()
	_, err = Restore(t.Context(), RestoreOptions{DataDir: dst, Archive: info.Path, Passphrase: "hunter2 hunter2"})
	require.NoError(t, err)
	want, _ := os.ReadFile(filepath.Join(e.DataDir, "node.key")) //nolint:gosec // test
	got, err := os.ReadFile(filepath.Join(dst, "node.key"))      //nolint:gosec // test
	require.NoError(t, err)
	assert.Equal(t, want, got, "the node key travels only inside the encrypted archive")
	assert.NotEmpty(t, got)

	// Truncation at any point fails; flipping a byte fails.
	for _, cut := range []int{len(raw) - 1, len(raw) / 2, 30} {
		p := filepath.Join(t.TempDir(), "t.enc")
		require.NoError(t, os.WriteFile(p, raw[:cut], 0o600)) //nolint:gosec // test temp path
		_, err = VerifyBackup(t.Context(), RestoreOptions{Archive: p, Passphrase: "hunter2 hunter2"})
		assert.Error(t, err, "cut at %d", cut)
	}
}

func TestPlainBackupOmitsNodeKey(t *testing.T) {
	e := seeded(t)
	info, err := e.Backup(t.Context(), BackupOptions{})
	require.NoError(t, err)
	vi, err := VerifyBackup(t.Context(), RestoreOptions{Archive: info.Path})
	require.NoError(t, err)
	assert.False(t, vi.Manifest.IncludeKey)
	assert.NotContains(t, vi.Manifest.Files, "data/node.key")
}

func TestPruneKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"20260101T000000Z", "20260102T000000Z", "20260103T000000Z", "20260104T000000Z"} {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, BackupsDirName), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, BackupsDirName, backupPrefix+n+backupExt), []byte("x"), 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, BackupsDirName, "notes.txt"), []byte("keep me"), 0o600))
	removed, err := PruneBackups(dir, 2)
	require.NoError(t, err)
	assert.Len(t, removed, 2)
	left, _ := ListBackups(dir)
	require.Len(t, left, 2)
	assert.Contains(t, left[0].Name, "20260104")
	assert.FileExists(t, filepath.Join(dir, BackupsDirName, "notes.txt"))
	removed, err = PruneBackups(dir, 0)
	require.NoError(t, err)
	assert.Empty(t, removed, "keep < 1 disables pruning")
}

func TestBackupJobRunsWhenDueAndPrunes(t *testing.T) {
	e := seeded(t)
	start := time.Now().UTC()
	at := start
	job := BackupJob{Store: e.Store, DataDir: e.DataDir, Every: 24 * time.Hour, Keep: 2, Now: func() time.Time { return at }}

	job.runOnce(t.Context())
	files, _ := ListBackups(e.DataDir)
	require.Len(t, files, 1)

	at = start.Add(time.Hour) // not due yet
	job.runOnce(t.Context())
	files, _ = ListBackups(e.DataDir)
	assert.Len(t, files, 1)

	for i := 1; i <= 3; i++ {
		at = start.Add(time.Duration(i) * 48 * time.Hour)
		job.runOnce(t.Context())
	}
	files, _ = ListBackups(e.DataDir)
	require.Len(t, files, 2, "retention keeps the newest two")
	assert.Contains(t, files[0].Name, at.Format("20060102"))

	rep, err := audit.Verify(t.Context(), e.Store)
	require.NoError(t, err)
	assert.Nil(t, rep.Problem, "scheduled backups are audited without breaking the chain")
}

func TestScheduledBackupCanBeEncrypted(t *testing.T) {
	e := seeded(t)
	job := BackupJob{Store: e.Store, DataDir: e.DataDir, Passphrase: "scheduled passphrase"}
	job.runOnce(t.Context())
	files, err := ListBackups(e.DataDir)
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.True(t, files[0].Encrypted)
	_, err = VerifyBackup(t.Context(), RestoreOptions{Archive: filepath.Join(e.DataDir, BackupsDirName, files[0].Name), Passphrase: "scheduled passphrase"})
	require.NoError(t, err)
}
