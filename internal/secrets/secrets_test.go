package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/store"
)

var quiet = slog.New(slog.DiscardHandler)

func newStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "s.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// readIn reads a file inside dir through os.Root, so a name cannot escape it.
func readIn(t *testing.T, dir, name string) ([]byte, error) {
	t.Helper()
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	return root.ReadFile(name)
}

func clearEnv(t *testing.T) {
	t.Helper()
	t.Setenv(envKey, "")
	t.Setenv(envKeyFile, "")
}

func seal1(t *testing.T, st store.Store, svc *Service, purpose string, pt []byte) string {
	t.Helper()
	var id string
	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		var err error
		id, err = svc.Seal(ctx, tx, purpose, pt)
		return err
	}))
	return id
}

func open1(t *testing.T, st store.Store, svc *Service, id, purpose string) ([]byte, error) {
	t.Helper()
	var out []byte
	err := st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		var err error
		out, err = svc.Open(ctx, tx, id, purpose)
		return err
	})
	return out, err
}

func TestFirstStartGeneratesAKeyWith0600(t *testing.T) {
	clearEnv(t)
	st, dir := newStore(t), t.TempDir()
	k, err := LoadKey(t.Context(), st, dir, quiet)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(dir, "node.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	again, err := LoadKey(t.Context(), st, dir, quiet)
	require.NoError(t, err)
	assert.Equal(t, k, again, "the same key is loaded on the next start")
}

func TestLooseKeyFilePermissionsAreRefused(t *testing.T) {
	clearEnv(t)
	st, dir := newStore(t), t.TempDir()
	_, err := LoadKey(t.Context(), st, dir, quiet)
	require.NoError(t, err)
	for _, mode := range []os.FileMode{0o640, 0o644, 0o604, 0o666} {
		require.NoError(t, os.Chmod(filepath.Join(dir, "node.key"), mode))
		_, err := LoadKey(t.Context(), st, dir, quiet)
		require.Error(t, err, "mode %o", mode)
		assert.Contains(t, err.Error(), "0600")
	}
	require.NoError(t, os.Chmod(filepath.Join(dir, "node.key"), 0o400))
	_, err = LoadKey(t.Context(), st, dir, quiet)
	assert.NoError(t, err, "stricter than 0600 is fine")
}

func TestKeyFileMustBeAFileAndWellFormed(t *testing.T) {
	clearEnv(t)
	st, dir := newStore(t), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "node.key"), []byte("not base64 !!"), 0o600))
	_, err := LoadKey(t.Context(), st, dir, quiet)
	require.Error(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "node.key"), []byte(base64.StdEncoding.EncodeToString([]byte("too short"))), 0o600))
	_, err = LoadKey(t.Context(), st, dir, quiet)
	require.Error(t, err)

	require.NoError(t, os.Remove(filepath.Join(dir, "node.key")))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "node.key"), 0o700))
	_, err = LoadKey(t.Context(), st, dir, quiet)
	require.Error(t, err)
}

// The rule the whole package exists for: a missing key next to existing secrets
// must stop the node, never mint a replacement that orphans them.
func TestMissingKeyWithExistingSecretsIsRefused(t *testing.T) {
	clearEnv(t)
	st, dir := newStore(t), t.TempDir()
	k, err := LoadKey(t.Context(), st, dir, quiet)
	require.NoError(t, err)
	seal1(t, st, New(k), "totp", []byte("seed"))

	require.NoError(t, os.Remove(filepath.Join(dir, "node.key")))
	_, err = LoadKey(t.Context(), st, dir, quiet)
	require.ErrorIs(t, err, ErrKeyMissing)
	_, statErr := os.Stat(filepath.Join(dir, "node.key"))
	assert.True(t, os.IsNotExist(statErr), "no replacement key may be written")
}

func TestWrongKeyIsDetected(t *testing.T) {
	clearEnv(t)
	st, dir := newStore(t), t.TempDir()
	_, err := LoadKey(t.Context(), st, dir, quiet)
	require.NoError(t, err)

	other, err := newKey()
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(dir, "node.key")))
	require.NoError(t, writeKeyFile(filepath.Join(dir, "node.key"), other))
	_, err = LoadKey(t.Context(), st, dir, quiet)
	require.ErrorIs(t, err, ErrWrongKey)
}

func TestKeyFromEnvironment(t *testing.T) {
	st, dir := newStore(t), t.TempDir()
	k, err := newKey()
	require.NoError(t, err)

	t.Run("file", func(t *testing.T) {
		clearEnv(t)
		path := filepath.Join(t.TempDir(), "elsewhere.key")
		require.NoError(t, writeKeyFile(path, k))
		t.Setenv(envKeyFile, path)
		got, err := LoadKey(t.Context(), st, dir, quiet)
		require.NoError(t, err)
		assert.Equal(t, k, got)
		_, statErr := os.Stat(filepath.Join(dir, "node.key"))
		assert.True(t, os.IsNotExist(statErr), "the data directory key is not created when a file is supplied")
	})
	t.Run("variable", func(t *testing.T) {
		clearEnv(t)
		st2 := newStore(t)
		t.Setenv(envKey, base64.StdEncoding.EncodeToString(k.raw[:]))
		got, err := LoadKey(t.Context(), st2, t.TempDir(), quiet)
		require.NoError(t, err)
		assert.Equal(t, k, got)
	})
	t.Run("malformed variable", func(t *testing.T) {
		clearEnv(t)
		t.Setenv(envKey, "short")
		_, err := LoadKey(t.Context(), newStore(t), t.TempDir(), quiet)
		require.Error(t, err)
	})
}

func TestSealOpenRoundTrip(t *testing.T) {
	clearEnv(t)
	st := newStore(t)
	k, _ := LoadKey(t.Context(), st, t.TempDir(), quiet)
	svc := New(k)
	secret := []byte("JBSWY3DPEHPK3PXP\x00binary\xff")
	id := seal1(t, st, svc, "totp", secret)

	got, err := open1(t, st, svc, id, "totp")
	require.NoError(t, err)
	assert.Equal(t, secret, got)

	var stored store.Secret
	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		var err error
		stored, err = tx.GetSecret(ctx, id)
		return err
	}))
	assert.False(t, bytes.Contains(stored.Ciphertext, secret), "the plaintext must not be stored")
	assert.Equal(t, k.ID(), stored.KeyID)
	assert.Len(t, stored.Nonce, 24)
}

func TestTamperedOrMovedCiphertextFailsAuthentication(t *testing.T) {
	clearEnv(t)
	st := newStore(t)
	k, _ := LoadKey(t.Context(), st, t.TempDir(), quiet)
	svc := New(k)
	a := seal1(t, st, svc, "totp", []byte("secret-a"))
	b := seal1(t, st, svc, "totp", []byte("secret-b"))

	t.Run("wrong purpose", func(t *testing.T) {
		_, err := open1(t, st, svc, a, "upstream-key")
		assert.ErrorIs(t, err, ErrDecrypt)
	})
	t.Run("flipped bit", func(t *testing.T) {
		require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
			rec, _ := tx.GetSecret(ctx, a)
			rec.Ciphertext[0] ^= 1
			return tx.UpdateSecret(ctx, rec)
		}))
		_, err := open1(t, st, svc, a, "totp")
		assert.ErrorIs(t, err, ErrDecrypt)
	})
	t.Run("ciphertext copied to another row", func(t *testing.T) {
		// Fresh, untouched secrets: the only thing wrong is that one ciphertext
		// now sits in the other's row, so only the authenticated row id can reject it.
		c := seal1(t, st, svc, "totp", []byte("secret-c"))
		d := seal1(t, st, svc, "totp", []byte("secret-d"))
		got, err := open1(t, st, svc, c, "totp")
		require.NoError(t, err)
		require.Equal(t, "secret-c", string(got), "precondition: c opens before the swap")
		require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
			rc, _ := tx.GetSecret(ctx, c)
			rd, _ := tx.GetSecret(ctx, d)
			rd.Nonce, rd.Ciphertext = rc.Nonce, rc.Ciphertext
			return tx.UpdateSecret(ctx, rd)
		}))
		_, err = open1(t, st, svc, d, "totp")
		assert.ErrorIs(t, err, ErrDecrypt, "the row id is authenticated, so ciphertexts cannot be swapped between rows")
	})
	t.Run("truncated nonce", func(t *testing.T) {
		require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
			rb, _ := tx.GetSecret(ctx, b)
			rb.Nonce = rb.Nonce[:5]
			return tx.UpdateSecret(ctx, rb)
		}))
		_, err := open1(t, st, svc, b, "totp")
		assert.ErrorIs(t, err, ErrDecrypt)
	})
	t.Run("different key", func(t *testing.T) {
		other, _ := newKey()
		_, err := open1(t, st, New(other), a, "totp")
		assert.ErrorIs(t, err, ErrDecrypt)
	})
}

func TestNoncesNeverRepeat(t *testing.T) {
	clearEnv(t)
	st := newStore(t)
	k, _ := LoadKey(t.Context(), st, t.TempDir(), quiet)
	seen := map[string]bool{}
	for range 2000 {
		nonce, _, err := seal(k, "id", "p", []byte("x"))
		require.NoError(t, err)
		require.False(t, seen[string(nonce)])
		seen[string(nonce)] = true
	}
}

func TestRotateKeyReEncryptsEverything(t *testing.T) {
	clearEnv(t)
	st, dir := newStore(t), t.TempDir()
	k, _ := LoadKey(t.Context(), st, dir, quiet)
	svc := New(k)
	id1 := seal1(t, st, svc, "totp", []byte("one"))
	id2 := seal1(t, st, svc, "upstream", []byte("two"))
	oldRaw, _ := readIn(t, dir, "node.key")

	rotated, err := RotateKey(t.Context(), st, dir)
	require.NoError(t, err)

	newRaw, _ := readIn(t, dir, "node.key")
	assert.NotEqual(t, oldRaw, newRaw, "the key file changed")
	for id, want := range map[string]string{id1: "one", id2: "two"} {
		purpose := map[string]string{id1: "totp", id2: "upstream"}[id]
		got, err := open1(t, st, rotated, id, purpose)
		require.NoError(t, err)
		assert.Equal(t, want, string(got))
		_, err = open1(t, st, svc, id, purpose)
		assert.ErrorIs(t, err, ErrDecrypt, "the old key no longer opens anything")
	}

	reloaded, err := LoadKey(t.Context(), st, dir, quiet)
	require.NoError(t, err, "the next start accepts the rotated key")
	assert.Equal(t, rotated.key, reloaded)
	_, err = os.Stat(filepath.Join(dir, "node.key.new"))
	assert.True(t, os.IsNotExist(err), "no leftover files")
}

// Simulates a crash after the database was re-encrypted but before node.key.new
// replaced node.key: the next start must finish the swap, not fail or regenerate.
func TestInterruptedRotationIsRecovered(t *testing.T) {
	clearEnv(t)
	st, dir := newStore(t), t.TempDir()
	k, _ := LoadKey(t.Context(), st, dir, quiet)
	id := seal1(t, st, New(k), "totp", []byte("seed"))
	oldRaw, _ := readIn(t, dir, "node.key")

	_, err := RotateKey(t.Context(), st, dir)
	require.NoError(t, err)
	newRaw, _ := readIn(t, dir, "node.key")

	// Rewind the file system to the crash point.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "node.key"), oldRaw, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "node.key.new"), newRaw, 0o600))

	recovered, err := LoadKey(t.Context(), st, dir, quiet)
	require.NoError(t, err)
	got, err := open1(t, st, New(recovered), id, "totp")
	require.NoError(t, err)
	assert.Equal(t, "seed", string(got))
	final, _ := readIn(t, dir, "node.key")
	assert.Equal(t, newRaw, final, "node.key now holds the rotated key")

	// And when node.key is gone entirely but node.key.new survives.
	require.NoError(t, os.Remove(filepath.Join(dir, "node.key")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "node.key.new"), newRaw, 0o600))
	_, err = LoadKey(t.Context(), st, dir, quiet)
	require.NoError(t, err)
}

func TestRotateKeyFailsCleanlyWhenASecretCannotBeRead(t *testing.T) {
	clearEnv(t)
	st, dir := newStore(t), t.TempDir()
	k, _ := LoadKey(t.Context(), st, dir, quiet)
	id := seal1(t, st, New(k), "totp", []byte("x"))
	require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		rec, _ := tx.GetSecret(ctx, id)
		rec.Ciphertext[0] ^= 1
		return tx.UpdateSecret(ctx, rec)
	}))
	before, _ := readIn(t, dir, "node.key")
	_, err := RotateKey(t.Context(), st, dir)
	require.Error(t, err)
	after, _ := readIn(t, dir, "node.key")
	assert.Equal(t, before, after, "a failed rotation leaves the key untouched")
	_, statErr := os.Stat(filepath.Join(dir, "node.key.new"))
	assert.True(t, os.IsNotExist(statErr), "and removes its temporary file")
}

func TestKeyIDIsStableAndDistinct(t *testing.T) {
	a, _ := newKey()
	b, _ := newKey()
	assert.Equal(t, a.ID(), a.ID())
	assert.NotEqual(t, a.ID(), b.ID())
	assert.NotEqual(t, a.check(), b.check())
}
