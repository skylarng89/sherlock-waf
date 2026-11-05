// Package secrets protects values the control plane must store but never show
// again (TOTP seeds, upstream client keys) with XChaCha20-Poly1305 under a
// per-node key.
//
// The key lives outside the database, so a stolen database alone yields only
// ciphertext. The one failure mode this package is built around is silently
// replacing the key: generating a new key while secrets exist would orphan every
// one of them, so that is refused.
package secrets

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/skylarng89/sherlock-waf/internal/store"
)

const (
	// KeySize is the node key length in bytes.
	KeySize = 32

	// Environment variables that supply the key instead of data/node.key.
	envKeyFile = "SHERLOCK_NODE_KEY_FILE"
	envKey     = "SHERLOCK_NODE_KEY"

	keyCheckKV  = "node_key_check"
	keyFileName = "node.key"
)

// Errors callers can test for.
var (
	// ErrKeyMissing means secrets exist but no key was supplied. Generating a new
	// key would make them unreadable, so the node refuses to start.
	ErrKeyMissing = errors.New("secrets: node key missing but encrypted secrets exist; restore the key (never regenerate it)")
	// ErrWrongKey means the supplied key does not belong to this database.
	ErrWrongKey = errors.New("secrets: node key does not match this database")
)

// Key is a node key and its id (the first 4 bytes of its SHA-256, stored with
// each ciphertext so a re-encryption can tell old rows from new).
type Key struct {
	raw [KeySize]byte
}

// ID returns the key's identifier.
func (k Key) ID() int {
	h := sha256.Sum256(k.raw[:])
	return int(uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3]))
}

// check is the key-check value stored in kv: it proves a key matches the
// database without revealing anything about the key.
func (k Key) check() string {
	m := hmac.New(sha256.New, k.raw[:])
	m.Write([]byte("sherlock-key-check"))
	return base64.RawStdEncoding.EncodeToString(m.Sum(nil))
}

func newKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k.raw[:]); err != nil {
		return Key{}, fmt.Errorf("generating node key: %w", err)
	}
	return k, nil
}

func parseKey(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != KeySize {
		return Key{}, fmt.Errorf("node key must be %d bytes of standard base64", KeySize)
	}
	var k Key
	copy(k.raw[:], b)
	return k, nil
}

func (k Key) encode() string { return base64.StdEncoding.EncodeToString(k.raw[:]) + "\n" }

// openKeyDir opens the directory holding the key as an os.Root, so every file
// operation on the key and its temporary copy stays inside that directory.
func openKeyDir(path string) (root *os.Root, base string, err error) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	root, err = os.OpenRoot(dir)
	return root, base, err
}

// promoteKey replaces the key at path with its pending copy (path + ".new").
func promoteKey(path string) error {
	root, base, err := openKeyDir(path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return root.Rename(base+".new", base)
}

// discardPendingKey removes the pending copy of the key at path, if any.
func discardPendingKey(path string) {
	if root, base, err := openKeyDir(path); err == nil {
		_ = root.Remove(base + ".new")
		_ = root.Close()
	}
}

// readKeyFile reads a key file, refusing one that anybody else could read.
func readKeyFile(path string) (Key, error) {
	root, base, err := openKeyDir(path)
	if err != nil {
		return Key{}, err
	}
	defer func() { _ = root.Close() }()
	st, err := root.Stat(base)
	if err != nil {
		return Key{}, err
	}
	if !st.Mode().IsRegular() {
		return Key{}, fmt.Errorf("node key %s is not a regular file", path)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return Key{}, fmt.Errorf("node key %s has permissions %o; it must be 0600 or stricter", path, perm)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Geteuid() {
		return Key{}, fmt.Errorf("node key %s is owned by uid %d, not the running user %d", path, sys.Uid, os.Geteuid())
	}
	b, err := root.ReadFile(base)
	if err != nil {
		return Key{}, fmt.Errorf("reading node key: %w", err)
	}
	return parseKey(string(b))
}

// writeKeyFile writes the key atomically with mode 0600 (create-new, fsync, rename).
func writeKeyFile(path string, k Key) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { //nolint:gosec // the key path is operator configuration (SHERLOCK_NODE_KEY_FILE), not request input
		return fmt.Errorf("creating key directory: %w", err)
	}
	root, base, err := openKeyDir(path)
	if err != nil {
		return fmt.Errorf("opening key directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	tmp := base + ".tmp"
	_ = root.Remove(tmp)
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating node key: %w", err)
	}
	if _, err := f.WriteString(k.encode()); err != nil {
		_ = f.Close()
		_ = root.Remove(tmp)
		return fmt.Errorf("writing node key: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = root.Remove(tmp)
		return fmt.Errorf("syncing node key: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("closing node key: %w", err)
	}
	if err := root.Rename(tmp, base); err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("installing node key: %w", err)
	}
	return nil
}

// LoadKey finds the node key and proves it belongs to the database behind st.
//
// Source, in order: the file named by SHERLOCK_NODE_KEY_FILE, SHERLOCK_NODE_KEY
// (base64; discouraged because environment variables leak through /proc and
// `docker inspect`), then dataDir/node.key. If none exists the key is generated,
// but only when the database holds no encrypted secrets and no key check yet.
func LoadKey(ctx context.Context, st store.Store, dataDir string, logger *slog.Logger) (Key, error) {
	if logger == nil {
		logger = slog.Default()
	}
	path := os.Getenv(envKeyFile)
	if path == "" {
		path = filepath.Join(dataDir, keyFileName)
	}

	var key Key
	var haveKey bool
	switch v := os.Getenv(envKey); {
	case os.Getenv(envKeyFile) == "" && v != "":
		k, err := parseKey(v)
		if err != nil {
			return Key{}, fmt.Errorf("%s: %w", envKey, err)
		}
		logger.Warn("node key supplied through the environment; prefer SHERLOCK_NODE_KEY_FILE", "env", envKey)
		key, haveKey = k, true
	default:
		k, err := readKeyFile(path)
		switch {
		case err == nil:
			key, haveKey = k, true
		case errors.Is(err, os.ErrNotExist):
		default:
			return Key{}, err
		}
	}

	var stored string
	var secretCount int
	if err := st.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		v, err := tx.GetKV(ctx, keyCheckKV)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return err
		default:
			stored = v
		}
		secretCount, err = tx.CountSecrets(ctx)
		return err
	}); err != nil {
		return Key{}, fmt.Errorf("reading key check: %w", err)
	}

	if haveKey && stored != "" && !hmac.Equal([]byte(key.check()), []byte(stored)) {
		// A rotation may have been interrupted after the database was updated
		// but before the new key replaced the old one.
		if pending, err := readKeyFile(path + ".new"); err == nil && hmac.Equal([]byte(pending.check()), []byte(stored)) {
			logger.Warn("finishing an interrupted key rotation", "path", path)
			if err := promoteKey(path); err != nil {
				return Key{}, fmt.Errorf("promoting rotated key: %w", err)
			}
			return pending, nil
		}
		return Key{}, ErrWrongKey
	}

	if !haveKey {
		if pending, err := readKeyFile(path + ".new"); err == nil && stored != "" && hmac.Equal([]byte(pending.check()), []byte(stored)) {
			if err := promoteKey(path); err != nil {
				return Key{}, fmt.Errorf("promoting rotated key: %w", err)
			}
			return pending, nil
		}
		if secretCount > 0 || stored != "" {
			return Key{}, ErrKeyMissing
		}
		k, err := newKey()
		if err != nil {
			return Key{}, err
		}
		if err := writeKeyFile(path, k); err != nil {
			return Key{}, err
		}
		logger.Info("generated a new node key", "path", path)
		key = k
	}

	if stored == "" {
		if err := st.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			return tx.SetKV(ctx, keyCheckKV, key.check())
		}); err != nil {
			return Key{}, fmt.Errorf("recording key check: %w", err)
		}
	}
	return key, nil
}
