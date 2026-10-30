package secrets

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/skylarng89/sherlock-waf/internal/ids"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// aadPrefix versions the authenticated context; changing it invalidates every secret.
const aadPrefix = "sherlock/secret/v1"

// ErrDecrypt means the ciphertext failed authentication: it was altered, moved
// to another row or purpose, or encrypted under a different key.
var ErrDecrypt = errors.New("secrets: cannot decrypt (wrong key, or the value was altered or moved)")

// Service seals and opens secrets under one node key.
type Service struct {
	key Key
	now func() time.Time
}

// New returns a Service using key.
func New(key Key) *Service { return &Service{key: key, now: time.Now} }

// aad binds a ciphertext to its row id and purpose, so copying a ciphertext to
// another row (or reading it for another purpose) fails authentication.
func aad(id, purpose string) []byte {
	return []byte(aadPrefix + "\x00" + id + "\x00" + purpose)
}

func seal(key Key, id, purpose string, plaintext []byte) (nonce, ciphertext []byte, err error) {
	c, err := chacha20poly1305.NewX(key.raw[:])
	if err != nil {
		return nil, nil, fmt.Errorf("creating cipher: %w", err)
	}
	nonce = make([]byte, c.NonceSize()) // 24 random bytes: collision-safe without a counter
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generating nonce: %w", err)
	}
	return nonce, c.Seal(nil, nonce, plaintext, aad(id, purpose)), nil
}

func open(key Key, s store.Secret) ([]byte, error) {
	c, err := chacha20poly1305.NewX(key.raw[:])
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	if len(s.Nonce) != c.NonceSize() {
		return nil, ErrDecrypt
	}
	pt, err := c.Open(nil, s.Nonce, s.Ciphertext, aad(s.ID, s.Purpose))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Seal encrypts plaintext for purpose, stores it through tx and returns its id.
func (s *Service) Seal(ctx context.Context, tx store.Tx, purpose string, plaintext []byte) (string, error) {
	now := s.now()
	id, err := ids.New(now)
	if err != nil {
		return "", err
	}
	nonce, ct, err := seal(s.key, id, purpose, plaintext)
	if err != nil {
		return "", err
	}
	if err := tx.InsertSecret(ctx, store.Secret{ID: id, Purpose: purpose, KeyID: s.key.ID(), Nonce: nonce, Ciphertext: ct, CreatedAt: now}); err != nil {
		return "", fmt.Errorf("storing secret: %w", err)
	}
	return id, nil
}

// Open decrypts the secret id. The caller states the purpose it expects; a
// secret stored for a different purpose does not open.
func (s *Service) Open(ctx context.Context, tx store.Tx, id, purpose string) ([]byte, error) {
	rec, err := tx.GetSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	if rec.Purpose != purpose {
		return nil, ErrDecrypt
	}
	return open(s.key, rec)
}

// RotateKey re-encrypts every secret under a freshly generated key and swaps the
// key file, crash-safely:
//
//  1. the new key is written to node.key.new (fsynced);
//  2. one transaction re-encrypts all secrets and updates the key check;
//  3. node.key.new is renamed over node.key.
//
// If the process dies between 2 and 3, LoadKey finds node.key.new matches the
// database and finishes the swap. The returned Service uses the new key.
func RotateKey(ctx context.Context, st store.Store, dataDir string) (*Service, error) {
	path := os.Getenv(envKeyFile)
	if path == "" {
		path = filepath.Join(dataDir, keyFileName)
	}
	old, err := readKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading current node key: %w", err)
	}
	next, err := newKey()
	if err != nil {
		return nil, err
	}
	if err := writeKeyFile(path+".new", next); err != nil {
		return nil, err
	}
	err = st.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		all, err := tx.ListSecrets(ctx)
		if err != nil {
			return err
		}
		for _, rec := range all {
			pt, err := open(old, rec)
			if err != nil {
				return fmt.Errorf("secret %s: %w", rec.ID, err)
			}
			nonce, ct, err := seal(next, rec.ID, rec.Purpose, pt)
			if err != nil {
				return err
			}
			rec.KeyID, rec.Nonce, rec.Ciphertext = next.ID(), nonce, ct
			if err := tx.UpdateSecret(ctx, rec); err != nil {
				return err
			}
		}
		return tx.SetKV(ctx, keyCheckKV, next.check())
	})
	if err != nil {
		discardPendingKey(path)
		return nil, fmt.Errorf("re-encrypting secrets: %w", err)
	}
	if err := promoteKey(path); err != nil {
		return nil, fmt.Errorf("installing rotated key (re-run to finish; the database already uses it): %w", err)
	}
	return New(next), nil
}
