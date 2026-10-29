// Package auth implements control-plane authentication: password hashing,
// TOTP, sessions, API tokens, login throttling and the role/permission model.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters (RFC 9106 second recommendation, tuned for an
// interactive login): t=3, m=64 MiB, p=2.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16

	// MinPasswordLength is enforced when a password is set, not when checked.
	MinPasswordLength = 12
	maxPasswordLength = 1024
)

// ErrWeakPassword reports a password that fails the policy.
var ErrWeakPassword = errors.New("password does not meet the policy")

// Hasher hashes and verifies passwords. A semaphore bounds concurrent
// argon2id runs so a login flood cannot exhaust memory (each run takes 64 MiB).
type Hasher struct {
	slots chan struct{}
}

// NewHasher allows at most concurrency simultaneous hash computations.
func NewHasher(concurrency int) *Hasher {
	if concurrency < 1 {
		concurrency = 4
	}
	return &Hasher{slots: make(chan struct{}, concurrency)}
}

func (h *Hasher) acquire(ctx context.Context) (release func(), err error) {
	select {
	case h.slots <- struct{}{}:
		return func() { <-h.slots }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for a password hashing slot: %w", ctx.Err())
	}
}

// ValidatePassword applies the password policy: length 12..1024 and not blank.
func ValidatePassword(p string) error {
	switch {
	case len(p) < MinPasswordLength:
		return fmt.Errorf("%w: at least %d characters", ErrWeakPassword, MinPasswordLength)
	case len(p) > maxPasswordLength:
		return fmt.Errorf("%w: at most %d characters", ErrWeakPassword, maxPasswordLength)
	case strings.TrimSpace(p) == "":
		return fmt.Errorf("%w: must not be blank", ErrWeakPassword)
	}
	return nil
}

// Hash returns a PHC-format argon2id hash of password.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	release, err := h.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	sum := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum)), nil
}

// Verify checks password against a stored hash in constant time. A malformed
// hash is an error (and never a match); a wrong password is (false, nil).
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (bool, error) {
	p, err := parsePHC(encoded)
	if err != nil {
		return false, err
	}
	release, err := h.acquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	sum := argon2.IDKey([]byte(password), p.salt, p.time, p.memory, p.threads, uint32(len(p.sum))) //nolint:gosec // length bounded by parsePHC
	return subtle.ConstantTimeCompare(sum, p.sum) == 1, nil
}

// Dummy burns the cost of one verification, so that an unknown username is not
// distinguishable from a wrong password by response time.
func (h *Hasher) Dummy(ctx context.Context, password string) {
	_, _ = h.Verify(ctx, password, dummyHash)
}

// dummyHash is a valid hash of an unguessable value with the production parameters.
var dummyHash = func() string {
	h, err := NewHasher(1).Hash(context.Background(), randomString(24))
	if err != nil {
		panic(err)
	}
	return h
}()

type phc struct {
	memory, time uint32
	threads      uint8
	salt, sum    []byte
}

// parsePHC accepts only argon2id and caps the cost parameters so a tampered
// database row cannot be used to exhaust memory.
func parsePHC(s string) (phc, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return phc{}, errors.New("unsupported password hash format")
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return phc{}, errors.New("unsupported argon2 version")
	}
	var p phc
	var m, t, th uint64
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return phc{}, errors.New("malformed argon2 parameters")
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return phc{}, errors.New("malformed argon2 parameters")
		}
		switch k {
		case "m":
			m = n
		case "t":
			t = n
		case "p":
			th = n
		}
	}
	if m < 8*1024 || m > 256*1024 || t < 1 || t > 10 || th < 1 || th > 16 {
		return phc{}, errors.New("argon2 parameters out of range")
	}
	var err error
	if p.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(p.salt) < 8 {
		return phc{}, errors.New("malformed argon2 salt")
	}
	if p.sum, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(p.sum) < 16 || len(p.sum) > 64 {
		return phc{}, errors.New("malformed argon2 digest")
	}
	p.memory, p.time, p.threads = uint32(m), uint32(t), uint8(th) //nolint:gosec // ranges checked above
	return p, nil
}
