package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"strings"
)

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// randomString returns n random bytes as lowercase unpadded base32, which is
// URL, cookie and header safe and free of the "_" used as a token separator.
func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error()) // no safe fallback exists
	}
	return strings.ToLower(base32NoPad.EncodeToString(b))
}

// hashToken is the stored form of a bearer secret: SHA-256, hex. The inputs
// carry 160+ bits of entropy, so a fast hash is appropriate (and lookups stay cheap).
func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
