package updater

import (
	"crypto/ed25519"
	_ "embed" // release_key.pub
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// releaseKeyB64 is the Ed25519 public key release manifests are signed with
// (base64, 32 bytes). Release builds replace the file's content with the real
// key before compiling; a source build carries the placeholder UNSET, which
// makes every update fail closed instead of trusting an empty key.
//
//go:embed release_key.pub
var releaseKeyB64 string

// ErrNoReleaseKey means this build has no release public key embedded.
var ErrNoReleaseKey = errors.New("updater: this build has no release public key; updates are disabled")

// ReleaseKey returns the embedded release public key.
func ReleaseKey() (ed25519.PublicKey, error) {
	return ParseKey(releaseKeyB64)
}

// ParseKey decodes a base64 Ed25519 public key.
func ParseKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "UNSET" {
		return nil, ErrNoReleaseKey
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("updater: embedded release key is malformed")
	}
	return ed25519.PublicKey(raw), nil
}
