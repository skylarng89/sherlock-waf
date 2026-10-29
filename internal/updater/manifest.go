package updater

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// signingContext is prefixed to the manifest bytes before signing so the key
// cannot be tricked into validating a document it signed for another purpose.
const signingContext = "sherlock-release-manifest-v1\n"

const (
	// ManifestName and SignatureName are the release asset names.
	ManifestName = "release-manifest.json"
	// SignatureName holds the base64 Ed25519 signature of the manifest bytes.
	SignatureName = "release-manifest.json.sig"

	maxManifestBytes = 1 << 20
)

// Manifest is the signed release description written by scripts/release-manifest.sh.
type Manifest struct {
	Schema         int               `json:"schema"`
	Version        string            `json:"version"`
	CRSVersion     string            `json:"crs_version"`
	MinUpgradeFrom string            `json:"min_upgrade_from"`
	Artefacts      map[string]string `json:"artifacts"` //nolint:misspell // key fixed by scripts/release-manifest.sh; value: file name -> hex sha256
}

// Sign returns the base64 signature of manifest under priv. Only the release
// pipeline and tests call it; the server never holds a private key.
func Sign(priv ed25519.PrivateKey, manifest []byte) []byte {
	sig := ed25519.Sign(priv, append([]byte(signingContext), manifest...))
	return []byte(base64.StdEncoding.EncodeToString(sig) + "\n")
}

// ErrBadSignature means the manifest was not signed by the release key.
var ErrBadSignature = errors.New("updater: manifest signature is invalid")

// ParseManifest verifies sig over raw with key and only then decodes raw: an
// unauthenticated document is never interpreted.
func ParseManifest(raw, sig []byte, key ed25519.PublicKey) (*Manifest, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, ErrNoReleaseKey
	}
	if len(raw) == 0 || len(raw) > maxManifestBytes {
		return nil, errors.New("updater: manifest is empty or too large")
	}
	rawSig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(rawSig) != ed25519.SignatureSize {
		return nil, ErrBadSignature
	}
	if !ed25519.Verify(key, append([]byte(signingContext), raw...), rawSig) {
		return nil, ErrBadSignature
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("updater: decoding manifest: %w", err)
	}
	if m.Schema != 1 {
		return nil, fmt.Errorf("updater: manifest schema %d is not supported by this version", m.Schema)
	}
	if _, err := ParseVersion(m.Version); err != nil {
		return nil, fmt.Errorf("updater: manifest version: %w", err)
	}
	if m.MinUpgradeFrom != "" {
		if _, err := ParseVersion(m.MinUpgradeFrom); err != nil {
			return nil, fmt.Errorf("updater: manifest min_upgrade_from: %w", err)
		}
	}
	return &m, nil
}

// Version is a parsed semantic version (build metadata ignored).
type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

// ParseVersion parses "1.2.3", "v1.2.3" and "1.2.3-rc.1".
func ParseVersion(s string) (Version, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	s, _, _ = strings.Cut(s, "+")
	core, pre, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("%q is not a semantic version", s)
	}
	var n [3]int
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || (len(p) > 1 && p[0] == '0') {
			return Version{}, fmt.Errorf("%q is not a semantic version", s)
		}
		n[i] = v
	}
	return Version{n[0], n[1], n[2], pre}, nil
}

// Compare orders versions; a pre-release sorts before its release.
func (v Version) Compare(o Version) int {
	for _, d := range [3]int{v.Major - o.Major, v.Minor - o.Minor, v.Patch - o.Patch} {
		if d != 0 {
			if d < 0 {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "":
		return 1
	case o.Pre == "":
		return -1
	}
	return strings.Compare(v.Pre, o.Pre)
}

func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}
