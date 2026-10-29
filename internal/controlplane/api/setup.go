package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SetupTokenFile is the file, in the data directory, that holds the one-time
// first-run setup token. The token is written there (mode 0600) rather than to
// the log, because logs are routinely shipped to systems the operator does not
// control; whoever can read the data directory can already administer the node.
const SetupTokenFile = "setup-token"

// SetupGate guards POST /setup/admin. It exists only when the node started with
// no users: the server creates it, the first administrator consumes it, and
// from then on the endpoint answers 409. The token is compared in constant
// time, can be used once, and failed attempts are throttled process-wide.
type SetupGate struct {
	path string

	mu       sync.Mutex
	token    string
	failures []time.Time
	now      func() time.Time
}

// NewSetupGate creates a token and writes it to dataDir/SetupTokenFile.
func NewSetupGate(dataDir string) (*SetupGate, error) {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("generating setup token: %w", err)
	}
	token := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
	path := filepath.Join(dataDir, SetupTokenFile)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("writing setup token file: %w", err)
	}
	return &SetupGate{path: path, token: token, now: time.Now}, nil
}

// Path is where the operator finds the token.
func (g *SetupGate) Path() string { return g.path }

// Active reports whether the gate can still be used.
func (g *SetupGate) Active() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.token != ""
}

// attempt checks token and, on success, consumes the gate. wait > 0 means
// throttled; ok is false for a wrong token.
func (g *SetupGate) attempt(token string) (ok bool, wait time.Duration) {
	if g == nil {
		return false, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token == "" {
		return false, 0
	}
	now := g.now()
	cutoff := now.Add(-time.Minute)
	kept := g.failures[:0]
	for _, t := range g.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	g.failures = kept
	if len(g.failures) >= 5 {
		return false, g.failures[0].Add(time.Minute).Sub(now)
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(token)), []byte(g.token)) != 1 {
		g.failures = append(g.failures, now)
		return false, 0
	}
	g.token = ""
	_ = os.Remove(g.path)
	return true, 0
}

// restore re-arms a gate whose consumption did not lead to an admin being created.
func (g *SetupGate) restore(token string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token == "" {
		g.token = strings.TrimSpace(token)
		_ = os.WriteFile(g.path, []byte(g.token+"\n"), 0o600)
	}
}
