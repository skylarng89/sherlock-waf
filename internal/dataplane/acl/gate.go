package acl

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// gate verifies HTTP Basic credentials against an argon2id hash. Verifying
// costs tens of milliseconds and 64 MiB, so successful credentials are cached
// (as an HMAC under a per-process key, never the password) for a few minutes
// and concurrent verifications are bounded; without both, anonymous clients
// could exhaust CPU and memory by guessing at the gate.
type gate struct {
	username string
	hash     phc

	key   [32]byte
	slots chan struct{}

	mu    sync.Mutex
	cache map[[32]byte]time.Time
	now   func() time.Time
}

const (
	gateCacheTTL = 5 * time.Minute
	gateCacheMax = 1024
	gateSlots    = 4
)

type phc struct {
	memory, time uint32
	threads      uint8
	salt, sum    []byte
}

func newGate(username, encoded string) (*gate, error) {
	h, err := parsePHC(encoded)
	if err != nil {
		return nil, err
	}
	g := &gate{username: username, hash: h, slots: make(chan struct{}, gateSlots), cache: map[[32]byte]time.Time{}, now: time.Now}
	if _, err := rand.Read(g.key[:]); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *gate) check(user, pass string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(g.username)) == 1
	tag := g.tag(user, pass)
	if userOK && g.cached(tag) {
		return true
	}
	g.slots <- struct{}{}
	defer func() { <-g.slots }()
	sum := argon2.IDKey([]byte(pass), g.hash.salt, g.hash.time, g.hash.memory, g.hash.threads, uint32(len(g.hash.sum))) //nolint:gosec // length bounded by parsePHC
	ok := subtle.ConstantTimeCompare(sum, g.hash.sum) == 1 && userOK
	if ok {
		g.remember(tag)
	}
	return ok
}

func (g *gate) tag(user, pass string) [32]byte {
	m := hmac.New(sha256.New, g.key[:])
	m.Write([]byte(user))
	m.Write([]byte{0})
	m.Write([]byte(pass))
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func (g *gate) cached(tag [32]byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	exp, ok := g.cache[tag]
	if ok && g.now().Before(exp) {
		return true
	}
	delete(g.cache, tag)
	return false
}

func (g *gate) remember(tag [32]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.cache) >= gateCacheMax {
		now := g.now()
		for k, exp := range g.cache {
			if now.After(exp) {
				delete(g.cache, k)
			}
		}
		if len(g.cache) >= gateCacheMax {
			clear(g.cache)
		}
	}
	g.cache[tag] = g.now().Add(gateCacheTTL)
}

// parsePHC accepts only argon2id and caps cost parameters so a hostile
// configuration cannot demand unbounded memory per request.
func parsePHC(s string) (phc, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return phc{}, errors.New("password_hash must be an argon2id hash (v=19)")
	}
	var p phc
	var m, t, th uint64
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if !ok || err != nil {
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
