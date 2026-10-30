// Package bot is the sherlock_bot Caddy module: it makes suspicious clients
// prove they are a browser (a self-hosted proof of work, or Turnstile or
// hCaptcha), remembers the result in a signed clearance cookie, and gives
// search-engine crawlers that verify by reverse DNS their own policy.
package bot

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Cookie is the clearance cookie name.
const Cookie = "__sherlock_clearance"

// keyLifetime is how often the signing key rotates. The previous key stays
// valid for one more period so a rotation does not drop every clearance.
const keyLifetime = 24 * time.Hour

type keyRing struct {
	mu      sync.Mutex
	cur     [32]byte
	prev    [32]byte
	hasPrev bool
	born    time.Time
}

var ring = &keyRing{}

func (k *keyRing) keys(now time.Time) (cur [32]byte, prev [32]byte, hasPrev bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.born.IsZero() {
		mustRead(k.cur[:])
		k.born = now
	} else if now.Sub(k.born) >= keyLifetime {
		k.prev, k.hasPrev = k.cur, true
		mustRead(k.cur[:])
		k.born = now
	}
	return k.cur, k.prev, k.hasPrev
}

func mustRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error()) // no safe fallback exists
	}
}

// binding is what a token is tied to: the client network, its user agent and
// the site. A cookie copied to another network or browser does not verify.
type binding struct {
	prefix string
	ua     string
	site   string
}

func bindingFor(ip netip.Addr, userAgent, site string) binding {
	ip = ip.Unmap()
	bits := 24
	if ip.Is6() {
		bits = 48
	}
	p, _ := ip.Prefix(bits)
	sum := sha256.Sum256([]byte(userAgent))
	return binding{prefix: p.String(), ua: hex.EncodeToString(sum[:8]), site: site}
}

func (b binding) mac(key [32]byte, purpose string, payload []byte) []byte {
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte("v1|" + purpose + "|" + b.prefix + "|" + b.ua + "|" + b.site + "|"))
	m.Write(payload)
	return m.Sum(nil)
}

// seal returns base64url(payload || mac).
func (b binding) seal(key [32]byte, purpose string, payload []byte) string {
	return base64.RawURLEncoding.EncodeToString(append(append([]byte{}, payload...), b.mac(key, purpose, payload)...))
}

// open verifies a sealed value under the current or previous key, in constant
// time, and returns the payload.
func (b binding) open(now time.Time, purpose, token string, payloadLen int) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != payloadLen+sha256.Size {
		return nil, false
	}
	payload, tag := raw[:payloadLen], raw[payloadLen:]
	cur, prev, hasPrev := ring.keys(now)
	ok := subtle.ConstantTimeCompare(tag, b.mac(cur, purpose, payload)) == 1
	if hasPrev { // evaluated unconditionally so timing does not reveal which key matched
		ok = subtle.ConstantTimeCompare(tag, b.mac(prev, purpose, payload)) == 1 || ok
	}
	return payload, ok
}

// IssueClearance returns a cookie value valid for ttl.
func issueClearance(b binding, now time.Time, ttl time.Duration) (value string, expires time.Time) {
	expires = now.Add(ttl)
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(expires.Unix())) //nolint:gosec // positive unix time
	cur, _, _ := ring.keys(now)
	return b.seal(cur, "clr", payload), expires
}

// validClearance reports whether value is an unexpired clearance for this binding.
func validClearance(b binding, now time.Time, value string) bool {
	payload, ok := b.open(now, "clr", value, 8)
	if !ok {
		return false
	}
	exp := int64(binary.BigEndian.Uint64(payload)) //nolint:gosec // compared, not indexed
	return now.Unix() < exp
}

func itoa(n int) string { return strconv.Itoa(n) }
