// Package challenge is the hand-off between modules that notice a suspicious
// client only after the bot module has already run (login protection learns of
// a failure from the upstream's response) and the bot module, which serves the
// actual challenge. A module marks a client; the bot module consults the marks
// before it decides. Marks expire and the table is bounded, so a flood of
// distinct clients cannot grow it without limit (the oldest marks go first,
// which only makes the system more lenient, never stricter).
package challenge

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// MaxMarks bounds the table.
const MaxMarks = 1 << 16

type mark struct {
	key   string
	until time.Time
	elem  *list.Element
}

var (
	mu    sync.Mutex
	marks = map[string]*mark{}
	lru   = list.New() // front = most recently marked
	size  atomic.Int64 // len(marks), readable without the lock

	now = time.Now
)

// ClientKey identifies a client address on a site.
func ClientKey(site string, ip netip.Addr) string { return "ip|" + site + "|" + ip.Unmap().String() }

// DeviceKey identifies a device fingerprint (see Fingerprint) on a site.
func DeviceKey(site, fingerprint string) string { return "dev|" + site + "|" + fingerprint }

// Mark requires a challenge from key until ttl has passed.
func Mark(key string, ttl time.Duration) {
	until := now().Add(ttl)
	mu.Lock()
	defer mu.Unlock()
	if m, ok := marks[key]; ok {
		m.until = until
		lru.MoveToFront(m.elem)
		return
	}
	m := &mark{key: key, until: until}
	m.elem = lru.PushFront(m)
	marks[key] = m
	for len(marks) > MaxMarks {
		oldest := lru.Back()
		lru.Remove(oldest)
		delete(marks, oldest.Value.(*mark).key) //nolint:forcetypeassert // the list only holds *mark
	}
	size.Store(int64(len(marks)))
}

// Marked reports whether key must still be challenged.
func Marked(key string) bool {
	if size.Load() == 0 {
		return false // the common case: nothing marked, no lock taken
	}
	mu.Lock()
	defer mu.Unlock()
	m, ok := marks[key]
	if !ok {
		return false
	}
	if !now().Before(m.until) {
		lru.Remove(m.elem)
		delete(marks, key)
		size.Store(int64(len(marks)))
		return false
	}
	return true
}

// Any reports whether any mark exists, so callers can skip deriving keys.
func Any() bool { return size.Load() > 0 }

// Len is the number of marks held (for tests).
func Len() int { return int(size.Load()) }

// Reset drops every mark (for tests).
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	clear(marks)
	lru.Init()
	size.Store(0)
}

// stableHeaders are request headers whose value identifies a browser build and
// language setup rather than a page or a session. The values of the first group
// are hashed; the second group only contributes whether the header is present.
var (
	valueHeaders    = []string{"User-Agent", "Accept-Language", "Accept-Encoding", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform"}
	presenceHeaders = []string{"Accept", "Dnt", "Sec-Gpc", "Upgrade-Insecure-Requests"}
)

// Fingerprint is a short hash of what stays the same for one browser or tool
// across addresses: a few stable header values, which headers are present, and
// the TLS version and cipher when the request came over TLS. It is not a
// secret and not unique to a person: many users of the same browser build share
// one, so a counter on it is only a hint. JA4 is not available from the
// embedded Caddy, so it is not part of this.
func Fingerprint(r *http.Request) string {
	var buf [384]byte
	b := buf[:0]
	for _, h := range valueHeaders {
		b = append(b, r.Header.Get(h)...)
		b = append(b, 0)
	}
	for _, h := range presenceHeaders {
		if _, ok := r.Header[h]; ok {
			b = append(b, '1')
		} else {
			b = append(b, '0')
		}
	}
	if r.TLS != nil {
		b = binary.BigEndian.AppendUint16(b, r.TLS.Version)
		b = binary.BigEndian.AppendUint16(b, r.TLS.CipherSuite)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
