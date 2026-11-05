package bot

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

const (
	challengeLifetime = 5 * time.Minute
	maxCounter        = 1 << 40
	replayCap         = 100_000
)

// issueChallenge returns a stateless proof-of-work challenge bound to the
// client. The solution is a counter such that hex(SHA-256(token + ":" + counter))
// starts with `difficulty` zero digits.
func issueChallenge(b binding, now time.Time, difficulty int) string {
	payload := make([]byte, 16+8+1)
	mustRead(payload[:16])
	binary.BigEndian.PutUint64(payload[16:24], uint64(now.Add(challengeLifetime).Unix())) //nolint:gosec // positive unix time
	payload[24] = byte(difficulty)                                                        //nolint:gosec // validated 1..6
	cur, _, _ := ring.keys(now)
	return b.seal(cur, "pow", payload)
}

// solved reports whether counter solves token for this client, and consumes the
// challenge so one solution cannot be replayed for further clearances.
func solved(b binding, now time.Time, token string, counter uint64) bool {
	payload, ok := b.open(now, "pow", token, 25)
	if !ok {
		return false
	}
	if now.Unix() >= int64(binary.BigEndian.Uint64(payload[16:24])) { //nolint:gosec // compared only
		return false
	}
	if counter > maxCounter || !leadingZeroHex(token, counter, int(payload[24])) {
		return false
	}
	return replays.consume(string(payload[:16]), now.Add(challengeLifetime))
}

func leadingZeroHex(token string, counter uint64, digits int) bool {
	sum := sha256.Sum256([]byte(token + ":" + utoa(counter)))
	const hexd = "0123456789abcdef"
	for i := range digits {
		b := sum[i/2]
		var nib byte
		if i%2 == 0 {
			nib = b >> 4
		} else {
			nib = b & 0x0f
		}
		if hexd[nib] != '0' {
			return false
		}
	}
	return true
}

func utoa(n uint64) string {
	var buf [20]byte
	i := len(buf)
	for {
		i--
		buf[i] = byte('0' + n%10) //nolint:gosec // single digit
		n /= 10
		if n == 0 {
			break
		}
	}
	return string(buf[i:])
}

// replayCache remembers used challenge nonces until they would have expired anyway.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

var replays = &replayCache{seen: map[string]time.Time{}}

// consume records nonce and reports whether it was new.
func (c *replayCache) consume(nonce string, until time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, used := c.seen[nonce]; used {
		return false
	}
	if len(c.seen) >= replayCap {
		now := time.Now()
		for k, exp := range c.seen {
			if now.After(exp) {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= replayCap { // an attacker burning nonces: fail closed for new solutions
			return false
		}
	}
	c.seen[nonce] = until
	return true
}

// SolveForTest finds a counter; production solving happens in the browser.
func solve(token string, difficulty int) uint64 {
	for c := uint64(0); ; c++ {
		if leadingZeroHex(token, c, difficulty) {
			return c
		}
	}
}
