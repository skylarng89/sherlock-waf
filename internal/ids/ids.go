// Package ids generates the identifiers used across the control plane.
package ids

import (
	"crypto/rand"
	"fmt"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New returns a ULID: 48-bit millisecond timestamp plus 80 random
// bits, Crockford base32. It is sortable by creation time and unguessable.
func New(now time.Time) (string, error) {
	var b [16]byte
	ms := uint64(now.UnixMilli()) //nolint:gosec // UnixMilli is non-negative for any realistic clock
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("generating event id: %w", err)
	}

	// 128 bits encode as 26 base32 characters, the first holding only 3 bits.
	var out [26]byte
	var acc uint16
	bits, pos := 0, 25
	for i := 15; i >= 0; i-- {
		acc |= uint16(b[i]) << bits
		bits += 8
		for bits >= 5 {
			out[pos] = crockford[acc&31]
			pos--
			acc >>= 5
			bits -= 5
		}
	}
	if bits > 0 {
		out[pos] = crockford[acc&31]
	}
	return string(out[:]), nil
}
