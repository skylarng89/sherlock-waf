package api

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 test helper
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// totpNow is an independent TOTP implementation, so the API tests do not
// depend on the production one they are checking.
func totpNow(t *testing.T, seed string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
	require.NoError(t, err)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(time.Now().Unix()/30)) //nolint:gosec // positive
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}
