package challenge

import (
	"crypto/tls"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fakeClock(t *testing.T) *time.Time {
	t.Helper()
	Reset()
	c := time.Unix(1_000_000, 0)
	now = func() time.Time { return c }
	t.Cleanup(func() { now = time.Now; Reset() })
	return &c
}

func TestMarksExpireAndAreScopedPerKey(t *testing.T) {
	c := fakeClock(t)
	k := ClientKey("shop", netip.MustParseAddr("203.0.113.7"))
	assert.False(t, Any())
	assert.False(t, Marked(k))

	Mark(k, time.Minute)
	assert.True(t, Any())
	assert.True(t, Marked(k))
	assert.False(t, Marked(ClientKey("shop", netip.MustParseAddr("203.0.113.8"))), "another client is unaffected")
	assert.False(t, Marked(ClientKey("other", netip.MustParseAddr("203.0.113.7"))), "so is another site")

	*c = c.Add(2 * time.Minute)
	assert.False(t, Marked(k), "marks expire")
	assert.Zero(t, Len(), "an expired mark is dropped when seen")
	assert.False(t, Any())
}

func TestRemarkingExtendsAndIPv4MappedIsTheSameClient(t *testing.T) {
	c := fakeClock(t)
	Mark(ClientKey("s", netip.MustParseAddr("::ffff:198.51.100.1")), time.Minute)
	*c = c.Add(50 * time.Second)
	assert.True(t, Marked(ClientKey("s", netip.MustParseAddr("198.51.100.1"))))
	Mark(ClientKey("s", netip.MustParseAddr("198.51.100.1")), time.Minute)
	*c = c.Add(50 * time.Second)
	assert.True(t, Marked(ClientKey("s", netip.MustParseAddr("198.51.100.1"))), "marking again extends the mark")
	assert.Equal(t, 1, Len())
}

func TestTableIsBounded(t *testing.T) {
	fakeClock(t)
	for i := range MaxMarks + 500 {
		Mark(DeviceKey("s", string(rune('a'+i%26))+time.Duration(i).String()), time.Hour)
	}
	assert.LessOrEqual(t, Len(), MaxMarks)
	require.NotZero(t, Len())
}

func TestFingerprintIsStableAndSeparatesBrowsers(t *testing.T) {
	req := func(ua, lang string) *http.Request {
		r, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://x/login", http.NoBody)
		r.Header.Set("User-Agent", ua)
		r.Header.Set("Accept-Language", lang)
		r.Header.Set("Cookie", "session=volatile")
		return r
	}
	a := Fingerprint(req("Mozilla/5.0 A", "en-GB"))
	assert.Equal(t, a, Fingerprint(req("Mozilla/5.0 A", "en-GB")))
	assert.NotEqual(t, a, Fingerprint(req("Mozilla/5.0 B", "en-GB")))
	assert.NotEqual(t, a, Fingerprint(req("Mozilla/5.0 A", "fr-FR")))

	withCookie := req("Mozilla/5.0 A", "en-GB")
	withCookie.Header.Set("Cookie", "session=another")
	withCookie.Header.Set("X-Request-Id", "abc")
	assert.Equal(t, a, Fingerprint(withCookie), "per-session headers do not change the fingerprint")

	tlsReq := req("Mozilla/5.0 A", "en-GB")
	tlsReq.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256}
	assert.NotEqual(t, a, Fingerprint(tlsReq), "the TLS parameters are part of it")
}
