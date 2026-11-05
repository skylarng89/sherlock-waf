package netx

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlocked(t *testing.T) {
	for ip, want := range map[string][2]bool{ // {blocked by default, blocked with AllowPrivate}
		"127.0.0.1":              {true, false},
		"::1":                    {true, false},
		"10.1.2.3":               {true, false},
		"192.168.0.9":            {true, false},
		"172.16.5.5":             {true, false},
		"fd00::1":                {true, false},
		"100.64.1.1":             {true, false},
		"169.254.169.254":        {true, true}, // cloud metadata: never allowed
		"fe80::1":                {true, true},
		"0.0.0.0":                {true, true},
		"224.0.0.1":              {true, true},
		"::ffff:127.0.0.1":       {true, false},
		"::ffff:169.254.169.254": {true, true},
		"203.0.113.9":            {false, false},
		"2001:db8::1":            {false, false},
	} {
		a := netip.MustParseAddr(ip)
		assert.Equal(t, want[0], Blocked(a, false), "%s default", ip)
		assert.Equal(t, want[1], Blocked(a, true), "%s allow-private", ip)
	}
}

func TestClientRefusesLoopbackByDefaultAndAllowsItWhenAsked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hello")) }))
	defer srv.Close()

	_, err := Get(t.Context(), NewClient(Options{}), srv.URL, 1024, nil)
	require.ErrorIs(t, err, ErrBlockedAddress)

	b, err := Get(t.Context(), NewClient(Options{AllowPrivate: true}), srv.URL, 1024, nil)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(b))
}

func TestRedirectsCannotReachBlockedAddresses(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("internal")) }))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer redirector.Close()

	// The first hop is allowed (opted in); the point is that the check is on every dial.
	c := NewClient(Options{AllowPrivate: true})
	b, err := Get(t.Context(), c, redirector.URL, 1024, nil)
	require.NoError(t, err)
	assert.Equal(t, "internal", string(b))

	_, err = Get(t.Context(), NewClient(Options{}), redirector.URL, 1024, nil)
	require.ErrorIs(t, err, ErrBlockedAddress)

	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer meta.Close()
	_, err = Get(t.Context(), NewClient(Options{AllowPrivate: true}), meta.URL, 1024, nil)
	require.ErrorIs(t, err, ErrBlockedAddress, "a redirect to the metadata address is refused even when private ranges are allowed")
}

func TestGetLimitsStatusSizeAndScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("a", 5000)))
		case "/404":
			http.NotFound(w, r)
		default:
			_, _ = w.Write([]byte(html.EscapeString(r.Header.Get("X-Api-Key"))))
		}
	}))
	defer srv.Close()
	c := NewClient(Options{AllowPrivate: true, Timeout: 5 * time.Second})

	_, err := Get(t.Context(), c, srv.URL+"/big", 1000, nil)
	assert.ErrorContains(t, err, "larger than")
	_, err = Get(t.Context(), c, srv.URL+"/404", 1000, nil)
	assert.ErrorContains(t, err, "status 404")
	_, err = Get(t.Context(), c, "file:///etc/passwd", 1000, nil)
	assert.ErrorContains(t, err, "not allowed")
	_, err = Get(t.Context(), c, "ftp://x/", 1000, nil)
	assert.Error(t, err)
	b, err := Get(t.Context(), c, srv.URL+"/key", 1000, http.Header{"X-Api-Key": {"k"}})
	require.NoError(t, err)
	assert.Equal(t, "k", string(b))
}

func TestErrorsDoNotLeakQueryStrings(t *testing.T) {
	_, err := Get(t.Context(), NewClient(Options{}), "http://127.0.0.1:1/x?key=secret", 10, nil)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secret")
}
