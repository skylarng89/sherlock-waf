package feeds

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
)

// The fixtures come from tools/cmd/mmdbfixture; they use documentation address space.
const (
	countryFixture = "testdata/GeoLite2-Country-test.mmdb"
	cityFixture    = "testdata/GeoIP2-City-test.mmdb"

	testAccount = "123456"
	testKey     = "license-key-sekret-XYZ"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // fixed test fixture path
	require.NoError(t, err)
	return b
}

// tarGz builds an archive holding the given regular files.
func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}))
		_, err := tw.Write(body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func maxMindArchive(t *testing.T, mmdb []byte) []byte {
	t.Helper()
	return tarGz(t, map[string][]byte{"GeoLite2-Country_20261027/LICENSE.txt": []byte("license"), "GeoLite2-Country_20261027/GeoLite2-Country.mmdb": mmdb})
}

// maxMindServer serves body at the GeoLite2 permalink and records every request.
type maxMindServer struct {
	*httptest.Server
	hits     atomic.Int32
	lastAuth atomic.Value
	lastURL  atomic.Value
}

func newMaxMindServer(t *testing.T, status int, body []byte) *maxMindServer {
	t.Helper()
	s := &maxMindServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.lastAuth.Store(r.Header.Get("Authorization"))
		s.lastURL.Store(r.URL.String())
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func maxMindManager(t *testing.T, dir, url string, logger *slog.Logger) *Manager {
	t.Helper()
	m := New(Options{
		DataDir:           dir,
		URLs:              URLs{MaxMindCountry: url},
		HTTPAllowPublic:   true,
		Logger:            logger,
		MaxMindAccountID:  func() string { return testAccount },
		MaxMindLicenseKey: func() string { return testKey },
	})
	m.Apply(config.Feeds{GeoIP: config.GeoIPFeed{Provider: config.GeoMaxMind, AutoUpdate: true}})
	return m
}

func geoFile(dir string) string { return filepath.Join(dir, "geoip", maxMindGeoFile) }

func TestMaxMindCountryLookups(t *testing.T) {
	db, err := ParseMaxMindCountry(readFixture(t, countryFixture))
	require.NoError(t, err)
	for ip, want := range map[string]string{
		"198.51.100.7":        "AU",
		"203.0.113.250":       "DE",
		"2001:db8::1":         "JP",
		"::ffff:198.51.100.7": "AU", // mapped IPv4 resolves like IPv4
	} {
		cc, ok := db.Country(netip.MustParseAddr(ip))
		assert.True(t, ok, ip)
		assert.Equal(t, want, cc, ip)
	}
	_, ok := db.Country(netip.MustParseAddr("192.0.2.1"))
	assert.False(t, ok, "an address outside the database is unknown")
}

func TestParseMaxMindCountryRejectsOtherDatabasesAndGarbage(t *testing.T) {
	tests := map[string]struct {
		data    []byte
		wantErr string
	}{
		"city database":  {readFixture(t, cityFixture), "not a country database"},
		"not an mmdb":    {[]byte("<html>Too many requests</html>"), "opening mmdb"},
		"empty download": {nil, "opening mmdb"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseMaxMindCountry(tc.data)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestExtractMMDB(t *testing.T) {
	mmdb := readFixture(t, countryFixture)
	const big = 64 << 10
	tests := map[string]struct {
		archive    []byte
		maxStream  int64
		maxEntry   int64
		wantErr    string
		wantSameAs []byte
	}{
		"entry found in a nested directory": {archive: maxMindArchive(t, mmdb), maxStream: big, maxEntry: big, wantSameAs: mmdb},
		"traversal-looking name is only matched by base name": {
			archive:    tarGz(t, map[string][]byte{"../../etc/GeoLite2-Country.mmdb": mmdb}),
			maxStream:  big,
			maxEntry:   big,
			wantSameAs: mmdb,
		},
		"no entry":        {archive: tarGz(t, map[string][]byte{"LICENSE.txt": []byte("x")}), maxStream: big, maxEntry: big, wantErr: "has no GeoLite2-Country.mmdb"},
		"not gzip":        {archive: []byte("plain text"), maxStream: big, maxEntry: big, wantErr: "opening archive"},
		"entry too large": {archive: maxMindArchive(t, mmdb), maxStream: big, maxEntry: 16, wantErr: "larger than 16 bytes"},
		"stream too large": {
			archive:   maxMindArchive(t, mmdb),
			maxStream: 512, // the tar stream is larger than this, so reading stops with an error
			maxEntry:  big,
			wantErr:   "unexpected EOF",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := extractMMDB(tc.archive, tc.maxStream, tc.maxEntry)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantSameAs, got)
		})
	}
}

func TestRedactRemovesSecretsFromErrors(t *testing.T) {
	base := base64.StdEncoding.EncodeToString([]byte(testAccount + ":" + testKey))
	err := redact(errors.New("boom "+testKey+" "+testAccount+" "+base), testAccount, testKey, base)
	assert.NotContains(t, err.Error(), testKey)
	assert.NotContains(t, err.Error(), base)
	assert.Contains(t, err.Error(), "boom <redacted>")

	clean := errors.New("status 500")
	assert.Same(t, clean, redact(clean, testKey), "an error without secrets is returned unchanged")
}

func TestMaxMindRefreshDownloadsWithBasicAuthAndSwaps(t *testing.T) {
	resetACL(t)
	dir := t.TempDir()
	srv := newMaxMindServer(t, http.StatusOK, maxMindArchive(t, readFixture(t, countryFixture)))
	m := maxMindManager(t, dir, srv.URL+"/download?suffix=tar.gz", nil)

	m.RefreshGeo(t.Context())

	require.Equal(t, int32(1), srv.hits.Load())
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(testAccount+":"+testKey))
	assert.Equal(t, wantAuth, srv.lastAuth.Load())
	assert.NotContains(t, srv.lastURL.Load(), testKey, "the licence key never appears in the URL")
	assert.NotContains(t, srv.lastURL.Load(), testAccount, "nor the account ID")

	s := statusOf(m, "geoip")
	assert.Equal(t, StateOK, s.State)
	assert.Empty(t, s.LastError)
	cc, ok := acl.CountryOf(netip.MustParseAddr("198.51.100.7"))
	assert.True(t, ok)
	assert.Equal(t, "AU", cc)

	info, err := os.Stat(geoFile(dir))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	_, err = os.Stat(geoFile(dir) + ".tmp")
	assert.True(t, os.IsNotExist(err), "the temporary file is renamed away")
}

func TestMaxMindBadDownloadsNeverReplaceAGoodDatabase(t *testing.T) {
	cityArchive := maxMindArchive(t, readFixture(t, cityFixture))
	tests := map[string]struct {
		status  int
		body    []byte
		wantErr string
	}{
		"not an archive":           {http.StatusOK, []byte("<html>nope</html>"), "opening archive"},
		"wrong database_type":      {http.StatusOK, cityArchive, "not a country database"},
		"unauthorised":             {http.StatusUnauthorized, []byte("bad credentials"), "status 401"},
		"archive without the mmdb": {http.StatusOK, tarGz(t, map[string][]byte{"README": []byte("x")}), "has no GeoLite2-Country.mmdb"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			resetACL(t)
			dir := t.TempDir()
			good := readFixture(t, countryFixture)
			require.NoError(t, os.MkdirAll(filepath.Dir(geoFile(dir)), 0o700))
			require.NoError(t, os.WriteFile(geoFile(dir), good, 0o600))
			old := time.Now().Add(-30 * 24 * time.Hour)
			require.NoError(t, os.Chtimes(geoFile(dir), old, old)) // stale, so a download is attempted

			srv := newMaxMindServer(t, tc.status, tc.body)
			m := maxMindManager(t, dir, srv.URL, nil)
			m.RefreshGeo(t.Context())

			after, err := os.ReadFile(geoFile(dir)) //nolint:gosec // test path
			require.NoError(t, err)
			assert.Equal(t, good, after, "the good file is untouched")
			s := statusOf(m, "geoip")
			assert.Equal(t, StateFailed, s.State)
			assert.Contains(t, s.LastError, tc.wantErr)
			assert.True(t, acl.Status().GeoReady, "the previous database stays in force")
		})
	}
}

func TestMaxMindOversizeArchiveIsRefused(t *testing.T) {
	resetACL(t)
	dir := t.TempDir()
	srv := newMaxMindServer(t, http.StatusOK, maxMindArchive(t, readFixture(t, countryFixture)))
	m := maxMindManager(t, dir, srv.URL, nil)
	m.limits.archive = 100
	m.RefreshGeo(t.Context())

	s := statusOf(m, "geoip")
	assert.Equal(t, StateFailed, s.State)
	assert.Contains(t, s.LastError, "larger than 100 bytes")
	_, err := os.Stat(geoFile(dir))
	assert.True(t, os.IsNotExist(err), "nothing is written")
}

func TestMaxMindCredentialsNeverReachStatusOrLogs(t *testing.T) {
	resetACL(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// The server echoes the request credentials back in its error body, the way a
	// careless upstream might. The status must not store them.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("denied for account " + testAccount + " with key " + testKey))
	}))
	defer srv.Close()

	m := maxMindManager(t, t.TempDir(), srv.URL, logger)
	m.RefreshGeo(t.Context())

	s := statusOf(m, "geoip")
	assert.Equal(t, StateFailed, s.State)
	base := base64.StdEncoding.EncodeToString([]byte(testAccount + ":" + testKey))
	for _, secret := range []string{testKey, testAccount, base} {
		assert.NotContains(t, s.LastError, secret)
		assert.NotContains(t, logs.String(), secret)
	}
}

func TestMaxMindRedirectToMetadataAddressIsRefused(t *testing.T) {
	resetACL(t)
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("secret")) }))
	defer meta.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The first hop is reachable (HTTPAllowPublic in tests); the redirect target is the metadata address.
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer first.Close()

	m := maxMindManager(t, t.TempDir(), first.URL, nil)
	m.RefreshGeo(t.Context())

	s := statusOf(m, "geoip")
	assert.Equal(t, StateFailed, s.State)
	assert.Contains(t, s.LastError, "not allowed", "the redirect hop is dialled and refused by netx")
	assert.Contains(t, s.LastError, "169.254.169.254", "the blocked destination is named")
}

func TestMaxMindNeedsBothCredentials(t *testing.T) {
	resetACL(t)
	srv := newMaxMindServer(t, http.StatusOK, nil)
	m := New(Options{
		DataDir:           t.TempDir(),
		URLs:              URLs{MaxMindCountry: srv.URL},
		HTTPAllowPublic:   true,
		MaxMindAccountID:  func() string { return testAccount },
		MaxMindLicenseKey: func() string { return "" },
	})
	m.Apply(config.Feeds{GeoIP: config.GeoIPFeed{Provider: config.GeoMaxMind, AutoUpdate: true}})
	m.RefreshGeo(t.Context())

	s := statusOf(m, "geoip")
	assert.Equal(t, StateFailed, s.State)
	assert.Contains(t, s.LastError, EnvMaxMindLicenseKey)
	assert.Equal(t, int32(0), srv.hits.Load(), "no request is made without credentials")
}

func TestMaxMindAutoUpdateFollowsTheWeeklyAge(t *testing.T) {
	tests := map[string]struct {
		age      time.Duration
		wantHits int32
	}{
		"fresh file is not downloaded": {age: 2 * 24 * time.Hour, wantHits: 0},
		"week-old file is refreshed":   {age: 9 * 24 * time.Hour, wantHits: 1},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			resetACL(t)
			dir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Dir(geoFile(dir)), 0o700))
			require.NoError(t, os.WriteFile(geoFile(dir), readFixture(t, countryFixture), 0o600))
			mod := time.Now().Add(-tc.age)
			require.NoError(t, os.Chtimes(geoFile(dir), mod, mod))

			srv := newMaxMindServer(t, http.StatusOK, maxMindArchive(t, readFixture(t, countryFixture)))
			m := maxMindManager(t, dir, srv.URL, nil)
			m.RefreshGeo(t.Context())
			assert.Equal(t, tc.wantHits, srv.hits.Load())
			assert.Equal(t, StateOK, statusOf(m, "geoip").State)
		})
	}
}

func TestMaxMindManualUploadIsUsedAsIs(t *testing.T) {
	resetACL(t)
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Dir(geoFile(dir)), 0o700))
	require.NoError(t, os.WriteFile(geoFile(dir), readFixture(t, countryFixture), 0o600))

	m := New(Options{DataDir: dir})
	m.Apply(config.Feeds{GeoIP: config.GeoIPFeed{Provider: config.GeoMaxMind}})
	m.RefreshGeo(t.Context())

	assert.Equal(t, StateOK, statusOf(m, "geoip").State)
	assert.True(t, acl.Status().GeoReady)
	cc, ok := acl.CountryOf(netip.MustParseAddr("2001:db8::1"))
	assert.True(t, ok)
	assert.Equal(t, "JP", cc)
}

func TestProvidersNeverReadEachOthersFiles(t *testing.T) {
	resetACL(t)
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Dir(geoFile(dir)), 0o700))
	require.NoError(t, os.WriteFile(geoFile(dir), readFixture(t, countryFixture), 0o600))

	// A MaxMind file alone must not satisfy the DB-IP provider.
	m := New(Options{DataDir: dir})
	m.Apply(config.Feeds{GeoIP: config.GeoIPFeed{Provider: config.GeoDBIPLite}})
	m.RefreshGeo(t.Context())
	assert.Equal(t, StateDisabled, statusOf(m, "geoip").State)
	assert.False(t, acl.Status().GeoReady)
}
