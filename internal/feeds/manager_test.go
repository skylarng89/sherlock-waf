package feeds

import (
	"fmt"
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

func resetACL(t *testing.T) {
	t.Helper()
	acl.SetReputation(nil)
	acl.SetGeo(nil)
	acl.SetFeedStatus(acl.FeedStatus{})
	acl.Bans.Replace(nil)
	t.Cleanup(func() {
		acl.SetReputation(nil)
		acl.SetGeo(nil)
		acl.SetFeedStatus(acl.FeedStatus{})
		acl.Bans.Replace(nil)
	})
}

func statusOf(m *Manager, name string) Status {
	for _, s := range m.Statuses() {
		if s.Name == name {
			return s
		}
	}
	return Status{}
}

type fakeClock struct{ t atomic.Pointer[time.Time] }

func (c *fakeClock) now() time.Time  { return *c.t.Load() }
func (c *fakeClock) set(t time.Time) { c.t.Store(&t) }

func TestReputationListsRefreshAndKeepPreviousDataOnFailure(t *testing.T) {
	resetACL(t)
	var failDrop atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/firehol", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "# fh\n198.51.100.0/24\n") })
	mux.HandleFunc("/drop", func(w http.ResponseWriter, r *http.Request) {
		if failDrop.Load() {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprint(w, "; drop\n203.0.113.0/24 ; SBL1\n")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m := New(Options{DataDir: t.TempDir(), URLs: URLs{FireHOL: srv.URL + "/firehol", DROP: srv.URL + "/drop"}, HTTPAllowPublic: true})
	m.Apply(config.Feeds{ReputationLists: []string{config.ListFireHOLLevel1, config.ListSpamhausDROP}})
	assert.Equal(t, StateNeverLoaded, statusOf(m, config.ListSpamhausDROP).State)

	m.RefreshReputation(t.Context())
	assert.Equal(t, StateOK, statusOf(m, config.ListFireHOLLevel1).State)
	assert.Equal(t, 1, statusOf(m, config.ListSpamhausDROP).Entries)
	assert.True(t, acl.Status().ReputationReady)

	failDrop.Store(true)
	m.RefreshReputation(t.Context())
	drop := statusOf(m, config.ListSpamhausDROP)
	assert.Equal(t, StateFailed, drop.State)
	assert.Contains(t, drop.LastError, "502")
	assert.Equal(t, StateOK, statusOf(m, config.ListFireHOLLevel1).State, "one failing list does not affect the other")
	assert.Equal(t, 1, drop.Entries, "the previous entry count is retained")

	// The data from the failed list is still being enforced.
	m.mu.Lock()
	assert.Len(t, m.lists[config.ListSpamhausDROP], 1)
	m.mu.Unlock()
	assert.Equal(t, StateDisabled, statusOf(m, "crowdsec").State)
	assert.Equal(t, StateDisabled, statusOf(m, "geoip").State)
}

func TestReputationDownloadOfGarbageIsAFailureNotAnEmptyList(t *testing.T) {
	resetACL(t)
	good := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if good {
			_, _ = fmt.Fprint(w, "198.51.100.0/24\n")
			return
		}
		_, _ = fmt.Fprint(w, "<html>Too many requests</html>")
	}))
	defer srv.Close()
	m := New(Options{DataDir: t.TempDir(), URLs: URLs{FireHOL: srv.URL}, HTTPAllowPublic: true})
	m.Apply(config.Feeds{ReputationLists: []string{config.ListFireHOLLevel1}})
	m.RefreshReputation(t.Context())
	good = false
	m.RefreshReputation(t.Context())
	assert.Equal(t, StateFailed, statusOf(m, config.ListFireHOLLevel1).State)
	assert.True(t, acl.Status().ReputationReady, "the earlier list stays in force")
}

func TestStaleStatusAfterTooLongWithoutSuccess(t *testing.T) {
	resetACL(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "198.51.100.0/24\n") }))
	defer srv.Close()
	clk := &fakeClock{}
	clk.set(time.Now())
	m := New(Options{DataDir: t.TempDir(), URLs: URLs{FireHOL: srv.URL}, HTTPAllowPublic: true, Now: clk.now, ListEvery: time.Hour})
	m.Apply(config.Feeds{ReputationLists: []string{config.ListFireHOLLevel1}})
	m.RefreshReputation(t.Context())
	assert.Equal(t, StateOK, statusOf(m, config.ListFireHOLLevel1).State)
	clk.set(clk.now().Add(4 * time.Hour))
	assert.Equal(t, StateStale, statusOf(m, config.ListFireHOLLevel1).State)
}

func TestGeoManualUploadAndAutoUpdate(t *testing.T) {
	resetACL(t)
	dir := t.TempDir()
	csvData := "\"1.0.0.0\",\"1.0.0.255\",\"AU\"\n"

	// A file placed by hand is used even with auto-update off.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "geoip"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "geoip", "dbip-country-lite.csv.gz"), gz(t, csvData), 0o600))
	m := New(Options{DataDir: dir})
	m.Apply(config.Feeds{GeoIP: config.GeoIPFeed{Provider: config.GeoDBIPLite}})
	m.RefreshGeo(t.Context())
	assert.Equal(t, StateOK, statusOf(m, "geoip").State)
	assert.True(t, acl.Status().GeoReady)

	// Auto-update downloads when the file is missing, trying the previous month if this one 404s.
	dir2 := t.TempDir()
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if len(asked) == 1 {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(gz(t, "\"5.0.0.0\",\"5.0.0.255\",\"DE\"\n"))
	}))
	defer srv.Close()
	m2 := New(Options{DataDir: dir2, URLs: URLs{DBIPCountry: srv.URL + "/dbip-%s.csv.gz"}, HTTPAllowPublic: true})
	m2.Apply(config.Feeds{GeoIP: config.GeoIPFeed{Provider: config.GeoDBIPLite, AutoUpdate: true}})
	m2.RefreshGeo(t.Context())
	require.Len(t, asked, 2, "falls back to the previous month")
	assert.Equal(t, StateOK, statusOf(m2, "geoip").State)
	_, err := os.Stat(filepath.Join(dir2, "geoip", "dbip-country-lite.csv.gz"))
	assert.NoError(t, err)
}

func TestGeoBadDownloadNeverReplacesAGoodDatabase(t *testing.T) {
	resetACL(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "geoip", "dbip-country-lite.csv.gz")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	good := gz(t, "\"1.0.0.0\",\"1.0.0.255\",\"AU\"\n")
	require.NoError(t, os.WriteFile(path, good, 0o600))
	old := time.Now().Add(-40 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(path, old, old)) // stale, so a download is attempted

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "not a database") }))
	defer srv.Close()
	m := New(Options{DataDir: dir, URLs: URLs{DBIPCountry: srv.URL + "/%s"}, HTTPAllowPublic: true})
	m.Apply(config.Feeds{GeoIP: config.GeoIPFeed{Provider: config.GeoDBIPLite, AutoUpdate: true}})
	m.RefreshGeo(t.Context())

	after, err := os.ReadFile(path) //nolint:gosec // test path
	require.NoError(t, err)
	assert.Equal(t, good, after, "the good file is untouched")
	assert.True(t, acl.Status().GeoReady, "and still loaded")
}

func TestMaxMindIsReportedAsUnsupported(t *testing.T) {
	resetACL(t)
	m := New(Options{DataDir: t.TempDir()})
	m.Apply(config.Feeds{GeoIP: config.GeoIPFeed{Provider: config.GeoMaxMind, AutoUpdate: true}})
	m.RefreshGeo(t.Context())
	s := statusOf(m, "geoip")
	assert.Equal(t, StateFailed, s.State)
	assert.Contains(t, s.LastError, "maxmind")
}

func TestCrowdSecStreamBecomesBans(t *testing.T) {
	resetACL(t)
	var seen []string
	var key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RawQuery)
		key = r.Header.Get("X-Api-Key")
		if len(seen) == 1 {
			_, _ = fmt.Fprint(w, `{"new":[{"value":"203.0.113.50","duration":"3h59m59.5s","type":"ban","scope":"Ip","origin":"crowdsec"},
				{"value":"198.51.100.0/24","duration":"1h","type":"ban","scope":"Range","origin":"cscli"},
				{"value":"203.0.113.51","duration":"1h","type":"captcha","scope":"Ip","origin":"crowdsec"}],"deleted":null}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"new":null,"deleted":[{"value":"203.0.113.50","scope":"Ip"}]}`)
	}))
	defer srv.Close()

	m := New(Options{DataDir: t.TempDir(), HTTPAllowPublic: true, APIKey: func() string { return "sekret" }})
	m.Apply(config.Feeds{CrowdSec: config.CrowdSecConfig{Enabled: true, LAPIURL: srv.URL, AllowPrivate: true}})

	m.PollCrowdSec(t.Context())
	assert.Equal(t, "startup=true", seen[0], "the first poll asks for the full snapshot")
	assert.Equal(t, "sekret", key)
	_, banned := acl.Bans.Active(netip.MustParseAddr("203.0.113.50"), "any-site", time.Now())
	assert.True(t, banned, "an Ip ban decision becomes a ban on every site")
	_, other := acl.Bans.Active(netip.MustParseAddr("203.0.113.51"), "any-site", time.Now())
	assert.False(t, other, "only ban decisions are applied")
	assert.Equal(t, 1, statusOf(m, "crowdsec").Entries)

	m.PollCrowdSec(t.Context())
	assert.Equal(t, "", seen[1], "later polls ask for changes only")
	_, banned = acl.Bans.Active(netip.MustParseAddr("203.0.113.50"), "any-site", time.Now())
	assert.False(t, banned, "a deleted decision lifts the ban")
}

func TestCrowdSecRefusesInternalAddressesUnlessAllowedAndNeedsAKey(t *testing.T) {
	resetACL(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, `{"new":null,"deleted":null}`) }))
	defer srv.Close()

	m := New(Options{DataDir: t.TempDir(), APIKey: func() string { return "k" }})
	m.Apply(config.Feeds{CrowdSec: config.CrowdSecConfig{Enabled: true, LAPIURL: srv.URL}})
	m.PollCrowdSec(t.Context())
	s := statusOf(m, "crowdsec")
	assert.Equal(t, StateFailed, s.State)
	assert.Contains(t, s.LastError, "not allowed", "loopback is refused without allow_private")

	m.Apply(config.Feeds{CrowdSec: config.CrowdSecConfig{Enabled: true, LAPIURL: "http://169.254.169.254", AllowPrivate: true}})
	m.PollCrowdSec(t.Context())
	assert.Contains(t, statusOf(m, "crowdsec").LastError, "not allowed", "the metadata address is refused even with allow_private")

	noKey := New(Options{DataDir: t.TempDir(), APIKey: func() string { return "" }})
	noKey.Apply(config.Feeds{CrowdSec: config.CrowdSecConfig{Enabled: true, LAPIURL: srv.URL, AllowPrivate: true}})
	noKey.PollCrowdSec(t.Context())
	assert.Contains(t, statusOf(noKey, "crowdsec").LastError, EnvCrowdSecKey)
}
