package feeds

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/acl"
	"github.com/skylarng89/sherlock-waf/internal/netx"
	"github.com/skylarng89/sherlock-waf/internal/policy/ipset"
)

// Environment variables holding feed credentials; they are never part of the configuration.
const (
	EnvCrowdSecKey       = "SHERLOCK_CROWDSEC_API_KEY"
	EnvMaxMindAccountID  = "SHERLOCK_MAXMIND_ACCOUNT_ID"
	EnvMaxMindLicenseKey = "SHERLOCK_MAXMIND_LICENSE_KEY"
)

// Geo database files under <data-dir>/geoip and their maximum age before a download is due.
// GeoLite2 is published weekly, so a week-old MaxMind file is already due.
const (
	dbipGeoFile      = "dbip-country-lite.csv.gz"
	maxMindGeoFile   = "GeoLite2-Country.mmdb"
	maxMindEntryName = "GeoLite2-Country.mmdb"
	dbipGeoMaxAge    = 21 * 24 * time.Hour
	maxMindGeoMaxAge = 8 * 24 * time.Hour
)

// Size caps for the MaxMind download: the archive as received, the decompressed
// tar stream (which bounds gzip bombs) and the .mmdb entry itself.
const (
	maxMindArchiveCap = 64 << 20
	maxMindStreamCap  = 256 << 20
	maxMindEntryCap   = 128 << 20
)

// State values reported for each feed.
const (
	StateDisabled    = "disabled"
	StateNeverLoaded = "never_loaded"
	StateOK          = "ok"
	StateStale       = "stale"
	StateFailed      = "failed"
)

// Status is the health of one feed, for GET /feeds/status and metrics.
type Status struct {
	Name        string
	State       string
	LastSuccess time.Time
	LastError   string
	Entries     int
}

// URLs are the download locations; tests point them at local servers.
type URLs struct {
	FireHOL string
	DROP    string
	// DBIPCountry is a format with %s for "YYYY-MM".
	DBIPCountry string
	// MaxMindCountry is the GeoLite2-Country permalink (tar.gz). Credentials go
	// in an Authorization header, never in this URL.
	MaxMindCountry string
}

// DefaultURLs are the public sources.
var DefaultURLs = URLs{
	FireHOL:        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
	DROP:           "https://www.spamhaus.org/drop/drop.txt",
	DBIPCountry:    "https://download.db-ip.com/free/dbip-country-lite-%s.csv.gz",
	MaxMindCountry: "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz",
}

// Options configures a Manager.
type Options struct {
	DataDir string
	Logger  *slog.Logger
	URLs    URLs
	// Now and the intervals are overridable for tests.
	Now             func() time.Time
	ListEvery       time.Duration // reputation lists
	GeoEvery        time.Duration // GeoIP file freshness check
	CrowdSecEvery   time.Duration
	HTTPAllowPublic bool // tests: use a client that may dial loopback for every feed
	APIKey          func() string
	// MaxMind credentials: the account ID is the HTTP basic user, the licence key the password.
	MaxMindAccountID  func() string
	MaxMindLicenseKey func() string
}

// mmdbLimits bounds the MaxMind download; tests lower them.
type mmdbLimits struct {
	archive, stream, entry int64
}

// Manager refreshes feeds according to the live configuration.
type Manager struct {
	o      Options
	client *http.Client
	limits mmdbLimits

	mu       sync.Mutex
	cfg      config.Feeds
	status   map[string]*Status
	lists    map[string][]netip.Prefix // per reputation list, last good copy
	csClient *http.Client
	csAllow  bool
	csCursor bool // the startup snapshot was received
	wake     chan struct{}
}

// New returns a Manager. Call Apply with the configuration, then Run.
func New(o Options) *Manager {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.URLs == (URLs{}) {
		o.URLs = DefaultURLs
	}
	if o.ListEvery <= 0 {
		o.ListEvery = 6 * time.Hour
	}
	if o.GeoEvery <= 0 {
		o.GeoEvery = 12 * time.Hour
	}
	if o.CrowdSecEvery <= 0 {
		o.CrowdSecEvery = 30 * time.Second
	}
	if o.APIKey == nil {
		o.APIKey = func() string { return os.Getenv(EnvCrowdSecKey) }
	}
	if o.MaxMindAccountID == nil {
		o.MaxMindAccountID = func() string { return os.Getenv(EnvMaxMindAccountID) }
	}
	if o.MaxMindLicenseKey == nil {
		o.MaxMindLicenseKey = func() string { return os.Getenv(EnvMaxMindLicenseKey) }
	}
	m := &Manager{
		o:      o,
		status: map[string]*Status{},
		lists:  map[string][]netip.Prefix{},
		wake:   make(chan struct{}, 1),
		limits: mmdbLimits{archive: maxMindArchiveCap, stream: maxMindStreamCap, entry: maxMindEntryCap},
	}
	m.client = netx.NewClient(netx.Options{AllowPrivate: o.HTTPAllowPublic, Timeout: 60 * time.Second})
	return m
}

// Apply installs a configuration and triggers a refresh of anything newly enabled.
func (m *Manager) Apply(f config.Feeds) {
	m.mu.Lock()
	m.cfg = f
	m.csClient = netx.NewClient(netx.Options{AllowPrivate: f.CrowdSec.AllowPrivate || m.o.HTTPAllowPublic, Timeout: 20 * time.Second})
	m.csAllow = f.CrowdSec.AllowPrivate
	m.csCursor = false // a changed LAPI starts from a fresh snapshot
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Statuses reports every feed, enabled or not, in a stable order.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.o.Now()
	enabled := m.enabledLocked()
	var out []Status
	for _, name := range []string{"geoip", config.ListFireHOLLevel1, config.ListSpamhausDROP, "crowdsec"} {
		st := Status{Name: name, State: StateDisabled}
		if !enabled[name] {
			out = append(out, st)
			continue
		}
		st.State = StateNeverLoaded
		if s := m.status[name]; s != nil {
			st = *s
			st.State = m.stateLocked(name, s, now)
		}
		out = append(out, st)
	}
	return out
}

func (m *Manager) stateLocked(name string, s *Status, now time.Time) string {
	switch {
	case s.LastError != "":
		return StateFailed
	case s.LastSuccess.IsZero():
		return StateNeverLoaded
	}
	limit := 3 * m.o.ListEvery
	switch name {
	case "geoip":
		limit = 45 * 24 * time.Hour
	case "crowdsec":
		limit = 10 * m.o.CrowdSecEvery
	}
	if now.Sub(s.LastSuccess) > limit {
		return StateStale
	}
	return StateOK
}

func (m *Manager) enabledLocked() map[string]bool {
	e := map[string]bool{"geoip": m.cfg.GeoIP.AutoUpdate || m.geoFileExists(m.cfg.GeoIP.Provider), "crowdsec": m.cfg.CrowdSec.Enabled}
	for _, l := range m.cfg.ReputationLists {
		e[l] = true
	}
	return e
}

func (m *Manager) setStatus(name string, entries int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status[name]
	if s == nil {
		s = &Status{Name: name}
		m.status[name] = s
	}
	if err != nil {
		s.LastError = err.Error()
		return
	}
	s.LastError, s.LastSuccess, s.Entries = "", m.o.Now(), entries
}

// Run refreshes until ctx ends: once when started or reconfigured, then on the intervals.
func (m *Manager) Run(ctx context.Context) {
	lists := time.NewTicker(m.o.ListEvery)
	geo := time.NewTicker(m.o.GeoEvery)
	cs := time.NewTicker(m.o.CrowdSecEvery)
	defer lists.Stop()
	defer geo.Stop()
	defer cs.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
			m.RefreshReputation(ctx)
			m.RefreshGeo(ctx)
			m.PollCrowdSec(ctx)
		case <-lists.C:
			m.RefreshReputation(ctx)
		case <-geo.C:
			m.RefreshGeo(ctx)
		case <-cs.C:
			m.PollCrowdSec(ctx)
		}
	}
}

// RefreshReputation downloads the enabled lists and swaps the union in. A list
// that fails keeps its previous copy; the others still refresh.
func (m *Manager) RefreshReputation(ctx context.Context) {
	m.mu.Lock()
	names := slices.Clone(m.cfg.ReputationLists)
	m.mu.Unlock()

	urls := map[string]string{config.ListFireHOLLevel1: m.o.URLs.FireHOL, config.ListSpamhausDROP: m.o.URLs.DROP}
	for _, name := range names {
		body, err := netx.Get(ctx, m.client, urls[name], 16<<20, nil)
		var ps []netip.Prefix
		if err == nil {
			ps, err = ParseNetset(body)
		}
		if err != nil {
			m.o.Logger.Warn("reputation list refresh failed; keeping the previous copy", "list", name, "error", err)
			m.setStatus(name, 0, err)
			continue
		}
		m.mu.Lock()
		m.lists[name] = ps
		m.mu.Unlock()
		m.setStatus(name, len(ps), nil)
	}
	m.publishReputation(names)
}

func (m *Manager) publishReputation(enabled []string) {
	b := ipset.NewBuilder()
	n := 0
	m.mu.Lock()
	for _, name := range enabled {
		for _, p := range m.lists[name] {
			b.Add(p)
			n++
		}
	}
	m.mu.Unlock()
	if n == 0 {
		acl.SetReputation(nil)
	} else {
		acl.SetReputation(b.Build())
	}
	st := acl.Status()
	st.ReputationReady = n > 0
	acl.SetFeedStatus(st)
}

// geoFileName is the file under <data-dir>/geoip for a provider. Each provider
// has its own file, so switching providers never loads the wrong format.
func geoFileName(provider string) string {
	if provider == config.GeoMaxMind {
		return maxMindGeoFile
	}
	return dbipGeoFile
}

func geoMaxAge(provider string) time.Duration {
	if provider == config.GeoMaxMind {
		return maxMindGeoMaxAge
	}
	return dbipGeoMaxAge
}

func (m *Manager) geoPath(provider string) string {
	return filepath.Join(m.o.DataDir, "geoip", geoFileName(provider))
}

func (m *Manager) geoFileExists(provider string) bool {
	_, err := os.Stat(m.geoPath(provider))
	return err == nil
}

// RefreshGeo loads the country database, downloading it first when auto-update
// is on and the file is missing or older than the provider's maximum age. A
// file placed in <data-dir>/geoip by hand (a manual upload) is used as is.
func (m *Manager) RefreshGeo(ctx context.Context) {
	m.mu.Lock()
	cfg := m.cfg.GeoIP
	m.mu.Unlock()
	path := m.geoPath(cfg.Provider)
	info, err := os.Stat(path)
	stale := err != nil || m.o.Now().Sub(info.ModTime()) > geoMaxAge(cfg.Provider)
	if cfg.AutoUpdate && stale {
		if err := m.downloadGeo(ctx, cfg.Provider, path); err != nil {
			m.o.Logger.Warn("geoip download failed; keeping the previous database", "provider", cfg.Provider, "error", err)
			m.setStatus("geoip", 0, err)
		}
	}
	raw, err := os.ReadFile(path) //nolint:gosec // path built from the data dir
	if err != nil {
		m.reportUnreadable(cfg, err)
		return
	}
	db, entries, err := parseGeo(cfg.Provider, raw)
	if err != nil {
		m.o.Logger.Warn("geoip database unusable; keeping the previous one", "provider", cfg.Provider, "error", err)
		m.setStatus("geoip", 0, err)
		return
	}
	acl.SetGeo(db)
	st := acl.Status()
	st.GeoReady = true
	acl.SetFeedStatus(st)
	m.setStatus("geoip", entries, nil)
}

// reportUnreadable records why the database cannot be read, unless an earlier
// failure already explains it.
func (m *Manager) reportUnreadable(cfg config.GeoIPFeed, err error) {
	if !cfg.AutoUpdate && !m.geoFileExists(cfg.Provider) {
		return
	}
	m.mu.Lock()
	s := m.status["geoip"]
	explained := s != nil && s.LastError != ""
	m.mu.Unlock()
	if !explained {
		m.setStatus("geoip", 0, fmt.Errorf("reading database: %w", err))
	}
}

// parseGeo validates raw bytes as the provider's format and returns the lookup and its size.
func parseGeo(provider string, raw []byte) (acl.CountryLookup, int, error) {
	if provider == config.GeoMaxMind {
		db, err := ParseMaxMindCountry(raw)
		if err != nil {
			return nil, 0, err
		}
		return db, db.Len(), nil
	}
	db, err := ParseDBIPCountry(raw)
	if err != nil {
		return nil, 0, err
	}
	return db, db.Len(), nil
}

// downloadGeo fetches and validates a database, then replaces the file. A bad
// download never replaces a good file: validation happens before the rename.
func (m *Manager) downloadGeo(ctx context.Context, provider, path string) error {
	body, err := m.fetchGeo(ctx, provider)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating geoip dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("writing geoip database: %w", err)
	}
	return os.Rename(tmp, path)
}

// fetchGeo returns a validated database in the provider's on-disk format.
func (m *Manager) fetchGeo(ctx context.Context, provider string) ([]byte, error) {
	if provider == config.GeoMaxMind {
		return m.fetchMaxMind(ctx)
	}
	return m.fetchDBIP(ctx)
}

func (m *Manager) fetchDBIP(ctx context.Context) ([]byte, error) {
	now := m.o.Now().UTC()
	var lastErr error
	for _, month := range []string{now.Format("2006-01"), now.AddDate(0, -1, 0).Format("2006-01")} {
		body, err := netx.Get(ctx, m.client, fmt.Sprintf(m.o.URLs.DBIPCountry, month), 128<<20, nil)
		if err != nil {
			lastErr = err
			continue
		}
		if _, err := ParseDBIPCountry(body); err != nil {
			lastErr = err
			continue
		}
		return body, nil
	}
	return nil, lastErr
}

// fetchMaxMind downloads the GeoLite2-Country archive with HTTP basic auth and
// returns the extracted, validated .mmdb. Credentials are redacted from every
// error before it can reach the status or the log.
func (m *Manager) fetchMaxMind(ctx context.Context) ([]byte, error) {
	account, key := m.o.MaxMindAccountID(), m.o.MaxMindLicenseKey()
	if account == "" || key == "" {
		return nil, fmt.Errorf("%s and %s must be set", EnvMaxMindAccountID, EnvMaxMindLicenseKey)
	}
	basic := base64.StdEncoding.EncodeToString([]byte(account + ":" + key))
	header := http.Header{"Authorization": {"Basic " + basic}}
	archive, err := netx.Get(ctx, m.client, m.o.URLs.MaxMindCountry, m.limits.archive, header)
	if err != nil {
		return nil, redact(err, account, key, basic)
	}
	mmdb, err := extractMMDB(archive, m.limits.stream, m.limits.entry)
	if err != nil {
		return nil, err
	}
	if _, err := ParseMaxMindCountry(mmdb); err != nil {
		return nil, err
	}
	return mmdb, nil
}

// redact replaces each secret in err's message. Only the message survives,
// which is what the status and the logs store.
func redact(err error, secrets ...string) error {
	msg := err.Error()
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "<redacted>")
		}
	}
	if msg == err.Error() {
		return err
	}
	return errors.New(msg)
}

type decision struct {
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Origin   string `json:"origin"`
}

type stream struct {
	New     []decision `json:"new"`
	Deleted []decision `json:"deleted"`
}

// PollCrowdSec applies the decision stream of a CrowdSec local API as bans.
// The first poll after (re)configuration asks for the full snapshot.
func (m *Manager) PollCrowdSec(ctx context.Context) {
	m.mu.Lock()
	cfg := m.cfg.CrowdSec
	client := m.csClient
	startup := !m.csCursor
	m.mu.Unlock()
	if !cfg.Enabled || client == nil {
		return
	}
	key := m.o.APIKey()
	if key == "" {
		m.setStatus("crowdsec", 0, fmt.Errorf("%s is not set", EnvCrowdSecKey))
		return
	}
	u := strings.TrimRight(cfg.LAPIURL, "/") + "/v1/decisions/stream"
	if startup {
		u += "?startup=true"
	}
	body, err := netx.Get(ctx, client, u, 64<<20, http.Header{"X-Api-Key": {key}})
	if err != nil {
		m.o.Logger.Warn("crowdsec poll failed", "error", err)
		m.setStatus("crowdsec", 0, err)
		return
	}
	var s stream
	if err := json.Unmarshal(body, &s); err != nil {
		m.setStatus("crowdsec", 0, fmt.Errorf("decoding decisions: %w", err))
		return
	}
	now := m.o.Now()
	applied := 0
	for _, d := range s.New {
		if d.Type != "ban" || !strings.EqualFold(d.Scope, "ip") {
			continue // ranges and non-ban decisions are not applied
		}
		ip, err := netip.ParseAddr(d.Value)
		dur, derr := time.ParseDuration(d.Duration)
		if err != nil || derr != nil || dur <= 0 {
			continue
		}
		acl.Bans.Add(acl.Ban{IP: ip, Until: now.Add(dur), Source: "crowdsec", Reason: "crowdsec: " + d.Origin, CreatedAt: now})
		applied++
	}
	for _, d := range s.Deleted {
		if ip, err := netip.ParseAddr(d.Value); err == nil && strings.EqualFold(d.Scope, "ip") {
			acl.Bans.RemoveSite(ip, "")
		}
	}
	m.mu.Lock()
	m.csCursor = true
	m.mu.Unlock()
	m.setStatus("crowdsec", applied, nil)
}
