package feeds

import (
	"context"
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
	EnvCrowdSecKey = "SHERLOCK_CROWDSEC_API_KEY"
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
}

// DefaultURLs are the public sources.
var DefaultURLs = URLs{
	FireHOL:     "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
	DROP:        "https://www.spamhaus.org/drop/drop.txt",
	DBIPCountry: "https://download.db-ip.com/free/dbip-country-lite-%s.csv.gz",
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
}

// Manager refreshes feeds according to the live configuration.
type Manager struct {
	o      Options
	client *http.Client

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
	m := &Manager{o: o, status: map[string]*Status{}, lists: map[string][]netip.Prefix{}, wake: make(chan struct{}, 1)}
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
	e := map[string]bool{"geoip": m.cfg.GeoIP.AutoUpdate || m.geoFileExists(), "crowdsec": m.cfg.CrowdSec.Enabled}
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

func (m *Manager) geoPath() string {
	return filepath.Join(m.o.DataDir, "geoip", "dbip-country-lite.csv.gz")
}

func (m *Manager) geoFileExists() bool {
	_, err := os.Stat(m.geoPath())
	return err == nil
}

// RefreshGeo loads the country database, downloading it first when auto-update
// is on and the file is missing or older than three weeks. A file placed in
// <data-dir>/geoip by hand (a manual upload) is used as is.
func (m *Manager) RefreshGeo(ctx context.Context) {
	m.mu.Lock()
	cfg := m.cfg.GeoIP
	m.mu.Unlock()
	if cfg.Provider == config.GeoMaxMind {
		m.setStatus("geoip", 0, errors.New("the maxmind provider is not implemented yet; use dbip-lite"))
		return
	}
	path := m.geoPath()
	info, err := os.Stat(path)
	stale := err != nil || m.o.Now().Sub(info.ModTime()) > 21*24*time.Hour
	if cfg.AutoUpdate && stale {
		if err := m.downloadGeo(ctx, path); err != nil {
			m.o.Logger.Warn("geoip download failed; keeping the previous database", "error", err)
			m.setStatus("geoip", 0, err)
		}
	}
	raw, err := os.ReadFile(path) //nolint:gosec // path built from the data dir
	if err != nil {
		if cfg.AutoUpdate || m.geoFileExists() {
			m.mu.Lock()
			if s := m.status["geoip"]; s == nil || s.LastError == "" {
				m.mu.Unlock()
				m.setStatus("geoip", 0, fmt.Errorf("reading database: %w", err))
			} else {
				m.mu.Unlock()
			}
		}
		return
	}
	db, err := ParseDBIPCountry(raw)
	if err != nil {
		m.o.Logger.Warn("geoip database unusable; keeping the previous one", "error", err)
		m.setStatus("geoip", 0, err)
		return
	}
	acl.SetGeo(db)
	st := acl.Status()
	st.GeoReady = true
	acl.SetFeedStatus(st)
	m.setStatus("geoip", db.Len(), nil)
}

func (m *Manager) downloadGeo(ctx context.Context, path string) error {
	now := m.o.Now().UTC()
	var lastErr error
	for _, month := range []string{now.Format("2006-01"), now.AddDate(0, -1, 0).Format("2006-01")} {
		body, err := netx.Get(ctx, m.client, fmt.Sprintf(m.o.URLs.DBIPCountry, month), 128<<20, nil)
		if err != nil {
			lastErr = err
			continue
		}
		if _, err := ParseDBIPCountry(body); err != nil { // never replace a good file with a bad download
			lastErr = err
			continue
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
	return lastErr
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
