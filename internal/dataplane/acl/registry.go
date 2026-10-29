// Package acl is the sherlock_acl Caddy module: explicit bans, deny and allow
// lists, country rules, reputation feeds and the site password gate. It runs
// before rate limiting and the WAF because its checks are cheap (a trie lookup)
// and decisive.
package acl

import (
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/policy/ipset"
)

// CountryLookup resolves an address to an ISO 3166-1 alpha-2 code.
type CountryLookup interface {
	Country(ip netip.Addr) (code string, ok bool)
}

// The registry holds data the modules read on every request. Each part is an
// atomic pointer swapped as a whole, so feeds and configuration reloads update
// it without locks on the request path and without dropped requests.
var (
	lists      atomic.Pointer[map[string]*ipset.Set]
	reputation atomic.Pointer[ipset.Set]
	geo        atomic.Pointer[CountryLookup]
	feedState  atomic.Pointer[FeedStatus]

	// Bans is the process-wide temporary-ban set.
	Bans = NewBanSet()
)

// SetLists replaces the named IP lists (from the configuration).
func SetLists(m map[string]*ipset.Set) { lists.Store(&m) }

// Lists returns the current named lists (a copy of the map; the sets are immutable).
func Lists() map[string]*ipset.Set {
	out := map[string]*ipset.Set{}
	if m := lists.Load(); m != nil {
		maps.Copy(out, *m)
	}
	return out
}

// MergeLists adds (or overrides) lists without removing existing ones. A
// configuration swap uses it before the new handlers go live so that neither the
// old nor the new handlers ever see a list missing.
func MergeLists(add map[string]*ipset.Set) {
	m := Lists()
	maps.Copy(m, add)
	lists.Store(&m)
}

// SetReputation replaces the reputation set (from the feeds job).
func SetReputation(s *ipset.Set) { reputation.Store(s) }

// SetGeo replaces the country database; nil removes it.
func SetGeo(l CountryLookup) {
	if l == nil {
		geo.Store(nil)
		return
	}
	geo.Store(&l)
}

// FeedStatus reports feed health for metrics and the dashboard.
type FeedStatus struct {
	GeoReady        bool
	ReputationReady bool
}

// SetFeedStatus records which feeds are loaded.
func SetFeedStatus(s FeedStatus) { feedState.Store(&s) }

// Status returns the last recorded feed status.
func Status() FeedStatus {
	if s := feedState.Load(); s != nil {
		return *s
	}
	return FeedStatus{}
}

func list(name string) *ipset.Set {
	if m := lists.Load(); m != nil {
		return (*m)[name]
	}
	return nil
}

func country(ip netip.Addr) (string, bool) {
	if g := geo.Load(); g != nil {
		return (*g).Country(ip)
	}
	return "", false
}

// Ban is one temporary ban.
type Ban struct {
	IP        netip.Addr
	Until     time.Time
	Source    string // manual | auto | crowdsec
	Reason    string
	SiteID    string // empty: applies to every site
	CreatedAt time.Time
}

// BanSet is a concurrent set of temporary bans keyed by address.
type BanSet struct {
	mu sync.RWMutex
	m  map[netip.Addr][]Ban
}

// NewBanSet returns an empty set.
func NewBanSet() *BanSet { return &BanSet{m: map[netip.Addr][]Ban{}} }

// Add records a ban, replacing an existing ban for the same address and site.
func (s *BanSet) Add(b Ban) {
	b.IP = b.IP.WithZone("").Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.m[b.IP]
	i := slices.IndexFunc(cur, func(x Ban) bool { return x.SiteID == b.SiteID })
	if i >= 0 {
		cur[i] = b
	} else {
		cur = append(cur, b)
	}
	s.m[b.IP] = cur
}

// Active returns a live ban for ip that applies to site.
func (s *BanSet) Active(ip netip.Addr, site string, now time.Time) (Ban, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, b := range s.m[ip] {
		if b.Until.After(now) && (b.SiteID == "" || b.SiteID == site) {
			return b, true
		}
	}
	return Ban{}, false
}

// Remove deletes every ban of ip (any site), reporting whether one existed.
func (s *BanSet) Remove(ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[ip]
	delete(s.m, ip)
	return ok
}

// Replace swaps the contents (used when syncing from the database).
func (s *BanSet) Replace(bans []Ban) {
	m := make(map[netip.Addr][]Ban, len(bans))
	for _, b := range bans {
		b.IP = b.IP.WithZone("").Unmap()
		m[b.IP] = append(m[b.IP], b)
	}
	s.mu.Lock()
	s.m = m
	s.mu.Unlock()
}

// List returns live bans, soonest to expire first, dropping expired ones.
func (s *BanSet) List(now time.Time) []Ban {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Ban
	for ip, bs := range s.m {
		live := bs[:0]
		for _, b := range bs {
			if b.Until.After(now) {
				live = append(live, b)
				out = append(out, b)
			}
		}
		if len(live) == 0 {
			delete(s.m, ip)
		} else {
			s.m[ip] = live
		}
	}
	slices.SortFunc(out, func(a, b Ban) int { return a.Until.Compare(b.Until) })
	return out
}

var banSink atomic.Pointer[func(Ban)]

// SetBanSink registers a function told about every ban the data plane creates
// by itself (auto-ban), so the control plane can persist and audit it. It runs
// on the request path and must not block.
func SetBanSink(f func(Ban)) {
	if f == nil {
		banSink.Store(nil)
		return
	}
	banSink.Store(&f)
}

// AddAutoBan records an automatic ban and notifies the sink.
func AddAutoBan(b Ban) {
	Bans.Add(b)
	if f := banSink.Load(); f != nil {
		(*f)(b)
	}
}

// RemoveSite deletes the ban of ip scoped to site ("" for the all-sites ban).
func (s *BanSet) RemoveSite(ip netip.Addr, site string) bool {
	ip = ip.WithZone("").Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.m[ip]
	i := slices.IndexFunc(cur, func(b Ban) bool { return b.SiteID == site })
	if i < 0 {
		return false
	}
	cur = slices.Delete(cur, i, i+1)
	if len(cur) == 0 {
		delete(s.m, ip)
	} else {
		s.m[ip] = cur
	}
	return true
}

// CountryOf resolves an address with the loaded country database.
func CountryOf(ip netip.Addr) (string, bool) { return country(ip) }

// Listed reports whether ip is on a loaded reputation list.
func Listed(ip netip.Addr) bool { return reputation.Load().Contains(ip) }
