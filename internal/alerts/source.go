package alerts

import (
	"context"
	"fmt"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/metrics"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// Source is the data the rules look at. Implementations return snapshots and
// must be cheap enough to call every 30 seconds.
type Source interface {
	// BlocksBySite counts blocked requests per site in [from, to).
	BlocksBySite(ctx context.Context, from, to time.Time) ([]SiteCount, error)
	// TopCountries lists the countries of events in [from, to), busiest first;
	// siteID narrows it to one site when non-empty.
	TopCountries(ctx context.Context, siteID string, from, to time.Time) ([]CountryCount, error)
	CertExpiries(ctx context.Context) ([]CertExpiry, error)
	FeedStatuses(ctx context.Context) ([]FeedStatus, error)
	// EventsDropped is the cumulative count of events the bus dropped.
	EventsDropped(ctx context.Context) (uint64, error)
	Upstreams(ctx context.Context) ([]Upstream, error)
}

// SiteCount is a per-site count.
type SiteCount struct {
	Site  string
	Count int64
}

// CountryCount is a per-country event count.
type CountryCount struct {
	Country string
	Count   int64
}

// CertExpiry is when the certificate serving a host expires.
type CertExpiry struct {
	Site     string
	Host     string
	NotAfter time.Time
}

// FeedStatus is the health of one feed.
type FeedStatus struct {
	Name   string
	Failed bool
}

// Upstream is one origin's last probe result.
type Upstream struct {
	Site     string
	Upstream string
	Healthy  bool
}

// StoreSource builds a Source from the pieces the server already has. Each
// dependency is a function so the package needs no new store queries and tests
// can fake any of them; a nil function makes that rule kind report an error
// instead of silently never firing.
type StoreSource struct {
	// TopValues is store.Tx.TopEventValues run in a transaction.
	TopValues func(ctx context.Context, dim string, f store.EventFilter, limit int) ([]store.ValueCount, error)
	Certs     func() []metrics.CertExpiry
	Feeds     func() []FeedStatus
	Dropped   func() uint64
	Upstream  func() []metrics.UpstreamStatus
}

var _ Source = StoreSource{}

const (
	topSites     = 500
	topCountries = 100
)

// BlocksBySite implements Source.
func (s StoreSource) BlocksBySite(ctx context.Context, from, to time.Time) ([]SiteCount, error) {
	if s.TopValues == nil {
		return nil, errNotWired("event counts")
	}
	vs, err := s.TopValues(ctx, store.DimSite, store.EventFilter{Action: "block", From: from, To: to}, topSites)
	if err != nil {
		return nil, fmt.Errorf("counting blocks per site: %w", err)
	}
	out := make([]SiteCount, len(vs))
	for i, v := range vs {
		out[i] = SiteCount{Site: v.Value, Count: v.Count}
	}
	return out, nil
}

// TopCountries implements Source.
func (s StoreSource) TopCountries(ctx context.Context, siteID string, from, to time.Time) ([]CountryCount, error) {
	if s.TopValues == nil {
		return nil, errNotWired("event counts")
	}
	vs, err := s.TopValues(ctx, store.DimCountry, store.EventFilter{SiteID: siteID, From: from, To: to}, topCountries)
	if err != nil {
		return nil, fmt.Errorf("counting events per country: %w", err)
	}
	out := make([]CountryCount, len(vs))
	for i, v := range vs {
		out[i] = CountryCount{Country: v.Value, Count: v.Count}
	}
	return out, nil
}

// CertExpiries implements Source.
func (s StoreSource) CertExpiries(context.Context) ([]CertExpiry, error) {
	if s.Certs == nil {
		return nil, errNotWired("certificate expiry")
	}
	cs := s.Certs()
	out := make([]CertExpiry, len(cs))
	for i, c := range cs {
		out[i] = CertExpiry{Site: c.Site, Host: c.Host, NotAfter: c.NotAfter}
	}
	return out, nil
}

// FeedStatuses implements Source.
func (s StoreSource) FeedStatuses(context.Context) ([]FeedStatus, error) {
	if s.Feeds == nil {
		return nil, errNotWired("feed status")
	}
	return s.Feeds(), nil
}

// EventsDropped implements Source.
func (s StoreSource) EventsDropped(context.Context) (uint64, error) {
	if s.Dropped == nil {
		return 0, errNotWired("dropped events")
	}
	return s.Dropped(), nil
}

// Upstreams implements Source.
func (s StoreSource) Upstreams(context.Context) ([]Upstream, error) {
	if s.Upstream == nil {
		return nil, errNotWired("upstream health")
	}
	us := s.Upstream()
	out := make([]Upstream, len(us))
	for i, u := range us {
		out[i] = Upstream{Site: u.Site, Upstream: u.Upstream, Healthy: u.Healthy}
	}
	return out, nil
}

func errNotWired(what string) error {
	return fmt.Errorf("alerts: %s is not available on this node", what)
}
