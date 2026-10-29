package events

import (
	"math/rand/v2"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

const maxPathBytes = 2048

// Publisher turns finished requests into redacted events and puts them on a
// bus. Data plane modules reach it through Default so they need no wiring in
// their JSON config, and every method is safe when the publisher is nil.
type Publisher struct {
	// Bus carries security events: requests with findings or a terminating action.
	Bus *Bus
	// AccessBus carries the optional sampled access log; nil disables it.
	AccessBus *Bus
	// AccessSampleRate is the probability in [0,1] that a clean request is logged.
	AccessSampleRate float64
	// BodyExcerpt enables redacted request body excerpts (off by default).
	BodyExcerpt bool
	Redactor    *Redactor
	Node        string
	// Country resolves a client address to an ISO country code for the event's
	// client.country field; nil leaves it empty.
	Country func(netip.Addr) (string, bool)

	// sample returns a uniform value in [0,1); nil uses math/rand. Tests inject it.
	sample func() float64
}

var defaultPublisher atomic.Pointer[Publisher]

// SetDefault installs p as the process-wide publisher (nil removes it).
func SetDefault(p *Publisher) { defaultPublisher.Store(p) }

// Default returns the process-wide publisher or nil.
func Default() *Publisher { return defaultPublisher.Load() }

// BodyExcerptEnabled reports whether modules should capture body samples.
func (p *Publisher) BodyExcerptEnabled() bool { return p != nil && p.BodyExcerpt }

// Completed describes a finished request.
type Completed struct {
	Request  *http.Request
	Decision *policy.Decision
	Start    time.Time
	Status   int
	Bytes    int64
	Total    time.Duration
}

// IsSecurityEvent reports whether the decision belongs on the security stream.
func IsSecurityEvent(d *policy.Decision) bool {
	return len(d.Findings()) > 0 || d.Action() != policy.ActionAllow
}

// Publish builds and publishes the event for c without ever blocking. Clean
// requests are only recorded when the access log is enabled and sampled in.
func (p *Publisher) Publish(c Completed) {
	if p == nil || c.Decision == nil || c.Request == nil {
		return
	}
	bus := p.Bus
	if !IsSecurityEvent(c.Decision) {
		if p.AccessBus == nil || !p.sampledIn() {
			return
		}
		bus = p.AccessBus
	}
	if bus == nil {
		return
	}
	bus.Publish(p.Build(c))
}

func (p *Publisher) sampledIn() bool {
	switch {
	case p.AccessSampleRate <= 0:
		return false
	case p.AccessSampleRate >= 1:
		return true
	}
	f := p.sample
	if f == nil {
		f = rand.Float64 //nolint:gosec // sampling needs no CSPRNG
	}
	return f() < p.AccessSampleRate
}

// Build converts c into a redacted v1 event.
func (p *Publisher) Build(c Completed) *Event {
	d, r, red := c.Decision, c.Request, p.Redactor
	if red == nil {
		red, _ = NewRedactor(nil)
	}

	headers := make(map[string]string, len(AllowedHeaders))
	for _, name := range AllowedHeaders {
		if vs := r.Header.Values(name); len(vs) > 0 {
			headers[name] = red.Header(name, strings.Join(vs, ", "))
		}
	}

	findings := d.Findings()
	out := make([]Finding, len(findings))
	for i, f := range findings {
		out[i] = red.Finding(f)
	}

	in, outb := d.AnomalyScore()
	ev := &Event{
		ID:           d.EventID,
		Schema:       SchemaV1,
		TS:           c.Start.UTC(),
		Node:         p.Node,
		SiteID:       d.SiteID,
		Action:       string(d.Action()),
		Mode:         string(d.Mode),
		TerminatedBy: d.Terminated(),
		Client:       Client{IP: d.ClientIP.String(), Country: p.countryOf(d.ClientIP)},
		Request: Request{
			Method:  r.Method,
			Host:    truncateUTF8(r.Host, 253),
			Path:    truncateUTF8(red.Text(r.URL.Path), maxPathBytes),
			Query:   red.Query(r.URL.RawQuery),
			Headers: headers,
		},
		Response:     Response{Status: c.Status, Bytes: c.Bytes},
		Timing:       Timing{TotalMS: ms(c.Total), WAFMS: ms(d.WAFTime())},
		Findings:     out,
		AnomalyScore: AnomalyScore{Inbound: in, Outbound: outb},
	}
	if !d.ClientIP.IsValid() {
		ev.Client.IP = ""
	}
	if p.BodyExcerpt {
		if ct, sample := d.BodySample(); len(sample) > 0 {
			ev.Request.BodyExcerpt = red.Body(ct, sample)
		}
	}
	return ev
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// countryOf resolves the client's country with the configured lookup, or "".
func (p *Publisher) countryOf(ip netip.Addr) string {
	if p == nil || p.Country == nil || !ip.IsValid() {
		return ""
	}
	cc, _ := p.Country(ip)
	return cc
}
