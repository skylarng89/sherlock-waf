package config

import (
	"strings"
	"time"
)

// Defaults for non-policy fields; policy defaults live in DefaultPolicy so
// the inheritance layers stay distinguishable.
const (
	DefaultMaxBodyBytes      int64 = 10 << 20
	DefaultInboundThreshold        = 5
	DefaultOutboundThreshold       = 4
	DefaultBlockPageTemplate       = "default"
	DefaultHSTSMaxAge              = 31536000
	DefaultAdminListen             = "127.0.0.1:9444" // the control plane owns 9443
	DefaultAccessSampleRate        = 0.01
	DefaultEventFileMaxMB          = 100
	DefaultEventFileKeep           = 5
	// DefaultEventRetentionDays is how long the control-plane database keeps events.
	DefaultEventRetentionDays = 30
)

// DefaultSkipInspectionExtensions lists static asset extensions that skip
// body inspection for GET and HEAD.
func DefaultSkipInspectionExtensions() []string {
	return []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2"}
}

// ApplyDefaults fills unset non-policy fields and normalises hosts.
func (r *Root) ApplyDefaults() {
	if r.SchemaVersion == 0 {
		r.SchemaVersion = SchemaVersion
	}
	g := &r.Global
	if g.Admin.Listen == "" {
		g.Admin.Listen = DefaultAdminListen
	}
	if g.Events.RetentionDays == 0 {
		g.Events.RetentionDays = DefaultEventRetentionDays
	}
	if g.Events.AccessLog.SampleRate == nil {
		g.Events.AccessLog.SampleRate = ptr(DefaultAccessSampleRate)
	}
	if g.Events.Sinks.Stdout == nil {
		g.Events.Sinks.Stdout = ptr(true)
	}
	if g.Events.Sinks.File == nil {
		g.Events.Sinks.File = ptr(true)
	}
	if g.Events.Sinks.FileMaxMB == 0 {
		g.Events.Sinks.FileMaxMB = DefaultEventFileMaxMB
	}
	if g.Events.Sinks.FileKeep == 0 {
		g.Events.Sinks.FileKeep = DefaultEventFileKeep
	}
	if g.Feeds.GeoIP.Provider == "" {
		g.Feeds.GeoIP.Provider = GeoDBIPLite
	}
	g.Defaults.applyAccessDefaults()
	if len(r.Global.TrustedProxies) > 0 && len(r.Global.ClientIPHeaders) == 0 {
		r.Global.ClientIPHeaders = []string{"X-Forwarded-For"}
	}
	for i := range r.Sites {
		r.Sites[i].applyDefaults()
	}
}

// applyAccessDefaults fills the access-control defaults of one policy layer.
// Only values that are meaningless when unset are filled; absence of a whole
// block stays absence so inheritance still works.
func (p *Policy) applyAccessDefaults() {
	p.applyBotDefaults()
	for i := range p.RateLimits {
		rl := &p.RateLimits[i]
		if rl.Key == "" {
			rl.Key = KeyIP
		}
		if rl.Action == "" {
			rl.Action = ActionBlock
		}
		if len(rl.Match.Paths) == 0 {
			rl.Match.Paths = []string{"/*"}
		}
	}
	if p.ACL != nil {
		if c := p.ACL.Countries; c != nil && c.Mode == "" {
			c.Mode = CountryOff
		}
		if r := p.ACL.Reputation; r != nil && r.Action == "" {
			r.Action = ActionBlock
		}
	}
	if a := p.AutoBan; a != nil {
		if a.BlocksThreshold == 0 {
			a.BlocksThreshold = 20
		}
		if a.Window == 0 {
			a.Window = Duration(5 * time.Minute)
		}
		if a.BanDuration == 0 {
			a.BanDuration = Duration(30 * time.Minute)
		}
	}
}

func (s *Site) applyDefaults() {
	s.Policy.applyAccessDefaults()
	for i := range s.Endpoints {
		s.Endpoints[i].Policy.applyAccessDefaults()
	}
	for i, h := range s.Hosts {
		s.Hosts[i] = strings.ToLower(strings.TrimSpace(h))
	}
	if s.TLS.Mode == "" {
		s.TLS.Mode = TLSACME
	}
	if s.TLS.MinVersion == "" {
		s.TLS.MinVersion = "1.2"
	}
	if s.TLS.HSTS.Enabled == nil {
		s.TLS.HSTS.Enabled = ptr(true)
	}
	if s.TLS.HSTS.MaxAge == 0 {
		s.TLS.HSTS.MaxAge = DefaultHSTSMaxAge
	}
	if s.Upstreams.LBPolicy == "" {
		s.Upstreams.LBPolicy = LBRoundRobin
	}
	if s.Upstreams.HealthCheck.Path != "" {
		if s.Upstreams.HealthCheck.Interval == 0 {
			s.Upstreams.HealthCheck.Interval = Duration(10 * time.Second)
		}
		if s.Upstreams.HealthCheck.Timeout == 0 {
			s.Upstreams.HealthCheck.Timeout = Duration(2 * time.Second)
		}
	}
	if s.Upstreams.Timeouts.Dial == 0 {
		s.Upstreams.Timeouts.Dial = Duration(5 * time.Second)
	}
	if s.Upstreams.Timeouts.Read == 0 {
		s.Upstreams.Timeouts.Read = Duration(60 * time.Second)
	}
	if s.Upstreams.Timeouts.Write == 0 {
		s.Upstreams.Timeouts.Write = Duration(60 * time.Second)
	}
	if s.Headers.SecurityHeaders == nil {
		s.Headers.SecurityHeaders = ptr(true)
	}
}

func ptr[T any](v T) *T { return &v }
