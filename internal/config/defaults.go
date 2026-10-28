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
	if len(r.Global.TrustedProxies) > 0 && len(r.Global.ClientIPHeaders) == 0 {
		r.Global.ClientIPHeaders = []string{"X-Forwarded-For"}
	}
	for i := range r.Sites {
		r.Sites[i].applyDefaults()
	}
}

func (s *Site) applyDefaults() {
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
