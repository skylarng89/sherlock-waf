// Package config is the source of truth for Sherlock's configuration model
// (ADR-0005): YAML loading, defaults, validation and policy resolution.
package config

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

// SchemaVersion is the only schema version this build understands.
const SchemaVersion = 1

// Mode is a site's enforcement mode.
type Mode string

// Enforcement modes.
const (
	ModeOff    Mode = "off"
	ModeDetect Mode = "detect"
	ModeBlock  Mode = "block"
)

// FailMode decides what happens when a data plane module fails internally.
type FailMode string

// Fail modes.
const (
	FailOpen   FailMode = "open"
	FailClosed FailMode = "closed"
)

// TLSMode selects how a site obtains certificates.
type TLSMode string

// TLS modes.
const (
	TLSACME TLSMode = "acme"
	TLSFile TLSMode = "file"
	TLSNone TLSMode = "none"
)

// LBPolicy is an upstream load-balancing policy.
type LBPolicy string

// Load-balancing policies.
const (
	LBRoundRobin LBPolicy = "round_robin"
	LBLeastConn  LBPolicy = "least_conn"
	LBIPHash     LBPolicy = "ip_hash"
)

// Duration is a time.Duration that reads and writes Go duration strings.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string such as \"10s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Std returns the value as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Root is the whole configuration document.
type Root struct {
	SchemaVersion int    `yaml:"schema_version" json:"schema_version"`
	Global        Global `yaml:"global,omitempty" json:"global"`
	Sites         []Site `yaml:"sites" json:"sites"`
}

// Global holds settings shared by every site.
type Global struct {
	TrustedProxies  []string `yaml:"trusted_proxies,omitempty" json:"trusted_proxies,omitempty"`
	ClientIPHeaders []string `yaml:"client_ip_headers,omitempty" json:"client_ip_headers,omitempty"`
	ACME            ACME     `yaml:"acme,omitempty" json:"acme"`
	Defaults        Policy   `yaml:"defaults,omitempty" json:"defaults"`
}

// ACME configures automatic certificate issuance.
type ACME struct {
	Email string `yaml:"email,omitempty" json:"email,omitempty"`
	CA    string `yaml:"ca,omitempty" json:"ca,omitempty"`
}

// Site is one protected website or API.
type Site struct {
	ID         string     `yaml:"id" json:"id"`
	Name       string     `yaml:"name,omitempty" json:"name,omitempty"`
	Hosts      []string   `yaml:"hosts" json:"hosts"`
	PathPrefix string     `yaml:"path_prefix,omitempty" json:"path_prefix,omitempty"`
	TLS        TLS        `yaml:"tls,omitempty" json:"tls"`
	Upstreams  Upstreams  `yaml:"upstreams" json:"upstreams"`
	Headers    Headers    `yaml:"headers,omitempty" json:"headers"`
	Policy     Policy     `yaml:"policy,omitempty" json:"policy"`
	Endpoints  []Endpoint `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
}

// TLS configures a site's certificates and transport security.
// CertFile and KeyFile are the file-config form of the future uploaded
// certificate reference (cert_id) and are only valid with mode "file".
type TLS struct {
	Mode       TLSMode `yaml:"mode,omitempty" json:"mode,omitempty"`
	CertFile   string  `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
	KeyFile    string  `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	MinVersion string  `yaml:"min_version,omitempty" json:"min_version,omitempty"`
	HSTS       HSTS    `yaml:"hsts,omitempty" json:"hsts"`
}

// HSTS configures Strict-Transport-Security.
type HSTS struct {
	Enabled           *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	MaxAge            int   `yaml:"max_age,omitempty" json:"max_age,omitempty"`
	IncludeSubdomains bool  `yaml:"include_subdomains,omitempty" json:"include_subdomains,omitempty"`
}

// Upstreams describes the origin servers behind a site.
type Upstreams struct {
	Targets     []string    `yaml:"targets" json:"targets"`
	LBPolicy    LBPolicy    `yaml:"lb_policy,omitempty" json:"lb_policy,omitempty"`
	HealthCheck HealthCheck `yaml:"health_check,omitempty" json:"health_check"`
	TLS         UpstreamTLS `yaml:"tls,omitempty" json:"tls"`
	Timeouts    Timeouts    `yaml:"timeouts,omitempty" json:"timeouts"`
}

// HealthCheck is an active upstream health probe; it is off when Path is empty.
type HealthCheck struct {
	Path     string   `yaml:"path,omitempty" json:"path,omitempty"`
	Interval Duration `yaml:"interval,omitempty" json:"interval,omitempty"`
	Timeout  Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// UpstreamTLS configures TLS towards the origin.
type UpstreamTLS struct {
	Enabled            bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty" json:"insecure_skip_verify,omitempty"`
	ClientCertID       string `yaml:"client_cert_id,omitempty" json:"client_cert_id,omitempty"`
}

// Timeouts bound upstream connections.
type Timeouts struct {
	Dial  Duration `yaml:"dial,omitempty" json:"dial,omitempty"`
	Read  Duration `yaml:"read,omitempty" json:"read,omitempty"`
	Write Duration `yaml:"write,omitempty" json:"write,omitempty"`
}

// Headers controls response headers added by Sherlock.
type Headers struct {
	SecurityHeaders *bool `yaml:"security_headers,omitempty" json:"security_headers,omitempty"`
}

// Policy is the protection block used at global, site and endpoint level
// (ADR-0012). Every field is optional; unset fields inherit.
type Policy struct {
	Mode      *Mode      `yaml:"mode,omitempty" json:"mode,omitempty"`
	FailMode  *FailMode  `yaml:"fail_mode,omitempty" json:"fail_mode,omitempty"`
	WAF       *WAFPolicy `yaml:"waf,omitempty" json:"waf,omitempty"`
	BlockPage *BlockPage `yaml:"block_page,omitempty" json:"block_page,omitempty"`
}

// WAFPolicy tunes Coraza and CRS. Exclusions and custom rules arrive in M8.
type WAFPolicy struct {
	Enabled                  *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	ParanoiaLevel            *int     `yaml:"paranoia_level,omitempty" json:"paranoia_level,omitempty"`
	BlockingParanoiaLevel    *int     `yaml:"blocking_paranoia_level,omitempty" json:"blocking_paranoia_level,omitempty"`
	InboundThreshold         *int     `yaml:"inbound_threshold,omitempty" json:"inbound_threshold,omitempty"`
	OutboundThreshold        *int     `yaml:"outbound_threshold,omitempty" json:"outbound_threshold,omitempty"`
	OutboundInspection       *bool    `yaml:"outbound_inspection,omitempty" json:"outbound_inspection,omitempty"`
	MaxBodyBytes             *int64   `yaml:"max_body_bytes,omitempty" json:"max_body_bytes,omitempty"`
	SkipInspectionExtensions []string `yaml:"skip_inspection_extensions,omitempty" json:"skip_inspection_extensions,omitempty"`
}

// BlockPage selects the page shown for terminated requests.
type BlockPage struct {
	TemplateID *string `yaml:"template_id,omitempty" json:"template_id,omitempty"`
}

// Endpoint overrides the site policy for requests matching Match.
type Endpoint struct {
	ID     string        `yaml:"id" json:"id"`
	Match  EndpointMatch `yaml:"match" json:"match"`
	Policy Policy        `yaml:"policy,omitempty" json:"policy"`
}

// EndpointMatch selects requests by exactly one of Path, PathPrefix or
// PathGlob (path.Match syntax), optionally narrowed to Methods.
type EndpointMatch struct {
	Path       string   `yaml:"path,omitempty" json:"path,omitempty"`
	PathPrefix string   `yaml:"path_prefix,omitempty" json:"path_prefix,omitempty"`
	PathGlob   string   `yaml:"path_glob,omitempty" json:"path_glob,omitempty"`
	Methods    []string `yaml:"methods,omitempty" json:"methods,omitempty"`
}
