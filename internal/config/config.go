// Package config is the source of truth for Sherlock's configuration model
// (ADR-0005): YAML loading, defaults, validation and policy resolution.
package config

import (
	"encoding/json"
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

// MarshalJSON writes the Go duration string ("10s"), matching the YAML form.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON accepts a duration string ("10s").
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string such as \"10s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// Std returns the value as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Root is the whole configuration document.
type Root struct {
	// Version of this document format; must be 1, the only version this build accepts (default 1 when omitted).
	SchemaVersion int `yaml:"schema_version" json:"schema_version"`
	// Settings shared by every site: admin listener, trusted proxies, certificate authority, events, default policy, IP lists and feeds.
	Global Global `yaml:"global,omitempty" json:"global"`
	// The protected sites; at least one is required.
	Sites []Site `yaml:"sites" json:"sites"`
}

// Global holds settings shared by every site.
type Global struct {
	// The admin listener that serves /metrics, /healthz and /readyz.
	Admin Admin `yaml:"admin,omitempty" json:"admin"`
	// Addresses or CIDR ranges of reverse proxies and load balancers in front of Sherlock whose client-address headers are trusted; empty means the client is the TCP peer and forwarded headers are ignored.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty" json:"trusted_proxies,omitempty"`
	// Headers read, in order, for the real client address when the request comes from a trusted proxy (default X-Forwarded-For when trusted_proxies is set).
	ClientIPHeaders []string `yaml:"client_ip_headers,omitempty" json:"client_ip_headers,omitempty"`
	// Settings for automatic certificates (sites with tls.mode acme).
	ACME ACME `yaml:"acme,omitempty" json:"acme"`
	// The event pipeline: node name, retention, access log, redaction and sinks.
	Events Events `yaml:"events,omitempty" json:"events"`
	// A policy block applied to every site; sites and endpoints override it field by field.
	Defaults Policy `yaml:"defaults,omitempty" json:"defaults"`
	// Named lists of addresses and CIDR ranges that acl allow_lists and deny_lists refer to (at most 1000 lists and 1,000,000 entries in total).
	IPLists []IPList `yaml:"ip_lists,omitempty" json:"ip_lists,omitempty"`
	// Background data the node downloads and refreshes: country database, reputation lists and CrowdSec.
	Feeds Feeds `yaml:"feeds,omitempty" json:"feeds"`
}

// AdminOff disables the admin listener when used as Admin.Listen.
const AdminOff = "off"

// Admin configures the node's admin listener, which serves /metrics,
// /healthz and /readyz. It is separate from proxied traffic.
type Admin struct {
	// Address of the admin listener as host:port, or "off" to disable it (default 127.0.0.1:9444).
	Listen string `yaml:"listen,omitempty" json:"listen,omitempty"`
	// Client addresses or CIDR ranges allowed to reach the admin listener; empty allows any client that can connect.
	AllowedCIDRs []string `yaml:"allowed_cidrs,omitempty" json:"allowed_cidrs,omitempty"`
}

// Events configures the event pipeline.
type Events struct {
	// Name stamped on every event so exports can tell nodes apart (default: the host name; at most 128 characters).
	NodeName string `yaml:"node_name,omitempty" json:"node_name,omitempty"`
	// RetentionDays is how long stored events are kept (control-plane database only).
	RetentionDays int `yaml:"retention_days,omitempty" json:"retention_days,omitempty"`
	// The optional sampled log of clean requests, off by default.
	AccessLog AccessLog `yaml:"access_log,omitempty" json:"access_log"`
	// Records a redacted excerpt of the request body in events (default false).
	BodyExcerpt bool `yaml:"body_excerpt,omitempty" json:"body_excerpt,omitempty"`
	// Extra redaction rules applied to events on top of the built-in ones.
	Redaction Redaction `yaml:"redaction,omitempty" json:"redaction"`
	// Where events are written on the node itself.
	Sinks Sinks `yaml:"sinks,omitempty" json:"sinks"`
}

// AccessLog is the optional sampled log of clean requests (FR-EVT-3).
type AccessLog struct {
	// Turns the sampled access log on (default false).
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Fraction of clean requests logged, from 0 to 1 (default 0.01).
	SampleRate *float64 `yaml:"sample_rate,omitempty" json:"sample_rate,omitempty"`
}

// Redaction adds operator patterns to the built-in ones.
type Redaction struct {
	// Patterns match parameter names (case-sensitive RE2; use (?i) for case-insensitive).
	Patterns []string `yaml:"patterns,omitempty" json:"patterns,omitempty"`
}

// Sinks selects the temporary event outputs used until the store exists.
type Sinks struct {
	// Writes security events as JSON lines to standard output (default true).
	Stdout *bool `yaml:"stdout,omitempty" json:"stdout,omitempty"`
	// Writes security events to events.jsonl (and the access log to access.jsonl) in the data directory, with rotation (default true).
	File *bool `yaml:"file,omitempty" json:"file,omitempty"`
	// Size in MiB at which an event file is rotated, 1 to 10240 (default 100).
	FileMaxMB int `yaml:"file_max_mb,omitempty" json:"file_max_mb,omitempty"`
	// Number of rotated event files kept, 1 to 100 (default 5).
	FileKeep int `yaml:"file_keep,omitempty" json:"file_keep,omitempty"`
}

// ACME configures automatic certificate issuance.
type ACME struct {
	// Contact address sent to the certificate authority when ordering certificates; must contain an @. Optional.
	Email string `yaml:"email,omitempty" json:"email,omitempty"`
	// HTTPS URL of an ACME directory to use instead of Caddy's default certificate authorities (for example a private or staging CA).
	CA string `yaml:"ca,omitempty" json:"ca,omitempty"`
}

// Site is one protected website or API.
type Site struct {
	// Lowercase slug (a-z, 0-9, '-', at most 63 characters) that identifies the site; unique.
	ID string `yaml:"id" json:"id"`
	// Display name shown in the dashboard.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	// Host names the site answers for: lowercase DNS names, optionally with a leading "*." wildcard, or IP addresses; at least one.
	Hosts []string `yaml:"hosts" json:"hosts"`
	// Serves only requests under this path (starts with '/', no '..'), so several sites can share a host; the longest prefix wins. Empty means the whole host.
	PathPrefix string `yaml:"path_prefix,omitempty" json:"path_prefix,omitempty"`
	// Certificates and transport security.
	TLS TLS `yaml:"tls,omitempty" json:"tls"`
	// The origin servers behind the site.
	Upstreams Upstreams `yaml:"upstreams" json:"upstreams"`
	// Response headers Sherlock adds.
	Headers Headers `yaml:"headers,omitempty" json:"headers"`
	// The site's protection policy; overrides global.defaults.
	Policy Policy `yaml:"policy,omitempty" json:"policy"`
	// Per-path policy overrides, at most 500.
	Endpoints []Endpoint `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
}

// TLS configures a site's certificates and transport security. With mode
// "file" the certificate is either a pair of files on the node (CertFile and
// KeyFile) or an uploaded certificate (CertID); never both.
type TLS struct {
	// acme obtains certificates automatically, file uses certificates you supply, none serves plain HTTP only (default acme).
	Mode TLSMode `yaml:"mode,omitempty" json:"mode,omitempty"`
	// Path on the node of the PEM certificate chain; with mode file, use cert_file and key_file together or cert_id.
	CertFile string `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
	// Path on the node of the PEM private key; used with cert_file.
	KeyFile string `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	// Id of an uploaded certificate; with mode file, use this instead of cert_file and key_file.
	CertID string `yaml:"cert_id,omitempty" json:"cert_id,omitempty"`
	// Lowest TLS version accepted, "1.2" or "1.3" (default "1.2").
	MinVersion string `yaml:"min_version,omitempty" json:"min_version,omitempty"`
	// Strict-Transport-Security header settings.
	HSTS HSTS `yaml:"hsts,omitempty" json:"hsts"`
}

// HSTS configures Strict-Transport-Security.
type HSTS struct {
	// Sends Strict-Transport-Security on TLS sites (default true; only sent while headers.security_headers is on).
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// max-age in seconds (default 31536000, one year).
	MaxAge int `yaml:"max_age,omitempty" json:"max_age,omitempty"`
	// Adds includeSubDomains (default false).
	IncludeSubdomains bool `yaml:"include_subdomains,omitempty" json:"include_subdomains,omitempty"`
}

// Upstreams describes the origin servers behind a site.
type Upstreams struct {
	// Origin servers as host:port; at least one.
	Targets []string `yaml:"targets" json:"targets"`
	// How requests are spread over targets: round_robin, least_conn or ip_hash (default round_robin).
	LBPolicy LBPolicy `yaml:"lb_policy,omitempty" json:"lb_policy,omitempty"`
	// Active health probe of the targets; off unless a path is set.
	HealthCheck HealthCheck `yaml:"health_check,omitempty" json:"health_check"`
	// TLS towards the origin.
	TLS UpstreamTLS `yaml:"tls,omitempty" json:"tls"`
	// Timeouts for upstream connections.
	Timeouts Timeouts `yaml:"timeouts,omitempty" json:"timeouts"`
	// HTTPVersion pins the protocol spoken to the origin: "" (Caddy's default),
	// "1.1", "2", or "h2c" (cleartext HTTP/2, which gRPC origins need).
	HTTPVersion string `yaml:"http_version,omitempty" json:"http_version,omitempty"`
	// WebSockets allows connection upgrades through to the origin (default
	// true). The WAF cannot inspect frames, so deny is the strict choice.
	WebSockets *bool `yaml:"websockets,omitempty" json:"websockets,omitempty"`
}

// HealthCheck is an active upstream health probe; it is off when Path is empty.
type HealthCheck struct {
	// Path requested on each target, starting with '/'; empty turns health checking off.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	// Time between probes (default 10s).
	Interval Duration `yaml:"interval,omitempty" json:"interval,omitempty"`
	// Time a probe may take; positive and not longer than interval (default 2s).
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// UpstreamTLS configures TLS towards the origin.
type UpstreamTLS struct {
	// Connects to the origin over TLS (default false).
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Skips verifying the origin's certificate (default false). Leaves the connection open to interception: use for testing only.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty" json:"insecure_skip_verify,omitempty"`
	// Id of an uploaded certificate presented to the origin for mutual TLS; needs enabled.
	ClientCertID string `yaml:"client_cert_id,omitempty" json:"client_cert_id,omitempty"`
}

// Timeouts bound upstream connections.
type Timeouts struct {
	// Time allowed to connect to the origin (default 5s).
	Dial Duration `yaml:"dial,omitempty" json:"dial,omitempty"`
	// Time allowed to read the origin's response (default 60s).
	Read Duration `yaml:"read,omitempty" json:"read,omitempty"`
	// Time allowed to send the request to the origin (default 60s).
	Write Duration `yaml:"write,omitempty" json:"write,omitempty"`
}

// Headers controls response headers added by Sherlock.
type Headers struct {
	// Adds X-Content-Type-Options, Referrer-Policy and, on TLS sites, Strict-Transport-Security to responses (default true).
	SecurityHeaders *bool `yaml:"security_headers,omitempty" json:"security_headers,omitempty"`
}

// Policy is the protection block used at global, site and endpoint level
// (ADR-0012). Every field is optional; unset fields inherit.
type Policy struct {
	// off turns inspection off, detect records what would be blocked without blocking, block enforces (default detect).
	Mode *Mode `yaml:"mode,omitempty" json:"mode,omitempty"`
	// What happens to a request when a protection module fails internally: open lets it through, closed refuses it (default closed in block mode, otherwise open).
	FailMode *FailMode `yaml:"fail_mode,omitempty" json:"fail_mode,omitempty"`
	// Coraza and OWASP CRS tuning.
	WAF *WAFPolicy `yaml:"waf,omitempty" json:"waf,omitempty"`
	// The page shown for requests Sherlock terminates.
	BlockPage *BlockPage `yaml:"block_page,omitempty" json:"block_page,omitempty"`
	// Access control: allow and deny lists, countries, reputation and the password gate.
	ACL *ACLPolicy `yaml:"acl,omitempty" json:"acl,omitempty"`
	// RateLimits are named items: levels are unioned by name, and a lower
	// level may replace an item that has the same name.
	RateLimits []RateLimit `yaml:"rate_limits,omitempty" json:"rate_limits,omitempty"`
	// Bans a client address that keeps getting blocked. There is no built-in default: set blocks_threshold, window and ban_duration together.
	AutoBan *AutoBan `yaml:"auto_ban,omitempty" json:"auto_ban,omitempty"`
	// Bot defence: challenge pages for suspicious clients.
	Bot *BotPolicy `yaml:"bot,omitempty" json:"bot,omitempty"`
	// API protection: OpenAPI conformance, JWT validation and mutual TLS.
	API *APIPolicy `yaml:"api,omitempty" json:"api,omitempty"`
	// Login protection: failed-login velocity per client address, username and device on declared login endpoints.
	Login *LoginPolicy `yaml:"login_protection,omitempty" json:"login_protection,omitempty"`
	// Data protection: scans responses for card numbers, IBANs and custom patterns and masks or blocks them.
	DLP *DLPPolicy `yaml:"dlp,omitempty" json:"dlp,omitempty"`
	// Stacks declares the technologies behind the site (wordpress, php,
	// spring, ...). Product-specific virtual patches activate only for
	// declared stacks. Unset means "auto": generic patches only.
	Stacks *NameList `yaml:"stacks,omitempty" json:"stacks,omitempty"`
	// VirtualPatches switches the CVE rule pack (ADR-0013) per level.
	VirtualPatches *VirtualPatchPolicy `yaml:"virtual_patches,omitempty" json:"virtual_patches,omitempty"`
	// OptOut removes inherited named items, written "rate_limits:<name>",
	// "exclusions:<id>" or "virtual_patches:<id>". It is the only way to drop a
	// global item (and is audited with the change).
	OptOut []string `yaml:"opt_out,omitempty" json:"opt_out,omitempty"`
}

// VirtualPatchPolicy enables the virtual-patch pack and lists patches to skip.
type VirtualPatchPolicy struct {
	// Turns the virtual-patch pack on or off at this level (default true).
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Disabled are patch ids (SV-2021-0001) switched off at this level; levels
	// are unioned and a global entry is removed only through opt_out.
	Disabled []string `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// WAFPolicy tunes Coraza and CRS.
type WAFPolicy struct {
	// Turns the WAF on or off for this level (default true).
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// CRS paranoia level, 1 to 4: higher levels enable more rules and produce more false positives (default 1).
	ParanoiaLevel *int `yaml:"paranoia_level,omitempty" json:"paranoia_level,omitempty"`
	// Paranoia level at or below which rules count towards blocking, 1 to 4; it must not exceed paranoia_level (default: the paranoia_level).
	BlockingParanoiaLevel *int `yaml:"blocking_paranoia_level,omitempty" json:"blocking_paranoia_level,omitempty"`
	// Anomaly score at which a request is blocked; at least 1 (default 5).
	InboundThreshold *int `yaml:"inbound_threshold,omitempty" json:"inbound_threshold,omitempty"`
	// Anomaly score at which a response is blocked when outbound inspection is on; at least 1 (default 4).
	OutboundThreshold *int `yaml:"outbound_threshold,omitempty" json:"outbound_threshold,omitempty"`
	// Also inspects response bodies for data leaks and error pages (default false).
	OutboundInspection *bool `yaml:"outbound_inspection,omitempty" json:"outbound_inspection,omitempty"`
	// Largest request body in bytes that is inspected, 1 to 1073741824 (1 GiB); default 10485760 (10 MiB).
	MaxBodyBytes *int64 `yaml:"max_body_bytes,omitempty" json:"max_body_bytes,omitempty"`
	// File extensions such as ".css" whose GET and HEAD requests skip body inspection (default: common static assets: css, js, images, icons and fonts).
	SkipInspectionExtensions []string `yaml:"skip_inspection_extensions,omitempty" json:"skip_inspection_extensions,omitempty"`
	// OutboundMaxBodyBytes bounds the response body kept for inspection when
	// outbound_inspection is on; larger responses are inspected up to the limit.
	OutboundMaxBodyBytes *int64 `yaml:"outbound_max_body_bytes,omitempty" json:"outbound_max_body_bytes,omitempty"`
	// OutboundContentTypes are the media types whose responses are inspected
	// (prefix match on the type, e.g. "text/" or "application/json").
	OutboundContentTypes []string `yaml:"outbound_content_types,omitempty" json:"outbound_content_types,omitempty"`
	// Exclusions are named, scoped rule removals (false-positive tuning).
	// Levels are unioned by id; a lower level replaces an item with the same id.
	Exclusions []Exclusion `yaml:"exclusions,omitempty" json:"exclusions,omitempty"`
	// CustomRules is operator SecLang (ids 10000-99999) loaded before CRS.
	// The lowest level that sets it wins; it is validated by customrules.
	CustomRules *string `yaml:"custom_rules,omitempty" json:"custom_rules,omitempty"`
}

// BlockPage selects the page shown for terminated requests.
type BlockPage struct {
	// "default" or the id of an uploaded block page (default "default").
	TemplateID *string `yaml:"template_id,omitempty" json:"template_id,omitempty"`
}

// Endpoint overrides the site policy for requests matching Match.
type Endpoint struct {
	// Lowercase slug that names the endpoint; unique within the site.
	ID string `yaml:"id" json:"id"`
	// Which requests the endpoint applies to.
	Match EndpointMatch `yaml:"match" json:"match"`
	// Policy overrides for matching requests; unset fields inherit from the site.
	Policy Policy `yaml:"policy,omitempty" json:"policy"`
}

// EndpointMatch selects requests by exactly one of Path, PathPrefix or
// PathGlob (path.Match syntax), optionally narrowed to Methods.
type EndpointMatch struct {
	// Exact request path, starting with '/'.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	// Path prefix, starting with '/'.
	PathPrefix string `yaml:"path_prefix,omitempty" json:"path_prefix,omitempty"`
	// Path glob in path.Match syntax, starting with '/'.
	PathGlob string `yaml:"path_glob,omitempty" json:"path_glob,omitempty"`
	// Upper-case HTTP methods the endpoint applies to; empty means every method.
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
}
