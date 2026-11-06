package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"go.yaml.in/yaml/v3"
)

// IPList is a named set of CIDRs referenced by ACL allow and deny lists.
type IPList struct {
	// Lowercase letters, digits, '-' or '_' (at most 63); unique.
	Name string `yaml:"name" json:"name"`
	// CIDR ranges or single addresses (IPv4 or IPv6).
	CIDRs []string `yaml:"cidrs" json:"cidrs"`
}

// Feeds configures the background data the node refreshes. Secrets are
// never part of the document: the MaxMind licence key and the CrowdSec API key
// come from the environment (SHERLOCK_MAXMIND_LICENSE_KEY, SHERLOCK_CROWDSEC_API_KEY).
type Feeds struct {
	// The country database used by country ACLs and rules.
	GeoIP GeoIPFeed `yaml:"geoip,omitempty" json:"geoip"`
	// Public reputation lists to download: firehol_level1, spamhaus_drop.
	ReputationLists []string `yaml:"reputation_lists,omitempty" json:"reputation_lists,omitempty"`
	// Connection to a CrowdSec local API.
	CrowdSec CrowdSecConfig `yaml:"crowdsec,omitempty" json:"crowdsec"`
}

// GeoIPFeed selects the country database.
type GeoIPFeed struct {
	Provider string `yaml:"provider,omitempty" json:"provider,omitempty"` // dbip-lite (default) | maxmind
	// Downloads and refreshes the database automatically when it is missing or stale (default false: a database file placed in the data directory by hand is used as is).
	AutoUpdate bool `yaml:"auto_update,omitempty" json:"auto_update,omitempty"`
}

// CrowdSecConfig connects to a CrowdSec local API as a bouncer.
type CrowdSecConfig struct {
	// Turns the CrowdSec bouncer on (default false).
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// http or https URL of the CrowdSec local API; required when enabled. The API key comes from SHERLOCK_CROWDSEC_API_KEY.
	LAPIURL string `yaml:"lapi_url,omitempty" json:"lapi_url,omitempty"`
	// AllowPrivate lets the API live on a loopback or private address, which
	// is where a local CrowdSec agent usually listens. Link-local addresses
	// (the cloud metadata service) stay refused.
	AllowPrivate bool `yaml:"allow_private,omitempty" json:"allow_private,omitempty"`
}

// Known reputation lists and geo providers.
const (
	ListFireHOLLevel1 = "firehol_level1"
	ListSpamhausDROP  = "spamhaus_drop"
	GeoDBIPLite       = "dbip-lite"
	GeoMaxMind        = "maxmind"
)

// NameList is a list of names that a lower policy level either replaces
// wholesale (written as a YAML sequence) or edits (written as {add, remove}).
type NameList struct {
	Items  []string `yaml:"-" json:"-"`
	Add    []string `yaml:"add,omitempty" json:"add,omitempty"`
	Remove []string `yaml:"remove,omitempty" json:"remove,omitempty"`
	edit   bool
}

// Replaces reports whether the list replaces the inherited one.
func (l NameList) Replaces() bool { return !l.edit }

// Apply returns the effective list given the inherited one.
func (l NameList) Apply(inherited []string) []string {
	if !l.edit {
		return slices.Clone(l.Items)
	}
	out := slices.Clone(inherited)
	for _, a := range l.Add {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return slices.DeleteFunc(out, func(n string) bool { return slices.Contains(l.Remove, n) })
}

// Names returns every name the list mentions, for reference checks.
func (l NameList) Names() []string { return slices.Concat(l.Items, l.Add, l.Remove) }

// UnmarshalYAML implements yaml.Unmarshaler.
func (l *NameList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.SequenceNode:
		var items []string
		if err := n.Decode(&items); err != nil {
			return err
		}
		*l = NameList{Items: append([]string{}, items...)}
		return nil
	case yaml.MappingNode:
		var m struct {
			Add    []string `yaml:"add"`
			Remove []string `yaml:"remove"`
		}
		if err := n.Decode(&m); err != nil {
			return err
		}
		*l = NameList{Add: m.Add, Remove: m.Remove, edit: true}
		return nil
	case yaml.DocumentNode, yaml.ScalarNode, yaml.AliasNode:
	}
	return fmt.Errorf("line %d: expected a list of names or {add, remove}", n.Line)
}

// MarshalYAML implements yaml.Marshaler.
func (l NameList) MarshalYAML() (any, error) {
	if !l.edit {
		return append([]string{}, l.Items...), nil
	}
	return struct {
		Add    []string `yaml:"add,omitempty"`
		Remove []string `yaml:"remove,omitempty"`
	}{l.Add, l.Remove}, nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (l *NameList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '[' {
		var items []string
		if err := json.Unmarshal(b, &items); err != nil {
			return err
		}
		*l = NameList{Items: append([]string{}, items...)}
		return nil
	}
	var m struct {
		Add    []string `json:"add"`
		Remove []string `json:"remove"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return fmt.Errorf("expected a list of names or {add, remove}: %w", err)
	}
	*l = NameList{Add: m.Add, Remove: m.Remove, edit: true}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (l NameList) MarshalJSON() ([]byte, error) {
	if !l.edit {
		return json.Marshal(append([]string{}, l.Items...))
	}
	return json.Marshal(struct {
		Add    []string `json:"add,omitempty"`
		Remove []string `json:"remove,omitempty"`
	}{l.Add, l.Remove})
}

// ACLPolicy is the access-control block of a policy.
type ACLPolicy struct {
	// Names of ip_lists whose clients are allowed: they skip rate limits and bot checks. A list of names replaces the inherited list; {add, remove} edits it.
	AllowLists *NameList `yaml:"allow_lists,omitempty" json:"allow_lists,omitempty"`
	// Names of ip_lists whose clients are blocked. A list of names replaces the inherited list; {add, remove} edits it.
	DenyLists *NameList `yaml:"deny_lists,omitempty" json:"deny_lists,omitempty"`
	// Allows or denies clients by country, using the GeoIP database from feeds.geoip.
	Countries *Countries `yaml:"countries,omitempty" json:"countries,omitempty"`
	// Acts on clients listed by the reputation feeds.
	Reputation *ReputationACL `yaml:"reputation,omitempty" json:"reputation,omitempty"`
	// PasswordGate puts HTTP Basic authentication in front of the site.
	PasswordGate *PasswordGate `yaml:"password_gate,omitempty" json:"password_gate,omitempty"`
	// AllowBypassWAF lets allow-listed clients skip WAF inspection. Off by
	// default: an allow list skips rate limits and bot checks, not the WAF.
	AllowBypassWAF *bool `yaml:"allow_bypass_waf,omitempty" json:"allow_bypass_waf,omitempty"`
}

// Country list modes.
const (
	CountryOff   = "off"
	CountryAllow = "allow"
	CountryDeny  = "deny"
)

// Countries allows or denies ISO 3166-1 alpha-2 country codes.
type Countries struct {
	// off, allow (only the listed countries) or deny (all but the listed countries); default off.
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`
	// ISO 3166-1 alpha-2 country codes in capitals, without duplicates; an empty list with mode allow is rejected because it would block every country.
	List []string `yaml:"list,omitempty" json:"list,omitempty"`
}

// ReputationACL acts on feed-listed addresses.
type ReputationACL struct {
	// Turns reputation checks on (on by default whenever the reputation block is present).
	Enabled *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Action  string `yaml:"action,omitempty" json:"action,omitempty"` // block | log
}

// PasswordGate configures the site password gate. PasswordHash is an argon2id
// PHC string (create one with `sherlock hash-password`); the clear password is
// never stored.
type PasswordGate struct {
	// Turns the gate on (on by default whenever the block is present); needs username and password_hash.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// The accepted user name, at most 64 characters, without ':' or line breaks.
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	// argon2id hash of the password, starting with $argon2id$; never returned by the API.
	PasswordHash string `yaml:"password_hash,omitempty" json:"password_hash,omitempty"`
}

// RateLimit is one named limit.
type RateLimit struct {
	// Lowercase letters, digits, '-' or '_' (at most 63); a lower level replaces an inherited limit of the same name.
	Name string `yaml:"name" json:"name"`
	// Restricts the limit to matching requests; empty applies it to every request.
	Match RateLimitMatch `yaml:"match,omitempty" json:"match"`
	Key   string         `yaml:"key,omitempty" json:"key,omitempty"` // ip | header:<name>
	// Requests allowed per window and key, 1 to 1,000,000.
	Limit int `yaml:"limit" json:"limit"`
	// Length of the counting window, 1s to 24h.
	Window Duration `yaml:"window" json:"window"`
	Action string   `yaml:"action,omitempty" json:"action,omitempty"` // block | challenge | log
}

// RateLimitMatch narrows a limit to paths (path.Match globs) and methods.
type RateLimitMatch struct {
	// Path globs starting with '/' (at most 50); default ["/*"].
	Paths []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	// Upper-case HTTP methods; empty means every method.
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
}

// AutoBan bans a client that keeps getting blocked.
type AutoBan struct {
	// Turns auto-ban on (on by default whenever the block is present).
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Number of blocked requests within window that triggers a ban, 1 to 1,000,000.
	BlocksThreshold int `yaml:"blocks_threshold,omitempty" json:"blocks_threshold,omitempty"`
	// Period in which blocks are counted, 1s to 24h.
	Window Duration `yaml:"window,omitempty" json:"window,omitempty"`
	// How long the client stays banned, 1m to 30d.
	BanDuration Duration `yaml:"ban_duration,omitempty" json:"ban_duration,omitempty"`
}

// Rate-limit actions and keys.
const (
	ActionBlock     = "block"
	ActionChallenge = "challenge"
	ActionLog       = "log"
	KeyIP           = "ip"
	KeyHeaderPrefix = "header:"
)
