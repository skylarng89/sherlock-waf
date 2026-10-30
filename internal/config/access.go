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
	Name  string   `yaml:"name" json:"name"`
	CIDRs []string `yaml:"cidrs" json:"cidrs"`
}

// Feeds configures the background data the node refreshes (M5). Secrets are
// never part of the document: the MaxMind licence key and the CrowdSec API key
// come from the environment (SHERLOCK_MAXMIND_LICENSE_KEY, SHERLOCK_CROWDSEC_API_KEY).
type Feeds struct {
	GeoIP           GeoIPFeed      `yaml:"geoip,omitempty" json:"geoip"`
	ReputationLists []string       `yaml:"reputation_lists,omitempty" json:"reputation_lists,omitempty"`
	CrowdSec        CrowdSecConfig `yaml:"crowdsec,omitempty" json:"crowdsec"`
}

// GeoIPFeed selects the country database.
type GeoIPFeed struct {
	Provider   string `yaml:"provider,omitempty" json:"provider,omitempty"` // dbip-lite (default) | maxmind
	AutoUpdate bool   `yaml:"auto_update,omitempty" json:"auto_update,omitempty"`
}

// CrowdSecConfig connects to a CrowdSec local API as a bouncer.
type CrowdSecConfig struct {
	Enabled bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
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
	AllowLists *NameList      `yaml:"allow_lists,omitempty" json:"allow_lists,omitempty"`
	DenyLists  *NameList      `yaml:"deny_lists,omitempty" json:"deny_lists,omitempty"`
	Countries  *Countries     `yaml:"countries,omitempty" json:"countries,omitempty"`
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
	Mode string   `yaml:"mode,omitempty" json:"mode,omitempty"`
	List []string `yaml:"list,omitempty" json:"list,omitempty"`
}

// ReputationACL acts on feed-listed addresses.
type ReputationACL struct {
	Enabled *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Action  string `yaml:"action,omitempty" json:"action,omitempty"` // block | log
}

// PasswordGate configures the site password gate. PasswordHash is an argon2id
// PHC string (create one with `sherlock hash-password`); the clear password is
// never stored.
type PasswordGate struct {
	Enabled      *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Username     string `yaml:"username,omitempty" json:"username,omitempty"`
	PasswordHash string `yaml:"password_hash,omitempty" json:"password_hash,omitempty"`
}

// RateLimit is one named limit.
type RateLimit struct {
	Name   string         `yaml:"name" json:"name"`
	Match  RateLimitMatch `yaml:"match,omitempty" json:"match"`
	Key    string         `yaml:"key,omitempty" json:"key,omitempty"` // ip | header:<name>
	Limit  int            `yaml:"limit" json:"limit"`
	Window Duration       `yaml:"window" json:"window"`
	Action string         `yaml:"action,omitempty" json:"action,omitempty"` // block | challenge | log
}

// RateLimitMatch narrows a limit to paths (path.Match globs) and methods.
type RateLimitMatch struct {
	Paths   []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
}

// AutoBan bans a client that keeps getting blocked.
type AutoBan struct {
	Enabled         *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	BlocksThreshold int      `yaml:"blocks_threshold,omitempty" json:"blocks_threshold,omitempty"`
	Window          Duration `yaml:"window,omitempty" json:"window,omitempty"`
	BanDuration     Duration `yaml:"ban_duration,omitempty" json:"ban_duration,omitempty"`
}

// Rate-limit actions and keys.
const (
	ActionBlock     = "block"
	ActionChallenge = "challenge"
	ActionLog       = "log"
	KeyIP           = "ip"
	KeyHeaderPrefix = "header:"
)
