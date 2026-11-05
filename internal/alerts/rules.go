// Package alerts evaluates alert rules every 30 seconds and notifies channels
// when one fires. State (which subjects already alerted, cool-down clocks) is
// held in memory: after a restart a condition that is still true alerts again
// once, which is the safe direction for an alerting system.
package alerts

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/notify"
)

// Rule kinds.
const (
	KindBlocksThreshold   = "blocks_threshold"
	KindNewCountry        = "new_country"
	KindCertExpiring      = "cert_expiring"
	KindFeedFailure       = "feed_failure"
	KindEventsDropped     = "events_dropped"
	KindUpstreamUnhealthy = "upstream_unhealthy"
)

// Limits.
const (
	DefaultCooldownSeconds = 900
	MinCooldownSeconds     = 60
	MaxCooldownSeconds     = 7 * 24 * 3600
	MinWindowSeconds       = 60
	MaxWindowSeconds       = 24 * 3600
	MaxChannels            = 10
	maxThreshold           = 10_000_000
)

// ErrInvalid wraps every rule validation failure.
var ErrInvalid = errors.New("alerts: invalid rule")

// Rule is one configured alert.
type Rule struct {
	ID              string
	Name            string
	Enabled         bool
	Kind            string
	Params          json.RawMessage
	Severity        string // info | warning | critical; empty means warning
	CooldownSeconds int    // 0 means DefaultCooldownSeconds
	ChannelIDs      []string
}

func (r Rule) cooldown() time.Duration {
	if r.CooldownSeconds <= 0 {
		return DefaultCooldownSeconds * time.Second
	}
	return time.Duration(r.CooldownSeconds) * time.Second
}

func (r Rule) severity() string {
	if r.Severity == "" {
		return notify.SeverityWarning
	}
	return r.Severity
}

// Kinds lists the supported rule kinds.
func Kinds() []string {
	return []string{KindBlocksThreshold, KindNewCountry, KindCertExpiring, KindFeedFailure, KindEventsDropped, KindUpstreamUnhealthy}
}

var siteIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type blocksParams struct {
	SiteID        string `json:"site_id"`
	Threshold     int    `json:"threshold"`
	WindowSeconds int    `json:"window_seconds"`
}

type countryParams struct {
	SiteID          string `json:"site_id"`
	WindowSeconds   int    `json:"window_seconds"`
	BaselineSeconds int    `json:"baseline_seconds"`
}

type certParams struct {
	Days int `json:"days"`
}

type upstreamParams struct {
	SiteID string `json:"site_id"`
}

type noParams struct{}

func decodeParams(raw json.RawMessage, dst any) error {
	if len(raw) == 0 || string(raw) == "null" {
		raw = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%w: params: %s", ErrInvalid, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: params: trailing data", ErrInvalid)
	}
	return nil
}

func checkSite(id string) error {
	if id != "" && !siteIDPattern.MatchString(id) {
		return fmt.Errorf("%w: site_id is not valid", ErrInvalid)
	}
	return nil
}

func checkWindow(name string, seconds int) error {
	if seconds < MinWindowSeconds || seconds > MaxWindowSeconds {
		return fmt.Errorf("%w: %s must be %d-%d", ErrInvalid, name, MinWindowSeconds, MaxWindowSeconds)
	}
	return nil
}

// Validate checks the parameters of a rule of the given kind.
func Validate(kind string, params json.RawMessage) error {
	switch kind {
	case KindBlocksThreshold:
		var p blocksParams
		if err := decodeParams(params, &p); err != nil {
			return err
		}
		if p.Threshold < 1 || p.Threshold > maxThreshold {
			return fmt.Errorf("%w: threshold must be 1-%d", ErrInvalid, maxThreshold)
		}
		if err := checkWindow("window_seconds", p.WindowSeconds); err != nil {
			return err
		}
		return checkSite(p.SiteID)
	case KindNewCountry:
		var p countryParams
		if err := decodeParams(params, &p); err != nil {
			return err
		}
		if err := checkWindow("window_seconds", p.WindowSeconds); err != nil {
			return err
		}
		if err := checkWindow("baseline_seconds", p.BaselineSeconds); err != nil {
			return err
		}
		return checkSite(p.SiteID)
	case KindCertExpiring:
		var p certParams
		if err := decodeParams(params, &p); err != nil {
			return err
		}
		if p.Days < 1 || p.Days > 365 {
			return fmt.Errorf("%w: days must be 1-365", ErrInvalid)
		}
		return nil
	case KindUpstreamUnhealthy:
		var p upstreamParams
		if err := decodeParams(params, &p); err != nil {
			return err
		}
		return checkSite(p.SiteID)
	case KindFeedFailure, KindEventsDropped:
		var p noParams
		return decodeParams(params, &p)
	}
	return fmt.Errorf("%w: unknown kind %q", ErrInvalid, kind)
}

// ValidateRule checks everything about a rule except that its channels exist.
func ValidateRule(r Rule) error {
	if n := strings.TrimSpace(r.Name); n == "" || len(n) > 100 {
		return fmt.Errorf("%w: name must be 1-100 characters", ErrInvalid)
	}
	if !slices.Contains([]string{"", notify.SeverityInfo, notify.SeverityWarning, notify.SeverityCritical}, r.Severity) {
		return fmt.Errorf("%w: severity must be info, warning or critical", ErrInvalid)
	}
	if r.CooldownSeconds != 0 && (r.CooldownSeconds < MinCooldownSeconds || r.CooldownSeconds > MaxCooldownSeconds) {
		return fmt.Errorf("%w: cooldown_seconds must be %d-%d", ErrInvalid, MinCooldownSeconds, MaxCooldownSeconds)
	}
	if len(r.ChannelIDs) > MaxChannels {
		return fmt.Errorf("%w: at most %d channels", ErrInvalid, MaxChannels)
	}
	seen := map[string]bool{}
	for _, id := range r.ChannelIDs {
		if id == "" || seen[id] {
			return fmt.Errorf("%w: channel ids must be non-empty and unique", ErrInvalid)
		}
		seen[id] = true
	}
	return Validate(r.Kind, r.Params)
}
