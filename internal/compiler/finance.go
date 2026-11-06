package compiler

import (
	"fmt"
	"slices"
	"strings"

	"github.com/skylarng89/sherlock-waf/internal/config"
)

// loginHandler emits sherlock_login (M11-T1), or nil while login protection is
// off, has no declared endpoint, or the site is in mode off. The handler runs
// after the bot module so a challenge it asks for is served by the next request.
func loginHandler(siteID string, eff config.EffectivePolicy) obj {
	l := eff.Login
	if eff.Mode == config.ModeOff || !l.Active() {
		return nil
	}
	endpoints := make([]obj, len(l.Endpoints))
	for i, ep := range l.Endpoints {
		endpoints[i] = obj{
			"path": ep.Path, "method": ep.Method, "username_field": ep.UsernameField,
			"failure_statuses": ep.FailureStatuses,
		}
	}
	h := obj{
		"handler": "sherlock_login", "site_id": siteID, "mode": string(eff.Mode),
		"action": l.Action, "endpoints": endpoints,
		"per_ip": l.PerIP, "per_username": l.PerUser, "per_device": l.PerDevice, "window": l.Window.String(),
	}
	if eff.Bot.Enabled {
		h["challenge_handoff"] = true // a challenge is served by the bot module
	}
	return h
}

// dlpHandler emits sherlock_dlp (M11-T2), or nil while data protection is off or
// the site is in mode off. It checks the resolved custom_patterns against detect,
// which validation can only do for a level that declares its own patterns.
func dlpHandler(siteID string, eff config.EffectivePolicy) (obj, error) {
	d := eff.DLP
	if eff.Mode == config.ModeOff || !d.Active() {
		return nil, nil
	}
	known := make(map[string]bool, len(d.Custom))
	for _, cp := range d.Custom {
		known[cp.Name] = true
	}
	for _, det := range d.Detect {
		if name, ok := strings.CutPrefix(det, config.DLPCustom); ok && !known[name] {
			return nil, fmt.Errorf("dlp: detect %q has no matching entry in custom_patterns", det)
		}
	}
	h := obj{
		"handler": "sherlock_dlp", "site_id": siteID, "mode": string(eff.Mode),
		"action": d.Action, "detect": slices.Clone(d.Detect),
		"content_types": d.ContentTypes, "max_body_bytes": d.MaxBodyBytes,
	}
	if len(d.Custom) > 0 {
		patterns := make([]obj, len(d.Custom))
		for i, cp := range d.Custom {
			patterns[i] = obj{"name": cp.Name, "pattern": cp.Pattern}
		}
		h["custom_patterns"] = patterns
	}
	return h, nil
}
