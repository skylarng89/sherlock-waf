package config

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// DLPPolicy configures the data-loss-prevention module (FR-FIN-2): it scans
// responses for card numbers, IBANs and custom patterns and masks or blocks
// them. Matched values are never written to events, logs or exports.
type DLPPolicy struct {
	// Turns data protection on (on by default whenever the block is present).
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Detect lists what to look for: pan, iban, or custom:<name> for an entry of
	// CustomPatterns. A list: a lower level replaces it.
	Detect []string `yaml:"detect,omitempty" json:"detect,omitempty"`
	// Named custom detectors, at most 20; a lower level replaces the whole list.
	CustomPatterns []DLPPattern `yaml:"custom_patterns,omitempty" json:"custom_patterns,omitempty"`
	// Action is mask (default), block or log. In detect mode a match is only
	// recorded; the response is never changed.
	Action string `yaml:"action,omitempty" json:"action,omitempty"`
	// ContentTypes is the allow-list of response media types that are scanned.
	ContentTypes []string `yaml:"content_types,omitempty" json:"content_types,omitempty"`
	// MaxBodyBytes bounds how much of a response is scanned; a larger response
	// is passed through untouched and counted as skipped.
	MaxBodyBytes *int64 `yaml:"max_body_bytes,omitempty" json:"max_body_bytes,omitempty"`
}

// DLPPattern is a named custom detector. The pattern is a Go (RE2) regular
// expression, so it cannot cause catastrophic backtracking.
type DLPPattern struct {
	// Name used in detect as custom:<name>: lower-case letters, digits and underscores, starting with a letter (at most 32).
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	// RE2 regular expression, at most 512 characters, that must not match the empty string.
	Pattern string `yaml:"pattern,omitempty" json:"pattern,omitempty"`
}

// DLP detector names, actions and bounds.
const (
	DLPDetectPAN  = "pan"
	DLPDetectIBAN = "iban"
	DLPCustom     = "custom:"
	DLPActionMask = "mask"

	DefaultDLPMaxBodyBytes int64 = 1 << 20
	minDLPMaxBodyBytes     int64 = 1 << 10
	maxDLPMaxBodyBytes     int64 = 16 << 20
	maxDLPPatterns               = 20
	maxDLPPatternLen             = 512
)

var dlpNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// EffectiveDLP is the resolved DLP policy.
type EffectiveDLP struct {
	Enabled      bool         `json:"enabled"`
	Detect       []string     `json:"detect"`
	Custom       []DLPPattern `json:"custom_patterns"`
	Action       string       `json:"action"`
	ContentTypes []string     `json:"content_types"`
	MaxBodyBytes int64        `json:"max_body_bytes"`
}

func newEffectiveDLP() EffectiveDLP {
	return EffectiveDLP{
		Detect: []string{DLPDetectPAN}, Custom: []DLPPattern{}, Action: DLPActionMask,
		ContentTypes: DefaultOutboundContentTypes(), MaxBodyBytes: DefaultDLPMaxBodyBytes,
	}
}

// Active reports whether the module should be compiled in.
func (e EffectiveDLP) Active() bool { return e.Enabled && len(e.Detect) > 0 }

func (e *EffectivePolicy) applyDLP(p *Policy, src string) {
	d := p.DLP
	if d == nil {
		return
	}
	set := func(f string) { e.Sources["dlp."+f] = src }
	e.DLP.Enabled = d.Enabled == nil || *d.Enabled
	set("enabled")
	if d.Detect != nil {
		e.DLP.Detect = slices.Clone(d.Detect)
		set("detect")
	}
	if d.CustomPatterns != nil {
		e.DLP.Custom = slices.Clone(d.CustomPatterns)
		set("custom_patterns")
	}
	if d.Action != "" {
		e.DLP.Action = d.Action
		set("action")
	}
	if d.ContentTypes != nil {
		e.DLP.ContentTypes = slices.Clone(d.ContentTypes)
		set("content_types")
	}
	if d.MaxBodyBytes != nil {
		e.DLP.MaxBodyBytes = *d.MaxBodyBytes
		set("max_body_bytes")
	}
}

func (p *Policy) validateDLP(pth string, errs *Errors) {
	d := p.DLP
	if d == nil {
		return
	}
	if !slices.Contains([]string{"", DLPActionMask, ActionBlock, ActionLog}, d.Action) {
		errs.add(pth+"/action", CodeInvalid, "must be mask, block or log")
	}
	if d.MaxBodyBytes != nil && (*d.MaxBodyBytes < minDLPMaxBodyBytes || *d.MaxBodyBytes > maxDLPMaxBodyBytes) {
		errs.add(pth+"/max_body_bytes", CodeOutOfRange, "must be between %d and %d", minDLPMaxBodyBytes, maxDLPMaxBodyBytes)
	}
	for i, ct := range d.ContentTypes {
		if !contentTypRE.MatchString(ct) {
			errs.add(pth+"/content_types/"+strconv.Itoa(i), CodeInvalid, "%q must be a media type or prefix such as text/ or application/json", ct)
		}
	}
	if len(d.CustomPatterns) > maxDLPPatterns {
		errs.add(pth+"/custom_patterns", CodeOutOfRange, "at most %d patterns", maxDLPPatterns)
	}
	names := map[string]bool{}
	for i, cp := range d.CustomPatterns {
		cpath := pth + "/custom_patterns/" + strconv.Itoa(i)
		if !dlpNameRE.MatchString(cp.Name) {
			errs.add(cpath+"/name", CodeInvalid, "must be lower-case letters, digits and underscores, starting with a letter (at most 32)")
		} else if names[cp.Name] {
			errs.add(cpath+"/name", CodeDuplicate, "pattern %q is declared twice", cp.Name)
		}
		names[cp.Name] = true
		switch {
		case cp.Pattern == "":
			errs.add(cpath+"/pattern", CodeRequired, "a regular expression is required")
		case len(cp.Pattern) > maxDLPPatternLen:
			errs.add(cpath+"/pattern", CodeOutOfRange, "at most %d characters", maxDLPPatternLen)
		default:
			re, err := regexp.Compile(cp.Pattern)
			switch {
			case err != nil:
				errs.add(cpath+"/pattern", CodeInvalid, "not a valid RE2 expression: %v", err)
			case re.MatchString(""):
				errs.add(cpath+"/pattern", CodeInvalid, "must not match the empty string")
			}
		}
	}
	for i, det := range d.Detect {
		dpath := pth + "/detect/" + strconv.Itoa(i)
		switch {
		case det == DLPDetectPAN, det == DLPDetectIBAN:
		case strings.HasPrefix(det, DLPCustom):
			// A level that declares no patterns inherits them, so the name is only
			// checkable here when this level declares some; the compiler checks the
			// resolved policy.
			if d.CustomPatterns != nil && !names[strings.TrimPrefix(det, DLPCustom)] {
				errs.add(dpath, CodeInvalid, "%q refers to a custom pattern that is not declared in custom_patterns", det)
			}
		default:
			errs.add(dpath, CodeInvalid, "must be pan, iban or custom:<name>")
		}
	}
}
