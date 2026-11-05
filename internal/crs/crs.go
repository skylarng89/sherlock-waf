// Package crs is the catalogue of OWASP CRS rules behind the dashboard's CRS
// page (M8-T6): every rule with its description, paranoia level, category and
// tags, parsed once from the CRS files embedded in the binary, plus the state
// of each rule under a site's effective policy.
package crs

import (
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"

	"github.com/skylarng89/sherlock-waf/internal/config"
)

// Rule is one CRS detection rule.
type Rule struct {
	ID            int      `json:"id"`
	File          string   `json:"file"`
	Phase         int      `json:"phase"`
	Direction     string   `json:"direction"` // request | response
	Category      string   `json:"category"`
	Message       string   `json:"message"`
	Severity      string   `json:"severity,omitempty"`
	ParanoiaLevel int      `json:"paranoia_level"`
	Tags          []string `json:"tags"`
}

var (
	idRE   = regexp.MustCompile(`(?:^|[\s",])id:\s*'?(\d+)`)
	msgRE  = regexp.MustCompile(`(?:^|[\s",])msg:\s*'((?:[^'\\]|\\.)*)'`)
	sevRE  = regexp.MustCompile(`(?:^|[\s",])severity:\s*'?([A-Za-z]+)'?`)
	phaseR = regexp.MustCompile(`(?:^|[\s",])phase:\s*'?(\d)`)
	tagRE  = regexp.MustCompile(`(?:^|[\s",])tag:\s*'([^']*)'`)
	plRE   = regexp.MustCompile(`^paranoia-level/(\d)$`)
	fileRE = regexp.MustCompile(`^(REQUEST|RESPONSE)-(\d{3})-(.+)\.conf$`)

	once    sync.Once
	rules   []Rule
	loadErr error
)

// Rules returns the catalogue ordered by rule id.
func Rules() ([]Rule, error) {
	once.Do(func() { rules, loadErr = parse(coreruleset.FS, "@owasp_crs") })
	return slices.Clone(rules), loadErr
}

func parse(fsys fs.FS, dir string) ([]Rule, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("reading CRS rules: %w", err)
	}
	var out []Rule
	for _, e := range entries {
		m := fileRE.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		b, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		fileCategory := strings.ToLower(strings.TrimPrefix(m[3], "APPLICATION-"))
		direction := strings.ToLower(m[1])
		text := strings.ReplaceAll(string(b), "\\\n", " ")
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "SecRule") && !strings.HasPrefix(line, "SecAction") {
				continue
			}
			idm := idRE.FindStringSubmatch(line)
			msg := msgRE.FindStringSubmatch(line)
			if idm == nil || msg == nil { // chained part, or housekeeping without a description
				continue
			}
			id, _ := strconv.Atoi(idm[1])
			r := Rule{ID: id, File: e.Name(), Direction: direction, Category: fileCategory, Message: strings.ReplaceAll(msg[1], `\'`, "'"), ParanoiaLevel: 1, Tags: []string{}}
			if p := phaseR.FindStringSubmatch(line); p != nil {
				r.Phase, _ = strconv.Atoi(p[1])
			}
			if s := sevRE.FindStringSubmatch(line); s != nil {
				r.Severity = strings.ToLower(s[1])
			}
			for _, t := range tagRE.FindAllStringSubmatch(line, -1) {
				r.Tags = append(r.Tags, t[1])
				if p := plRE.FindStringSubmatch(t[1]); p != nil {
					r.ParanoiaLevel, _ = strconv.Atoi(p[1])
				}
				if strings.HasPrefix(t[1], "attack-") {
					r.Category = t[1]
				}
			}
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Get returns one rule.
func Get(id int) (Rule, bool) {
	all, err := Rules()
	if err != nil {
		return Rule{}, false
	}
	i, ok := slices.BinarySearchFunc(all, id, func(r Rule, id int) int { return r.ID - id })
	if !ok {
		return Rule{}, false
	}
	return all[i], true
}

// Match reports whether q (lower case, may be empty) occurs in the rule's id,
// message, category or tags.
func (r Rule) Match(q string) bool {
	if q == "" {
		return true
	}
	if strings.Contains(strconv.Itoa(r.ID), q) || strings.Contains(strings.ToLower(r.Message), q) || strings.Contains(r.Category, q) {
		return true
	}
	return slices.ContainsFunc(r.Tags, func(t string) bool { return strings.Contains(strings.ToLower(t), q) })
}

// State of a rule for one site policy.
type State string

// Rule states.
const (
	// Enforcing: the rule scores and its score counts towards blocking.
	Enforcing State = "enforcing"
	// DetectOnly: the rule runs and records findings, but sits above the
	// blocking paranoia level, so it never blocks on its own.
	DetectOnly State = "detect_only"
	// Inactive: the rule does not run (paranoia level too low, outbound
	// inspection off, WAF off).
	Inactive State = "inactive"
	// Disabled: an exclusion without a path or method scope removes the rule.
	Disabled State = "disabled"
	// PartlyExcluded: scoped exclusions remove the rule for some requests.
	PartlyExcluded State = "partly_excluded"
)

// Status is a rule's state under a policy and why.
type Status struct {
	State  State    `json:"state"`
	Reason string   `json:"reason,omitempty"`
	By     []string `json:"excluded_by,omitempty"` // exclusion ids
}

// StateFor evaluates r under an effective policy.
func StateFor(r Rule, eff config.EffectivePolicy) Status {
	switch {
	case eff.Mode == config.ModeOff || !eff.WAF.Enabled:
		return Status{State: Inactive, Reason: "waf_off"}
	case r.Direction == "response" && !eff.WAF.OutboundInspection:
		return Status{State: Inactive, Reason: "outbound_inspection_off"}
	case r.ParanoiaLevel > eff.WAF.ParanoiaLevel:
		return Status{State: Inactive, Reason: "paranoia_level_too_low"}
	}
	var global, scoped []string
	for _, x := range eff.WAF.Exclusions {
		if !RemovesRule(x, r) {
			continue
		}
		if len(x.Match.Paths) == 0 && len(x.Match.Methods) == 0 {
			global = append(global, x.ID)
		} else {
			scoped = append(scoped, x.ID)
		}
	}
	switch {
	case len(global) > 0:
		return Status{State: Disabled, Reason: "exclusion", By: global}
	case len(scoped) > 0:
		return Status{State: PartlyExcluded, Reason: "scoped_exclusion", By: scoped}
	case r.ParanoiaLevel > eff.WAF.BlockingParanoiaLevel && r.Direction == "request":
		return Status{State: DetectOnly, Reason: "above_blocking_paranoia_level"}
	}
	return Status{State: Enforcing}
}

// RemovesRule reports whether the exclusion removes the whole rule (by id,
// range or tag) wherever its scope matches. Target-only removals do not.
func RemovesRule(x config.Exclusion, r Rule) bool {
	for _, s := range x.RemoveRuleIDs {
		if lo, hi, ok := config.ParseRuleIDRange(s); ok && r.ID >= lo && r.ID <= hi {
			return true
		}
	}
	return slices.ContainsFunc(x.RemoveTags, func(t string) bool { return slices.Contains(r.Tags, t) })
}
