package config

import (
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/skylarng89/sherlock-waf/internal/customrules"
)

// Limits for tuning objects.
const (
	maxExclusionsPerLevel = 200
	maxStacks             = 50

	// DefaultOutboundMaxBodyBytes bounds inspected response bodies.
	DefaultOutboundMaxBodyBytes int64 = 1 << 20
	maxOutboundBodyBytes        int64 = 64 << 20
)

// DefaultOutboundContentTypes are inspected when outbound inspection is on and
// no filter is configured: text responses are where data leaks and error
// pages show up; binary downloads are skipped.
func DefaultOutboundContentTypes() []string {
	return []string{"text/html", "text/plain", "application/json", "application/xml", "text/xml"}
}

// Reserved rule id ranges used by validation and by the exclusion compiler.
const (
	// VirtualPatchMinID and VirtualPatchMaxID bound the virtual-patch pack (ADR-0013).
	VirtualPatchMinID = 9_500_000
	VirtualPatchMaxID = 9_599_999
	// engineMaxProtectedID is the top of the ids that belong to Sherlock itself
	// (body processors at 200000-200099).
	engineMinProtectedID = 200_000
	engineMaxProtectedID = 200_099
)

// Exclusion removes CRS rules, tags or rule targets for requests that match
// Match. It compiles to a runtime exclusion rule placed before CRS (T1).
type Exclusion struct {
	ID            string            `yaml:"id" json:"id"`
	Description   string            `yaml:"description,omitempty" json:"description,omitempty"`
	Match         ExclusionMatch    `yaml:"match,omitempty" json:"match"`
	RemoveRuleIDs []string          `yaml:"remove_rule_ids,omitempty" json:"remove_rule_ids,omitempty"`
	RemoveTags    []string          `yaml:"remove_tags,omitempty" json:"remove_tags,omitempty"`
	RemoveTargets []ExclusionTarget `yaml:"remove_targets,omitempty" json:"remove_targets,omitempty"`
}

// ExclusionMatch scopes an exclusion. Empty Paths means every path, empty
// Methods every method. Paths use path.Match globs ("*" does not cross "/");
// a trailing "/**" matches the prefix and everything below it.
type ExclusionMatch struct {
	Paths   []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
}

// ExclusionTarget removes one request target (ARGS:q, REQUEST_COOKIES:/^_ga/)
// from the checks of the listed rules or tags.
type ExclusionTarget struct {
	RuleIDs []string `yaml:"rule_ids,omitempty" json:"rule_ids,omitempty"`
	Tags    []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Target  string   `yaml:"target" json:"target"`
}

var (
	ruleIDRE     = regexp.MustCompile(`^(\d{1,9})(?:-(\d{1,9}))?$`)
	tagRE        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/_.:-]{0,100}$`)
	targetRE     = regexp.MustCompile(`^[!&]?[A-Z][A-Z_]{1,40}(?::(?:[^\s;"'\\,]{1,200}|/[^\s;"'\\]{1,200}/))?$`)
	vpatchIDRE   = regexp.MustCompile(`^SV-\d{4}-\d{4}$`)
	stackRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,40}$`)
	contentTypRE = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*(/[a-z0-9!#$&^_.+*-]*)?$`)
)

// ParseRuleIDRange parses "942100" or "942100-942199".
func ParseRuleIDRange(s string) (lo, hi int, ok bool) {
	m := ruleIDRE.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, false
	}
	lo, _ = strconv.Atoi(m[1])
	hi = lo
	if m[2] != "" {
		hi, _ = strconv.Atoi(m[2])
	}
	return lo, hi, hi >= lo && lo > 0
}

// ExclusionRuleIDError explains why a rule id may not be removed by an
// exclusion, or returns "" when it may.
func exclusionRuleIDError(s string) string {
	lo, hi, ok := ParseRuleIDRange(s)
	switch {
	case !ok:
		return "must be a rule id such as 942100 or a range such as 942100-942199"
	case lo <= engineMaxProtectedID && hi >= engineMinProtectedID:
		return "rules 200000-200099 are Sherlock's own body parsers and cannot be removed"
	case lo <= VirtualPatchMaxID && hi >= VirtualPatchMinID:
		return "virtual patches are switched off with virtual_patches.disabled, not with an exclusion"
	case lo >= customrules.MinID && hi <= customrules.MaxID:
		return "custom rules (10000-99999) are edited in custom_rules, not excluded"
	}
	return ""
}

func (m ExclusionMatch) validate(p string, errs *Errors) {
	for i, g := range m.Paths {
		gp := p + "/paths/" + strconv.Itoa(i)
		switch {
		case !validPath(g) || strings.ContainsAny(g, "\"'\\") || strings.IndexFunc(g, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0:
			errs.add(gp, CodeInvalid, "must start with '/' and contain no '..' segments, quotes, backslashes or control characters")
		default:
			if _, err := path.Match(strings.TrimSuffix(g, "/**"), ""); err != nil {
				errs.add(gp, CodeInvalid, "invalid glob: %v", err)
			}
		}
	}
	seen := map[string]bool{}
	for i, v := range m.Methods {
		mp := p + "/methods/" + strconv.Itoa(i)
		if !slices.Contains(validVerbs, v) {
			errs.add(mp, CodeInvalid, "%q must be an upper-case HTTP method", v)
		}
		if seen[v] {
			errs.add(mp, CodeDuplicate, "method %q listed twice", v)
		}
		seen[v] = true
	}
}

func (e Exclusion) validate(p string, errs *Errors) {
	switch {
	case e.ID == "":
		errs.add(p+"/id", CodeRequired, "id is required")
	case !slugRE.MatchString(e.ID):
		errs.add(p+"/id", CodeInvalid, "id must be a lowercase slug (a-z, 0-9, '-', max 63 chars)")
	}
	if len(e.Description) > 500 {
		errs.add(p+"/description", CodeOutOfRange, "at most 500 characters")
	}
	e.Match.validate(p+"/match", errs)
	if len(e.RemoveRuleIDs) == 0 && len(e.RemoveTags) == 0 && len(e.RemoveTargets) == 0 {
		errs.add(p, CodeRequired, "an exclusion must remove at least one rule id, tag or target")
	}
	for i, id := range e.RemoveRuleIDs {
		if msg := exclusionRuleIDError(id); msg != "" {
			errs.add(p+"/remove_rule_ids/"+strconv.Itoa(i), CodeInvalid, "%q: %s", id, msg)
		}
	}
	for i, t := range e.RemoveTags {
		if !tagRE.MatchString(t) {
			errs.add(p+"/remove_tags/"+strconv.Itoa(i), CodeInvalid, "%q is not a valid rule tag", t)
		}
	}
	for i, t := range e.RemoveTargets {
		tp := p + "/remove_targets/" + strconv.Itoa(i)
		if len(t.RuleIDs) == 0 && len(t.Tags) == 0 {
			errs.add(tp, CodeRequired, "rule_ids or tags is required")
		}
		for j, id := range t.RuleIDs {
			if msg := exclusionRuleIDError(id); msg != "" {
				errs.add(tp+"/rule_ids/"+strconv.Itoa(j), CodeInvalid, "%q: %s", id, msg)
			}
		}
		for j, tag := range t.Tags {
			if !tagRE.MatchString(tag) {
				errs.add(tp+"/tags/"+strconv.Itoa(j), CodeInvalid, "%q is not a valid rule tag", tag)
			}
		}
		if !targetRE.MatchString(t.Target) {
			errs.add(tp+"/target", CodeInvalid, "%q must look like ARGS:q, ARGS_NAMES:q or REQUEST_COOKIES:/^_ga/", t.Target)
		}
	}
}

// validateRules checks the M8 additions of one policy layer. inherited lists
// the ids of exclusions and patches defined above this level, for opt_out.
func (p *Policy) validateRules(path string, errs *Errors) {
	if s := p.Stacks; s != nil {
		names := s.Names()
		if len(names) > maxStacks {
			errs.add(path+"/stacks", CodeOutOfRange, "at most %d stacks", maxStacks)
		}
		for i, n := range names {
			if n != StackAuto && !stackRE.MatchString(n) {
				errs.add(path+"/stacks/"+strconv.Itoa(i), CodeInvalid, "%q must be a lowercase name such as wordpress or spring (or %q)", n, StackAuto)
			}
		}
	}
	if v := p.VirtualPatches; v != nil {
		seen := map[string]bool{}
		for i, id := range v.Disabled {
			vp := path + "/virtual_patches/disabled/" + strconv.Itoa(i)
			if !vpatchIDRE.MatchString(id) {
				errs.add(vp, CodeInvalid, "%q must look like SV-2021-0001", id)
			}
			if seen[id] {
				errs.add(vp, CodeDuplicate, "%q listed twice", id)
			}
			seen[id] = true
		}
	}
	w := p.WAF
	if w == nil {
		return
	}
	wp := path + "/waf"
	if len(w.Exclusions) > maxExclusionsPerLevel {
		errs.add(wp+"/exclusions", CodeOutOfRange, "at most %d exclusions per level", maxExclusionsPerLevel)
	}
	seen := map[string]bool{}
	for i, e := range w.Exclusions {
		ep := wp + "/exclusions/" + strconv.Itoa(i)
		e.validate(ep, errs)
		if seen[e.ID] && e.ID != "" {
			errs.add(ep+"/id", CodeDuplicate, "exclusion %q listed twice at this level", e.ID)
		}
		seen[e.ID] = true
	}
	if w.CustomRules != nil {
		res := customrules.Check(*w.CustomRules)
		for _, is := range res.Issues {
			errs.add(wp+"/custom_rules", is.Code, "%s", is.String())
		}
	}
	if w.OutboundMaxBodyBytes != nil && (*w.OutboundMaxBodyBytes < 1 || *w.OutboundMaxBodyBytes > maxOutboundBodyBytes) {
		errs.add(wp+"/outbound_max_body_bytes", CodeOutOfRange, "must be between 1 and %d", maxOutboundBodyBytes)
	}
	for i, ct := range w.OutboundContentTypes {
		if !contentTypRE.MatchString(ct) {
			errs.add(wp+"/outbound_content_types/"+strconv.Itoa(i), CodeInvalid, "%q must be a media type or prefix such as text/ or application/json", ct)
		}
	}
}

// StackAuto in a stack list means "no declared stack": generic patches only.
const StackAuto = "auto"

// EffectiveVirtualPatches is the resolved virtual-patch policy.
type EffectiveVirtualPatches struct {
	Enabled  bool     `json:"enabled"`
	Disabled []string `json:"disabled"`
}

// optOut prefixes besides rate_limits.
const (
	optOutExclusions     = "exclusions:"
	optOutVirtualPatches = "virtual_patches:"
)

// applyRules merges one layer's M8 fields into e.
func (e *EffectivePolicy) applyRules(p *Policy, src string) {
	set := func(field string) { e.Sources[field] = src }

	for _, o := range p.OptOut {
		if id, ok := strings.CutPrefix(o, optOutExclusions); ok {
			e.WAF.Exclusions = slices.DeleteFunc(e.WAF.Exclusions, func(x Exclusion) bool { return x.ID == id })
			delete(e.Sources, "waf.exclusions."+id)
		}
		if id, ok := strings.CutPrefix(o, optOutVirtualPatches); ok {
			e.VirtualPatches.Disabled = slices.DeleteFunc(e.VirtualPatches.Disabled, func(x string) bool { return x == id })
		}
	}
	if p.Stacks != nil {
		e.Stacks = p.Stacks.Apply(e.Stacks)
		set("stacks")
	}
	if v := p.VirtualPatches; v != nil {
		if v.Enabled != nil {
			e.VirtualPatches.Enabled = *v.Enabled
			set("virtual_patches.enabled")
		}
		for _, id := range v.Disabled {
			if !slices.Contains(e.VirtualPatches.Disabled, id) {
				e.VirtualPatches.Disabled = append(e.VirtualPatches.Disabled, id)
			}
			set("virtual_patches.disabled")
		}
	}
	w := p.WAF
	if w == nil {
		return
	}
	for _, x := range w.Exclusions {
		if i := slices.IndexFunc(e.WAF.Exclusions, func(y Exclusion) bool { return y.ID == x.ID }); i >= 0 {
			e.WAF.Exclusions[i] = x
		} else {
			e.WAF.Exclusions = append(e.WAF.Exclusions, x)
		}
		set("waf.exclusions." + x.ID)
	}
	if w.CustomRules != nil {
		e.WAF.CustomRules = *w.CustomRules
		set("waf.custom_rules")
	}
	if w.OutboundMaxBodyBytes != nil {
		e.WAF.OutboundMaxBodyBytes = *w.OutboundMaxBodyBytes
		set("waf.outbound_max_body_bytes")
	}
	if w.OutboundContentTypes != nil {
		e.WAF.OutboundContentTypes = slices.Clone(w.OutboundContentTypes)
		set("waf.outbound_content_types")
	}
}

// DeclaredStacks returns the effective stacks without the "auto" marker.
func (e EffectivePolicy) DeclaredStacks() []string {
	return slices.DeleteFunc(slices.Clone(e.Stacks), func(s string) bool { return s == StackAuto })
}

// ValidateExclusion checks one exclusion on its own, with paths rooted at
// "/exclusion" (used by the tuning API before it touches the configuration).
func ValidateExclusion(x Exclusion) Errors {
	var errs Errors
	x.validate("/exclusion", &errs)
	return errs
}
