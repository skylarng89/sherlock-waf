// Package tuning holds the pure logic behind false-positive tuning (M8-T2)
// and the paranoia-level helper (M8-T5): proposing the narrowest exclusion for
// an event, previewing which past events it would have affected, warning when
// it would switch off a whole attack category, and predicting how many more
// requests a higher blocking paranoia level would block.
//
// Nothing here touches the store or the network; the API layer feeds it
// events that were already read.
package tuning

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/crs"
	"github.com/skylarng89/sherlock-waf/internal/events"
)

// Evaluation rules add no score of their own and are not detections.
var evaluationRules = map[string]bool{"949110": true, "959100": true, "980130": true}

// Scope chooses how wide a proposed exclusion is.
type Scope string

// Proposal scopes.
const (
	// ScopeTarget removes only the offending request target (ARGS:q) from the
	// rule. It is the default whenever the finding names a target.
	ScopeTarget Scope = "target"
	// ScopeRule removes the whole rule for the path and method.
	ScopeRule Scope = "rule"
)

// ErrNoFinding means the event has no finding that an exclusion can address.
var ErrNoFinding = errors.New("the event has no WAF rule finding to exclude")

// Detections are the WAF findings of an event that are real rule matches.
func Detections(ev events.Event) []events.Finding {
	var out []events.Finding
	for _, f := range ev.Findings {
		if f.Module == "waf" && f.RuleID != "" && !evaluationRules[f.RuleID] {
			out = append(out, f)
		}
	}
	return out
}

// Propose builds the narrowest exclusion that silences ruleID on the event's
// path and method. An empty ruleID picks the finding with the highest score.
func Propose(ev events.Event, ruleID string, scope Scope) (config.Exclusion, events.Finding, error) {
	dets := Detections(ev)
	if len(dets) == 0 {
		return config.Exclusion{}, events.Finding{}, ErrNoFinding
	}
	var f events.Finding
	if ruleID == "" {
		f = dets[0]
		for _, d := range dets[1:] {
			if d.Score > f.Score {
				f = d
			}
		}
	} else {
		i := slices.IndexFunc(dets, func(d events.Finding) bool { return d.RuleID == ruleID })
		if i < 0 {
			return config.Exclusion{}, events.Finding{}, fmt.Errorf("rule %s did not match in this event", ruleID)
		}
		f = dets[i]
	}
	if _, err := strconv.Atoi(f.RuleID); err != nil {
		return config.Exclusion{}, events.Finding{}, fmt.Errorf("finding rule id %q is not numeric", f.RuleID)
	}
	if strings.ContainsAny(ev.Request.Path, `*?[]\"'`) || !strings.HasPrefix(ev.Request.Path, "/") {
		return config.Exclusion{}, events.Finding{}, fmt.Errorf("the request path %q cannot be used as an exclusion scope; write the exclusion by hand", ev.Request.Path)
	}

	if scope == "" {
		scope = ScopeTarget
	}
	x := config.Exclusion{
		Match: config.ExclusionMatch{Paths: []string{ev.Request.Path}, Methods: []string{strings.ToUpper(ev.Request.Method)}},
	}
	target := cleanTarget(f.Target)
	if scope == ScopeTarget && target != "" {
		x.RemoveTargets = []config.ExclusionTarget{{RuleIDs: []string{f.RuleID}, Target: target}}
	} else {
		x.RemoveRuleIDs = []string{f.RuleID}
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{ev.Request.Method, ev.Request.Path, f.RuleID, target, string(scope)}, "\x00")))
	x.ID = "fp-" + f.RuleID + "-" + hex.EncodeToString(sum[:4])
	what := "rule " + f.RuleID
	if len(x.RemoveTargets) > 0 {
		what += " on " + target
	}
	x.Description = truncate(fmt.Sprintf("From event %s: %s for %s %s", ev.ID, what, ev.Request.Method, ev.Request.Path), 500)
	return x, f, nil
}

var targetOK = regexp.MustCompile(`^[A-Z][A-Z_]{1,40}(?::[^\s;"'\\,]{1,200})?$`)

// cleanTarget returns the finding's target when it is safe to use in
// ctl:ruleRemoveTargetById, otherwise "" (the rule is then removed whole).
func cleanTarget(t string) string {
	if targetOK.MatchString(t) {
		return t
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Impact is what an exclusion would have changed over a set of past events.
type Impact struct {
	Scanned int `json:"events_scanned"`
	// Matching are events in the exclusion's path and method scope that
	// carried a finding the exclusion removes.
	Matching int `json:"matching_events"`
	// NoLongerTriggering are matching events left with no WAF finding at all.
	NoLongerTriggering int `json:"no_longer_triggering"`
	// NoLongerBlocking are matching events that were blocked (or would have
	// been) and whose remaining blocking score falls under the threshold.
	NoLongerBlocking int `json:"no_longer_blocking"`
	// ByRule counts removed findings per rule id.
	ByRule map[string]int `json:"by_rule"`
	// SampleEventIDs are up to ten matching events, newest first as supplied.
	SampleEventIDs []string `json:"sample_event_ids"`
}

// Preview replays x over events (newest first) under the site's thresholds.
func Preview(x config.Exclusion, evs []events.Event, threshold, blockingPL int) (Impact, error) {
	in, err := x.Match.Matcher()
	if err != nil {
		return Impact{}, err
	}
	imp := Impact{ByRule: map[string]int{}, SampleEventIDs: []string{}}
	for _, ev := range evs {
		imp.Scanned++
		if !in(ev.Request.Path, ev.Request.Method) {
			continue
		}
		dets := Detections(ev)
		var kept []events.Finding
		removed := 0
		for _, f := range dets {
			if removes(x, f) {
				removed++
				imp.ByRule[f.RuleID]++
			} else {
				kept = append(kept, f)
			}
		}
		if removed == 0 {
			continue
		}
		imp.Matching++
		if len(imp.SampleEventIDs) < 10 {
			imp.SampleEventIDs = append(imp.SampleEventIDs, ev.ID)
		}
		if len(kept) == 0 {
			imp.NoLongerTriggering++
		}
		if blockingScore(dets, blockingPL) >= threshold && blockingScore(kept, blockingPL) < threshold {
			imp.NoLongerBlocking++
		}
	}
	return imp, nil
}

// removes reports whether the exclusion drops the finding: the whole rule by
// id, range or tag, or just the finding's target for a target removal.
func removes(x config.Exclusion, f events.Finding) bool {
	id, err := strconv.Atoi(f.RuleID)
	if err != nil {
		return false
	}
	for _, s := range x.RemoveRuleIDs {
		if lo, hi, ok := config.ParseRuleIDRange(s); ok && id >= lo && id <= hi {
			return true
		}
	}
	if slices.ContainsFunc(x.RemoveTags, func(t string) bool { return slices.Contains(f.Tags, t) }) {
		return true
	}
	for _, t := range x.RemoveTargets {
		ruleHit := false
		for _, s := range t.RuleIDs {
			if lo, hi, ok := config.ParseRuleIDRange(s); ok && id >= lo && id <= hi {
				ruleHit = true
			}
		}
		if !ruleHit && !slices.ContainsFunc(t.Tags, func(tag string) bool { return slices.Contains(f.Tags, tag) }) {
			continue
		}
		if targetMatches(t.Target, f.Target) {
			return true
		}
	}
	return false
}

// targetMatches compares a ctl target ("ARGS:q", "REQUEST_COOKIES:/^_ga/",
// "ARGS") with the target a finding reported.
func targetMatches(spec, got string) bool {
	if strings.HasPrefix(spec, "!") || strings.HasPrefix(spec, "&") {
		return false
	}
	name, key, hasKey := strings.Cut(spec, ":")
	gname, gkey, _ := strings.Cut(got, ":")
	if !strings.EqualFold(name, gname) {
		return false
	}
	switch {
	case !hasKey:
		return true
	case len(key) > 2 && strings.HasPrefix(key, "/") && strings.HasSuffix(key, "/"):
		re, err := regexp.Compile("(?i)" + key[1:len(key)-1])
		return err == nil && re.MatchString(gkey)
	default:
		return strings.EqualFold(key, gkey)
	}
}

// rulePL reads the paranoia level from a finding's tags (PL1 when untagged).
func rulePL(f events.Finding) int {
	for _, t := range f.Tags {
		if rest, ok := strings.CutPrefix(t, "paranoia-level/"); ok {
			if n, err := strconv.Atoi(rest); err == nil {
				return n
			}
		}
	}
	return 1
}

// blockingScore sums the scores of findings at or below paranoia level pl,
// which is how CRS computes the blocking anomaly score.
func blockingScore(fs []events.Finding, pl int) int {
	total := 0
	for _, f := range fs {
		if rulePL(f) <= pl {
			total += f.Score
		}
	}
	return total
}

// Warning is a caution shown before an exclusion is saved.
type Warning struct {
	Code     string `json:"code"`
	Severity string `json:"severity"` // info | warning | critical
	Message  string `json:"message"`
}

// Warning severities and codes.
const (
	SevInfo     = "info"
	SevWarning  = "warning"
	SevCritical = "critical"

	WarnCategory        = "whole_category"
	WarnBlockingEval    = "blocking_evaluation"
	WarnUnscoped        = "unscoped_rule_removal"
	WarnBroadScope      = "broad_scope"
	WarnNoMatchingEvent = "no_matching_events"
)

// Warnings inspects an exclusion for choices that weaken protection broadly.
// impact may be nil when no events were available.
func Warnings(x config.Exclusion, impact *Impact) []Warning {
	var out []Warning
	scoped := len(x.Match.Paths) > 0

	removed := removedRules(x)
	for _, c := range categoriesDisabled(removed) {
		sev := SevCritical
		if scoped {
			sev = SevWarning
		}
		where := "on every path"
		if scoped {
			where = "on the matched paths"
		}
		out = append(out, Warning{
			Code: WarnCategory, Severity: sev,
			Message: fmt.Sprintf("This exclusion switches off most or all %s rules (%d of %d) %s. An attacker can use that attack class there without being detected. Prefer excluding one rule and one target.", c.name, c.removed, c.total, where),
		})
	}
	for _, r := range removed {
		if r.ID >= 949000 && r.ID < 950000 || r.ID >= 959000 && r.ID < 960000 {
			out = append(out, Warning{
				Code: WarnBlockingEval, Severity: SevCritical,
				Message: fmt.Sprintf("Rule %d decides whether a request is blocked at all; removing it turns blocking off for the matched requests.", r.ID),
			})
			break
		}
	}
	for _, s := range x.RemoveRuleIDs {
		if lo, hi, ok := config.ParseRuleIDRange(s); ok && !scoped && hi == lo {
			out = append(out, Warning{
				Code: WarnUnscoped, Severity: SevWarning,
				Message: fmt.Sprintf("Rule %s is removed for every URL. Restrict the exclusion to the path that needs it.", s),
			})
			break
		}
	}
	for _, g := range x.Match.Paths {
		if g == "/**" || g == "/*" {
			out = append(out, Warning{Code: WarnBroadScope, Severity: SevWarning, Message: "The path scope " + g + " covers (nearly) the whole site."})
			break
		}
	}
	if impact != nil && impact.Scanned > 0 && impact.Matching == 0 {
		out = append(out, Warning{
			Code: WarnNoMatchingEvent, Severity: SevInfo,
			Message: "None of the recent events would have been affected. Check the path, method and rule before saving.",
		})
	}
	return out
}

// NeedsAcknowledgement reports whether any warning is critical.
func NeedsAcknowledgement(ws []Warning) bool {
	return slices.ContainsFunc(ws, func(w Warning) bool { return w.Severity == SevCritical })
}

// removedRules resolves the whole-rule removals of x against the catalogue.
func removedRules(x config.Exclusion) []crs.Rule {
	all, err := crs.Rules()
	if err != nil {
		return nil
	}
	var out []crs.Rule
	for _, r := range all {
		if crs.RemovesRule(x, r) {
			out = append(out, r)
		}
	}
	return out
}

type categoryLoss struct {
	name           string
	removed, total int
}

// categoriesDisabled lists attack categories where at least half of the rules
// (and at least four) are removed.
func categoriesDisabled(removed []crs.Rule) []categoryLoss {
	all, err := crs.Rules()
	if err != nil {
		return nil
	}
	totals := map[string]int{}
	for _, r := range all {
		if r.Direction == "request" && strings.HasPrefix(r.Category, "attack-") {
			totals[r.Category]++
		}
	}
	gone := map[string]int{}
	for _, r := range removed {
		if r.Direction == "request" && strings.HasPrefix(r.Category, "attack-") {
			gone[r.Category]++
		}
	}
	var out []categoryLoss
	for c, n := range gone {
		if n >= 4 && n*2 >= totals[c] {
			out = append(out, categoryLoss{c, n, totals[c]})
		}
	}
	slices.SortFunc(out, func(a, b categoryLoss) int { return strings.Compare(a.name, b.name) })
	return out
}

// PLPrediction is the effect of raising the blocking paranoia level.
type PLPrediction struct {
	Scanned          int            `json:"events_scanned"`
	AlreadyBlocking  int            `json:"already_blocking"`
	AdditionalBlocks int            `json:"additional_blocks"`
	ByRule           map[string]int `json:"by_rule"`
	ByPath           map[string]int `json:"by_path"`
	SampleEventIDs   []string       `json:"sample_event_ids"`
}

// PredictPL counts events that the current blocking level lets through but
// the target level would block, from the findings recorded at the detection
// level (rules above the current blocking level score but do not block).
func PredictPL(evs []events.Event, threshold, currentBlocking, target int) PLPrediction {
	p := PLPrediction{ByRule: map[string]int{}, ByPath: map[string]int{}, SampleEventIDs: []string{}}
	for _, ev := range evs {
		p.Scanned++
		dets := Detections(ev)
		if blockingScore(dets, currentBlocking) >= threshold {
			p.AlreadyBlocking++
			continue
		}
		if blockingScore(dets, target) < threshold {
			continue
		}
		p.AdditionalBlocks++
		p.ByPath[ev.Request.Path]++
		for _, f := range dets {
			if rulePL(f) > currentBlocking && rulePL(f) <= target {
				p.ByRule[f.RuleID]++
			}
		}
		if len(p.SampleEventIDs) < 10 {
			p.SampleEventIDs = append(p.SampleEventIDs, ev.ID)
		}
	}
	return p
}
