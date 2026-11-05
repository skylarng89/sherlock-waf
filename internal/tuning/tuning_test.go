package tuning

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/events"
)

func finding(rule, target string, score, pl int) events.Finding {
	return events.Finding{Module: "waf", RuleID: rule, Target: target, Score: score, Tags: []string{"attack-sqli", "paranoia-level/" + strconv.Itoa(pl)}}
}

func event(id, method, path string, fs ...events.Finding) events.Event {
	return events.Event{ID: id, Request: events.Request{Method: method, Path: path}, Findings: fs}
}

func TestProposeIsAsNarrowAsTheEventAllows(t *testing.T) {
	ev := event("E1", "get", "/search", finding("942100", "ARGS:q", 5, 1), events.Finding{Module: "waf", RuleID: "949110"})
	x, f, err := Propose(ev, "", "")
	require.NoError(t, err)
	assert.Equal(t, "942100", f.RuleID)
	assert.Equal(t, []string{"/search"}, x.Match.Paths)
	assert.Equal(t, []string{"GET"}, x.Match.Methods)
	assert.Empty(t, x.RemoveRuleIDs)
	assert.Equal(t, []config.ExclusionTarget{{RuleIDs: []string{"942100"}, Target: "ARGS:q"}}, x.RemoveTargets)
	assert.Contains(t, x.Description, "E1")
	require.Empty(t, validateExclusion(t, x))

	again, _, _ := Propose(ev, "", "")
	assert.Equal(t, x.ID, again.ID, "ids are deterministic so the same proposal cannot be saved twice")

	whole, _, err := Propose(ev, "942100", ScopeRule)
	require.NoError(t, err)
	assert.Equal(t, []string{"942100"}, whole.RemoveRuleIDs)
	assert.Empty(t, whole.RemoveTargets)
	assert.NotEqual(t, x.ID, whole.ID)
}

func validateExclusion(t *testing.T, x config.Exclusion) config.Errors {
	t.Helper()
	root := &config.Root{SchemaVersion: 1, Sites: []config.Site{{
		ID: "s", Hosts: []string{"s.example.com"}, TLS: config.TLS{Mode: config.TLSNone},
		Upstreams: config.Upstreams{Targets: []string{"h:1"}}, Policy: config.Policy{WAF: &config.WAFPolicy{Exclusions: []config.Exclusion{x}}},
	}}}
	root.ApplyDefaults()
	return root.Validate()
}

func TestProposeFallsBackAndRefuses(t *testing.T) {
	noTarget := event("E2", "POST", "/api/x", finding("920420", "", 5, 1))
	x, _, err := Propose(noTarget, "", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"920420"}, x.RemoveRuleIDs, "no target to narrow to: remove the rule for this path")

	_, _, err = Propose(event("E3", "GET", "/x"), "", "")
	assert.ErrorIs(t, err, ErrNoFinding)

	_, _, err = Propose(event("E4", "GET", "/a/*/b", finding("942100", "ARGS:q", 5, 1)), "", "")
	assert.Error(t, err, "glob characters in the path cannot be an exact scope")

	_, _, err = Propose(event("E5", "GET", "/x", finding("942100", "ARGS:q", 5, 1)), "999999", "")
	assert.Error(t, err)

	unsafe := event("E6", "GET", "/x", finding("942100", "ARGS:q;ctl:ruleEngine=Off", 5, 1))
	x, _, err = Propose(unsafe, "", "")
	require.NoError(t, err)
	assert.Empty(t, x.RemoveTargets, "an unsafe target is never copied into a ctl action")
	assert.Equal(t, []string{"942100"}, x.RemoveRuleIDs)
}

func TestPreviewCountsWhatWouldHaveChanged(t *testing.T) {
	evs := []events.Event{
		event("a", "GET", "/search", finding("942100", "ARGS:q", 5, 1)),
		event("b", "GET", "/search", finding("942100", "ARGS:q", 5, 1), finding("942260", "ARGS:q", 5, 2)),
		event("c", "GET", "/search", finding("942100", "ARGS:other", 5, 1)),
		event("d", "POST", "/search", finding("942100", "ARGS:q", 5, 1)),
		event("e", "GET", "/other", finding("942100", "ARGS:q", 5, 1)),
		event("f", "GET", "/search", finding("941100", "ARGS:q", 5, 1)),
	}
	x := config.Exclusion{
		ID: "x", Match: config.ExclusionMatch{Paths: []string{"/search"}, Methods: []string{"GET"}},
		RemoveTargets: []config.ExclusionTarget{{RuleIDs: []string{"942100"}, Target: "ARGS:q"}},
	}
	imp, err := Preview(x, evs, 5, 1)
	require.NoError(t, err)
	assert.Equal(t, 6, imp.Scanned)
	assert.Equal(t, 2, imp.Matching, "only GET /search with 942100 on ARGS:q")
	assert.Equal(t, 1, imp.NoLongerTriggering, "b still carries 942260 so it still triggers")
	assert.Equal(t, 2, imp.NoLongerBlocking, "b's remaining PL2 score does not count at blocking PL1")
	assert.Equal(t, map[string]int{"942100": 2}, imp.ByRule)
	assert.Equal(t, []string{"a", "b"}, imp.SampleEventIDs)
}

func TestPreviewByTagAndRange(t *testing.T) {
	evs := []events.Event{event("a", "GET", "/x", finding("942100", "ARGS:q", 5, 1)), event("b", "GET", "/x", finding("930100", "REQUEST_URI", 5, 1))}
	imp, err := Preview(config.Exclusion{ID: "t", RemoveTags: []string{"attack-sqli"}}, evs, 5, 1)
	require.NoError(t, err)
	assert.Equal(t, 2, imp.Matching, "the test helper tags every finding attack-sqli")
	imp, err = Preview(config.Exclusion{ID: "r", RemoveRuleIDs: []string{"942000-942999"}}, evs, 5, 1)
	require.NoError(t, err)
	assert.Equal(t, 1, imp.Matching)
}

func TestWarnings(t *testing.T) {
	codes := func(ws []Warning) map[string]string {
		m := map[string]string{}
		for _, w := range ws {
			m[w.Code] = w.Severity
		}
		return m
	}
	t.Run("one target is quiet", func(t *testing.T) {
		x := config.Exclusion{ID: "x", Match: config.ExclusionMatch{Paths: []string{"/s"}}, RemoveTargets: []config.ExclusionTarget{{RuleIDs: []string{"942100"}, Target: "ARGS:q"}}}
		assert.Empty(t, Warnings(x, &Impact{Scanned: 3, Matching: 1}))
	})
	t.Run("a whole attack tag everywhere is critical", func(t *testing.T) {
		ws := Warnings(config.Exclusion{ID: "x", RemoveTags: []string{"attack-sqli"}}, nil)
		assert.Equal(t, SevCritical, codes(ws)[WarnCategory])
		assert.True(t, NeedsAcknowledgement(ws))
	})
	t.Run("the same on one path is a warning", func(t *testing.T) {
		ws := Warnings(config.Exclusion{ID: "x", Match: config.ExclusionMatch{Paths: []string{"/s"}}, RemoveTags: []string{"attack-sqli"}}, nil)
		assert.Equal(t, SevWarning, codes(ws)[WarnCategory])
		assert.False(t, NeedsAcknowledgement(ws))
	})
	t.Run("a rule id range covering a category", func(t *testing.T) {
		ws := Warnings(config.Exclusion{ID: "x", RemoveRuleIDs: []string{"941000-941999"}}, nil)
		assert.Contains(t, codes(ws), WarnCategory)
	})
	t.Run("blocking evaluation", func(t *testing.T) {
		ws := Warnings(config.Exclusion{ID: "x", Match: config.ExclusionMatch{Paths: []string{"/s"}}, RemoveRuleIDs: []string{"949110"}}, nil)
		assert.Equal(t, SevCritical, codes(ws)[WarnBlockingEval])
	})
	t.Run("one rule on every url", func(t *testing.T) {
		ws := Warnings(config.Exclusion{ID: "x", RemoveRuleIDs: []string{"920350"}}, nil)
		assert.Equal(t, SevWarning, codes(ws)[WarnUnscoped])
		assert.False(t, NeedsAcknowledgement(ws))
	})
	t.Run("broad path and no matching events", func(t *testing.T) {
		ws := Warnings(config.Exclusion{ID: "x", Match: config.ExclusionMatch{Paths: []string{"/**"}}, RemoveRuleIDs: []string{"920350"}}, &Impact{Scanned: 10})
		assert.Contains(t, codes(ws), WarnBroadScope)
		assert.Contains(t, codes(ws), WarnNoMatchingEvent)
	})
}

func TestPredictPL(t *testing.T) {
	evs := []events.Event{
		event("blocked-now", "GET", "/a", finding("942100", "ARGS:q", 5, 1)),
		event("pl2-only", "GET", "/b", finding("942260", "ARGS:q", 5, 2)),
		event("pl2-low-score", "GET", "/b", finding("920272", "ARGS:q", 3, 2)),
		event("pl3-only", "GET", "/c", finding("932200", "ARGS:q", 5, 3)),
		event("two-pl2", "GET", "/b", finding("942260", "ARGS:q", 3, 2), finding("942431", "ARGS:q", 3, 2)),
	}
	p := PredictPL(evs, 5, 1, 2)
	assert.Equal(t, 5, p.Scanned)
	assert.Equal(t, 1, p.AlreadyBlocking)
	assert.Equal(t, 2, p.AdditionalBlocks, "pl2-only and two-pl2 (3+3) reach the threshold at PL2")
	assert.Equal(t, 2, p.ByPath["/b"])
	assert.Equal(t, []string{"pl2-only", "two-pl2"}, p.SampleEventIDs)

	p3 := PredictPL(evs, 5, 1, 3)
	assert.Equal(t, 3, p3.AdditionalBlocks)

	same := PredictPL(evs, 5, 1, 1)
	assert.Zero(t, same.AdditionalBlocks, "raising to the current level changes nothing")
}
