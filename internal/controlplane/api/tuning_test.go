package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/internal/vpatch"
)

func wafEvent(t *testing.T, id string, ago time.Duration, method, path, action string, fs ...events.Finding) store.EventRow {
	t.Helper()
	ts := time.Now().UTC().Add(-ago)
	body, err := json.Marshal(events.Event{
		ID: id, Schema: events.SchemaV1, TS: ts, SiteID: "shop", Action: action, Mode: "detect",
		Request: events.Request{Method: method, Host: "shop.example.test", Path: path}, Findings: fs,
	})
	require.NoError(t, err)
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.RuleID)
	}
	return store.EventRow{ID: id, TS: ts, SiteID: "shop", Action: action, Mode: "detect", ClientIP: "203.0.113.9", Method: method, Host: "shop.example.test", Path: path, Status: 200, RuleIDs: ids, Body: body}
}

func fp(rule, target string, score, pl int) events.Finding {
	tag := "paranoia-level/" + strconv.Itoa(pl)
	return events.Finding{Module: "waf", RuleID: rule, Target: target, Score: score, Severity: "critical", Message: "m " + rule, Tags: []string{"attack-sqli", tag}}
}

func TestExclusionFromEventEndToEnd(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	seedEvents(t, h,
		wafEvent(t, "01E1", time.Hour, "GET", "/search", "log", fp("942100", "ARGS:q", 5, 1)),
		wafEvent(t, "01E2", 2*time.Hour, "GET", "/search", "log", fp("942100", "ARGS:q", 5, 1)),
		wafEvent(t, "01E3", 3*time.Hour, "GET", "/other", "log", fp("942100", "ARGS:q", 5, 1)),
	)

	prop := a.do("POST", "/sites/shop/exclusions/propose", map[string]any{"event_id": "01E1"})
	require.Equal(t, http.StatusOK, prop.Status, string(prop.Body))
	p := prop.JSON(t)
	x := p["exclusion"].(map[string]any)
	assert.Equal(t, map[string]any{"paths": []any{"/search"}, "methods": []any{"GET"}}, x["match"])
	assert.Equal(t, []any{map[string]any{"rule_ids": []any{"942100"}, "target": "ARGS:q"}}, x["remove_targets"])
	impact := p["impact"].(map[string]any)
	assert.EqualValues(t, 3, impact["events_scanned"])
	assert.EqualValues(t, 2, impact["matching_events"], "the other path is outside the scope")
	assert.EqualValues(t, 2, impact["no_longer_triggering"])
	assert.Empty(t, p["warnings"])
	assert.Equal(t, false, p["requires_acknowledgement"])

	// A proposal for an event of another site, or an unknown event, is a 404.
	assert.Equal(t, http.StatusNotFound, a.do("POST", "/sites/shop/exclusions/propose", map[string]any{"event_id": "nope"}).Status)
	assert.Equal(t, http.StatusBadRequest, a.do("POST", "/sites/shop/exclusions/propose", map[string]any{}).Status)

	// Viewers may preview but not create.
	v := h.mint(h.view, "full")
	assert.Equal(t, http.StatusOK, v.do("POST", "/sites/shop/exclusions/propose", map[string]any{"event_id": "01E1"}).Status)

	cur := a.do("GET", "/sites/shop/exclusions", nil)
	require.Equal(t, http.StatusOK, cur.Status)
	assert.Empty(t, cur.JSON(t)["items"])
	tag := etagOf(t, cur)

	body := map[string]any{"exclusion": x, "event_id": "01E1"}
	assert.Equal(t, http.StatusForbidden, v.do("POST", "/sites/shop/exclusions", body, "If-Match", tag).Status)
	assert.Equal(t, http.StatusPreconditionRequired, a.do("POST", "/sites/shop/exclusions", body).Status)

	made := a.do("POST", "/sites/shop/exclusions", body, "If-Match", tag)
	require.Equal(t, http.StatusCreated, made.Status, string(made.Body))

	// The exclusion is part of the live configuration for that site only.
	h.plane.mu.Lock()
	live := h.plane.live
	h.plane.mu.Unlock()
	got := live.EffectivePolicy(&live.Sites[0], nil).WAF.Exclusions
	require.Len(t, got, 1)
	assert.Equal(t, x["id"], got[0].ID)

	// Creating it again is a conflict, not a duplicate.
	assert.Equal(t, http.StatusConflict, a.do("POST", "/sites/shop/exclusions", body, "If-Match", etagOf(t, made)).Status)

	// The audit log says who added it, and from which event.
	entries, err := listAudit(t, h)
	require.NoError(t, err)
	var found bool
	for _, e := range entries {
		if e.Action == "waf.exclusion.create" {
			found = true
			assert.Equal(t, audit.ActorUser, e.ActorType)
			assert.Equal(t, h.admin.ID, e.ActorID)
			assert.Equal(t, "shop/"+x["id"].(string), e.ObjectID)
			assert.Contains(t, string(e.Details), "01E1")
		}
	}
	assert.True(t, found, "the exclusion creation is audited with the actor")

	// Delete.
	del := a.do("DELETE", "/sites/shop/exclusions/"+x["id"].(string), nil, "If-Match", etagOf(t, made))
	require.Equal(t, http.StatusOK, del.Status, string(del.Body))
	assert.Equal(t, http.StatusNotFound, a.do("DELETE", "/sites/shop/exclusions/"+x["id"].(string), nil, "If-Match", etagOf(t, del)).Status)
}

func listAudit(t *testing.T, h *harness) ([]store.AuditEntry, error) {
	t.Helper()
	var out []store.AuditEntry
	err := h.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
		out, err = tx.ListAudit(ctx, 0, 100)
		return err
	})
	return out, err
}

func TestWholeCategoryExclusionNeedsAcknowledgement(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	x := map[string]any{"id": "no-sqli", "remove_tags": []string{"attack-sqli"}}

	prop := a.do("POST", "/sites/shop/exclusions/propose", map[string]any{"exclusion": x}).JSON(t)
	assert.Equal(t, true, prop["requires_acknowledgement"])
	ws := prop["warnings"].([]any)
	require.NotEmpty(t, ws)
	assert.Equal(t, "whole_category", ws[0].(map[string]any)["code"])

	tag := etagOf(t, a.do("GET", "/sites/shop/exclusions", nil))
	r := a.do("POST", "/sites/shop/exclusions", map[string]any{"exclusion": x}, "If-Match", tag)
	assert.Equal(t, http.StatusUnprocessableEntity, r.Status, string(r.Body))
	assert.Contains(t, string(r.Body), "acknowledge_warnings")

	r = a.do("POST", "/sites/shop/exclusions", map[string]any{"exclusion": x, "acknowledge_warnings": true}, "If-Match", tag)
	assert.Equal(t, http.StatusCreated, r.Status, string(r.Body))
	entries, _ := listAudit(t, h)
	var details string
	for _, e := range entries {
		if e.Action == "waf.exclusion.create" {
			details = string(e.Details)
		}
	}
	assert.Contains(t, details, "whole_category")
	assert.Contains(t, details, `"warnings_acknowledged":true`)
}

func TestInvalidExclusionIsRejectedWithPaths(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	tag := etagOf(t, a.do("GET", "/sites/shop/exclusions", nil))
	for name, x := range map[string]map[string]any{
		"injection": {"id": "x", "remove_targets": []any{map[string]any{"rule_ids": []string{"942100"}, "target": "ARGS:q;ctl:ruleEngine=Off"}}},
		"empty":     {"id": "x"},
		"vpatch":    {"id": "x", "remove_rule_ids": []string{"9500010"}},
	} {
		r := a.do("POST", "/sites/shop/exclusions", map[string]any{"exclusion": x}, "If-Match", tag)
		assert.Equal(t, http.StatusUnprocessableEntity, r.Status, name+" "+string(r.Body))
		assert.Contains(t, string(r.Body), "/exclusion", name)
	}
}

func TestCustomRulesAreValidatedBeforeSaving(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)

	good := `SecRule REQUEST_FILENAME "@beginsWith /admin" "id:10001,phase:1,deny,status:403,msg:'Admin path blocked'"`
	v := a.do("POST", "/sites/shop/custom-rules/validate", map[string]any{"rules": good})
	require.Equal(t, http.StatusOK, v.Status, string(v.Body))
	assert.Equal(t, true, v.JSON(t)["valid"])
	assert.Equal(t, []any{float64(10001)}, v.JSON(t)["rule_ids"])

	for name, bad := range map[string]string{
		"exec":   `SecRule ARGS "@rx x" "id:10002,phase:2,pass,exec:/bin/sh"`,
		"lua":    `SecRuleScript /tmp/a.lua "id:10003,phase:2"`,
		"ctl":    `SecRule ARGS "@rx x" "id:10004,phase:2,pass,ctl:ruleEngine=Off"`,
		"range":  `SecAction "id:42,phase:1,pass"`,
		"syntax": `SecRule ARGS "@rx (" "id:10005,phase:2,deny"`,
	} {
		r := a.do("POST", "/sites/shop/custom-rules/validate", map[string]any{"rules": bad}).JSON(t)
		assert.Equal(t, false, r["valid"], name)
		require.NotEmpty(t, r["issues"], name)
		assert.NotEmpty(t, r["issues"].([]any)[0].(map[string]any)["message"], name)
	}

	cur := a.do("GET", "/sites/shop/custom-rules", nil)
	require.Equal(t, http.StatusOK, cur.Status)
	assert.Equal(t, "none", cur.JSON(t)["source"])
	tag := etagOf(t, cur)

	// Rejected rules are never saved: 422 with the issue and the line.
	rej := a.do("PUT", "/sites/shop/custom-rules", map[string]any{"rules": "\n" + `SecRule ARGS "@rx x" "id:10002,phase:2,pass,exec:/bin/sh"`}, "If-Match", tag)
	assert.Equal(t, http.StatusUnprocessableEntity, rej.Status)
	assert.Contains(t, string(rej.Body), "line 2")
	assert.Contains(t, string(rej.Body), "exec")
	assert.Equal(t, "none", a.do("GET", "/sites/shop/custom-rules", nil).JSON(t)["source"])

	ok := a.do("PUT", "/sites/shop/custom-rules", map[string]any{"rules": good}, "If-Match", tag)
	require.Equal(t, http.StatusOK, ok.Status, string(ok.Body))
	saved := a.do("GET", "/sites/shop/custom-rules", nil).JSON(t)
	assert.Equal(t, "site", saved["source"])
	assert.Equal(t, good, saved["rules"])

	entries, _ := listAudit(t, h)
	var found bool
	for _, e := range entries {
		if e.Action == "waf.custom_rules.update" {
			found = true
			assert.Equal(t, h.admin.ID, e.ActorID)
			assert.Contains(t, string(e.Details), "10001")
		}
	}
	assert.True(t, found)

	assert.Equal(t, http.StatusForbidden, h.mint(h.view, "full").do("PUT", "/sites/shop/custom-rules", map[string]any{"rules": good}, "If-Match", etagOf(t, ok)).Status)
}

func TestCrsCatalogueSearchAndSiteState(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)

	r := a.do("GET", "/crs/rules?q=sql+injection&limit=5", nil)
	require.Equal(t, http.StatusOK, r.Status, string(r.Body))
	j := r.JSON(t)
	assert.Equal(t, "4.25.0", j["crs_version"])
	assert.Len(t, j["items"], 5)
	assert.Greater(t, j["total"], float64(5))
	assert.NotEmpty(t, j["categories"])
	assert.Nil(t, j["items"].([]any)[0].(map[string]any)["status"], "no site, no state")

	one := a.do("GET", "/crs/rules?q=942100&site=shop", nil).JSON(t)["items"].([]any)
	require.Len(t, one, 1)
	rule := one[0].(map[string]any)
	assert.Equal(t, "enforcing", rule["status"].(map[string]any)["state"])
	assert.Contains(t, rule["message"], "SQL Injection")

	pl2 := a.do("GET", "/crs/rules?q=942260&site=shop", nil).JSON(t)["items"].([]any)[0].(map[string]any)
	assert.Equal(t, "inactive", pl2["status"].(map[string]any)["state"])
	assert.Equal(t, "paranoia_level_too_low", pl2["status"].(map[string]any)["reason"])

	assert.Equal(t, http.StatusBadRequest, a.do("GET", "/crs/rules?state=disabled", nil).Status)
	assert.Equal(t, http.StatusNotFound, a.do("GET", "/crs/rules?site=ghost", nil).Status)

	// A site exclusion shows up in the per-site state.
	tag := etagOf(t, a.do("GET", "/sites/shop/exclusions", nil))
	require.Equal(t, http.StatusCreated, a.do("POST", "/sites/shop/exclusions", map[string]any{"exclusion": map[string]any{"id": "x", "match": map[string]any{"paths": []string{"/s"}}, "remove_rule_ids": []string{"942100"}}}, "If-Match", tag).Status)
	st := a.do("GET", "/crs/rules?q=942100&site=shop", nil).JSON(t)["items"].([]any)[0].(map[string]any)["status"].(map[string]any)
	assert.Equal(t, "partly_excluded", st["state"])
	assert.Equal(t, []any{"x"}, st["excluded_by"])
	filtered := a.do("GET", "/crs/rules?site=shop&state=partly_excluded", nil).JSON(t)
	assert.EqualValues(t, 1, filtered["total"])
}

func TestVirtualPatchCatalogueStateAndToggle(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	fm, ok := vpatch.Get("SV-2020-0001")
	require.True(t, ok)
	seedEvents(t, h, wafEvent(t, "01P1", time.Hour, "POST", "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", "block",
		events.Finding{Module: "waf", RuleID: strconv.Itoa(fm.RuleIDs[0]), Severity: "critical", Message: "vp"}))

	cat := a.do("GET", "/virtual-patches", nil)
	require.Equal(t, http.StatusOK, cat.Status, string(cat.Body))
	j := cat.JSON(t)
	items := j["items"].([]any)
	assert.GreaterOrEqual(t, len(items), 15)
	assert.NotEmpty(t, j["covered"])
	sum := j["summary"].(map[string]any)
	assert.EqualValues(t, len(items), sum["patches"])
	assert.EqualValues(t, 0, sum["sites_protected"], "no declared stacks, no product rules")
	for _, it := range items {
		m := it.(map[string]any)
		assert.Equal(t, "stack_not_declared", m["sites"].([]any)[0].(map[string]any)["state"], m["id"])
	}

	find := func(id string) map[string]any {
		for _, it := range a.do("GET", "/virtual-patches?site=shop", nil).JSON(t)["items"].([]any) {
			if it.(map[string]any)["id"] == id {
				return it.(map[string]any)
			}
		}
		t.Fatalf("patch %s missing", id)
		return nil
	}
	state := func(id string) string {
		return find(id)["sites"].([]any)[0].(map[string]any)["state"].(string)
	}

	// Declare the stack through the ordinary site PATCH.
	tag := etagOf(t, a.do("GET", "/sites/shop", nil))
	patched := a.do("PATCH", "/sites/shop", map[string]any{"policy": map[string]any{"stacks": []string{"wordpress"}}}, "If-Match", tag)
	require.Equal(t, http.StatusOK, patched.Status, string(patched.Body))
	wp := ""
	for _, it := range a.do("GET", "/virtual-patches?q=file+manager", nil).JSON(t)["items"].([]any) {
		wp = it.(map[string]any)["id"].(string)
	}
	require.NotEmpty(t, wp)
	assert.Equal(t, "active", state(wp))
	assert.Equal(t, "stack_not_declared", state("SV-2018-0001"), "a Drupal rule stays off on a WordPress site")
	assert.EqualValues(t, 1, find(wp)["hits"])
	assert.Greater(t, a.do("GET", "/virtual-patches?site=shop", nil).JSON(t)["summary"].(map[string]any)["sites_protected"], float64(0))

	off := a.do("PUT", "/sites/shop/virtual-patches/"+wp, map[string]any{"enabled": false}, "If-Match", etagOf(t, patched))
	require.Equal(t, http.StatusOK, off.Status, string(off.Body))
	assert.Equal(t, "disabled", state(wp))
	on := a.do("PUT", "/sites/shop/virtual-patches/"+wp, map[string]any{"enabled": true}, "If-Match", etagOf(t, off))
	require.Equal(t, http.StatusOK, on.Status, string(on.Body))
	assert.Equal(t, "active", state(wp))

	assert.Equal(t, http.StatusNotFound, a.do("PUT", "/sites/shop/virtual-patches/SV-1999-0001", map[string]any{"enabled": false}, "If-Match", etagOf(t, on)).Status)
	assert.Equal(t, http.StatusBadRequest, a.do("GET", "/virtual-patches?severity=bogus", nil).Status)
	assert.Equal(t, http.StatusNotFound, a.do("GET", "/virtual-patches?site=ghost", nil).Status)

	filtered := a.do("GET", "/virtual-patches?kev=true&severity=critical&q=confluence", nil).JSON(t)["items"].([]any)
	assert.NotEmpty(t, filtered)
	for _, it := range filtered {
		assert.Equal(t, "critical", it.(map[string]any)["severity"])
	}
}

func TestParanoiaImpactPredictsAdditionalBlocks(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	seedEvents(t, h,
		wafEvent(t, "01Q1", time.Hour, "GET", "/a", "block", fp("942100", "ARGS:q", 5, 1)),
		wafEvent(t, "01Q2", time.Hour, "GET", "/b", "log", fp("942260", "ARGS:q", 5, 2)),
		wafEvent(t, "01Q3", time.Hour, "GET", "/b", "log", fp("942260", "ARGS:q", 5, 2)),
	)

	// Detection PL1: findings above PL1 are not recorded, so nothing is predictable.
	r := a.do("GET", "/sites/shop/paranoia-impact?target=2", nil)
	require.Equal(t, http.StatusOK, r.Status, string(r.Body))
	j := r.JSON(t)
	assert.Equal(t, false, j["observable"])
	assert.NotEmpty(t, j["advice"])

	tag := etagOf(t, a.do("GET", "/sites/shop", nil))
	require.Equal(t, http.StatusOK, a.do("PATCH", "/sites/shop", map[string]any{"policy": map[string]any{"waf": map[string]any{"paranoia_level": 2, "blocking_paranoia_level": 1}}}, "If-Match", tag).Status)

	j = a.do("GET", "/sites/shop/paranoia-impact?target=2", nil).JSON(t)
	assert.Equal(t, true, j["observable"])
	assert.EqualValues(t, 3, j["events_scanned"])
	assert.EqualValues(t, 1, j["already_blocking"])
	assert.EqualValues(t, 2, j["additional_blocks"])
	assert.Equal(t, []any{map[string]any{"rule_id": "942260", "count": float64(2)}}, j["by_rule"])
	assert.Equal(t, []any{map[string]any{"path": "/b", "count": float64(2)}}, j["by_path"])

	assert.Equal(t, http.StatusBadRequest, a.do("GET", "/sites/shop/paranoia-impact?target=5", nil).Status)
	assert.Equal(t, http.StatusNotFound, a.do("GET", "/sites/ghost/paranoia-impact?target=2", nil).Status)
}
