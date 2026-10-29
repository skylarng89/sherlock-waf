package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/store"
)

func seedEvents(t *testing.T, h *harness, evs ...store.EventRow) {
	t.Helper()
	require.NoError(t, h.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		for _, e := range evs {
			if len(e.Body) == 0 {
				e.Body = []byte(fmt.Sprintf(`{"id":%q,"action":%q}`, e.ID, e.Action))
			}
			if err := tx.InsertEvent(ctx, e); err != nil {
				return err
			}
		}
		return nil
	}))
}

var t0 = time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)

func ev(id string, offMin int, mut func(*store.EventRow)) store.EventRow {
	e := store.EventRow{
		ID: id, TS: t0.Add(time.Duration(offMin) * time.Minute), SiteID: "shop", Action: "block", Mode: "block", ClientIP: "203.0.113.1",
		Method: "GET", Host: "shop.example.test", Path: "/", Status: 403,
	}
	if mut != nil {
		mut(&e)
	}
	return e
}

func rng() string {
	return "from=" + url.QueryEscape(t0.Add(-time.Hour).Format(time.RFC3339)) + "&to=" + url.QueryEscape(t0.Add(3*time.Hour).Format(time.RFC3339))
}

func TestEventFilteringThroughTheAPI(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	seedEvents(t, h,
		ev("01A", 1, func(e *store.EventRow) { e.Country, e.Path, e.RuleIDs = "NL", "/search", []string{"942100"} }),
		ev("01B", 2, func(e *store.EventRow) {
			e.Country, e.Method, e.Status, e.Mode, e.Action = "DE", "POST", 200, "detect", "log"
		}),
		ev("01C", 3, func(e *store.EventRow) { e.Path = "/Login" }),
	)
	ids := func(q string) []string {
		r := a.do("GET", "/events?"+q, nil)
		require.Equal(t, http.StatusOK, r.Status, string(r.Body))
		var out []string
		for _, it := range r.JSON(t)["items"].([]any) {
			out = append(out, it.(map[string]any)["id"].(string))
		}
		return out
	}
	assert.Equal(t, []string{"01A"}, ids("country=NL"))
	assert.Equal(t, []string{"01A"}, ids("country=NL&q=SEARCH"), "text search ignores case in paths")
	assert.Equal(t, []string{"01B"}, ids("method=post"), "method is case-insensitive")
	assert.Equal(t, []string{"01B"}, ids("status=200"))
	assert.Equal(t, []string{"01B"}, ids("mode=detect"))
	assert.Equal(t, []string{"01C"}, ids("q=login"))
	assert.Equal(t, []string{"01A"}, ids("q=942100"), "rule ids are searchable")
	assert.Equal(t, http.StatusBadRequest, a.do("GET", "/events?country=nl", nil).Status, "country must be a capital code")
	assert.Equal(t, http.StatusBadRequest, a.do("GET", "/events?mode=maybe", nil).Status)
}

func TestTopListings(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	seedEvents(t, h,
		ev("01A", 1, func(e *store.EventRow) { e.Country, e.RuleIDs = "NL", []string{"942100", "949110"} }),
		ev("01B", 2, func(e *store.EventRow) { e.Country, e.RuleIDs = "NL", []string{"942100"} }),
		ev("01C", 3, func(e *store.EventRow) { e.ClientIP, e.Path, e.RuleIDs = "203.0.113.2", "/x", []string{"941100"} }),
	)
	top := func(dim string, extra string) map[string]any {
		r := a.do("GET", "/stats/top?dim="+dim+"&"+rng()+extra, nil)
		require.Equal(t, http.StatusOK, r.Status, string(r.Body))
		return r.JSON(t)
	}
	first := func(m map[string]any) map[string]any { return m["items"].([]any)[0].(map[string]any) }

	assert.EqualValues(t, 2, first(top("ip", ""))["count"])
	assert.Equal(t, "203.0.113.1", first(top("ip", ""))["value"])
	assert.Equal(t, "NL", first(top("country", ""))["value"])
	assert.Equal(t, "942100", first(top("rule", ""))["value"], "rules are counted from the findings")
	assert.EqualValues(t, 2, first(top("rule", ""))["count"])
	assert.Equal(t, false, top("rule", "")["sampled"])
	assert.Len(t, top("path", "&limit=1")["items"], 1, "limit applies")

	for name, q := range map[string]string{
		"bad dim":  "/stats/top?dim=cookie&" + rng(),
		"inverted": "/stats/top?dim=ip&from=2030-01-02T00:00:00Z&to=2030-01-01T00:00:00Z",
		"too wide": "/stats/top?dim=ip&from=2000-01-01T00:00:00Z&to=2030-01-01T00:00:00Z",
		"no range": "/stats/top?dim=ip",
	} {
		assert.Equal(t, http.StatusBadRequest, a.do("GET", q, nil).Status, name)
	}
}

func TestWouldBlockReport(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	detect := func(e *store.EventRow) { e.Mode, e.Action, e.Status = "detect", "log", 200 }
	seedEvents(t, h,
		ev("01A", 1, func(e *store.EventRow) { detect(e); e.Path, e.RuleIDs = "/search", []string{"942100", "949110"} }),
		ev("01B", 2, func(e *store.EventRow) { detect(e); e.Path, e.RuleIDs = "/search", []string{"941100", "949110"} }),
		ev("01C", 3, func(e *store.EventRow) { detect(e); e.Path, e.RuleIDs = "/other", []string{"942100"} }),            // scored but below the threshold: no 949110
		ev("01D", 4, func(e *store.EventRow) { e.Path, e.RuleIDs = "/blocked", []string{"942100", "949110"} }),           // block mode: it WAS blocked
		ev("01E", 5, func(e *store.EventRow) { detect(e); e.SiteID, e.RuleIDs = "other", []string{"942100", "949110"} }), // another site
		ev("01F", 6, func(e *store.EventRow) { detect(e); e.Path, e.RuleIDs = "=HYPERLINK(1)", []string{"942100", "949110"} }),
	)
	r := a.do("GET", "/reports/would-block?site=shop&"+rng(), nil)
	require.Equal(t, http.StatusOK, r.Status, string(r.Body))
	rep := r.JSON(t)
	assert.EqualValues(t, 3, rep["total"], "only detect-mode requests that reached the blocking threshold, for this site")
	assert.Equal(t, false, rep["truncated"])
	byRule := rep["by_rule"].([]any)
	assert.Equal(t, "942100", byRule[0].(map[string]any)["rule_id"], "the triggering rules are counted, not the evaluation rule itself")
	assert.EqualValues(t, 2, byRule[0].(map[string]any)["count"])
	for _, br := range byRule {
		assert.NotEqual(t, "949110", br.(map[string]any)["rule_id"])
	}
	assert.Equal(t, "/search", rep["by_path"].([]any)[0].(map[string]any)["path"])
	assert.Len(t, rep["requests"], 3)

	assert.Equal(t, http.StatusNotFound, a.do("GET", "/reports/would-block?site=ghost&"+rng(), nil).Status)

	csv := a.do("GET", "/reports/would-block.csv?site=shop&"+rng(), nil)
	require.Equal(t, http.StatusOK, csv.Status)
	assert.Contains(t, csv.Header.Get("Content-Type"), "text/csv")
	lines := strings.Split(strings.TrimSpace(string(csv.Body)), "\n")
	assert.Len(t, lines, 4, "header plus the three requests")
	assert.Equal(t, "time,event_id,site,client_ip,method,path,status,rule_ids", lines[0])
	assert.Contains(t, string(csv.Body), "'=HYPERLINK(1)", "formula-looking cells are neutralised so a spreadsheet will not run them")
	assert.NotContains(t, string(csv.Body), ",=HYPERLINK")
	assert.Equal(t, http.StatusOK, h.mint(h.view, "full").do("GET", "/reports/would-block.csv?site=shop&"+rng(), nil).Status, "viewers may read reports")
}

func TestSystemStatus(t *testing.T) {
	h := newHarness(t)
	a := adminSession(h)
	seedEvents(t, h, ev("01A", 1, nil), ev("01B", 2, nil))
	require.NoError(t, os.WriteFile(filepath.Join(h.dataDir, "events.jsonl"), []byte("0123456789"), 0o600))
	st := a.do("GET", "/system/status", nil)
	require.Equal(t, http.StatusOK, st.Status, string(st.Body))
	body := st.JSON(t)
	assert.EqualValues(t, 2, body["events_stored"])
	assert.Greater(t, body["data_dir_bytes"].(float64), float64(0))
	assert.EqualValues(t, 30, body["retention_days"])
}
