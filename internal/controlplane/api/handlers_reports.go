package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// Reports scan events in pages and stop at this many, so one request cannot
// read a whole large table into memory. Results say so when they were capped.
const (
	scanPage    = 1000
	scanCap     = 50_000
	reportLimit = 100
	// wouldBlockRule is the CRS rule that evaluates the inbound anomaly score;
	// in detect mode it firing means the request would have been blocked.
	wouldBlockRule = "949110"
)

// recode converts between structurally identical types through JSON, which is
// how the generated anonymous response structs are filled.
func recode[T any](v any) (T, error) {
	var out T
	b, err := json.Marshal(v)
	if err != nil {
		return out, fmt.Errorf("encoding response: %w", err)
	}
	return out, json.Unmarshal(b, &out)
}

// scan pages through events matching f, newest first, calling fn until it
// returns false or the cap is reached. It reports whether more rows existed.
func (h *handlers) scan(ctx context.Context, f store.EventFilter, fn func(store.EventRow) bool) (truncated bool, err error) {
	cur := store.Cursor{}
	seen := 0
	for {
		var rows []store.EventRow
		if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
			rows, err = tx.ListEvents(ctx, f, cur, scanPage)
			return err
		}); err != nil {
			return false, err
		}
		for _, r := range rows {
			if seen >= scanCap {
				return true, nil
			}
			seen++
			if !fn(r) {
				return false, nil
			}
		}
		if len(rows) < scanPage {
			return false, nil
		}
		last := rows[len(rows)-1]
		cur = store.Cursor{Time: last.TS, ID: last.ID}
	}
}

func rangeCheck(from, to time.Time) error {
	if !from.Before(to) {
		return errBadRequest("from must be before to.")
	}
	if to.Sub(from) > 366*24*time.Hour {
		return errBadRequest("the range may be at most one year.")
	}
	return nil
}

func (h *handlers) GetTop(ctx context.Context, req apigen.GetTopRequestObject) (apigen.GetTopResponseObject, error) {
	p := req.Params
	if err := rangeCheck(p.From, p.To); err != nil {
		return nil, err
	}
	if !slices.Contains([]string{"ip", "path", "country", "rule", "site", "action"}, string(p.Dim)) {
		return nil, errBadRequest("dim must be one of ip, path, country, rule, site, action.")
	}
	limit := 10
	if p.Limit != nil {
		limit = min(max(*p.Limit, 1), 50)
	}
	f := store.EventFilter{From: p.From.UTC(), To: p.To.UTC()}
	if p.Site != nil {
		f.SiteID = *p.Site
	}
	if p.Action != nil {
		f.Action = *p.Action
	}

	type item struct {
		Value string `json:"value"`
		Count int64  `json:"count"`
	}
	res := struct {
		Dim     string    `json:"dim"`
		From    time.Time `json:"from"`
		To      time.Time `json:"to"`
		Sampled bool      `json:"sampled"`
		Items   []item    `json:"items"`
	}{Dim: string(p.Dim), From: f.From, To: f.To, Items: []item{}}

	if p.Dim == apigen.GetTopParamsDim("rule") {
		counts := map[string]int64{}
		truncated, err := h.scan(ctx, f, func(r store.EventRow) bool {
			for _, id := range r.RuleIDs {
				counts[id]++
			}
			return true
		})
		if err != nil {
			return nil, err
		}
		res.Sampled = truncated
		for id, n := range counts {
			res.Items = append(res.Items, item{id, n})
		}
		slices.SortFunc(res.Items, func(a, b item) int {
			if a.Count != b.Count {
				return int(b.Count - a.Count)
			}
			return strings.Compare(a.Value, b.Value)
		})
		if len(res.Items) > limit {
			res.Items = res.Items[:limit]
		}
	} else {
		var rows []store.ValueCount
		if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
			rows, err = tx.TopEventValues(ctx, string(p.Dim), f, limit)
			return err
		}); err != nil {
			return nil, err
		}
		for _, r := range rows {
			res.Items = append(res.Items, item{r.Value, r.Count})
		}
	}
	out, err := recode[apigen.TopResult](res)
	if err != nil {
		return nil, err
	}
	return apigen.GetTop200JSONResponse(out), nil
}

type wouldBlock struct {
	Site      string      `json:"site"`
	From      time.Time   `json:"from"`
	To        time.Time   `json:"to"`
	Total     int64       `json:"total"`
	Truncated bool        `json:"truncated"`
	ByRule    []ruleCount `json:"by_rule"`
	ByPath    []pathCount `json:"by_path"`
	Requests  []wbRequest `json:"requests"`
}

type (
	ruleCount struct {
		RuleID string `json:"rule_id"`
		Count  int64  `json:"count"`
	}
	pathCount struct {
		Path  string `json:"path"`
		Count int64  `json:"count"`
	}
	wbRequest struct {
		EventID  string    `json:"event_id"`
		TS       time.Time `json:"ts"`
		ClientIP string    `json:"client_ip"`
		Method   string    `json:"method"`
		Path     string    `json:"path"`
		RuleIDs  []string  `json:"rule_ids"`
	}
)

// wouldBlockFor builds the report, and calls keep for every matching event
// (the CSV export streams from the same scan).
func (h *handlers) wouldBlockFor(ctx context.Context, site string, from, to time.Time, keep func(store.EventRow)) (wouldBlock, error) {
	if err := rangeCheck(from, to); err != nil {
		return wouldBlock{}, err
	}
	_, live, err := h.s.Config.Current(ctx)
	if err != nil {
		return wouldBlock{}, err
	}
	if findSite(live, site) < 0 {
		return wouldBlock{}, errNotFound("site " + site)
	}
	rep := wouldBlock{Site: site, From: from.UTC(), To: to.UTC(), ByRule: []ruleCount{}, ByPath: []pathCount{}, Requests: []wbRequest{}}
	byRule, byPath := map[string]int64{}, map[string]int64{}
	f := store.EventFilter{SiteID: site, Mode: string(config.ModeDetect), RuleID: wouldBlockRule, From: rep.From, To: rep.To}
	rep.Truncated, err = h.scan(ctx, f, func(r store.EventRow) bool {
		rep.Total++
		byPath[r.Path]++
		for _, id := range r.RuleIDs {
			if id != wouldBlockRule {
				byRule[id]++
			}
		}
		if len(rep.Requests) < reportLimit {
			rep.Requests = append(rep.Requests, wbRequest{EventID: r.ID, TS: r.TS, ClientIP: r.ClientIP, Method: r.Method, Path: r.Path, RuleIDs: append([]string{}, r.RuleIDs...)})
		}
		if keep != nil {
			keep(r)
		}
		return true
	})
	if err != nil {
		return wouldBlock{}, err
	}
	for id, n := range byRule {
		rep.ByRule = append(rep.ByRule, ruleCount{id, n})
	}
	for p, n := range byPath {
		rep.ByPath = append(rep.ByPath, pathCount{p, n})
	}
	slices.SortFunc(rep.ByRule, func(a, b ruleCount) int {
		if a.Count != b.Count {
			return int(b.Count - a.Count)
		}
		return strings.Compare(a.RuleID, b.RuleID)
	})
	slices.SortFunc(rep.ByPath, func(a, b pathCount) int {
		if a.Count != b.Count {
			return int(b.Count - a.Count)
		}
		return strings.Compare(a.Path, b.Path)
	})
	if len(rep.ByRule) > 50 {
		rep.ByRule = rep.ByRule[:50]
	}
	if len(rep.ByPath) > 50 {
		rep.ByPath = rep.ByPath[:50]
	}
	return rep, nil
}

func (h *handlers) GetWouldBlockReport(ctx context.Context, req apigen.GetWouldBlockReportRequestObject) (apigen.GetWouldBlockReportResponseObject, error) {
	rep, err := h.wouldBlockFor(ctx, req.Params.Site, req.Params.From, req.Params.To, nil)
	if err != nil {
		return nil, err
	}
	out, err := recode[apigen.WouldBlockReport](rep)
	if err != nil {
		return nil, err
	}
	return apigen.GetWouldBlockReport200JSONResponse(out), nil
}

// csvCell neutralises spreadsheet formula injection: a value starting with = + - @
// or a tab/CR would be executed by Excel and Sheets when the file is opened.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (h *handlers) ExportWouldBlockReport(ctx context.Context, req apigen.ExportWouldBlockReportRequestObject) (apigen.ExportWouldBlockReportResponseObject, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"time", "event_id", "site", "client_ip", "method", "path", "status", "rule_ids"})
	if _, err := h.wouldBlockFor(ctx, req.Params.Site, req.Params.From, req.Params.To, func(r store.EventRow) {
		_ = w.Write([]string{r.TS.UTC().Format(time.RFC3339), r.ID, csvCell(r.SiteID), csvCell(r.ClientIP), csvCell(r.Method), csvCell(r.Path), strconv.Itoa(r.Status), csvCell(strings.Join(r.RuleIDs, " "))})
	}); err != nil {
		return nil, err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("writing csv: %w", err)
	}
	return apigen.ExportWouldBlockReport200TextcsvResponse{Body: io.Reader(&buf), ContentLength: int64(buf.Len())}, nil
}

func (h *handlers) GetSystemStatus(ctx context.Context, _ apigen.GetSystemStatusRequestObject) (apigen.GetSystemStatusResponseObject, error) {
	var n int
	if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
		n, err = tx.CountEvents(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	out := apigen.SystemStatus{EventsStored: int64(n)}
	if h.s.EventStats != nil {
		pub, drop := h.s.EventStats()
		out.EventsPublished, out.EventsDropped = int64(pub), int64(drop) //nolint:gosec // counters far below int64 max
	}
	size, truncated := dirSize(h.s.DataDir)
	out.DataDirBytes, out.DataDirTruncated = size, &truncated
	if _, live, err := h.s.Config.Current(ctx); err == nil {
		d := live.Global.Events.RetentionDays
		out.RetentionDays = &d
	}
	return apigen.GetSystemStatus200JSONResponse(out), nil
}

// dirSize totals the files under dir, stopping after a bounded number of entries.
func dirSize(dir string) (bytes int64, truncated bool) {
	if dir == "" {
		return 0, false
	}
	const maxEntries = 100_000
	count := 0
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entries are skipped, the total is advisory
		}
		if count++; count > maxEntries {
			truncated = true
			return filepath.SkipAll
		}
		if !d.IsDir() {
			if info, ierr := d.Info(); ierr == nil {
				bytes += info.Size()
			}
		}
		return nil
	})
	return bytes, truncated
}
