package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	"github.com/skylarng89/sherlock-waf/internal/crs"
	"github.com/skylarng89/sherlock-waf/internal/customrules"
	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/internal/tuning"
	"github.com/skylarng89/sherlock-waf/internal/vpatch"
)

// --- helpers ---

// loadSite returns the live configuration, the site and its site-level effective policy.
func (h *handlers) loadSite(ctx context.Context, id string) (store.ConfigVersion, *config.Root, *config.Site, config.EffectivePolicy, error) {
	v, root, err := h.current(ctx)
	if err != nil {
		return v, nil, nil, config.EffectivePolicy{}, err
	}
	i := findSite(root, id)
	if i < 0 {
		return v, nil, nil, config.EffectivePolicy{}, errNotFound("site " + id)
	}
	return v, root, &root.Sites[i], root.EffectivePolicy(&root.Sites[i], nil), nil
}

func decodeEvent(row store.EventRow) (events.Event, bool) {
	var ev events.Event
	if err := json.Unmarshal(row.Body, &ev); err != nil {
		return events.Event{}, false
	}
	if ev.ID == "" {
		ev.ID = row.ID
	}
	return ev, true
}

// siteEvents reads decoded events of a site, newest first, within the scan cap.
func (h *handlers) siteEvents(ctx context.Context, site string, from, to time.Time) (evs []events.Event, truncated bool, err error) {
	truncated, err = h.scan(ctx, store.EventFilter{SiteID: site, From: from.UTC(), To: to.UTC()}, func(r store.EventRow) bool {
		if ev, ok := decodeEvent(r); ok {
			evs = append(evs, ev)
		}
		return true
	})
	return evs, truncated, err
}

func (h *handlers) auditNote(ctx context.Context, action, objectType, objectID string, details any) {
	a := actorOf(ctx)
	if err := h.s.Audit.Record(context.WithoutCancel(ctx), h.s.Store, audit.Input{
		ActorType: a.Type, ActorID: a.ID, IP: a.IP, Action: action, ObjectType: objectType, ObjectID: objectID, Details: details,
	}); err != nil {
		h.s.log.Error("auditing tuning change failed", "action", action, "object", objectID, "error", err)
	}
}

func ensureWAF(p *config.Policy) *config.WAFPolicy {
	if p.WAF == nil {
		p.WAF = &config.WAFPolicy{}
	}
	return p.WAF
}

func exclusionProblem(errs config.Errors) *problem {
	return &problem{Status: 422, Code: "invalid_exclusion", Title: "Invalid exclusion", Detail: "The exclusion failed validation.", Errors: errs}
}

type kvCount struct {
	Key   string
	Count int
}

func topCounts(m map[string]int, n int) []kvCount {
	out := make([]kvCount, 0, len(m))
	for k, v := range m {
		out = append(out, kvCount{k, v})
	}
	slices.SortFunc(out, func(a, b kvCount) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.Key, b.Key)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// --- exclusions ---

func (h *handlers) ListExclusions(ctx context.Context, req apigen.ListExclusionsRequestObject) (apigen.ListExclusionsResponseObject, error) {
	v, _, site, _, err := h.loadSite(ctx, req.Site)
	if err != nil {
		return nil, err
	}
	items := []config.Exclusion{}
	if site.Policy.WAF != nil {
		items = append(items, site.Policy.WAF.Exclusions...)
	}
	return apigen.ListExclusions200JSONResponse{Body: apigen.ExclusionList{Items: items}, Headers: apigen.ListExclusions200ResponseHeaders{ETag: etag(v.ID)}}, nil
}

type impactJSON struct {
	From               time.Time      `json:"from"`
	To                 time.Time      `json:"to"`
	Scanned            int            `json:"events_scanned"`
	Matching           int            `json:"matching_events"`
	NoLongerTriggering int            `json:"no_longer_triggering"`
	NoLongerBlocking   int            `json:"no_longer_blocking"`
	ByRule             map[string]int `json:"by_rule"`
	SampleEventIDs     []string       `json:"sample_event_ids"`
	Truncated          bool           `json:"truncated"`
}

func (h *handlers) previewExclusion(ctx context.Context, site string, eff config.EffectivePolicy, x config.Exclusion, days int) (impactJSON, tuning.Impact, error) {
	to := h.s.Now().UTC()
	from := to.AddDate(0, 0, -days)
	evs, truncated, err := h.siteEvents(ctx, site, from, to)
	if err != nil {
		return impactJSON{}, tuning.Impact{}, err
	}
	imp, err := tuning.Preview(x, evs, eff.WAF.InboundThreshold, eff.WAF.BlockingParanoiaLevel)
	if err != nil {
		return impactJSON{}, tuning.Impact{}, errUnprocessed(err.Error())
	}
	return impactJSON{
		From: from, To: to, Scanned: imp.Scanned, Matching: imp.Matching, NoLongerTriggering: imp.NoLongerTriggering,
		NoLongerBlocking: imp.NoLongerBlocking, ByRule: imp.ByRule, SampleEventIDs: imp.SampleEventIDs, Truncated: truncated,
	}, imp, nil
}

func (h *handlers) ProposeExclusion(ctx context.Context, req apigen.ProposeExclusionRequestObject) (apigen.ProposeExclusionResponseObject, error) {
	b := req.Body
	if b == nil || (b.EventId == nil && b.Exclusion == nil) {
		return nil, errBadRequest("Send event_id to build an exclusion, or exclusion to evaluate one.")
	}
	_, _, _, eff, err := h.loadSite(ctx, req.Site)
	if err != nil {
		return nil, err
	}
	days := 30
	if b.Days != nil {
		days = min(max(*b.Days, 1), 90)
	}

	var (
		x       config.Exclusion
		finding *events.Finding
		eventID string
	)
	if b.EventId != nil {
		eventID = *b.EventId
		var row store.EventRow
		if err := h.s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
			row, err = tx.GetEvent(ctx, eventID)
			return err
		}); err != nil {
			return nil, err
		}
		if row.SiteID != req.Site {
			return nil, errNotFound("event " + eventID + " on site " + req.Site)
		}
		ev, ok := decodeEvent(row)
		if !ok {
			return nil, errUnprocessed("the stored event cannot be read")
		}
		var rule string
		if b.RuleId != nil {
			rule = *b.RuleId
		}
		scope := tuning.ScopeTarget
		if b.Scope != nil {
			scope = tuning.Scope(*b.Scope)
		}
		var f events.Finding
		x, f, err = tuning.Propose(ev, rule, scope)
		if err != nil {
			return nil, errUnprocessed(err.Error())
		}
		finding = &f
	}
	if b.Exclusion != nil {
		x = *b.Exclusion
	}
	if errs := config.ValidateExclusion(x); len(errs) > 0 {
		return nil, exclusionProblem(errs)
	}

	impact, raw, err := h.previewExclusion(ctx, req.Site, eff, x, days)
	if err != nil {
		return nil, err
	}
	warnings := tuning.Warnings(x, &raw)
	out := struct {
		Exclusion config.Exclusion `json:"exclusion"`
		EventID   string           `json:"event_id,omitempty"`
		Finding   *struct {
			RuleID  string `json:"rule_id"`
			Message string `json:"message,omitempty"`
			Target  string `json:"target,omitempty"`
			Matched string `json:"matched,omitempty"`
			Score   int    `json:"score,omitempty"`
		} `json:"finding,omitempty"`
		Impact                  impactJSON       `json:"impact"`
		Warnings                []tuning.Warning `json:"warnings"`
		RequiresAcknowledgement bool             `json:"requires_acknowledgement"`
	}{Exclusion: x, EventID: eventID, Impact: impact, Warnings: warnings, RequiresAcknowledgement: tuning.NeedsAcknowledgement(warnings)}
	if warnings == nil {
		out.Warnings = []tuning.Warning{}
	}
	if finding != nil {
		out.Finding = &struct {
			RuleID  string `json:"rule_id"`
			Message string `json:"message,omitempty"`
			Target  string `json:"target,omitempty"`
			Matched string `json:"matched,omitempty"`
			Score   int    `json:"score,omitempty"`
		}{finding.RuleID, finding.Message, finding.Target, finding.Matched, finding.Score}
	}
	resp, err := recode[apigen.ExclusionProposal](out)
	if err != nil {
		return nil, err
	}
	return apigen.ProposeExclusion200JSONResponse(resp), nil
}

func (h *handlers) CreateExclusion(ctx context.Context, req apigen.CreateExclusionRequestObject) (apigen.CreateExclusionResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	x := req.Body.Exclusion
	if errs := config.ValidateExclusion(x); len(errs) > 0 {
		return nil, exclusionProblem(errs)
	}
	_, _, _, eff, err := h.loadSite(ctx, req.Site)
	if err != nil {
		return nil, err
	}
	_, raw, err := h.previewExclusion(ctx, req.Site, eff, x, 30)
	if err != nil {
		return nil, err
	}
	warnings := tuning.Warnings(x, &raw)
	acked := req.Body.AcknowledgeWarnings != nil && *req.Body.AcknowledgeWarnings
	if tuning.NeedsAcknowledgement(warnings) && !acked {
		var msgs []string
		for _, w := range warnings {
			if w.Severity == tuning.SevCritical {
				msgs = append(msgs, w.Message)
			}
		}
		return nil, &problem{
			Status: 422, Code: "warnings_unacknowledged", Title: "Warnings need acknowledgement",
			Detail: "This exclusion removes protection broadly. Review the warnings and resend with acknowledge_warnings set to true.",
			Errors: []config.Error{{Path: "/acknowledge_warnings", Code: "required", Message: strings.Join(msgs, " ")}},
		}
	}

	v, err := h.mutate(ctx, req.Params.IfMatch, func(r *config.Root) error {
		i := findSite(r, req.Site)
		if i < 0 {
			return errNotFound("site " + req.Site)
		}
		w := ensureWAF(&r.Sites[i].Policy)
		if slices.ContainsFunc(w.Exclusions, func(e config.Exclusion) bool { return e.ID == x.ID }) {
			return errConflict(fmt.Sprintf("exclusion %q already exists on site %q", x.ID, req.Site))
		}
		w.Exclusions = append(w.Exclusions, x)
		return nil
	})
	if err != nil {
		return nil, err
	}
	details := map[string]any{
		"site": req.Site, "exclusion_id": x.ID, "description": x.Description, "config_version": v.ID,
		"match": x.Match, "remove_rule_ids": x.RemoveRuleIDs, "remove_tags": x.RemoveTags, "remove_targets": x.RemoveTargets,
		"warnings": warningCodes(warnings), "warnings_acknowledged": acked,
	}
	if req.Body.EventId != nil {
		details["event_id"] = *req.Body.EventId
	}
	h.auditNote(ctx, "waf.exclusion.create", "exclusion", req.Site+"/"+x.ID, details)
	return apigen.CreateExclusion201JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}

func warningCodes(ws []tuning.Warning) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = w.Severity + ":" + w.Code
	}
	return out
}

func (h *handlers) DeleteExclusion(ctx context.Context, req apigen.DeleteExclusionRequestObject) (apigen.DeleteExclusionResponseObject, error) {
	v, err := h.mutate(ctx, req.Params.IfMatch, func(r *config.Root) error {
		i := findSite(r, req.Site)
		if i < 0 {
			return errNotFound("site " + req.Site)
		}
		w := r.Sites[i].Policy.WAF
		if w == nil {
			return errNotFound("exclusion " + req.Exclusion)
		}
		j := slices.IndexFunc(w.Exclusions, func(e config.Exclusion) bool { return e.ID == req.Exclusion })
		if j < 0 {
			return errNotFound("exclusion " + req.Exclusion)
		}
		w.Exclusions = slices.Delete(w.Exclusions, j, j+1)
		return nil
	})
	if err != nil {
		return nil, err
	}
	h.auditNote(ctx, "waf.exclusion.delete", "exclusion", req.Site+"/"+req.Exclusion, map[string]any{"site": req.Site, "exclusion_id": req.Exclusion, "config_version": v.ID})
	return apigen.DeleteExclusion200JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}

// --- custom rules ---

func customRulesIssues(res customrules.Result) []config.Error {
	out := make([]config.Error, len(res.Issues))
	for i, is := range res.Issues {
		out[i] = config.Error{Path: "/custom_rules", Code: is.Code, Message: is.String()}
	}
	return out
}

func (h *handlers) GetCustomRules(ctx context.Context, req apigen.GetCustomRulesRequestObject) (apigen.GetCustomRulesResponseObject, error) {
	v, root, site, _, err := h.loadSite(ctx, req.Site)
	if err != nil {
		return nil, err
	}
	rules, source := "", "none"
	if w := site.Policy.WAF; w != nil && w.CustomRules != nil {
		rules, source = *w.CustomRules, config.SourceSite
	} else if w := root.Global.Defaults.WAF; w != nil && w.CustomRules != nil {
		rules, source = *w.CustomRules, config.SourceGlobal
	}
	body := apigen.CustomRules{Rules: rules, Source: source, RuleIds: customrules.Check(rules).RuleIDs}
	body.ReservedIdRange = &struct {
		Max *int `json:"max,omitempty"`
		Min *int `json:"min,omitempty"`
	}{Max: ptrTo(customrules.MaxID), Min: ptrTo(customrules.MinID)}
	return apigen.GetCustomRules200JSONResponse{Body: body, Headers: apigen.GetCustomRules200ResponseHeaders{ETag: etag(v.ID)}}, nil
}

func ptrTo[T any](v T) *T { return &v }

func (h *handlers) ValidateCustomRules(ctx context.Context, req apigen.ValidateCustomRulesRequestObject) (apigen.ValidateCustomRulesResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	if _, _, _, _, err := h.loadSite(ctx, req.Site); err != nil {
		return nil, err
	}
	res := customrules.Check(req.Body.Rules)
	out, err := recode[apigen.CustomRulesValidation](struct {
		Valid   bool                `json:"valid"`
		Issues  []customrules.Issue `json:"issues"`
		RuleIDs []int               `json:"rule_ids"`
	}{res.Valid(), res.Issues, res.RuleIDs})
	if err != nil {
		return nil, err
	}
	return apigen.ValidateCustomRules200JSONResponse(out), nil
}

func (h *handlers) PutCustomRules(ctx context.Context, req apigen.PutCustomRulesRequestObject) (apigen.PutCustomRulesResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	res := customrules.Check(req.Body.Rules)
	if !res.Valid() {
		return nil, &problem{Status: 422, Code: "invalid_custom_rules", Title: "Custom rules rejected", Detail: "The custom rules failed validation and were not saved.", Errors: customRulesIssues(res)}
	}
	v, err := h.mutate(ctx, req.Params.IfMatch, func(r *config.Root) error {
		i := findSite(r, req.Site)
		if i < 0 {
			return errNotFound("site " + req.Site)
		}
		w := ensureWAF(&r.Sites[i].Policy)
		if strings.TrimSpace(req.Body.Rules) == "" {
			w.CustomRules = nil // inherit again
		} else {
			w.CustomRules = &req.Body.Rules
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(req.Body.Rules))
	h.auditNote(ctx, "waf.custom_rules.update", "custom_rules", req.Site, map[string]any{
		"site": req.Site, "rule_ids": res.RuleIDs, "sha256": hex.EncodeToString(sum[:]), "bytes": len(req.Body.Rules), "config_version": v.ID,
	})
	return apigen.PutCustomRules200JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}

// --- paranoia level helper ---

func (h *handlers) GetParanoiaImpact(ctx context.Context, req apigen.GetParanoiaImpactRequestObject) (apigen.GetParanoiaImpactResponseObject, error) {
	target := req.Params.Target
	if target < 1 || target > 4 {
		return nil, errBadRequest("target must be between 1 and 4.")
	}
	_, _, _, eff, err := h.loadSite(ctx, req.Site)
	if err != nil {
		return nil, err
	}
	to := h.s.Now().UTC()
	if req.Params.To != nil {
		to = req.Params.To.UTC()
	}
	from := to.AddDate(0, 0, -7)
	if req.Params.From != nil {
		from = req.Params.From.UTC()
	}
	if err := rangeCheck(from, to); err != nil {
		return nil, err
	}

	out := struct {
		Site             string           `json:"site"`
		From             time.Time        `json:"from"`
		To               time.Time        `json:"to"`
		DetectionPL      int              `json:"detection_paranoia_level"`
		BlockingPL       int              `json:"blocking_paranoia_level"`
		TargetPL         int              `json:"target_paranoia_level"`
		Threshold        int              `json:"inbound_threshold"`
		Observable       bool             `json:"observable"`
		Advice           string           `json:"advice,omitempty"`
		Scanned          int              `json:"events_scanned"`
		AlreadyBlocking  int              `json:"already_blocking"`
		AdditionalBlocks int              `json:"additional_blocks"`
		ByRule           []map[string]any `json:"by_rule"`
		ByPath           []map[string]any `json:"by_path"`
		SampleEventIDs   []string         `json:"sample_event_ids"`
		Truncated        bool             `json:"truncated"`
	}{
		Site: req.Site, From: from, To: to, DetectionPL: eff.WAF.ParanoiaLevel, BlockingPL: eff.WAF.BlockingParanoiaLevel, TargetPL: target,
		Threshold: eff.WAF.InboundThreshold, Observable: target <= eff.WAF.ParanoiaLevel,
		ByRule: []map[string]any{}, ByPath: []map[string]any{}, SampleEventIDs: []string{},
	}
	if !out.Observable {
		out.Advice = fmt.Sprintf("Findings above paranoia level %d are not being recorded. Set waf.paranoia_level to %d and keep waf.blocking_paranoia_level at %d for a few days, then ask again.", eff.WAF.ParanoiaLevel, target, eff.WAF.BlockingParanoiaLevel)
	}
	evs, truncated, err := h.siteEvents(ctx, req.Site, from, to)
	if err != nil {
		return nil, err
	}
	out.Truncated = truncated
	pred := tuning.PredictPL(evs, eff.WAF.InboundThreshold, eff.WAF.BlockingParanoiaLevel, target)
	out.Scanned, out.AlreadyBlocking, out.AdditionalBlocks, out.SampleEventIDs = pred.Scanned, pred.AlreadyBlocking, pred.AdditionalBlocks, pred.SampleEventIDs
	for _, c := range topCounts(pred.ByRule, 10) {
		out.ByRule = append(out.ByRule, map[string]any{"rule_id": c.Key, "count": c.Count})
	}
	for _, c := range topCounts(pred.ByPath, 10) {
		out.ByPath = append(out.ByPath, map[string]any{"path": c.Key, "count": c.Count})
	}
	resp, err := recode[apigen.ParanoiaImpact](out)
	if err != nil {
		return nil, err
	}
	return apigen.GetParanoiaImpact200JSONResponse(resp), nil
}

// --- CRS catalogue ---

func (h *handlers) ListCrsRules(ctx context.Context, req apigen.ListCrsRulesRequestObject) (apigen.ListCrsRulesResponseObject, error) {
	p := req.Params
	if p.State != nil && p.Site == nil {
		return nil, errBadRequest("state needs a site.")
	}
	if p.State != nil && !slices.Contains([]string{"enforcing", "detect_only", "inactive", "disabled", "partly_excluded"}, string(*p.State)) {
		return nil, errBadRequest("state must be one of enforcing, detect_only, inactive, disabled, partly_excluded.")
	}
	if p.Direction != nil && *p.Direction != "request" && *p.Direction != "response" {
		return nil, errBadRequest("direction must be request or response.")
	}
	if p.ParanoiaLevel != nil && (*p.ParanoiaLevel < 1 || *p.ParanoiaLevel > 4) {
		return nil, errBadRequest("paranoia_level must be between 1 and 4.")
	}
	all, err := crs.Rules()
	if err != nil {
		return nil, err
	}
	var eff *config.EffectivePolicy
	if p.Site != nil {
		_, _, _, e, err := h.loadSite(ctx, *p.Site)
		if err != nil {
			return nil, err
		}
		eff = &e
	}
	q := ""
	if p.Q != nil {
		q = strings.ToLower(strings.TrimSpace(*p.Q))
	}
	type item struct {
		crs.Rule
		Status *crs.Status `json:"status,omitempty"`
	}
	cats := map[string]struct{}{}
	var matched []item
	for _, r := range all {
		cats[r.Category] = struct{}{}
		if !r.Match(q) ||
			(p.Category != nil && r.Category != *p.Category) ||
			(p.ParanoiaLevel != nil && r.ParanoiaLevel != *p.ParanoiaLevel) ||
			(p.Direction != nil && r.Direction != string(*p.Direction)) {
			continue
		}
		it := item{Rule: r}
		if eff != nil {
			st := crs.StateFor(r, *eff)
			if p.State != nil && string(st.State) != string(*p.State) {
				continue
			}
			it.Status = &st
		}
		matched = append(matched, it)
	}
	limit, offset := 50, 0
	if p.Limit != nil {
		limit = min(max(*p.Limit, 1), 500)
	}
	if p.Offset != nil {
		offset = max(*p.Offset, 0)
	}
	total := len(matched)
	page := []item{}
	if offset < total {
		page = matched[offset:min(offset+limit, total)]
	}
	categories := make([]string, 0, len(cats))
	for c := range cats {
		categories = append(categories, c)
	}
	slices.Sort(categories)
	out, err := recode[apigen.CrsRuleList](struct {
		CRSVersion string   `json:"crs_version"`
		Total      int      `json:"total"`
		Categories []string `json:"categories"`
		Items      []item   `json:"items"`
	}{h.s.Info.CRSVersion, total, categories, page})
	if err != nil {
		return nil, err
	}
	return apigen.ListCrsRules200JSONResponse(out), nil
}

// --- virtual patches ---

type patchSiteState struct {
	Site    string     `json:"site"`
	State   string     `json:"state"`
	Hits    int        `json:"hits"`
	LastHit *time.Time `json:"last_hit"`
}

func patchState(p vpatch.Patch, eff config.EffectivePolicy) string {
	switch {
	case !eff.VirtualPatches.Enabled:
		return "pack_off"
	case slices.Contains(eff.VirtualPatches.Disabled, p.ID):
		return "disabled"
	case !p.Active(true, nil, eff.DeclaredStacks()):
		return "stack_not_declared"
	}
	return "active"
}

func (h *handlers) ListVirtualPatches(ctx context.Context, req apigen.ListVirtualPatchesRequestObject) (apigen.ListVirtualPatchesResponseObject, error) {
	p := req.Params
	if p.Severity != nil && !slices.Contains([]string{"low", "medium", "high", "critical"}, string(*p.Severity)) {
		return nil, errBadRequest("severity must be one of low, medium, high, critical.")
	}
	days := 30
	if p.Days != nil {
		days = min(max(*p.Days, 1), 90)
	}
	_, root, err := h.current(ctx)
	if err != nil {
		return nil, err
	}
	var sites []*config.Site
	for i := range root.Sites {
		if p.Site == nil || root.Sites[i].ID == *p.Site {
			sites = append(sites, &root.Sites[i])
		}
	}
	if p.Site != nil && len(sites) == 0 {
		return nil, errNotFound("site " + *p.Site)
	}
	patches, err := vpatch.All()
	if err != nil {
		return nil, err
	}
	covered, err := vpatch.Covered()
	if err != nil {
		return nil, err
	}

	// One capped scan of recent events counts hits for every patch and site.
	ruleToPatch := map[string]string{}
	for _, pt := range patches {
		for _, id := range pt.RuleIDs {
			ruleToPatch[fmt.Sprint(id)] = pt.ID
		}
	}
	type key struct{ patch, site string }
	hits := map[key]int{}
	last := map[key]time.Time{}
	to := h.s.Now().UTC()
	f := store.EventFilter{From: to.AddDate(0, 0, -days), To: to}
	if p.Site != nil {
		f.SiteID = *p.Site
	}
	truncated, err := h.scan(ctx, f, func(r store.EventRow) bool {
		seen := map[string]bool{}
		for _, id := range r.RuleIDs {
			if pid, ok := ruleToPatch[id]; ok && !seen[pid] {
				seen[pid] = true
				k := key{pid, r.SiteID}
				hits[k]++
				if r.TS.After(last[k]) {
					last[k] = r.TS
				}
			}
		}
		return true
	})
	if err != nil {
		return nil, err
	}

	q := ""
	if p.Q != nil {
		q = strings.ToLower(strings.TrimSpace(*p.Q))
	}
	type item struct {
		vpatch.Patch
		Generic bool             `json:"generic"`
		Hits    int              `json:"hits"`
		Sites   []patchSiteState `json:"sites"`
	}
	items := []item{}
	protected := map[string]bool{}
	cveSet, kevSet := map[string]bool{}, map[string]bool{}
	totalHits := 0
	for _, pt := range patches {
		for _, c := range pt.CVEs {
			cveSet[c] = true
			if pt.KEV {
				kevSet[c] = true
			}
		}
		if (p.Severity != nil && pt.Severity != string(*p.Severity)) || (p.Kev != nil && pt.KEV != *p.Kev) || !patchMatches(pt, q) {
			continue
		}
		it := item{Patch: pt, Generic: pt.Generic(), Sites: []patchSiteState{}}
		for _, s := range sites {
			st := patchState(pt, root.EffectivePolicy(s, nil))
			k := key{pt.ID, s.ID}
			ps := patchSiteState{Site: s.ID, State: st, Hits: hits[k]}
			if t, ok := last[k]; ok {
				t := t
				ps.LastHit = &t
			}
			it.Hits += ps.Hits
			if st == "active" {
				protected[s.ID] = true
			}
			it.Sites = append(it.Sites, ps)
		}
		totalHits += it.Hits
		items = append(items, it)
	}
	cov := []vpatch.CoveredCVE{}
	for _, c := range covered {
		if c.KEV {
			kevSet[c.CVE] = true
		}
		if (p.Severity != nil && c.Severity != string(*p.Severity)) || (p.Kev != nil && c.KEV != *p.Kev) ||
			(q != "" && !strings.Contains(strings.ToLower(c.CVE+" "+c.Product), q)) {
			continue
		}
		cov = append(cov, c)
	}
	packVersion := ""
	for _, pt := range patches {
		packVersion = max(packVersion, pt.AddedIn)
	}
	out, err := recode[apigen.VirtualPatchCatalogue](struct {
		PackVersion string              `json:"pack_version"`
		WindowDays  int                 `json:"window_days"`
		KnownStacks []string            `json:"known_stacks"`
		Items       []item              `json:"items"`
		Covered     []vpatch.CoveredCVE `json:"covered"`
		Summary     map[string]int      `json:"summary"`
		Truncated   bool                `json:"truncated"`
	}{packVersion, days, vpatch.KnownStacks(), items, cov, map[string]int{
		"patches": len(patches), "covered_cves": len(covered), "cves_with_rule": len(cveSet), "kev_cves": len(kevSet),
		"sites_protected": len(protected), "hits": totalHits,
	}, truncated})
	if err != nil {
		return nil, err
	}
	return apigen.ListVirtualPatches200JSONResponse(out), nil
}

func patchMatches(p vpatch.Patch, q string) bool {
	if q == "" {
		return true
	}
	hay := strings.ToLower(p.ID + " " + strings.Join(p.CVEs, " ") + " " + p.Vendor + " " + p.Product + " " + p.Title)
	return strings.Contains(hay, q)
}

func (h *handlers) SetVirtualPatchState(ctx context.Context, req apigen.SetVirtualPatchStateRequestObject) (apigen.SetVirtualPatchStateResponseObject, error) {
	if req.Body == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	if _, ok := vpatch.Get(req.Patch); !ok {
		return nil, errNotFound("virtual patch " + req.Patch)
	}
	enabled := req.Body.Enabled
	optOut := "virtual_patches:" + req.Patch
	v, err := h.mutate(ctx, req.Params.IfMatch, func(r *config.Root) error {
		i := findSite(r, req.Site)
		if i < 0 {
			return errNotFound("site " + req.Site)
		}
		pol := &r.Sites[i].Policy
		if pol.VirtualPatches == nil {
			pol.VirtualPatches = &config.VirtualPatchPolicy{}
		}
		vp := pol.VirtualPatches
		inherited := r.Global.Defaults.VirtualPatches != nil && slices.Contains(r.Global.Defaults.VirtualPatches.Disabled, req.Patch)
		if enabled {
			vp.Disabled = slices.DeleteFunc(vp.Disabled, func(s string) bool { return s == req.Patch })
			if inherited && !slices.Contains(pol.OptOut, optOut) {
				pol.OptOut = append(pol.OptOut, optOut) // the global default disables it; this site opts out
			}
		} else {
			pol.OptOut = slices.DeleteFunc(pol.OptOut, func(s string) bool { return s == optOut })
			if !slices.Contains(vp.Disabled, req.Patch) && !inherited {
				vp.Disabled = append(vp.Disabled, req.Patch)
			}
		}
		slices.Sort(vp.Disabled)
		return nil
	})
	if err != nil {
		return nil, err
	}
	h.auditNote(ctx, "waf.virtual_patch.set", "virtual_patch", req.Site+"/"+req.Patch, map[string]any{"site": req.Site, "patch": req.Patch, "enabled": enabled, "config_version": v.ID})
	return apigen.SetVirtualPatchState200JSONResponse{ConfigVersionJSONResponse: versionResponse(v)}, nil
}
