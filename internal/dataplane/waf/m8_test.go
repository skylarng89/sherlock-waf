package waf

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

func withExclusions(ex ...config.Exclusion) func(*Handler) {
	return func(h *Handler) { h.Exclusions = ex }
}

func TestExclusionsRemoveOnlyWhatTheyScope(t *testing.T) {
	search := "/search?q=" + url.QueryEscape(sqli)
	other := "/other?q=" + url.QueryEscape(sqli)
	tests := []struct {
		name       string
		ex         config.Exclusion
		method     string
		target     string
		wantBlock  bool
		wantAbsent []string
	}{
		{"target on path and method", config.Exclusion{
			ID: "q", Match: config.ExclusionMatch{Paths: []string{"/search"}, Methods: []string{"GET"}},
			RemoveTargets: []config.ExclusionTarget{{RuleIDs: []string{"942100"}, Target: "ARGS:q"}},
		}, "GET", search, false, []string{"942100"}},
		{"same exclusion, other path", config.Exclusion{
			ID: "q", Match: config.ExclusionMatch{Paths: []string{"/search"}},
			RemoveTargets: []config.ExclusionTarget{{RuleIDs: []string{"942100"}, Target: "ARGS:q"}},
		}, "GET", other, true, nil},
		{"same exclusion, other method", config.Exclusion{
			ID: "q", Match: config.ExclusionMatch{Paths: []string{"/search"}, Methods: []string{"POST"}},
			RemoveRuleIDs: []string{"942100"},
		}, "GET", search, true, nil},
		{"rule range on glob", config.Exclusion{ID: "g", Match: config.ExclusionMatch{Paths: []string{"/sea*"}}, RemoveRuleIDs: []string{"942000-942999"}}, "GET", search, false, []string{"942100"}},
		{"glob star does not cross a slash", config.Exclusion{ID: "g", Match: config.ExclusionMatch{Paths: []string{"/*"}}, RemoveRuleIDs: []string{"942000-942999"}}, "GET", "/a/b?q=" + url.QueryEscape(sqli), true, nil},
		{"deep glob", config.Exclusion{ID: "g", Match: config.ExclusionMatch{Paths: []string{"/a/**"}}, RemoveRuleIDs: []string{"942000-942999"}}, "GET", "/a/b/c?q=" + url.QueryEscape(sqli), false, []string{"942100"}},
		{"by tag, everywhere", config.Exclusion{ID: "t", RemoveTags: []string{"attack-sqli"}}, "GET", other, false, []string{"942100"}},
		{"target of other parameter keeps the rule", config.Exclusion{ID: "q", RemoveTargets: []config.ExclusionTarget{{RuleIDs: []string{"942100"}, Target: "ARGS:other"}}}, "GET", search, true, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler(t, config.ModeBlock, config.FailClosed, withExclusions(tc.ex))
			out := serve(t, h, tc.method, tc.target, "", "")
			if tc.wantBlock {
				assert.Equal(t, http.StatusForbidden, out.rec.Code, "rules=%v", ruleIDs(out.d))
			} else {
				assert.Equal(t, http.StatusOK, out.rec.Code, "rules=%v", ruleIDs(out.d))
			}
			for _, id := range tc.wantAbsent {
				assert.NotContains(t, ruleIDs(out.d), id)
			}
		})
	}
}

func TestExclusionsOnOneInstanceDoNotAffectAnother(t *testing.T) {
	plain := newHandler(t, config.ModeBlock, config.FailClosed)
	excluded := newHandler(t, config.ModeBlock, config.FailClosed, withExclusions(config.Exclusion{ID: "all", RemoveTags: []string{"attack-sqli"}}))
	target := "/x?q=" + url.QueryEscape(sqli)
	assert.Equal(t, http.StatusOK, serve(t, excluded, "GET", target, "", "").rec.Code)
	assert.Equal(t, http.StatusForbidden, serve(t, plain, "GET", target, "", "").rec.Code, "an exclusion is part of one site's instance only")
}

func TestExclusionDirectivesAreDeterministicAndQuoted(t *testing.T) {
	s := Settings{
		Mode: config.ModeBlock, ParanoiaLevel: 1, BlockingParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, MaxBodyBytes: 1 << 20,
		Exclusions: []config.Exclusion{
			{ID: "b", Match: config.ExclusionMatch{Paths: []string{"/a.b/*", "/x/**"}, Methods: []string{"GET", "POST"}}, RemoveRuleIDs: []string{"920350"}},
			{ID: "a", RemoveTargets: []config.ExclusionTarget{{Tags: []string{"attack-xss"}, Target: "REQUEST_COOKIES:/^_ga/"}}},
		},
	}
	first, err := s.Directives()
	require.NoError(t, err)
	second, err := s.Directives()
	require.NoError(t, err)
	assert.Equal(t, first, second)
	assert.Contains(t, first, `SecAction "id:9100000,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetByTag=attack-xss;REQUEST_COOKIES:/^_ga/"`)
	assert.Contains(t, first, `SecRule REQUEST_FILENAME "@rx ^(?:/a\.b/[^/]*|/x(?:/.*)?)$" "id:9100001,phase:1,pass,nolog,t:none,chain"`)
	assert.Contains(t, first, `SecRule REQUEST_METHOD "@rx ^(?:GET|POST)$" "t:none,ctl:ruleRemoveById=920350"`)
	assert.Less(t, strings.Index(first, "id:9100000"), strings.Index(first, "Include @owasp_crs/REQUEST-*.conf"), "exclusions must precede CRS")
}

func TestExclusionDirectivesRefuseInjection(t *testing.T) {
	base := Settings{Mode: config.ModeBlock, ParanoiaLevel: 1, BlockingParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, MaxBodyBytes: 1 << 20}
	for name, ex := range map[string]config.Exclusion{
		"target":  {ID: "x", RemoveTargets: []config.ExclusionTarget{{RuleIDs: []string{"942100"}, Target: `ARGS:q;ctl:ruleEngine=Off`}}},
		"rule id": {ID: "x", RemoveRuleIDs: []string{`1,ctl:ruleEngine=Off`}},
		"tag":     {ID: "x", RemoveTags: []string{`a,ctl:ruleEngine=Off`}},
	} {
		t.Run(name, func(t *testing.T) {
			s := base
			s.Exclusions = []config.Exclusion{ex}
			_, err := s.Directives()
			assert.Error(t, err)
		})
	}
}

func TestCustomRulesRunBeforeCRS(t *testing.T) {
	h := newHandler(t, config.ModeBlock, config.FailClosed, func(h *Handler) {
		h.CustomRules = `SecRule REQUEST_FILENAME "@beginsWith /admin" "id:10001,phase:1,deny,status:403,log,msg:'Admin path blocked'"`
	})
	out := serve(t, h, "GET", "/admin/users", "", "")
	assert.Equal(t, http.StatusForbidden, out.rec.Code)
	assert.Equal(t, http.StatusOK, serve(t, h, "GET", "/public", "", "").rec.Code)
}

func TestBlockingParanoiaLevelBelowDetectionRecordsWithoutBlocking(t *testing.T) {
	// 942260 is a PL2 rule: with detection PL2 and blocking PL1 it must be
	// recorded as a finding (score 5, tag paranoia-level/2) but never block.
	h := newHandler(t, config.ModeBlock, config.FailClosed, func(h *Handler) { h.ParanoiaLevel = 2; h.BlockingParanoiaLevel = 1 })
	out := serve(t, h, "GET", "/?q="+url.QueryEscape("select name from users"), "", "")
	assert.Equal(t, http.StatusOK, out.rec.Code, "PL2 finding must not block at blocking PL1")
	require.Contains(t, ruleIDs(out.d), "942260")
	for _, f := range out.d.Findings() {
		if f.RuleID == "942260" {
			assert.Contains(t, f.Tags, "paranoia-level/2")
			assert.Equal(t, 5, f.Score)
		}
	}
	// A PL1 attack still blocks at blocking PL1.
	assert.Equal(t, http.StatusForbidden, serve(t, h, "GET", "/?q="+url.QueryEscape(sqli), "", "").rec.Code)

	// With blocking PL2 the same request is blocked.
	h2 := newHandler(t, config.ModeBlock, config.FailClosed, func(h *Handler) { h.ParanoiaLevel = 2; h.BlockingParanoiaLevel = 2 })
	assert.Equal(t, http.StatusForbidden, serve(t, h2, "GET", "/?q="+url.QueryEscape("select name from users"), "", "").rec.Code)
}

// --- outbound ---

func outboundHandler(t *testing.T, mode config.Mode, mutate ...func(*Handler)) *Handler {
	t.Helper()
	return newHandler(t, mode, config.FailClosed, append([]func(*Handler){func(h *Handler) {
		h.OutboundInspection = true
		h.OutboundMaxBodyBytes = 1 << 20
		h.OutboundContentTypes = config.DefaultOutboundContentTypes()
	}}, mutate...)...)
}

const sqlLeak = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1"

type respOutcome struct {
	rec *httptest.ResponseRecorder
	d   *policy.Decision
}

func serveResponse(t *testing.T, h *Handler, status int, contentType, body string, extra ...func(http.Header)) respOutcome {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://shop.example.com/page", http.NoBody)
	r.RemoteAddr = "192.0.2.10:4000"
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0")
	r.Header.Set("Accept", "text/html")
	d := policy.NewDecision("01TESTEVENT0000000000000000", "shop", policy.Mode(h.Mode), netip.MustParseAddr("192.0.2.10"))
	r = r.WithContext(policy.WithDecision(r.Context(), d))
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Set-Cookie", "session=secret")
		for _, e := range extra {
			e(w.Header())
		}
		w.WriteHeader(status)
		_, err := w.Write([]byte(body))
		return err
	})
	require.NoError(t, h.ServeHTTP(rec, r, next))
	return respOutcome{rec, d}
}

func TestOutboundBlockModeReplacesALeakingResponse(t *testing.T) {
	h := outboundHandler(t, config.ModeBlock)
	out := serveResponse(t, h, http.StatusInternalServerError, "text/html", "<html>"+sqlLeak+"</html>")
	assert.Contains(t, ruleIDs(out.d), "951230")
	_, outScore := out.d.AnomalyScore()
	assert.GreaterOrEqual(t, outScore, 4)
	assert.Equal(t, policy.ActionBlock, out.d.Action())
	assert.NotContains(t, out.rec.Body.String(), "MySQL", "the leaking body must not reach the client")
	assert.Empty(t, out.rec.Header().Get("Set-Cookie"), "origin headers must not leak into the block page")
	assert.Equal(t, out.d.EventID, out.rec.Header().Get("X-Sherlock-Event-Id"))
}

func TestOutboundDetectModeRecordsAndPassesThrough(t *testing.T) {
	h := outboundHandler(t, config.ModeDetect)
	out := serveResponse(t, h, http.StatusInternalServerError, "text/html", "<html>"+sqlLeak+"</html>")
	assert.Contains(t, ruleIDs(out.d), "951230", "findings appear like inbound ones")
	assert.Equal(t, http.StatusInternalServerError, out.rec.Code)
	assert.Contains(t, out.rec.Body.String(), "MySQL")
	assert.Equal(t, "session=secret", out.rec.Header().Get("Set-Cookie"))
	assert.Equal(t, policy.ActionLog, out.d.Action(), "detect mode surfaces would-block as log")
}

func TestOutboundCleanResponseIsUntouched(t *testing.T) {
	h := outboundHandler(t, config.ModeBlock)
	out := serveResponse(t, h, http.StatusOK, "text/html; charset=utf-8", "<html>hello</html>")
	assert.Equal(t, http.StatusOK, out.rec.Code)
	assert.Equal(t, "<html>hello</html>", out.rec.Body.String())
	assert.Empty(t, ruleIDs(out.d))
}

func TestOutboundContentTypeFilter(t *testing.T) {
	h := outboundHandler(t, config.ModeBlock)
	out := serveResponse(t, h, http.StatusOK, "image/png", sqlLeak)
	assert.Equal(t, http.StatusOK, out.rec.Code, "types outside the filter are not inspected")
	assert.Contains(t, out.rec.Body.String(), "MySQL")
	assert.Empty(t, ruleIDs(out.d))

	narrow := outboundHandler(t, config.ModeBlock, func(h *Handler) { h.OutboundContentTypes = []string{"application/json"} })
	assert.Equal(t, http.StatusOK, serveResponse(t, narrow, http.StatusOK, "text/html", sqlLeak).rec.Code)
	assert.Equal(t, http.StatusForbidden, serveResponse(t, narrow, http.StatusOK, "application/json", `{"e":"`+sqlLeak+`"}`).rec.Code)
}

func TestOutboundBodyLimitInspectsThePrefixOnly(t *testing.T) {
	h := outboundHandler(t, config.ModeBlock, func(h *Handler) { h.OutboundMaxBodyBytes = 256 })
	pad := strings.Repeat("a", 300)
	// Leak beyond the limit: streams through uninspected, complete.
	out := serveResponse(t, h, http.StatusOK, "text/plain", pad+sqlLeak)
	assert.Equal(t, http.StatusOK, out.rec.Code)
	assert.Equal(t, pad+sqlLeak, out.rec.Body.String())
	// Leak inside the limit is caught.
	out = serveResponse(t, h, http.StatusOK, "text/plain", sqlLeak+pad)
	assert.Equal(t, http.StatusForbidden, out.rec.Code)
	assert.NotContains(t, out.rec.Body.String(), "MySQL")
}

func TestOutboundOffByDefault(t *testing.T) {
	h := newHandler(t, config.ModeBlock, config.FailClosed)
	out := serveResponse(t, h, http.StatusOK, "text/html", sqlLeak)
	assert.Equal(t, http.StatusOK, out.rec.Code)
	assert.Empty(t, ruleIDs(out.d))
}

func TestOutboundDirectivesNeedLimitAndTypes(t *testing.T) {
	s := Settings{Mode: config.ModeBlock, ParanoiaLevel: 1, BlockingParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4, MaxBodyBytes: 1 << 20, OutboundInspection: true}
	_, err := s.Directives()
	assert.Error(t, err)
}
