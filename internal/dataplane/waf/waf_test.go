package waf

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

const sqli = "1' OR '1'='1"

func newHandler(t *testing.T, mode config.Mode, fail config.FailMode, mutate ...func(*Handler)) *Handler {
	t.Helper()
	h := &Handler{
		SiteID:                   "shop",
		FailMode:                 fail,
		SkipInspectionExtensions: config.DefaultSkipInspectionExtensions(),
		Settings: Settings{
			Mode: mode, ParanoiaLevel: 1, BlockingParanoiaLevel: 1,
			InboundThreshold: 5, OutboundThreshold: 4, MaxBodyBytes: 1 << 20,
		},
	}
	for _, m := range mutate {
		m(h)
	}
	require.NoError(t, h.Validate())
	require.NoError(t, h.Provision(caddy.Context{}))
	return h
}

type outcome struct {
	rec      *httptest.ResponseRecorder
	d        *policy.Decision
	upstream bool
	body     string
}

// serve runs one request through the handler with a decision in context and
// a recording upstream that echoes whether it was reached and what body it saw.
func serve(t *testing.T, h *Handler, method, target, contentType, body string) outcome {
	t.Helper()
	return serveWith(t, h, method, target, contentType, body, nil)
}

func serveWith(t *testing.T, h *Handler, method, target, contentType, body string, hdr map[string]string) outcome {
	t.Helper()
	var rdr io.Reader = http.NoBody
	if body != "" {
		rdr = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(t.Context(), method, "http://shop.example.com"+target, rdr)
	r.RemoteAddr = "192.0.2.10:4000"
	r.Header.Set("Accept", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0")
	r.Header.Set("Accept-Language", "en-US")
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if body != "" {
		// A real server exposes the length as a header; httptest does not.
		r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	d := policy.NewDecision("01TESTEVENT0000000000000000", "shop", policy.Mode(h.Mode), netip.MustParseAddr("192.0.2.10"))
	r = r.WithContext(policy.WithDecision(r.Context(), d))

	out := outcome{rec: httptest.NewRecorder(), d: d}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		out.upstream = true
		if r.Body != nil {
			b, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			out.body = string(b)
		}
		w.WriteHeader(http.StatusOK)
		return nil
	})
	require.NoError(t, h.ServeHTTP(out.rec, r, next))
	return out
}

func ruleIDs(d *policy.Decision) []string {
	var ids []string
	for _, f := range d.Findings() {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func TestBlockModeBlocksSQLi(t *testing.T) {
	h := newHandler(t, config.ModeBlock, config.FailClosed)
	out := serve(t, h, http.MethodGet, "/get?id="+url.QueryEscape(sqli), "", "")

	assert.False(t, out.upstream, "blocked request must not reach the upstream")
	assert.Equal(t, http.StatusForbidden, out.rec.Code)
	assert.Equal(t, "application/problem+json", out.rec.Header().Get("Content-Type"))
	assert.Equal(t, out.d.EventID, out.rec.Header().Get("X-Sherlock-Event-Id"))

	var p map[string]any
	require.NoError(t, json.Unmarshal(out.rec.Body.Bytes(), &p))
	assert.Equal(t, out.d.EventID, p["event_id"])

	assert.Equal(t, policy.ActionBlock, out.d.Action())
	assert.Equal(t, "sherlock_waf", out.d.Terminated())
	assert.Contains(t, ruleIDs(out.d), "949110")
	var sawSQLi bool
	for _, f := range out.d.Findings() {
		if strings.HasPrefix(f.RuleID, "942") {
			sawSQLi = true
			assert.Equal(t, "waf", f.Module)
			assert.NotEmpty(t, f.Tags)
			assert.Contains(t, f.Target, "ARGS")
		}
	}
	assert.True(t, sawSQLi, "expected a 942xxx SQLi rule, got %v", ruleIDs(out.d))
}

func TestDetectModeProxiesAndRecordsWouldBlock(t *testing.T) {
	h := newHandler(t, config.ModeDetect, config.FailOpen)
	out := serve(t, h, http.MethodGet, "/get?id="+url.QueryEscape(sqli), "", "")

	assert.True(t, out.upstream)
	assert.Equal(t, http.StatusOK, out.rec.Code)
	assert.Empty(t, out.rec.Header().Get("X-Sherlock-Event-Id"))
	assert.Equal(t, policy.ActionLog, out.d.Action())
	assert.Empty(t, out.d.Terminated())
	assert.Contains(t, ruleIDs(out.d), "949110", "detect mode must surface would-have-blocked")
}

func TestBenignRequestsPass(t *testing.T) {
	for _, mode := range []config.Mode{config.ModeBlock, config.ModeDetect} {
		h := newHandler(t, mode, config.FailOpen)
		for _, target := range []string{"/", "/get?id=42&name=alice", "/products?page=2&sort=price", "/search?q=red+shoes"} {
			out := serve(t, h, http.MethodGet, target, "", "")
			assert.True(t, out.upstream, "%s %s", mode, target)
			assert.Equal(t, policy.ActionAllow, out.d.Action(), "%s %s: %v", mode, target, ruleIDs(out.d))
			assert.Empty(t, out.d.Findings(), "%s %s: housekeeping rules must not surface as findings", mode, target)
		}
	}
}

func TestPOSTBodiesAreInspectedAndForwardedIntact(t *testing.T) {
	h := newHandler(t, config.ModeBlock, config.FailClosed)

	benign := "name=alice&email=alice%40example.com"
	out := serve(t, h, http.MethodPost, "/signup", "application/x-www-form-urlencoded", benign)
	require.True(t, out.upstream)
	assert.Equal(t, benign, out.body, "upstream must receive the full original body")

	attack := "user=" + url.QueryEscape(sqli) + "&pass=x"
	out = serve(t, h, http.MethodPost, "/login", "application/x-www-form-urlencoded", attack)
	assert.False(t, out.upstream)
	assert.Equal(t, http.StatusForbidden, out.rec.Code)

	out = serve(t, h, http.MethodPost, "/api", "application/json", `{"q":"1' OR '1'='1"}`)
	assert.False(t, out.upstream, "JSON bodies are parsed and inspected")

	json := `{"name":"alice","tags":["a","b"]}`
	out = serve(t, h, http.MethodPost, "/api", "application/json", json)
	require.True(t, out.upstream)
	assert.Equal(t, json, out.body)
}

func TestBodyLimit(t *testing.T) {
	small := func(h *Handler) { h.MaxBodyBytes = 1024 }
	big := "a=" + strings.Repeat("x", 4096)

	t.Run("block rejects with 413", func(t *testing.T) {
		h := newHandler(t, config.ModeBlock, config.FailClosed, small)
		out := serve(t, h, http.MethodPost, "/upload", "application/x-www-form-urlencoded", big)
		assert.False(t, out.upstream)
		assert.Equal(t, http.StatusRequestEntityTooLarge, out.rec.Code)
	})
	t.Run("detect inspects the prefix and still proxies the whole body", func(t *testing.T) {
		h := newHandler(t, config.ModeDetect, config.FailOpen, small)
		out := serve(t, h, http.MethodPost, "/upload", "application/x-www-form-urlencoded", big)
		assert.True(t, out.upstream)
		assert.Equal(t, big, out.body)
	})
}

func TestSkipInspectionExtensions(t *testing.T) {
	h := newHandler(t, config.ModeBlock, config.FailClosed)

	assert.True(t, h.skips(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/static/app.JS", nil)))
	assert.True(t, h.skips(httptest.NewRequestWithContext(t.Context(), http.MethodHead, "/logo.png", nil)))
	assert.False(t, h.skips(httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/logo.png", nil)), "only GET/HEAD")
	assert.False(t, h.skips(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/a.css?id=1", nil)), "query strings are always inspected")
	assert.False(t, h.skips(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/dir.css/index", nil)), "dot must be in the last segment")
	assert.False(t, h.skips(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/noext", nil)))

	// Extension trick with an attack in the query is still blocked.
	out := serve(t, h, http.MethodGet, "/vuln.php/x.css?id="+url.QueryEscape(sqli), "", "")
	assert.False(t, out.upstream)
	assert.Equal(t, http.StatusForbidden, out.rec.Code)

	out = serve(t, h, http.MethodGet, "/static/site.css", "", "")
	assert.True(t, out.upstream)
	assert.Empty(t, out.d.Findings())
}

func TestParanoiaLevelChangesDetection(t *testing.T) {
	// 920272 (outside printable range in a header) style rules exist only at
	// higher PLs; use a request that PL1 ignores but PL2+ scores.
	target := "/get?q=" + url.QueryEscape("select name from users")
	pl1 := serve(t, newHandler(t, config.ModeDetect, config.FailOpen), http.MethodGet, target, "", "")
	pl4 := serve(t, newHandler(t, config.ModeDetect, config.FailOpen, func(h *Handler) {
		h.ParanoiaLevel, h.BlockingParanoiaLevel = 4, 4
	}), http.MethodGet, target, "", "")
	assert.Greater(t, len(pl4.d.Findings()), len(pl1.d.Findings()), "PL4 must evaluate more rules than PL1")
}

func TestThresholdControlsBlocking(t *testing.T) {
	target := "/get?id=" + url.QueryEscape(sqli)
	high := newHandler(t, config.ModeBlock, config.FailClosed, func(h *Handler) { h.InboundThreshold = 1000 })
	out := serve(t, high, http.MethodGet, target, "", "")
	assert.True(t, out.upstream, "a very high inbound threshold must not block")
	assert.NotEmpty(t, out.d.Findings())
}

func TestPanicFollowsFailMode(t *testing.T) {
	testHook = func(*http.Request) { panic("forced") }
	t.Cleanup(func() { testHook = nil })
	before := policy.InternalErrors.Load()

	closed := newHandler(t, config.ModeBlock, config.FailClosed)
	out := serve(t, closed, http.MethodGet, "/get?id=1", "", "")
	assert.False(t, out.upstream)
	assert.Equal(t, http.StatusServiceUnavailable, out.rec.Code)
	assert.Equal(t, "sherlock_waf", out.d.Terminated())
	assert.NotContains(t, out.rec.Body.String(), "forced")

	open := newHandler(t, config.ModeBlock, config.FailOpen)
	out = serve(t, open, http.MethodGet, "/get?id=1", "", "")
	assert.True(t, out.upstream)
	assert.Equal(t, http.StatusOK, out.rec.Code)
	var core bool
	for _, f := range out.d.Findings() {
		core = core || (f.Module == "core" && f.Severity == policy.SeverityError)
	}
	assert.True(t, core, "panic must be recorded as a core error finding")
	assert.Equal(t, before+2, policy.InternalErrors.Load())
}

func TestUpstreamPanicIsNotSwallowedByWAF(t *testing.T) {
	h := newHandler(t, config.ModeBlock, config.FailOpen)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://shop.example.com/", nil)
	r.RemoteAddr = "192.0.2.10:1"
	d := policy.NewDecision("id", "shop", policy.ModeBlock, netip.MustParseAddr("192.0.2.10"))
	r = r.WithContext(policy.WithDecision(r.Context(), d))
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { panic("upstream chain") })
	assert.PanicsWithValue(t, "upstream chain", func() { _ = h.ServeHTTP(httptest.NewRecorder(), r, next) })
}

func TestNoDecisionSkipsInspection(t *testing.T) {
	h := newHandler(t, config.ModeBlock, config.FailClosed)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://shop.example.com/get?id="+url.QueryEscape(sqli), nil)
	called := false
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { called = true; return nil })
	require.NoError(t, h.ServeHTTP(httptest.NewRecorder(), r, next))
	assert.True(t, called)
}

func TestInstancesAreShared(t *testing.T) {
	a := newHandler(t, config.ModeBlock, config.FailClosed)
	b := newHandler(t, config.ModeBlock, config.FailOpen)
	assert.Same(t, a.cached, b.cached, "identical directives must share one compiled WAF")
	c := newHandler(t, config.ModeDetect, config.FailOpen)
	assert.NotSame(t, a.cached, c.cached)
}

func TestValidate(t *testing.T) {
	require.Error(t, (&Handler{}).Validate())
	require.Error(t, (&Handler{SiteID: "a", FailMode: "x"}).Validate())
	require.Error(t, (&Handler{SiteID: "a", FailMode: config.FailOpen}).Validate(), "settings are required")
}

func TestModuleInfo(t *testing.T) {
	info := (&Handler{}).CaddyModule()
	assert.Equal(t, caddy.ModuleID("http.handlers.sherlock_waf"), info.ID)
	assert.IsType(t, &Handler{}, info.New())
}

func TestTruncateAndMappings(t *testing.T) {
	assert.Equal(t, "abc", truncate("abcdef", 3))
	assert.Equal(t, "ab", truncate("ab", 3))
	assert.Equal(t, 5, scoreOf(942100, 2))
	assert.Equal(t, 0, scoreOf(949110, 2))
	assert.Equal(t, 0, scoreOf(200002, 2))
}

func TestRESTMethodsAllowedButTraceBlocked(t *testing.T) {
	h := newHandler(t, config.ModeBlock, config.FailClosed)
	for _, m := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		out := serve(t, h, m, "/api/v1/things/1", "", "")
		assert.True(t, out.upstream, m)
	}
	out := serve(t, h, http.MethodTrace, "/api/v1/things/1", "", "")
	assert.False(t, out.upstream, "TRACE must stay blocked")
	assert.Contains(t, ruleIDs(out.d), "911100")
}

func TestCRSVersionMatchesEmbeddedRules(t *testing.T) {
	b, err := fs.ReadFile(coreruleset.FS, "@owasp_crs/REQUEST-901-INITIALIZATION.conf")
	require.NoError(t, err)
	assert.Contains(t, string(b), `SecComponentSignature "OWASP_CRS/`+CRSVersion+`"`)
}

func TestRequestTargetPrefersRawRequestURI(t *testing.T) {
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://shop.example.com/a%2Fb?x=1", nil)
	require.NoError(t, err)
	assert.Equal(t, "/a%2Fb?x=1", requestTarget(r), "client-side requests have no RequestURI and fall back to the parsed URL")
	r.RequestURI = "http://shop.example.com/a%2Fb?x=1"
	assert.Equal(t, "http://shop.example.com/a%2Fb?x=1", requestTarget(r), "the raw absolute-form target is preserved")
}
