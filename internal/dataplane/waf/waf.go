// Package waf implements sherlock_waf: a Caddy handler that runs request
// phases 1 and 2 of a Coraza transaction (OWASP CRS) per endpoint policy,
// records findings into the request's Decision and enforces block mode.
// It is modelled on coraza-caddy (Apache-2.0), see NOTICE.
package waf

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

const (
	moduleName = "sherlock_waf"
	// wouldBlockRuleID is CRS's inbound anomaly evaluation rule; matching it
	// in DetectionOnly means the request would have been blocked.
	wouldBlockRuleID = 949110
	maxMatchedBytes  = 256
)

// testHook is set only by builds with the sherlock_testhooks tag so the
// panic fail-mode path can be exercised end to end.
var testHook func(*http.Request)

func init() { caddy.RegisterModule(&Handler{}) }

// Handler is the sherlock_waf Caddy handler.
type Handler struct {
	SiteID                   string          `json:"site_id"`
	FailMode                 config.FailMode `json:"fail_mode"`
	SkipInspectionExtensions []string        `json:"skip_inspection_extensions,omitempty"`
	Settings

	instance coraza.WAF
	cached   *entry
	skipExt  map[string]struct{}
}

// CaddyModule implements caddy.Module.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers." + moduleName,
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision builds (or reuses) the Coraza instance for these settings.
func (h *Handler) Provision(caddy.Context) error {
	directives, err := h.Directives()
	if err != nil {
		return fmt.Errorf("sherlock_waf site %q: %w", h.SiteID, err)
	}
	h.cached, err = sharedInstance(directives, h.MaxBodyBytes)
	if err != nil {
		return fmt.Errorf("sherlock_waf site %q: %w", h.SiteID, err)
	}
	h.instance = h.cached.waf
	h.skipExt = make(map[string]struct{}, len(h.SkipInspectionExtensions))
	for _, e := range h.SkipInspectionExtensions {
		h.skipExt[strings.ToLower(e)] = struct{}{}
	}
	return nil
}

// Validate implements caddy.Validator.
func (h *Handler) Validate() error {
	if h.SiteID == "" {
		return errors.New("sherlock_waf: site_id is required")
	}
	if h.FailMode != config.FailOpen && h.FailMode != config.FailClosed {
		return fmt.Errorf("sherlock_waf: invalid fail_mode %q", h.FailMode)
	}
	if _, err := h.Directives(); err != nil {
		return fmt.Errorf("sherlock_waf: %w", err)
	}
	return nil
}

// instances caches compiled WAFs by directive hash: parsing CRS is expensive
// and most endpoints share settings. Entries live for the process lifetime;
// the set is bounded by the number of distinct settings ever configured.
var instances sync.Map // [32]byte -> *entry

type entry struct {
	once sync.Once
	waf  coraza.WAF
	err  error
}

func sharedInstance(directives string, maxBody int64) (*entry, error) {
	key := sha256.Sum256([]byte(directives))
	v, _ := instances.LoadOrStore(key, &entry{})
	e := v.(*entry) //nolint:errcheck,forcetypeassert // only *entry is ever stored
	e.once.Do(func() {
		cfg := coraza.NewWAFConfig().
			WithDirectives(directives).
			WithRootFS(coreruleset.FS).
			WithRequestBodyAccess().
			WithRequestBodyLimit(int(min(maxBody, 1<<30))).
			WithRequestBodyInMemoryLimit(int(min(maxBody, inMemoryBodyLimit)))
		e.waf, e.err = coraza.NewWAF(cfg)
		if e.err != nil {
			e.err = fmt.Errorf("building coraza instance: %w", e.err)
		}
	})
	return e, e.err
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	d := policy.DecisionFrom(r.Context())
	if d == nil || h.skips(r) {
		// No decision means sherlock_core failed open; nothing to record into.
		return next.ServeHTTP(w, r)
	}

	res := h.inspect(r, d)
	// The transaction owns the buffered request body, so it must stay open
	// until the upstream has consumed it.
	defer res.close()

	switch {
	case res.err != nil:
		policy.InternalErrors.Add(1)
		d.AddFinding(policy.Finding{Module: "core", Severity: policy.SeverityError, Message: "waf internal error: " + res.err.Error()})
		slog.ErrorContext(r.Context(), "waf internal error", "site_id", h.SiteID, "event_id", d.EventID,
			"fail_mode", h.FailMode, "error", res.err)
		if h.FailMode == config.FailClosed {
			d.Terminate(moduleName, policy.ActionBlock)
			blockpage.Write(w, r, http.StatusServiceUnavailable, d.EventID)
			return nil
		}
	case res.interruption != nil && h.Mode == config.ModeBlock:
		status := res.interruption.Status
		if status < 400 || status > 599 {
			status = http.StatusForbidden
		}
		d.Terminate(moduleName, policy.ActionBlock)
		blockpage.Write(w, r, status, d.EventID)
		return nil
	}
	return next.ServeHTTP(w, r)
}

// skips reports requests that bypass inspection: static assets fetched with
// GET or HEAD and no query string. A query string still reaches the upstream
// as arguments (e.g. /app.php/x.css?id=1), so those are always inspected.
func (h *Handler) skips(r *http.Request) bool {
	if (r.Method != http.MethodGet && r.Method != http.MethodHead) || r.URL.RawQuery != "" || len(h.skipExt) == 0 {
		return false
	}
	p := r.URL.Path
	dot := strings.LastIndexByte(p, '.')
	if dot < 0 || strings.LastIndexByte(p, '/') > dot {
		return false
	}
	_, ok := h.skipExt[strings.ToLower(p[dot:])]
	return ok
}

type result struct {
	tx           types.Transaction
	interruption *types.Interruption
	err          error
}

func (res *result) close() {
	if res.tx == nil {
		return
	}
	res.tx.ProcessLogging()
	if err := res.tx.Close(); err != nil {
		slog.Warn("closing waf transaction", "error", err)
	}
}

// inspect runs phases 1 and 2. Panics are confined here so the caller can
// apply fail mode without catching panics from the upstream chain.
func (h *Handler) inspect(r *http.Request, d *policy.Decision) (res result) {
	defer func() {
		if p := recover(); p != nil {
			res.err = fmt.Errorf("panic: %v", p)
		}
	}()
	if testHook != nil {
		testHook(r)
	}

	tx := h.instance.NewTransaction()
	res.tx = tx
	if tx.IsRuleEngineOff() {
		return res
	}

	ip := d.ClientIP.String()
	if !d.ClientIP.IsValid() {
		ip = ""
	}
	_, portStr, _ := net.SplitHostPort(r.RemoteAddr)
	port, _ := strconv.Atoi(portStr)
	tx.ProcessConnection(ip, port, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		tx.SetServerName(host)
	}
	if len(r.TransferEncoding) > 0 {
		tx.AddRequestHeader("Transfer-Encoding", strings.Join(r.TransferEncoding, ","))
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		res.interruption = it
		h.record(tx, d)
		return res
	}

	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		it, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			res.err = fmt.Errorf("reading request body: %w", err)
			return res
		}
		if it != nil {
			res.interruption = it
			h.record(tx, d)
			return res
		}
		// Hand the upstream the buffered prefix followed by whatever the
		// limit left unread (ProcessPartial).
		rbr, err := tx.RequestBodyReader()
		if err != nil {
			res.err = fmt.Errorf("rewinding request body: %w", err)
			return res
		}
		r.Body = readCloser{Reader: io.MultiReader(rbr, r.Body), Closer: r.Body}
	}

	it, err := tx.ProcessRequestBody()
	if err != nil {
		res.err = fmt.Errorf("processing request body: %w", err)
		return res
	}
	res.interruption = it
	h.record(tx, d)
	return res
}

type readCloser struct {
	io.Reader
	io.Closer
}

// record copies matched rules into the decision. In detect mode a match of
// the anomaly evaluation rule is surfaced as action=log ("would have blocked").
func (h *Handler) record(tx types.Transaction, d *policy.Decision) {
	for _, mr := range tx.MatchedRules() {
		msg := mr.Message()
		meta := mr.Rule()
		if msg == "" || !isFinding(meta) {
			continue
		}
		f := policy.Finding{
			Module:   "waf",
			RuleID:   strconv.Itoa(meta.ID()),
			Tags:     meta.Tags(),
			Severity: severityOf(meta.Severity()),
			Message:  msg,
			Score:    scoreOf(meta.ID(), meta.Severity()),
		}
		if mds := mr.MatchedDatas(); len(mds) > 0 {
			md := mds[0]
			f.Target = md.Variable().Name()
			if k := md.Key(); k != "" {
				f.Target += ":" + k
			}
			f.Matched = truncate(md.Value(), maxMatchedBytes)
		}
		d.AddFinding(f)
		if meta.ID() == wouldBlockRuleID && h.Mode == config.ModeDetect {
			d.SetAction(policy.ActionLog)
		}
	}
}

// isFinding separates detections from CRS housekeeping rules, which Coraza
// also reports as matched (e.g. 901340 "Enabling body inspection", nolog).
// Detections carry a severity; the anomaly evaluation rule is tagged instead.
func isFinding(m types.RuleMetadata) bool {
	return m.Severity() != types.RuleSeverityUnset || slices.Contains(m.Tags(), "anomaly-evaluation")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func severityOf(s types.RuleSeverity) policy.Severity {
	switch s {
	case types.RuleSeverityEmergency, types.RuleSeverityAlert, types.RuleSeverityCritical:
		return policy.SeverityCritical
	case types.RuleSeverityError:
		return policy.SeverityError
	case types.RuleSeverityWarning:
		return policy.SeverityWarning
	case types.RuleSeverityNotice:
		return policy.SeverityNotice
	case types.RuleSeverityInfo, types.RuleSeverityDebug, types.RuleSeverityUnset:
		return policy.SeverityInfo
	}
	return policy.SeverityInfo
}

// scoreOf mirrors CRS's default anomaly scores per severity for detection
// rules; evaluation rules (949xxx and above) contribute no score themselves.
func scoreOf(id int, s types.RuleSeverity) int {
	if id >= 949000 || id < 911000 {
		return 0
	}
	switch s {
	case types.RuleSeverityEmergency, types.RuleSeverityAlert, types.RuleSeverityCritical:
		return 5
	case types.RuleSeverityError:
		return 4
	case types.RuleSeverityWarning:
		return 3
	case types.RuleSeverityNotice:
		return 2
	case types.RuleSeverityInfo, types.RuleSeverityDebug, types.RuleSeverityUnset:
		return 0
	}
	return 0
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
