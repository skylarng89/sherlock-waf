// Package waf implements sherlock_waf: a Caddy handler that runs request
// phases 1 and 2 of a Coraza transaction (OWASP CRS) per endpoint policy,
// records findings into the request's Decision and enforces block mode.
// It is modelled on coraza-caddy (Apache-2.0), see NOTICE.
package waf

import (
	"bytes"
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
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/policy"
	"github.com/skylarng89/sherlock-waf/internal/vpatch"
)

// CRSVersion is the embedded OWASP CRS release; a test checks it against the
// rule files so a dependency bump cannot leave it stale.
const CRSVersion = "4.25.0"

const (
	moduleName = "sherlock_waf"
	// wouldBlockRuleID is CRS's inbound anomaly evaluation rule; matching it
	// in DetectionOnly means the request would have been blocked.
	wouldBlockRuleID = 949110
	// outboundWouldBlockRuleID is the CRS outbound anomaly evaluation rule.
	outboundWouldBlockRuleID = 959100
	maxMatchedBytes          = 256
	// bodySampleBytes is how much of a body is kept for the redacted excerpt.
	bodySampleBytes = 4096
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
	// BlockPageID selects a custom block page (empty: the built-in page).
	BlockPageID string `json:"block_page_id,omitempty"`
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
	if d == nil || d.SkipWAF || h.skips(r) {
		// No decision means sherlock_core failed open; nothing to record into.
		return next.ServeHTTP(w, r)
	}

	started := time.Now()
	res := h.inspect(r, d)
	d.AddWAFTime(time.Since(started))
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
			blockpage.WriteTemplate(w, r, http.StatusServiceUnavailable, d.EventID, h.BlockPageID)
			return nil
		}
	case res.interruption != nil && h.Mode == config.ModeBlock:
		status := res.interruption.Status
		if status < 400 || status > 599 {
			status = http.StatusForbidden
		}
		d.Terminate(moduleName, policy.ActionBlock)
		blockpage.WriteTemplate(w, r, status, d.EventID, h.BlockPageID)
		return nil
	}
	if h.OutboundInspection && res.tx != nil && !isUpgrade(r) {
		return h.serveInspected(w, r, next, d, &res)
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
	// recorded is how many matched rules were already copied into the
	// decision, so the response phase records only what is new.
	recorded int
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
	tx.ProcessURI(requestTarget(r), r.Method, r.Proto)
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
		res.recorded = h.record(tx, d, 0)
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
			res.recorded = h.record(tx, d, 0)
			return res
		}
		// Hand the upstream the buffered prefix followed by whatever the
		// limit left unread (ProcessPartial).
		rbr, err := tx.RequestBodyReader()
		if err != nil {
			res.err = fmt.Errorf("rewinding request body: %w", err)
			return res
		}
		head := io.Reader(rbr)
		if events.Default().BodyExcerptEnabled() {
			sample := make([]byte, bodySampleBytes)
			n, _ := io.ReadFull(rbr, sample)
			sample = sample[:n]
			d.SetBodySample(r.Header.Get("Content-Type"), sample)
			head = io.MultiReader(bytes.NewReader(sample), rbr)
		}
		r.Body = readCloser{Reader: io.MultiReader(head, r.Body), Closer: r.Body}
	}

	it, err := tx.ProcessRequestBody()
	if err != nil {
		res.err = fmt.Errorf("processing request body: %w", err)
		return res
	}
	res.interruption = it
	res.recorded = h.record(tx, d, 0)
	return res
}

// requestTarget is the request-target exactly as the client sent it, so rules
// see absolute-form targets and original escaping that net/http normalises
// into r.URL. It falls back to the parsed URL for synthetic requests.
func requestTarget(r *http.Request) string {
	if r.RequestURI != "" {
		return r.RequestURI
	}
	return r.URL.RequestURI()
}

type readCloser struct {
	io.Reader
	io.Closer
}

// record copies matched rules (from index `from`) into the decision and returns
// the number of matched rules seen. In detect mode a match of an anomaly
// evaluation rule, or of a virtual patch, is surfaced as action=log ("would
// have blocked"). Rules above the blocking paranoia level are recorded like any
// other finding: they score but do not block, which is what the paranoia-level
// helper reads back (M8-T5).
func (h *Handler) record(tx types.Transaction, d *policy.Decision, from int) int {
	if st, ok := tx.(plugintypes.TransactionState); ok {
		in := txInt(st, "detection_inbound_anomaly_score")
		out := txInt(st, "detection_outbound_anomaly_score")
		d.SetAnomalyScore(in, out)
	}
	matched := tx.MatchedRules()
	for i := from; i < len(matched); i++ {
		mr := matched[i]
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
		wouldBlock := meta.ID() == wouldBlockRuleID || meta.ID() == outboundWouldBlockRuleID || vpatch.IsRuleID(meta.ID())
		if wouldBlock && h.Mode == config.ModeDetect {
			d.SetAction(policy.ActionLog)
		}
	}
	return len(matched)
}

// isFinding separates detections from CRS housekeeping rules, which Coraza
// also reports as matched (e.g. 901340 "Enabling body inspection", nolog).
// Detections carry a severity; the anomaly evaluation rule is tagged instead.
func isFinding(m types.RuleMetadata) bool {
	return m.Severity() != types.RuleSeverityUnset || slices.Contains(m.Tags(), "anomaly-evaluation")
}

// txInt reads an integer CRS transaction variable, 0 when unset.
func txInt(st plugintypes.TransactionState, name string) int {
	vals := st.Variables().TX().Get(name)
	if len(vals) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(vals[0])
	return n
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
	if id < 911000 || (id >= 949000 && id < 950000) || id >= 959000 {
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
