package dlp

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/metrics"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

const moduleName = "sherlock_dlp"

func init() { caddy.RegisterModule(&Handler{}) }

// Handler is the sherlock_dlp Caddy handler (M11-T2, FR-FIN-2). Its JSON is
// produced by the compiler from the effective policy of a site or endpoint.
//
// The response body is held back until it ends or reaches MaxBodyBytes, scanned,
// and then sent masked, blocked or untouched. Memory per response is bounded by
// MaxBodyBytes. Matched values are never copied into events, logs, metrics or
// error messages: only detector names and counts leave this package.
type Handler struct {
	SiteID         string    `json:"site_id"`
	Mode           string    `json:"mode,omitempty"`
	Action         string    `json:"action,omitempty"`
	Detect         []string  `json:"detect,omitempty"`
	ContentTypes   []string  `json:"content_types,omitempty"`
	MaxBodyBytes   int64     `json:"max_body_bytes,omitempty"`
	CustomPatterns []Pattern `json:"custom_patterns,omitempty"`

	scanner *Scanner
}

// CaddyModule implements caddy.Module.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers." + moduleName, New: func() caddy.Module { return new(Handler) }}
}

// Provision implements caddy.Provisioner.
func (h *Handler) Provision(caddy.Context) error {
	if h.Action == "" {
		h.Action = config.DLPActionMask
	}
	if h.MaxBodyBytes <= 0 {
		h.MaxBodyBytes = config.DefaultDLPMaxBodyBytes
	}
	if len(h.ContentTypes) == 0 {
		h.ContentTypes = config.DefaultOutboundContentTypes()
	}
	for i, ct := range h.ContentTypes {
		h.ContentTypes[i] = strings.ToLower(ct)
	}
	s, err := NewScanner(h.Detect, h.CustomPatterns)
	if err != nil {
		return fmt.Errorf("sherlock_dlp site %q: %w", h.SiteID, err)
	}
	h.scanner = s
	return nil
}

// Validate implements caddy.Validator.
func (h *Handler) Validate() error {
	if h.SiteID == "" {
		return errors.New("sherlock_dlp: site_id is required")
	}
	if !slices.Contains([]string{"", config.DLPActionMask, config.ActionBlock, config.ActionLog}, h.Action) {
		return fmt.Errorf("sherlock_dlp: invalid action %q", h.Action)
	}
	if len(h.Detect) == 0 {
		return ErrNoDetector
	}
	return nil
}

// enforcing reports whether the response may be changed. In detect mode a match
// is recorded and the response is never touched.
func (h *Handler) enforcing() bool { return h.Mode == string(config.ModeBlock) }

// effectiveAction is what actually happens to a response with matches.
func (h *Handler) effectiveAction() string {
	if !h.enforcing() {
		return config.ActionLog
	}
	return h.Action
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	d := policy.DecisionFrom(r.Context())
	if d == nil || r.Header.Get("Upgrade") != "" {
		return next.ServeHTTP(w, r)
	}
	// Only identity and gzip bodies can be scanned. Ask the origin for gzip when
	// the client accepts it and for no encoding otherwise, so a client that
	// prefers br or zstd never receives a body this module could not read.
	if acceptsGzip(r.Header.Values("Accept-Encoding")) {
		r.Header.Set("Accept-Encoding", "gzip")
	} else {
		r.Header.Del("Accept-Encoding")
	}
	dw := &dlpWriter{ResponseWriter: w, h: h, r: r, d: d}
	err := next.ServeHTTP(dw, r)
	dw.finish()
	return err
}

// acceptsGzip reports whether an Accept-Encoding value lists gzip with a
// non-zero quality.
func acceptsGzip(values []string) bool {
	for _, v := range values {
		for part := range strings.SplitSeq(v, ",") {
			name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
			if !strings.EqualFold(strings.TrimSpace(name), "gzip") {
				continue
			}
			q := strings.ReplaceAll(strings.ToLower(params), " ", "")
			if q == "q=0" || q == "q=0.0" || q == "q=0.00" || q == "q=0.000" {
				return false
			}
			return true
		}
	}
	return false
}

type eligibility int

const (
	notScanned eligibility = iota // by design: images, downloads, no body
	scanBody
	skipUnknownType
	skipEncoding
)

// classify decides whether a response is scanned. A missing or unparsable
// Content-Type and an unsupported Content-Encoding are counted so an operator can
// see responses that bypass the scanner.
func (h *Handler) classify(method string, status int, hdr http.Header) eligibility {
	if method == http.MethodHead || status < 200 || status == http.StatusNoContent || status == http.StatusNotModified {
		return notScanned
	}
	ct := hdr.Get("Content-Type")
	if ct == "" {
		return skipUnknownType
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return skipUnknownType
	}
	if mt == "text/event-stream" || !h.typeAllowed(mt) {
		return notScanned // a stream never ends: holding it would hang the client
	}
	switch ce := strings.ToLower(strings.TrimSpace(hdr.Get("Content-Encoding"))); ce {
	case "", "identity", "gzip":
		return scanBody
	}
	return skipEncoding
}

// typeAllowed matches mt against the allow-list by prefix, so "text/" allows all
// text types. The "+json" and "+xml" structured suffixes count as their base type.
func (h *Handler) typeAllowed(mt string) bool {
	for _, ct := range h.ContentTypes {
		if strings.HasPrefix(mt, ct) {
			return true
		}
		if ct == "application/json" && strings.HasSuffix(mt, "+json") || ct == "application/xml" && strings.HasSuffix(mt, "+xml") {
			return true
		}
	}
	return false
}

type respState int

const (
	respInit respState = iota
	respBuffering
	respPassing
	respDenied
)

type dlpWriter struct {
	http.ResponseWriter
	h      *Handler
	r      *http.Request
	d      *policy.Decision
	state  respState
	status int
	gzip   bool
	buf    bytes.Buffer
}

func (w *dlpWriter) WriteHeader(code int) {
	if w.state != respInit {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.status = code
	switch w.h.classify(w.r.Method, code, w.Header()) {
	case scanBody:
		w.state = respBuffering
		w.gzip = strings.EqualFold(strings.TrimSpace(w.Header().Get("Content-Encoding")), "gzip")
		return
	case skipUnknownType:
		metrics.ObserveDLPSkipped(w.h.SiteID, "content_type_unknown")
	case skipEncoding:
		metrics.ObserveDLPSkipped(w.h.SiteID, "encoding")
	case notScanned:
	}
	w.state = respPassing
	w.ResponseWriter.WriteHeader(code)
}

func (w *dlpWriter) Write(p []byte) (int, error) {
	if w.state == respInit {
		w.WriteHeader(http.StatusOK)
	}
	switch w.state {
	case respDenied:
		return len(p), nil
	case respBuffering:
		room := int(min(w.h.MaxBodyBytes, 1<<31-1)) - w.buf.Len()
		if len(p) <= room {
			return w.buf.Write(p)
		}
		w.buf.Write(p[:room])
		// Over the limit: what is held is still handled, the rest streams through
		// unscanned (and is counted, because that is a gap an operator should see).
		metrics.ObserveDLPSkipped(w.h.SiteID, "too_large")
		w.release(true)
		if w.state == respPassing {
			if _, err := w.ResponseWriter.Write(p[room:]); err != nil {
				return room, err
			}
		}
		return len(p), nil
	case respInit, respPassing:
	}
	return w.ResponseWriter.Write(p)
}

// finish handles whatever is still held when the handler returns.
func (w *dlpWriter) finish() {
	if w.state == respBuffering {
		w.release(false)
	}
}

// FlushError keeps a held response held; once passing it flushes for real.
func (w *dlpWriter) FlushError() error {
	if w.state == respPassing {
		return http.NewResponseController(w.ResponseWriter).Flush()
	}
	return nil
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *dlpWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// release scans the held body and sends, masks or blocks it. truncated means
// more body follows that will not be scanned: a gzip stream cannot be handled in
// part, so it is passed on as it is.
func (w *dlpWriter) release(truncated bool) {
	defer func() {
		if p := recover(); p != nil {
			policy.InternalErrors.Add(1)
			slog.ErrorContext(w.r.Context(), "dlp internal error", "site_id", w.h.SiteID, "event_id", w.d.EventID, "panic", fmt.Sprint(p))
			if w.h.enforcing() && w.state == respBuffering {
				w.deny() // nothing has been sent yet: fail closed rather than leak
				return
			}
			w.send(w.buf.Bytes(), false)
		}
	}()
	held := w.buf.Bytes()
	target := held
	if w.gzip {
		if truncated {
			w.send(held, false)
			return
		}
		plain, ok := gunzip(held, w.h.MaxBodyBytes)
		if !ok {
			metrics.ObserveDLPSkipped(w.h.SiteID, "too_large")
			w.send(held, false)
			return
		}
		target = plain
	}
	matches := w.h.scanner.Scan(target)
	if len(matches) == 0 {
		w.send(held, false)
		return
	}
	action := w.h.effectiveAction()
	w.record(matches, action)
	switch action {
	case config.ActionBlock:
		w.deny()
	case config.DLPActionMask:
		Mask(target, matches, w.bareNumber(target))
		if !w.gzip {
			w.send(target, false) // same length: Content-Length stays valid
			return
		}
		enc, err := gzipBytes(target)
		if err != nil { // cannot re-encode: never send the unmasked original
			policy.InternalErrors.Add(1)
			w.deny()
			return
		}
		w.send(enc, true)
	default:
		w.send(held, false)
	}
}

// bareNumber tells Mask whether a card number is an unquoted JSON number, which
// must remain digits to keep the document valid.
func (w *dlpWriter) bareNumber(body []byte) func(Match) bool {
	mt, _, err := mime.ParseMediaType(w.Header().Get("Content-Type"))
	if err != nil || mt != "application/json" && !strings.HasSuffix(mt, "+json") {
		return nil
	}
	return func(m Match) bool {
		for _, c := range body[m.Start:m.End] {
			if !isDigit(c) {
				return false
			}
		}
		before, after := byte(0), byte(0)
		for i := m.Start - 1; i >= 0; i-- {
			if c := body[i]; c != ' ' && c != '\t' && c != '\r' && c != '\n' {
				before = c
				break
			}
		}
		for i := m.End; i < len(body); i++ {
			if c := body[i]; c != ' ' && c != '\t' && c != '\r' && c != '\n' {
				after = c
				break
			}
		}
		return (before == ':' || before == '[' || before == ',') && (after == ',' || after == '}' || after == ']')
	}
}

// send writes the status and body. When the body was re-encoded its length
// changed and the validators that describe the original no longer apply.
func (w *dlpWriter) send(body []byte, changed bool) {
	w.state = respPassing
	h := w.Header()
	if changed {
		h.Set("Content-Length", strconv.Itoa(len(body)))
		for _, k := range []string{"Content-Md5", "Digest", "Content-Digest", "Repr-Digest"} {
			h.Del(k)
		}
	}
	w.ResponseWriter.WriteHeader(w.status)
	if _, err := w.ResponseWriter.Write(body); err != nil {
		slog.DebugContext(w.r.Context(), "writing scanned response", "site_id", w.h.SiteID, "error", err)
	}
	w.buf.Reset()
}

// deny replaces the response with the block page before any byte of the
// origin's body is sent.
func (w *dlpWriter) deny() {
	w.state = respDenied
	w.buf.Reset()
	hdr := w.Header()
	for k := range hdr { // nothing from the origin may leak into the replacement
		delete(hdr, k)
	}
	w.d.Terminate(moduleName, policy.ActionBlock)
	blockpage.WriteTemplate(w.ResponseWriter, w.r, http.StatusBadGateway, w.d.EventID, "")
}

// record adds one finding per detector with counts only, and counts the matches.
func (w *dlpWriter) record(matches []Match, action string) {
	counts := map[string]int{}
	var order []string
	for _, m := range matches {
		if counts[m.Kind] == 0 {
			order = append(order, m.Kind)
		}
		counts[m.Kind]++
	}
	outcome := map[string]string{
		config.DLPActionMask: "masked",
		config.ActionBlock:   "response blocked",
		config.ActionLog:     "logged, response unchanged",
	}[action]
	if !w.h.enforcing() {
		outcome = "detect mode, response unchanged"
	}
	byLabel := map[string]int{}
	for _, kind := range order {
		n := counts[kind]
		w.d.AddFinding(policy.Finding{
			Module: "dlp", RuleID: kind, Severity: policy.SeverityError, Target: "RESPONSE_BODY",
			Message: fmt.Sprintf("%d %s found in the response (%s)", n, describe(kind), outcome),
		})
		label := kind
		if strings.HasPrefix(kind, customPrefix) {
			label = "custom" // user-defined names are unbounded: never a label
		}
		byLabel[label] += n
	}
	for label, n := range byLabel {
		metrics.ObserveDLPMatches(w.h.SiteID, label, action, n)
	}
	if action != config.ActionBlock && w.d.Action() == policy.ActionAllow {
		w.d.SetAction(policy.ActionLog)
	}
}

func describe(kind string) string {
	switch kind {
	case kindPAN:
		return "card numbers"
	case kindIBAN:
		return "IBANs"
	}
	return "matches of custom pattern " + strings.TrimPrefix(kind, customPrefix)
}

// gunzip decodes b, refusing to expand beyond limit bytes (a decompression bomb
// must not cost more memory than an identity body of the same limit).
func gunzip(b []byte, limit int64) ([]byte, bool) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, false
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(io.LimitReader(zr, limit+1))
	if err != nil || int64(len(out)) > limit {
		return nil, false
	}
	return out, true
}

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
