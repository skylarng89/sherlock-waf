package waf

import (
	"bytes"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

// Outbound inspection (FR-WAF-8, M8-T4) runs the CRS response rules on the
// upstream response. The body is held back until it either ends or reaches
// OutboundMaxBodyBytes; the held part is then inspected and only afterwards
// sent. Whatever follows the limit streams through uninspected, so memory per
// response is bounded by the limit. In detect mode findings are recorded and
// nothing is changed; in block mode a flagged response is replaced by the
// block page before any byte reaches the client.

func isUpgrade(r *http.Request) bool { return r.Header.Get("Upgrade") != "" }

// inspectsResponse reports whether a response is eligible: a final response
// with a body, an identity encoding Coraza can read, and a content type that
// matches the configured filter (prefix match on the media type).
func (h *Handler) inspectsResponse(method string, status int, hdr http.Header) bool {
	if method == http.MethodHead || status < 200 || status == http.StatusNoContent || status == http.StatusNotModified {
		return false
	}
	if ce := hdr.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return false
	}
	mt, _, err := mime.ParseMediaType(hdr.Get("Content-Type"))
	if err != nil {
		return false
	}
	for _, ct := range h.OutboundContentTypes {
		if strings.HasPrefix(mt, strings.ToLower(ct)) {
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

type inspectWriter struct {
	http.ResponseWriter
	h      *Handler
	r      *http.Request
	d      *policy.Decision
	res    *result
	state  respState
	status int
	buf    bytes.Buffer
}

// serveInspected wraps the response writer for the rest of the chain.
func (h *Handler) serveInspected(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, d *policy.Decision, res *result) error {
	// Compressed bodies cannot be read by the engine; ask the origin for plain text.
	r.Header.Del("Accept-Encoding")
	iw := &inspectWriter{ResponseWriter: w, h: h, r: r, d: d, res: res}
	err := next.ServeHTTP(iw, r)
	iw.finish()
	return err
}

func (iw *inspectWriter) WriteHeader(code int) {
	if iw.state != respInit {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		iw.ResponseWriter.WriteHeader(code)
		return
	}
	iw.status = code
	if iw.h.inspectsResponse(iw.r.Method, code, iw.Header()) {
		iw.state = respBuffering
		return
	}
	iw.state = respPassing
	iw.ResponseWriter.WriteHeader(code)
}

func (iw *inspectWriter) Write(p []byte) (int, error) {
	if iw.state == respInit {
		iw.WriteHeader(http.StatusOK)
	}
	switch iw.state {
	case respDenied:
		return len(p), nil
	case respBuffering:
		room := int(min(iw.h.OutboundMaxBodyBytes, 1<<31-1)) - iw.buf.Len()
		if len(p) <= room {
			return iw.buf.Write(p)
		}
		iw.buf.Write(p[:room])
		iw.flushInspected()
		if iw.state == respPassing {
			if _, err := iw.ResponseWriter.Write(p[room:]); err != nil {
				return room, err
			}
		}
		return len(p), nil
	case respInit, respPassing:
	}
	return iw.ResponseWriter.Write(p)
}

// finish inspects whatever is still held when the handler returns.
func (iw *inspectWriter) finish() {
	if iw.state == respBuffering {
		iw.flushInspected()
	}
}

// FlushError keeps a held response held; once passing it flushes for real.
func (iw *inspectWriter) FlushError() error {
	if iw.state == respPassing {
		return http.NewResponseController(iw.ResponseWriter).Flush()
	}
	return nil
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (iw *inspectWriter) Unwrap() http.ResponseWriter { return iw.ResponseWriter }

// flushInspected runs the response phases over the held body, then either
// sends it or replaces it with the block page.
func (iw *inspectWriter) flushInspected() {
	h, d := iw.h, iw.d
	started := time.Now()
	interruption, err := iw.evaluate()
	d.AddWAFTime(time.Since(started))

	switch {
	case err != nil:
		policy.InternalErrors.Add(1)
		d.AddFinding(policy.Finding{Module: "core", Severity: policy.SeverityError, Message: "waf internal error: " + err.Error()})
		slog.ErrorContext(iw.r.Context(), "waf response inspection error", "site_id", h.SiteID, "event_id", d.EventID, "fail_mode", h.FailMode, "error", err)
		if h.FailMode == config.FailClosed {
			iw.deny(http.StatusServiceUnavailable)
			return
		}
	case interruption != nil && h.Mode == config.ModeBlock:
		status := interruption.Status
		if status < 400 || status > 599 {
			status = http.StatusBadGateway
		}
		iw.deny(status)
		return
	}
	iw.state = respPassing
	iw.ResponseWriter.WriteHeader(iw.status)
	if _, werr := iw.ResponseWriter.Write(iw.buf.Bytes()); werr != nil {
		slog.DebugContext(iw.r.Context(), "writing inspected response", "site_id", h.SiteID, "error", werr)
	}
	iw.buf.Reset()
}

func (iw *inspectWriter) deny(status int) {
	iw.state = respDenied
	iw.buf.Reset()
	hdr := iw.Header()
	for k := range hdr { // nothing from the origin may leak into the replacement
		delete(hdr, k)
	}
	iw.d.Terminate(moduleName, policy.ActionBlock)
	blockpage.WriteTemplate(iw.ResponseWriter, iw.r, status, iw.d.EventID, iw.h.BlockPageID)
}

// evaluate feeds the response to the transaction. Panics are confined here
// for the same reason as in inspect.
func (iw *inspectWriter) evaluate() (it *types.Interruption, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	tx := iw.res.tx
	for k, vs := range iw.Header() {
		for _, v := range vs {
			tx.AddResponseHeader(k, v)
		}
	}
	it = tx.ProcessResponseHeaders(iw.status, iw.r.Proto)
	if it == nil && tx.IsResponseBodyAccessible() {
		if it, _, err = tx.WriteResponseBody(iw.buf.Bytes()); err != nil {
			return nil, fmt.Errorf("buffering response body: %w", err)
		}
		if it == nil {
			if it, err = tx.ProcessResponseBody(); err != nil {
				return nil, fmt.Errorf("processing response body: %w", err)
			}
		}
	}
	iw.res.recorded = iw.h.record(tx, iw.d, iw.res.recorded)
	return it, nil
}
