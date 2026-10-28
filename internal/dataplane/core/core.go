// Package core implements sherlock_core, the first handler of every site
// route. It resolves the client IP, creates the request's Decision, recovers
// panics according to the site's fail mode and logs the decision.
package core

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/policy"
)

const moduleName = "sherlock_core"

func init() { caddy.RegisterModule(&Handler{}) }

// Handler is the sherlock_core Caddy handler.
type Handler struct {
	SiteID          string          `json:"site_id"`
	Mode            config.Mode     `json:"mode"`
	FailMode        config.FailMode `json:"fail_mode"`
	TrustedProxies  []string        `json:"trusted_proxies,omitempty"`
	ClientIPHeaders []string        `json:"client_ip_headers,omitempty"`

	trusted policy.CIDRSet
	now     func() time.Time
}

// CaddyModule implements caddy.Module.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers." + moduleName,
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision implements caddy.Provisioner.
func (h *Handler) Provision(caddy.Context) error {
	set, err := policy.ParseCIDRSet(h.TrustedProxies)
	if err != nil {
		return fmt.Errorf("sherlock_core trusted_proxies: %w", err)
	}
	h.trusted = set
	if h.now == nil {
		h.now = time.Now
	}
	return nil
}

// Validate implements caddy.Validator.
func (h *Handler) Validate() error {
	if h.SiteID == "" {
		return errors.New("sherlock_core: site_id is required")
	}
	switch h.Mode {
	case config.ModeOff, config.ModeDetect, config.ModeBlock:
	default:
		return fmt.Errorf("sherlock_core: invalid mode %q", h.Mode)
	}
	switch h.FailMode {
	case config.FailOpen, config.FailClosed:
	default:
		return fmt.Errorf("sherlock_core: invalid fail_mode %q", h.FailMode)
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) (err error) {
	start := h.now()
	rec := &recorder{ResponseWriter: w}

	d, r, setupErr := h.begin(r, start)
	if setupErr != nil {
		// Setup failures happen before any downstream work, so fail mode can
		// still be honoured faithfully.
		return h.failSetup(rec, r, next, setupErr)
	}

	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler { //nolint:errorlint // sentinel panic value, not an error chain
				panic(p)
			}
			h.recordPanic(d, p)
			// The request body may be consumed, so a downstream panic cannot be
			// retried; answer safely if nothing has been sent yet.
			if !rec.started {
				blockpage.Write(rec, r, http.StatusServiceUnavailable, d.EventID)
				d.Terminate(moduleName, policy.ActionBlock)
			}
			err = nil
		}
		h.log(d, r, rec.status(), h.now().Sub(start))
	}()

	return next.ServeHTTP(rec, r)
}

// begin resolves the client IP and attaches the decision to the request.
func (h *Handler) begin(r *http.Request, now time.Time) (d *policy.Decision, out *http.Request, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	ip, err := resolveClientIP(r, h.trusted, h.ClientIPHeaders)
	if err != nil {
		return nil, r, fmt.Errorf("resolving client ip: %w", err)
	}
	id, err := policy.NewEventID(now)
	if err != nil {
		return nil, r, err
	}
	d = policy.NewDecision(id, h.SiteID, policy.Mode(h.Mode), ip)
	return d, r.WithContext(policy.WithDecision(r.Context(), d)), nil
}

func (h *Handler) failSetup(w *recorder, r *http.Request, next caddyhttp.Handler, cause error) error {
	policy.InternalErrors.Add(1)
	id, idErr := policy.NewEventID(h.now())
	if idErr != nil {
		id = "unavailable"
	}
	slog.ErrorContext(r.Context(), "core setup failed", "site_id", h.SiteID, "event_id", id,
		"fail_mode", h.FailMode, "error", cause)
	if h.FailMode == config.FailClosed {
		blockpage.Write(w, r, http.StatusServiceUnavailable, id)
		return nil
	}
	// Fail open without an IP: modules that need one must treat a missing
	// decision as "not inspectable" rather than guessing.
	return next.ServeHTTP(w, r)
}

func (h *Handler) recordPanic(d *policy.Decision, p any) {
	policy.InternalErrors.Add(1)
	d.AddFinding(policy.Finding{
		Module:   "core",
		Severity: policy.SeverityError,
		Message:  fmt.Sprintf("recovered panic: %v", p),
	})
	slog.Error("recovered panic", "site_id", h.SiteID, "event_id", d.EventID, "panic", fmt.Sprint(p))
}

// log writes a JSON decision line for requests that produced findings or were
// terminated; clean requests are not logged here (the access log owns those).
func (h *Handler) log(d *policy.Decision, r *http.Request, status int, took time.Duration) {
	findings := d.Findings()
	if len(findings) == 0 && d.Action() == policy.ActionAllow {
		return
	}
	// The query string is deliberately omitted: it routinely carries secrets.
	slog.InfoContext(r.Context(), "decision",
		"event_id", d.EventID,
		"site_id", d.SiteID,
		"mode", d.Mode,
		"action", d.Action(),
		"terminated_by", d.Terminated(),
		"client_ip", d.ClientIP.String(),
		"method", r.Method,
		"host", r.Host,
		"path", r.URL.Path,
		"status", status,
		"duration_ms", took.Milliseconds(),
		"findings", findings,
	)
}

// recorder tracks whether the response has started and its status code.
type recorder struct {
	http.ResponseWriter
	started bool
	code    int
}

func (r *recorder) WriteHeader(code int) {
	if !r.started {
		r.started, r.code = true, code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if !r.started {
		r.started, r.code = true, http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *recorder) status() int { return r.code }

// Unwrap lets http.ResponseController reach Flush, Hijack and friends.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
