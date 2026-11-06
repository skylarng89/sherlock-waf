// Package login is the sherlock_login Caddy module (M11-T1, FR-FIN-1): it
// counts failed logins per client address, per username and per device on the
// login endpoints a site declares, and challenges or blocks a client that goes
// over a threshold.
//
// It runs after the bot module and before the WAF. A failure is only known once
// the upstream has answered, so the module works in two halves: before calling
// the next handler it asks whether the request's keys are already over their
// threshold (and acts if so); after the response it records a failure when the
// upstream's status says the login failed. Refused requests never reach the
// upstream and are never counted, so a tripped counter drains with the window.
//
// Usernames are only ever used as a keyed hash (HMAC-SHA256, random per-process
// key) inside counter keys. The name itself, and the hash, are never written to
// findings, events, logs or metric labels.
package login

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/blockpage"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/bot"
	"github.com/skylarng89/sherlock-waf/internal/metrics"
	"github.com/skylarng89/sherlock-waf/internal/policy"
	"github.com/skylarng89/sherlock-waf/internal/policy/challenge"
	rl "github.com/skylarng89/sherlock-waf/internal/policy/ratelimit"
)

const moduleName = "sherlock_login"

// maxKeys bounds the failure counters' memory (roughly 150 bytes per key, three
// keys per failing client at most). When full, the least recently used key goes,
// which can only make the module more lenient, never stricter.
const maxKeys = 1 << 19

// Counter scopes, as they appear in rule ids, metrics and findings.
const (
	scopeIP       = "ip"
	scopeUsername = "username"
	scopeDevice   = "device"
)

var (
	limiter = rl.New(maxKeys)

	// secret keys the username hash. It lives only in this process, so a hash
	// leaked from memory or a core dump cannot be matched against a dictionary
	// without it, and counters restart (empty) with the process.
	secret = func() []byte {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			panic("login: no randomness for the username key: " + err.Error())
		}
		return k
	}()
	macPool = sync.Pool{New: func() any { return hmac.New(sha256.New, secret) }}
)

func init() { caddy.RegisterModule(&Handler{}) }

// Endpoint is one declared login request.
type Endpoint struct {
	Path            string `json:"path"`
	Method          string `json:"method"`
	UsernameField   string `json:"username_field"`
	FailureStatuses []int  `json:"failure_statuses"`

	tokens []string // the JSON pointer form of UsernameField, nil for a plain name
}

// Handler is the sherlock_login Caddy handler. Its JSON is produced by
// internal/compiler/finance.go.
type Handler struct {
	SiteID      string     `json:"site_id"`
	Mode        string     `json:"mode"`
	Action      string     `json:"action"`
	Endpoints   []Endpoint `json:"endpoints"`
	PerIP       int        `json:"per_ip"`
	PerUsername int        `json:"per_username"`
	PerDevice   int        `json:"per_device"`
	Window      string     `json:"window"`
	// Handoff means the bot module is enabled for the site and serves the
	// challenge. Without it a challenge is enforced as a block.
	Handoff bool `json:"challenge_handoff,omitempty"`

	window  time.Duration
	enforce bool
	now     func() time.Time
	lim     *rl.Limiter
	cleared func(*http.Request, netip.Addr, string) bool // bot.Cleared; replaceable in tests
}

// CaddyModule implements caddy.Module.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers." + moduleName, New: func() caddy.Module { return new(Handler) }}
}

// Provision implements caddy.Provisioner.
func (h *Handler) Provision(caddy.Context) error {
	w, err := time.ParseDuration(h.Window)
	if err != nil || w < time.Second {
		return fmt.Errorf("sherlock_login: invalid window %q", h.Window)
	}
	h.window = w
	h.enforce = h.Mode == string(policy.ModeBlock)
	if h.now == nil {
		h.now = time.Now
	}
	if h.lim == nil {
		h.lim = limiter
	}
	if h.cleared == nil {
		h.cleared = bot.Cleared
	}
	for i := range h.Endpoints {
		ep := &h.Endpoints[i]
		ep.tokens = pointer(ep.UsernameField)
	}
	return nil
}

// Validate implements caddy.Validator.
func (h *Handler) Validate() error {
	if h.SiteID == "" {
		return errors.New("sherlock_login: site_id is required")
	}
	if !slices.Contains([]string{config.ActionChallenge, config.ActionBlock, config.ActionLog}, h.Action) {
		return fmt.Errorf("sherlock_login: invalid action %q", h.Action)
	}
	if len(h.Endpoints) == 0 {
		return errors.New("sherlock_login: at least one endpoint is required")
	}
	for i, ep := range h.Endpoints {
		if !strings.HasPrefix(ep.Path, "/") || ep.Method == "" || ep.UsernameField == "" {
			return fmt.Errorf("sherlock_login: endpoint %d needs a path starting with '/', a method and a username_field", i)
		}
		if _, err := path.Match(ep.Path, "/"); err != nil {
			return fmt.Errorf("sherlock_login: endpoint %d: invalid path glob: %w", i, err)
		}
	}
	for name, v := range map[string]int{"per_ip": h.PerIP, "per_username": h.PerUsername, "per_device": h.PerDevice} {
		if v < 1 {
			return fmt.Errorf("sherlock_login: %s must be positive", name)
		}
	}
	return nil
}

func (ep *Endpoint) matches(r *http.Request) bool {
	if r.Method != ep.Method {
		return false
	}
	if ok, err := path.Match(ep.Path, r.URL.Path); err == nil && ok {
		return true
	}
	// "/api/*" is meant to cover everything below it, not one segment.
	pre, ok := strings.CutSuffix(ep.Path, "/*")
	return ok && strings.HasPrefix(r.URL.Path, pre+"/")
}

func (ep *Endpoint) failed(status int) bool { return slices.Contains(ep.FailureStatuses, status) }

// keys are the counter keys of one login attempt. The username key is empty
// when the request carried no readable username.
type keys struct {
	ip, user, device string
}

// hashUsername is the keyed hash a username is reduced to. Case and surrounding
// space do not change it, so "Ada@x" and " ada@x" are one account.
func hashUsername(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	m := macPool.Get().(hash.Hash) //nolint:forcetypeassert // the pool only holds hash.Hash
	defer macPool.Put(m)
	m.Reset()
	_, _ = m.Write([]byte(name))
	var sum [sha256.Size]byte
	return hex.EncodeToString(m.Sum(sum[:0])[:12])
}

func (h *Handler) keysFor(r *http.Request, d *policy.Decision, ep *Endpoint) keys {
	k := keys{
		ip:     "ip|" + h.SiteID + "|" + d.ClientIP.Unmap().String(),
		device: "dev|" + h.SiteID + "|" + challenge.Fingerprint(r),
	}
	if kind := kindOf(r.Header.Get("Content-Type")); kind != kindNone && r.ContentLength <= maxBodyPeek {
		if body, ok := peekBody(r); ok {
			if u := hashUsername(extractUsername(kind, body, ep.UsernameField, ep.tokens)); u != "" {
				k.user = "user|" + h.SiteID + "|" + u
			}
		}
	}
	return k
}

// tripped returns the first scope whose failures have reached its threshold.
func (h *Handler) tripped(k keys, now time.Time) (scope string, limit int) {
	switch {
	case h.lim.EstimateAt(k.ip, h.window, now) >= float64(h.PerIP):
		return scopeIP, h.PerIP
	case k.user != "" && h.lim.EstimateAt(k.user, h.window, now) >= float64(h.PerUsername):
		return scopeUsername, h.PerUsername
	case h.lim.EstimateAt(k.device, h.window, now) >= float64(h.PerDevice):
		return scopeDevice, h.PerDevice
	}
	return "", 0
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	d := policy.DecisionFrom(r.Context())
	if d == nil || !d.ClientIP.IsValid() || d.Allowlisted {
		return next.ServeHTTP(w, r)
	}
	var ep *Endpoint
	for i := range h.Endpoints {
		if h.Endpoints[i].matches(r) {
			ep = &h.Endpoints[i]
			break
		}
	}
	if ep == nil {
		return next.ServeHTTP(w, r) // not a login request: nothing allocated, nothing counted
	}

	k := h.keysFor(r, d, ep)
	now := h.now()
	if scope, limit := h.tripped(k, now); scope != "" {
		if h.act(w, r, d, scope, limit) {
			return nil
		}
	}

	sw := &statusWriter{ResponseWriter: w}
	err := next.ServeHTTP(sw, r)
	if ep.failed(sw.status) {
		h.record(d, k, h.now())
	}
	return err
}

// act applies the configured action to a client over a threshold. It reports
// whether it answered the request itself.
func (h *Handler) act(w http.ResponseWriter, r *http.Request, d *policy.Decision, scope string, limit int) bool {
	// The message names the scope and the number, never the account.
	msg := fmt.Sprintf("%d failed logins from this %s in %s reached the limit of %d", limit, scope, h.Window, limit)
	d.AddFinding(policy.Finding{Module: "login", RuleID: "login-" + scope, Severity: policy.SeverityWarning, Message: msg})
	if !h.enforce || h.Action == config.ActionLog {
		metrics.ObserveLoginAction(h.SiteID, config.ActionLog, scope)
		return false // detect mode and action log record the finding and let the request through
	}

	if h.Action == config.ActionChallenge && h.Handoff {
		// A client that already passed a challenge is exempt: otherwise it would
		// be sent round the same loop for the rest of the window.
		if h.cleared(r, d.ClientIP, h.SiteID) {
			return false
		}
		// The bot module has already run for this request, so the attempt itself
		// is refused; the marks make it serve its challenge page to this address
		// and to this device's next request, and a solved challenge ends it.
		challenge.Mark(challenge.ClientKey(h.SiteID, d.ClientIP), h.window)
		challenge.Mark(challenge.DeviceKey(h.SiteID, challenge.Fingerprint(r)), h.window)
		metrics.ObserveLoginAction(h.SiteID, config.ActionChallenge, scope)
		d.Terminate("login", policy.ActionChallenge)
		blockpage.Write(w, r, http.StatusForbidden, d.EventID)
		return true
	}

	// block, or a challenge with no bot module to serve it (the safe reading, as
	// the rate limiter does).
	metrics.ObserveLoginAction(h.SiteID, config.ActionBlock, scope)
	d.Terminate("login", policy.ActionRateLimit)
	w.Header().Set("Retry-After", strconv.Itoa(int(h.window.Seconds())))
	blockpage.Write(w, r, http.StatusTooManyRequests, d.EventID)
	return true
}

// record counts one failed login under each of the request's keys and notes in
// the event when a counter reaches its threshold.
func (h *Handler) record(d *policy.Decision, k keys, now time.Time) {
	metrics.ObserveLoginFailure(h.SiteID)
	count := func(key, scope string, limit int) {
		if key == "" {
			return
		}
		n := h.lim.AddAt(key, h.window, now)
		if n >= float64(limit) && n-1 < float64(limit) {
			d.AddFinding(policy.Finding{
				Module: "login", RuleID: "login-" + scope + "-threshold", Severity: policy.SeverityNotice,
				Message: fmt.Sprintf("failed logins from this %s reached %d in %s; the next attempt will be %s", scope, limit, h.Window, h.Action),
			})
		}
	}
	count(k.ip, scopeIP, h.PerIP)
	count(k.user, scopeUsername, h.PerUsername)
	count(k.device, scopeDevice, h.PerDevice)
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
