package policy

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Severity ranks a finding.
type Severity int

// Severities, lowest first.
const (
	SeverityInfo Severity = iota
	SeverityNotice
	SeverityWarning
	SeverityError
	SeverityCritical
)

var severityNames = [...]string{"info", "notice", "warning", "error", "critical"}

// String returns the lower-case severity name.
func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// MarshalText implements encoding.TextMarshaler so JSON logs use names.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Action is what Sherlock did with a request.
type Action string

// Actions.
const (
	ActionAllow     Action = "allow"
	ActionLog       Action = "log"
	ActionChallenge Action = "challenge"
	ActionBlock     Action = "block"
	ActionRateLimit Action = "ratelimit"
	ActionBan       Action = "ban"
)

// Mode is the site mode at the time of the request.
type Mode string

// Modes.
const (
	ModeOff    Mode = "off"
	ModeDetect Mode = "detect"
	ModeBlock  Mode = "block"
)

// Finding is one observation recorded by a module.
type Finding struct {
	Module   string   `json:"module"`
	RuleID   string   `json:"rule_id,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Severity Severity `json:"severity"`
	Target   string   `json:"target,omitempty"`
	Matched  string   `json:"-"` // never logged until event redaction exists
	Message  string   `json:"message,omitempty"`
	Score    int      `json:"score,omitempty"`
}

// Decision is the per-request record created by sherlock_core and extended by
// later modules. It is safe for concurrent use.
type Decision struct {
	EventID  string
	SiteID   string
	Mode     Mode
	ClientIP netip.Addr

	// Allowlisted is set by the ACL module when the client matched an allow
	// list: later modules that rate-limit or challenge skip it. SkipWAF
	// additionally lets the WAF skip it, and is only set when the policy
	// explicitly asks for that (allow_bypass_waf).
	Allowlisted bool
	SkipWAF     bool
	// ChallengeRequested is set by a module (a rate limit with action challenge)
	// that wants this client to prove it is a browser; the bot module acts on it.
	ChallengeRequested bool

	mu         sync.Mutex
	claims     ClaimSource
	certSubj   string
	action     Action
	terminated string
	findings   []Finding
	wafTime    time.Duration
	inbound    int
	outbound   int
	bodyType   string
	bodySample []byte
}

// ClaimSource gives access to the verified claims of the request's token.
type ClaimSource interface {
	// Claim returns a claim usable as a short key (string or number).
	Claim(name string) (string, bool)
}

// SetClaims records the claims of a token the API module verified. Only
// verified claims are ever stored, so rate limits can key on them safely.
func (d *Decision) SetClaims(c ClaimSource) {
	d.mu.Lock()
	d.claims = c
	d.mu.Unlock()
}

// Claim returns a verified token claim, if the request carried a valid token.
func (d *Decision) Claim(name string) (string, bool) {
	d.mu.Lock()
	c := d.claims
	d.mu.Unlock()
	if c == nil {
		return "", false
	}
	return c.Claim(name)
}

// SetClientCert records the subject of the verified client certificate.
func (d *Decision) SetClientCert(subject string) {
	d.mu.Lock()
	d.certSubj = subject
	d.mu.Unlock()
}

// ClientCertSubject is the verified client certificate subject, or "".
func (d *Decision) ClientCertSubject() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.certSubj
}

// NewDecision starts a decision with Action allow.
func NewDecision(eventID, siteID string, mode Mode, ip netip.Addr) *Decision {
	return &Decision{EventID: eventID, SiteID: siteID, Mode: mode, ClientIP: ip, action: ActionAllow}
}

// AddFinding appends a finding.
func (d *Decision) AddFinding(f Finding) {
	d.mu.Lock()
	d.findings = append(d.findings, f)
	d.mu.Unlock()
}

// Findings returns a copy of the findings recorded so far.
func (d *Decision) Findings() []Finding {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Finding, len(d.findings))
	copy(out, d.findings)
	return out
}

// SetAction records the action taken. Terminating actions should go through
// Terminate so the responsible module is recorded.
func (d *Decision) SetAction(a Action) {
	d.mu.Lock()
	d.action = a
	d.mu.Unlock()
}

// Terminate records that module ended the request with action.
func (d *Decision) Terminate(module string, a Action) {
	d.mu.Lock()
	d.action, d.terminated = a, module
	d.mu.Unlock()
}

// Action returns the current action.
func (d *Decision) Action() Action {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.action
}

// Terminated returns the module that ended the request, or "".
func (d *Decision) Terminated() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.terminated
}

// AddWAFTime accumulates time spent inside the WAF for this request.
func (d *Decision) AddWAFTime(t time.Duration) {
	d.mu.Lock()
	d.wafTime += t
	d.mu.Unlock()
}

// WAFTime is the total time spent inside the WAF.
func (d *Decision) WAFTime() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.wafTime
}

// SetAnomalyScore records the CRS anomaly totals.
func (d *Decision) SetAnomalyScore(inbound, outbound int) {
	d.mu.Lock()
	d.inbound, d.outbound = inbound, outbound
	d.mu.Unlock()
}

// AnomalyScore returns the CRS anomaly totals.
func (d *Decision) AnomalyScore() (inbound, outbound int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.inbound, d.outbound
}

// SetBodySample keeps an unredacted prefix of the request body for the event
// pipeline, which redacts it before anything leaves the request path. Only
// set when body excerpts are enabled.
func (d *Decision) SetBodySample(contentType string, sample []byte) {
	d.mu.Lock()
	d.bodyType, d.bodySample = contentType, sample
	d.mu.Unlock()
}

// BodySample returns the content type and unredacted body prefix, if any.
func (d *Decision) BodySample() (contentType string, sample []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.bodyType, d.bodySample
}

type decisionKey struct{}

// WithDecision stores d in ctx under a typed key.
func WithDecision(ctx context.Context, d *Decision) context.Context {
	return context.WithValue(ctx, decisionKey{}, d)
}

// DecisionFrom returns the decision stored by sherlock_core, or nil.
func DecisionFrom(ctx context.Context) *Decision {
	d, _ := ctx.Value(decisionKey{}).(*Decision)
	return d
}

// BlockObserver is told when a request ended in a block, after the response
// is complete. The rate-limit module registers one to count blocks for
// auto-ban. It must not block: it runs on the request goroutine.
type BlockObserver func(d *Decision)

var blockObserver atomic.Pointer[BlockObserver]

// SetBlockObserver installs (or, with nil, removes) the process-wide observer.
func SetBlockObserver(o BlockObserver) {
	if o == nil {
		blockObserver.Store(nil)
		return
	}
	blockObserver.Store(&o)
}

// NotifyBlock calls the observer if the decision ended in a block or ban.
func NotifyBlock(d *Decision) {
	if a := d.Action(); a != ActionBlock && a != ActionBan {
		return
	}
	if o := blockObserver.Load(); o != nil {
		(*o)(d)
	}
}
