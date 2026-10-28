package policy

import (
	"context"
	"net/netip"
	"sync"
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

	mu         sync.Mutex
	action     Action
	terminated string
	findings   []Finding
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
