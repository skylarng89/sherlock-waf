package config

import (
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// LoginPolicy configures the login-protection module (FR-FIN-1): failed-login
// velocity per client address, per username and per device, answered with a
// challenge or a block. Every field is optional and inherits like the rest of a
// policy; Endpoints is a list, so a lower level replaces it as a whole.
type LoginPolicy struct {
	// Turns login protection on (on by default whenever the block is present, but nothing is watched until an endpoint is declared).
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Endpoints declares the login requests Sherlock watches. Nothing is watched
	// until at least one is declared.
	Endpoints []LoginEndpoint `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
	// Failures allowed per window before the action applies; unset values inherit.
	Thresholds *LoginThresholds `yaml:"thresholds,omitempty" json:"thresholds,omitempty"`
	// Action is what happens to a client over a threshold: challenge (default),
	// block or log. In detect mode it is recorded and never enforced.
	Action string `yaml:"action,omitempty" json:"action,omitempty"`
}

// LoginEndpoint is one login request: a path glob and method, where the
// username is in the request, and which upstream statuses mean "failed".
type LoginEndpoint struct {
	// Path glob starting with '/'.
	Path   string `yaml:"path,omitempty" json:"path,omitempty"`
	Method string `yaml:"method,omitempty" json:"method,omitempty"` // default POST
	// UsernameField is a JSON pointer ("/user/email") for JSON bodies or a field
	// name ("email") for form bodies. Usernames are only ever kept as a keyed hash.
	UsernameField string `yaml:"username_field,omitempty" json:"username_field,omitempty"`
	// FailureStatuses are the upstream statuses counted as a failed login
	// (default 401 and 403).
	FailureStatuses []int `yaml:"failure_statuses,omitempty" json:"failure_statuses,omitempty"`
}

// LoginThresholds are the failures allowed per window before Action applies.
// A zero field inherits.
type LoginThresholds struct {
	// Failed logins per client address in the window, 1 to 100000 (default 20).
	PerIP int `yaml:"per_ip,omitempty" json:"per_ip,omitempty"`
	// Failed logins per username in the window, from any address, 1 to 100000 (default 5).
	PerUsername int `yaml:"per_username,omitempty" json:"per_username,omitempty"`
	// Failed logins per device fingerprint in the window, 1 to 100000 (default 10).
	PerDevice int `yaml:"per_device,omitempty" json:"per_device,omitempty"`
	// Period in which failures are counted, 1m to 24h (default 10m).
	Window Duration `yaml:"window,omitempty" json:"window,omitempty"`
}

// Login defaults and bounds.
const (
	DefaultLoginPerIP       = 20
	DefaultLoginPerUsername = 5
	DefaultLoginPerDevice   = 10
	DefaultLoginWindow      = 10 * time.Minute

	maxLoginEndpoints  = 20
	maxLoginThreshold  = 100_000
	maxUsernameFieldLn = 128
)

// EffectiveLogin is the resolved login-protection policy.
type EffectiveLogin struct {
	Enabled   bool            `json:"enabled"`
	Endpoints []LoginEndpoint `json:"endpoints"`
	PerIP     int             `json:"per_ip"`
	PerUser   int             `json:"per_username"`
	PerDevice int             `json:"per_device"`
	Window    time.Duration   `json:"window"`
	Action    string          `json:"action"`
}

func newEffectiveLogin() EffectiveLogin {
	return EffectiveLogin{
		Endpoints: []LoginEndpoint{}, PerIP: DefaultLoginPerIP, PerUser: DefaultLoginPerUsername,
		PerDevice: DefaultLoginPerDevice, Window: DefaultLoginWindow, Action: ActionChallenge,
	}
}

// Active reports whether the module should be compiled in: enabled and at least
// one endpoint declared.
func (e EffectiveLogin) Active() bool { return e.Enabled && len(e.Endpoints) > 0 }

func (e *EffectivePolicy) applyLogin(p *Policy, src string) {
	l := p.Login
	if l == nil {
		return
	}
	set := func(f string) { e.Sources["login_protection."+f] = src }
	e.Login.Enabled = l.Enabled == nil || *l.Enabled
	set("enabled")
	if l.Endpoints != nil {
		e.Login.Endpoints = slices.Clone(l.Endpoints)
		set("endpoints")
	}
	if t := l.Thresholds; t != nil {
		if t.PerIP != 0 {
			e.Login.PerIP = t.PerIP
			set("thresholds.per_ip")
		}
		if t.PerUsername != 0 {
			e.Login.PerUser = t.PerUsername
			set("thresholds.per_username")
		}
		if t.PerDevice != 0 {
			e.Login.PerDevice = t.PerDevice
			set("thresholds.per_device")
		}
		if t.Window != 0 {
			e.Login.Window = t.Window.Std()
			set("thresholds.window")
		}
	}
	if l.Action != "" {
		e.Login.Action = l.Action
		set("action")
	}
}

func (p *Policy) applyLoginDefaults() {
	if p.Login == nil {
		return
	}
	for i := range p.Login.Endpoints {
		ep := &p.Login.Endpoints[i]
		if ep.Method == "" {
			ep.Method = "POST"
		}
		if len(ep.FailureStatuses) == 0 {
			ep.FailureStatuses = []int{401, 403}
		}
	}
}

func (p *Policy) validateLogin(pth string, errs *Errors) {
	l := p.Login
	if l == nil {
		return
	}
	if !slices.Contains([]string{"", ActionChallenge, ActionBlock, ActionLog}, l.Action) {
		errs.add(pth+"/action", CodeInvalid, "must be challenge, block or log")
	}
	if len(l.Endpoints) > maxLoginEndpoints {
		errs.add(pth+"/endpoints", CodeOutOfRange, "at most %d endpoints", maxLoginEndpoints)
	}
	for i, ep := range l.Endpoints {
		ep := ep
		epath := pth + "/endpoints/" + strconv.Itoa(i)
		switch {
		case !strings.HasPrefix(ep.Path, "/"):
			errs.add(epath+"/path", CodeInvalid, "must start with '/'")
		default:
			if _, err := path.Match(ep.Path, "/"); err != nil {
				errs.add(epath+"/path", CodeInvalid, "invalid glob: %v", err)
			}
		}
		if !slices.Contains(validVerbs, ep.Method) {
			errs.add(epath+"/method", CodeInvalid, "%q is not an HTTP method", ep.Method)
		}
		if ep.UsernameField == "" {
			errs.add(epath+"/username_field", CodeRequired, "name the form field or JSON pointer that holds the username")
		} else if len(ep.UsernameField) > maxUsernameFieldLn || strings.ContainsAny(ep.UsernameField, "\r\n\x00") {
			errs.add(epath+"/username_field", CodeInvalid, "must be at most %d characters without control characters", maxUsernameFieldLn)
		}
		if len(ep.FailureStatuses) > 20 {
			errs.add(epath+"/failure_statuses", CodeOutOfRange, "at most 20 statuses")
		}
		for j, st := range ep.FailureStatuses {
			if st < 100 || st > 599 {
				errs.add(epath+"/failure_statuses/"+strconv.Itoa(j), CodeOutOfRange, "must be an HTTP status between 100 and 599")
			}
		}
	}
	if t := l.Thresholds; t != nil {
		for name, v := range map[string]int{"per_ip": t.PerIP, "per_username": t.PerUsername, "per_device": t.PerDevice} {
			if v < 0 || v > maxLoginThreshold {
				errs.add(pth+"/thresholds/"+name, CodeOutOfRange, "must be between 1 and %d", maxLoginThreshold)
			}
		}
		if w := t.Window.Std(); w != 0 && (w < time.Minute || w > 24*time.Hour) {
			errs.add(pth+"/thresholds/window", CodeOutOfRange, "must be between 1m and 24h")
		}
	}
}
