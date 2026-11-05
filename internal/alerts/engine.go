package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/notify"
)

// Engine defaults and bounds.
const (
	DefaultEvery    = 30 * time.Second
	sendTimeout     = 15 * time.Second
	maxSendsInFly   = 16
	maxFindings     = 25     // per rule per evaluation: a flood of subjects becomes 25 alerts, not thousands
	maxTracked      = 10_000 // dedup entries across all rules
	maxErrorLen     = 200
	droppedSubject  = "events_dropped"
	feedSubjectKind = "feed"
)

// Notifier delivers a message to one configured channel.
type Notifier interface {
	Notify(ctx context.Context, channelID string, m notify.Message) error
}

// Options configures an Engine.
type Options struct {
	Source Source
	// Rules returns the current rule set; it is called on every evaluation so
	// edits apply without a restart.
	Rules    func(ctx context.Context) ([]Rule, error)
	Notifier Notifier
	Now      func() time.Time
	Every    time.Duration
	Logger   *slog.Logger
}

// RuleState is what the dashboard shows for a rule.
type RuleState struct {
	RuleID          string
	Name            string
	Firing          bool // the condition was true at the last evaluation
	ActiveSubjects  int
	LastEvaluated   time.Time
	LastFired       time.Time
	Fired           uint64
	Suppressed      uint64 // repeats withheld during the cool-down
	LastError       string // evaluating the condition
	LastNotifyError string
}

type tracked struct {
	lastFired time.Time
	lastSeen  uint64 // evaluation number in which the condition was last true
}

type ruleRuntime struct {
	state       RuleState
	prevDropped uint64
	haveDropped bool
}

// Engine evaluates rules on a timer and dispatches notifications.
type Engine struct {
	o   Options
	sem chan struct{}
	wg  sync.WaitGroup

	mu      sync.Mutex
	round   uint64
	rules   map[string]*ruleRuntime
	tracked map[string]*tracked
}

// New returns an Engine; Now, Every and Logger default sensibly.
func New(o Options) *Engine {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Every <= 0 {
		o.Every = DefaultEvery
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Engine{o: o, sem: make(chan struct{}, maxSendsInFly), rules: map[string]*ruleRuntime{}, tracked: map[string]*tracked{}}
}

// Run evaluates immediately, then every Options.Every until ctx ends, and waits
// for in-flight notifications before returning.
func (e *Engine) Run(ctx context.Context) {
	defer e.Wait()
	t := time.NewTicker(e.o.Every)
	defer t.Stop()
	for {
		e.EvaluateOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Wait blocks until every dispatched notification has finished or timed out.
func (e *Engine) Wait() { e.wg.Wait() }

// finding is one true condition: the subject identifies it for deduplication.
type finding struct {
	subject string
	body    string
	fields  map[string]string
}

// EvaluateOnce evaluates every enabled rule. Notifications are sent in the
// background; use Wait to block for them. A rule that fails to evaluate is
// recorded and skipped, never fatal to the others.
func (e *Engine) EvaluateOnce(ctx context.Context) {
	rules, err := e.o.Rules(ctx)
	if err != nil {
		e.o.Logger.Error("loading alert rules", "error", err)
		return
	}
	now := e.o.Now()

	e.mu.Lock()
	e.round++
	round := e.round
	e.mu.Unlock()

	live := make(map[string]bool, len(rules))
	for _, r := range rules {
		live[r.ID] = true
		if !r.Enabled {
			e.forget(r.ID)
			continue
		}
		e.evaluateRule(ctx, r, now, round)
	}
	e.mu.Lock()
	for id := range e.rules {
		if !live[id] {
			delete(e.rules, id)
		}
	}
	e.pruneLocked(now, round, rules)
	e.mu.Unlock()
}

func (e *Engine) forget(ruleID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.rules, ruleID)
	prefix := ruleID + "\x00"
	for k := range e.tracked {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(e.tracked, k)
		}
	}
}

// pruneLocked drops dedup entries whose condition is gone and whose cool-down
// has passed, and entries of rules that no longer exist.
func (e *Engine) pruneLocked(now time.Time, round uint64, rules []Rule) {
	cool := make(map[string]time.Duration, len(rules))
	for _, r := range rules {
		if r.Enabled {
			cool[r.ID] = r.cooldown()
		}
	}
	for k, t := range e.tracked {
		id := ruleOf(k)
		c, ok := cool[id]
		if !ok || (t.lastSeen != round && now.Sub(t.lastFired) >= c) {
			delete(e.tracked, k)
		}
	}
}

func ruleOf(key string) string {
	for i := 0; i < len(key); i++ {
		if key[i] == 0 {
			return key[:i]
		}
	}
	return key
}

func (e *Engine) runtime(r Rule) *ruleRuntime {
	rt, ok := e.rules[r.ID]
	if !ok {
		rt = &ruleRuntime{}
		e.rules[r.ID] = rt
	}
	rt.state.RuleID, rt.state.Name = r.ID, r.Name
	return rt
}

func (e *Engine) evaluateRule(ctx context.Context, r Rule, now time.Time, round uint64) {
	findings, err := e.check(ctx, r, now)

	e.mu.Lock()
	rt := e.runtime(r)
	rt.state.LastEvaluated = now
	if err != nil {
		rt.state.LastError = truncate(err.Error())
		rt.state.Firing, rt.state.ActiveSubjects = false, 0
		e.mu.Unlock()
		e.o.Logger.Warn("evaluating alert rule", "rule_id", r.ID, "kind", r.Kind, "error", err)
		return
	}
	rt.state.LastError = ""
	rt.state.Firing, rt.state.ActiveSubjects = len(findings) > 0, len(findings)

	var fire []finding
	for _, f := range findings {
		key := r.ID + "\x00" + f.subject
		t, known := e.tracked[key]
		switch {
		case known && now.Sub(t.lastFired) < r.cooldown():
			t.lastSeen = round
			rt.state.Suppressed++
		case known:
			t.lastFired, t.lastSeen = now, round
			fire = append(fire, f)
		case len(e.tracked) >= maxTracked:
			e.o.Logger.Error("alert dedup table is full; not alerting on a new subject", "rule_id", r.ID, "limit", maxTracked)
		default:
			e.tracked[key] = &tracked{lastFired: now, lastSeen: round}
			fire = append(fire, f)
		}
	}
	if len(fire) > 0 {
		rt.state.LastFired = now
		rt.state.Fired += uint64(len(fire))
	}
	e.mu.Unlock()

	for _, f := range fire {
		e.dispatch(ctx, r, f, now)
	}
}

func (e *Engine) dispatch(ctx context.Context, r Rule, f finding, now time.Time) {
	fields := map[string]string{"kind": r.Kind}
	for k, v := range f.fields {
		fields[k] = v
	}
	msg := notify.Message{
		Title: r.Name, Body: f.body, Severity: r.severity(),
		RuleID: r.ID, RuleName: r.Name, At: now, Fields: fields,
	}
	for _, ch := range r.ChannelIDs {
		select {
		case e.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer func() { <-e.sem }()
			e.send(ctx, r, ch, msg)
		}()
	}
}

func (e *Engine) send(ctx context.Context, r Rule, channelID string, m notify.Message) {
	// A cancelled engine context must not drop an alert already decided on, but a
	// hung channel must not hold shutdown either, hence the detached timeout.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sendTimeout)
	defer cancel()
	var err error
	func() {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("notifier panicked: %v", p)
			}
		}()
		err = e.o.Notifier.Notify(sctx, channelID, m)
	}()
	if err == nil {
		return
	}
	e.o.Logger.Warn("sending alert notification", "rule_id", r.ID, "channel_id", channelID, "error", err)
	e.mu.Lock()
	if rt, ok := e.rules[r.ID]; ok {
		rt.state.LastNotifyError = truncate("channel " + channelID + ": " + err.Error())
	}
	e.mu.Unlock()
}

// Status returns the state of every rule evaluated so far, sorted by id.
func (e *Engine) Status() []RuleState {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RuleState, 0, len(e.rules))
	for _, rt := range e.rules {
		out = append(out, rt.state)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

func truncate(s string) string {
	if len(s) > maxErrorLen {
		return s[:maxErrorLen] + "…"
	}
	return s
}

var countryPattern = regexp.MustCompile(`^[A-Z]{2}$`)

// check evaluates the condition of one rule. It returns at most maxFindings.
func (e *Engine) check(ctx context.Context, r Rule, now time.Time) ([]finding, error) {
	var out []finding
	switch r.Kind {
	case KindBlocksThreshold:
		var p blocksParams
		if err := decodeParams(r.Params, &p); err != nil {
			return nil, err
		}
		window := time.Duration(p.WindowSeconds) * time.Second
		counts, err := e.o.Source.BlocksBySite(ctx, now.Add(-window), now)
		if err != nil {
			return nil, err
		}
		for _, c := range counts {
			if (p.SiteID != "" && c.Site != p.SiteID) || c.Count <= int64(p.Threshold) {
				continue
			}
			out = append(out, finding{
				subject: c.Site,
				body:    fmt.Sprintf("%d requests were blocked on site %s in the last %s (threshold %d).", c.Count, c.Site, window, p.Threshold),
				fields:  map[string]string{"site": c.Site, "blocks": strconv.FormatInt(c.Count, 10), "window_seconds": strconv.Itoa(p.WindowSeconds)},
			})
		}
	case KindNewCountry:
		var p countryParams
		if err := decodeParams(r.Params, &p); err != nil {
			return nil, err
		}
		window, baseline := time.Duration(p.WindowSeconds)*time.Second, time.Duration(p.BaselineSeconds)*time.Second
		recent, err := e.o.Source.TopCountries(ctx, p.SiteID, now.Add(-window), now)
		if err != nil {
			return nil, err
		}
		if len(recent) == 0 {
			break
		}
		past, err := e.o.Source.TopCountries(ctx, p.SiteID, now.Add(-window-baseline), now.Add(-window))
		if err != nil {
			return nil, err
		}
		if len(past) == 0 {
			break // no baseline yet: every country would look new
		}
		seen := make(map[string]bool, len(past))
		for _, c := range past {
			seen[c.Country] = true
		}
		for _, c := range recent {
			if seen[c.Country] || !countryPattern.MatchString(c.Country) {
				continue
			}
			subject := c.Country
			if p.SiteID != "" {
				subject = p.SiteID + "/" + c.Country
			}
			f := map[string]string{"country": c.Country, "events": strconv.FormatInt(c.Count, 10)}
			if p.SiteID != "" {
				f["site"] = p.SiteID
			}
			out = append(out, finding{
				subject: subject,
				body:    fmt.Sprintf("Country %s appeared among the top sources of attack events (%d events in the last %s) and was absent in the preceding %s.", c.Country, c.Count, window, baseline),
				fields:  f,
			})
		}
	case KindCertExpiring:
		var p certParams
		if err := decodeParams(r.Params, &p); err != nil {
			return nil, err
		}
		certs, err := e.o.Source.CertExpiries(ctx)
		if err != nil {
			return nil, err
		}
		limit := time.Duration(p.Days) * 24 * time.Hour
		for _, c := range certs {
			left := c.NotAfter.Sub(now)
			if left >= limit {
				continue
			}
			days := int(left.Hours() / 24)
			state := fmt.Sprintf("expires in %d days", days)
			if left < 0 {
				state = "has expired"
			}
			out = append(out, finding{
				subject: c.Site + "/" + c.Host,
				body:    fmt.Sprintf("The certificate for %s (site %s) %s.", c.Host, c.Site, state),
				fields:  map[string]string{"site": c.Site, "host": c.Host, "days_left": strconv.Itoa(days)},
			})
		}
	case KindFeedFailure:
		feeds, err := e.o.Source.FeedStatuses(ctx)
		if err != nil {
			return nil, err
		}
		for _, f := range feeds {
			if f.Failed {
				out = append(out, finding{
					subject: feedSubjectKind + "/" + f.Name,
					body:    fmt.Sprintf("The %s feed failed its last refresh.", f.Name),
					fields:  map[string]string{"feed": f.Name},
				})
			}
		}
	case KindEventsDropped:
		total, err := e.o.Source.EventsDropped(ctx)
		if err != nil {
			return nil, err
		}
		e.mu.Lock()
		rt := e.runtime(r)
		prev, had := rt.prevDropped, rt.haveDropped
		rt.prevDropped, rt.haveDropped = total, true
		e.mu.Unlock()
		// The first reading is only a baseline; a smaller one means the counter
		// restarted with the process.
		if had && total > prev {
			out = append(out, finding{
				subject: droppedSubject,
				body:    fmt.Sprintf("%d security events were dropped because the event buffer overflowed since the last check.", total-prev),
				fields:  map[string]string{"dropped": strconv.FormatUint(total-prev, 10)},
			})
		}
	case KindUpstreamUnhealthy:
		var p upstreamParams
		if err := decodeParams(r.Params, &p); err != nil {
			return nil, err
		}
		ups, err := e.o.Source.Upstreams(ctx)
		if err != nil {
			return nil, err
		}
		for _, u := range ups {
			if u.Healthy || (p.SiteID != "" && u.Site != p.SiteID) {
				continue
			}
			out = append(out, finding{
				subject: u.Site + "/" + u.Upstream,
				body:    fmt.Sprintf("Upstream %s of site %s failed its health probe.", u.Upstream, u.Site),
				fields:  map[string]string{"site": u.Site, "upstream": u.Upstream},
			})
		}
	default:
		return nil, fmt.Errorf("%w: unknown kind %q", ErrInvalid, r.Kind)
	}
	if len(out) > maxFindings {
		e.o.Logger.Warn("alert rule produced more subjects than the per-evaluation limit", "rule_id", r.ID, "subjects", len(out), "limit", maxFindings)
		out = out[:maxFindings]
	}
	return out, nil
}
