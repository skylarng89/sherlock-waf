// Package notify delivers alert messages to people: SMTP email and three kinds
// of webhook (generic JSON, Slack-compatible, Microsoft Teams). Channel
// settings hold secrets (webhook URLs, SMTP passwords), so no error returned
// from this package ever contains them.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Channel kinds.
const (
	KindSMTP    = "smtp"
	KindWebhook = "webhook"
	KindSlack   = "slack"
	KindTeams   = "teams"
)

// Message severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// ErrInvalid wraps every settings validation failure.
var ErrInvalid = errors.New("notify: invalid channel settings")

// Limits on what reaches a channel. Fields can carry attacker-influenced
// strings (paths, countries), so everything is length-bounded and stripped of
// control characters before any formatting.
const (
	maxTitle      = 200
	maxBody       = 2000
	maxFieldKey   = 64
	maxFieldValue = 256
	maxFields     = 20
)

// Message is one alert notification.
type Message struct {
	Title    string
	Body     string
	Severity string // info | warning | critical
	RuleID   string
	RuleName string
	At       time.Time
	// Fields are ids, counts, site, country and host: never request content.
	Fields map[string]string
}

// Sender delivers a Message to one channel.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Kinds lists the supported channel kinds.
func Kinds() []string { return []string{KindSMTP, KindSlack, KindTeams, KindWebhook} }

// Validate checks settings for kind without any network access.
func Validate(kind string, settings json.RawMessage) error {
	_, err := New(kind, settings)
	return err
}

// New builds a Sender from settings.
func New(kind string, settings json.RawMessage) (Sender, error) {
	switch kind {
	case KindSMTP:
		return newSMTP(settings)
	case KindWebhook, KindSlack, KindTeams:
		return newHTTP(kind, settings)
	}
	return nil, fmt.Errorf("%w: unknown channel kind %q", ErrInvalid, kind)
}

// Test sends a clearly labelled message so a channel can be checked before an
// alert depends on it.
func Test(ctx context.Context, kind string, settings json.RawMessage) error {
	s, err := New(kind, settings)
	if err != nil {
		return err
	}
	return s.Send(ctx, Message{
		Title:    "Sherlock WAF test notification",
		Body:     "This is a test message from Sherlock WAF. No action is needed.",
		Severity: SeverityInfo,
		RuleID:   "test",
		RuleName: "Channel test",
		At:       time.Now().UTC(),
		Fields:   map[string]string{"kind": "test"},
	})
}

func decodeStrict(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data after settings", ErrInvalid)
	}
	return nil
}

// clean removes control characters, collapses newlines to spaces when
// singleLine is set, and truncates to max runes.
func clean(s string, max int, singleLine bool) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == utf8.RuneError {
			continue
		}
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			if singleLine {
				r = ' '
			} else if r == '\r' {
				continue
			}
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ':
			continue
		}
		if n >= max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

type field struct{ Key, Value string }

// normalised is a Message after bounding and cleaning, with fields in a stable order.
type normalised struct {
	Title, Body, Severity, RuleID, RuleName string
	At                                      time.Time
	Fields                                  []field
}

func normalise(m Message) normalised {
	n := normalised{
		Title:    clean(m.Title, maxTitle, true),
		Body:     clean(m.Body, maxBody, false),
		Severity: m.Severity,
		RuleID:   clean(m.RuleID, maxFieldValue, true),
		RuleName: clean(m.RuleName, maxFieldValue, true),
		At:       m.At.UTC(),
	}
	if !slices.Contains([]string{SeverityInfo, SeverityWarning, SeverityCritical}, n.Severity) {
		n.Severity = SeverityWarning
	}
	if n.Title == "" {
		n.Title = "Sherlock WAF alert"
	}
	keys := make([]string, 0, len(m.Fields))
	for k := range m.Fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if len(n.Fields) >= maxFields {
			break
		}
		ck := clean(k, maxFieldKey, true)
		if ck == "" {
			continue
		}
		n.Fields = append(n.Fields, field{ck, clean(m.Fields[k], maxFieldValue, true)})
	}
	return n
}
