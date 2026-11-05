// Package integrations stores and edits the three kinds of operator-defined
// outbound objects: SIEM exporters, notification channels and alert rules.
//
// Each object is a row in the integrations table whose settings document is
// encrypted as one secret, so a webhook URL, an HMAC key or an SMTP password is
// never readable from the database or a backup without the node key. The API
// never returns those values: Mask replaces them, and a masked value sent back
// on update means "keep what is stored".
package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/secrets"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// Masked is what the API shows instead of a secret value.
const Masked = "********"

const secretPurpose = "integration"

// Errors returned by the Service.
var (
	// ErrInvalid wraps a user-correctable problem; the message is safe to show.
	ErrInvalid = errors.New("invalid")
	// ErrInUse means other objects still reference the one being deleted.
	ErrInUse = errors.New("in use")
)

var (
	idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// secretKey matches settings keys whose string values are credentials or
	// carry them (webhook URLs embed tokens). Matching broadly is deliberate:
	// over-masking costs a re-typed value, under-masking leaks a credential.
	secretKey = regexp.MustCompile(`(?i)secret|passw|token|key|hmac|authorization|url|credential|dsn`)
)

// Input is the editable part of an object.
type Input struct {
	Name    string
	Type    string
	Stream  string // exporters only
	Enabled bool
	// Settings is the type-specific document (for alert rules: AlertDoc).
	Settings json.RawMessage
}

// Item is a stored object with its decrypted settings.
type Item struct {
	store.Integration
	Settings json.RawMessage
}

// AlertDoc is the settings document of an alert rule.
type AlertDoc struct {
	Severity        string          `json:"severity"`
	CooldownSeconds int             `json:"cooldown_seconds"`
	ChannelIDs      []string        `json:"channel_ids"`
	Params          json.RawMessage `json:"params"`
}

// Backend is what the Service needs from the subsystems that give the objects
// meaning. Implementations must not put credentials into returned errors.
type Backend interface {
	ExporterTypes() []string
	ChannelKinds() []string
	AlertKinds() []string
	ValidateExporter(typ, stream string, settings json.RawMessage) error
	TestExporter(ctx context.Context, typ, stream string, settings json.RawMessage) error
	ValidateChannel(kind string, settings json.RawMessage) error
	TestChannel(ctx context.Context, kind string, settings json.RawMessage) error
	ValidateAlertRule(kind string, doc AlertDoc) error
}

// Service is the integrations store.
type Service struct {
	Store   store.Store
	Secrets *secrets.Service
	Backend Backend
	Now     func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// List returns the kind's objects with decrypted settings.
func (s *Service) List(ctx context.Context, kind string) (items []Item, err error) {
	err = s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		items, err = s.list(ctx, tx, kind)
		return err
	})
	return items, err
}

func (s *Service) list(ctx context.Context, tx store.Tx, kind string) ([]Item, error) {
	rows, err := tx.ListIntegrations(ctx, kind)
	if err != nil {
		return nil, err
	}
	out := make([]Item, 0, len(rows))
	for _, r := range rows {
		it, err := s.decrypt(ctx, tx, r)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, nil
}

// Get returns one object, or store.ErrNotFound.
func (s *Service) Get(ctx context.Context, kind, id string) (it Item, err error) {
	err = s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		it, err = s.get(ctx, tx, kind, id)
		return err
	})
	return it, err
}

func (s *Service) get(ctx context.Context, tx store.Tx, kind, id string) (Item, error) {
	r, err := tx.GetIntegration(ctx, kind, id)
	if err != nil {
		return Item{}, err
	}
	return s.decrypt(ctx, tx, r)
}

func (s *Service) decrypt(ctx context.Context, tx store.Tx, r store.Integration) (Item, error) {
	pt, err := s.Secrets.Open(ctx, tx, r.SecretID, secretPurpose)
	if err != nil {
		return Item{}, fmt.Errorf("decrypting settings of %s %q: %w", r.Kind, r.ID, err)
	}
	return Item{Integration: r, Settings: pt}, nil
}

// Put creates or replaces an object inside tx, so the caller can audit the
// change in the same transaction. Masked values in in.Settings keep the stored
// ones. It returns the stored object with its real (unmasked) settings.
func (s *Service) Put(ctx context.Context, tx store.Tx, kind, id string, in Input) (Item, error) {
	if !idPattern.MatchString(id) {
		return Item{}, invalid("id must match %s", idPattern)
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		return Item{}, invalid("name must be 1-64 characters")
	}
	old, err := s.get(ctx, tx, kind, id)
	exists := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return Item{}, err
	}
	var prev json.RawMessage
	if exists {
		prev = old.Settings
	}
	settings, err := UnmaskInto(prev, in.Settings)
	if err != nil {
		return Item{}, err
	}
	in.Settings = settings
	if err := s.validate(ctx, tx, kind, in); err != nil {
		return Item{}, err
	}

	secretID, err := s.Secrets.Seal(ctx, tx, secretPurpose, in.Settings)
	if err != nil {
		return Item{}, err
	}
	now := s.now()
	rec := store.Integration{
		Kind: kind, ID: id, Name: in.Name, Type: in.Type, Stream: in.Stream, Enabled: in.Enabled,
		SecretID: secretID, CreatedAt: now, UpdatedAt: now,
	}
	if exists {
		rec.CreatedAt = old.CreatedAt
		err = tx.UpdateIntegration(ctx, rec)
	} else {
		err = tx.InsertIntegration(ctx, rec)
	}
	if err != nil {
		return Item{}, err
	}
	if exists {
		if err := tx.DeleteSecret(ctx, old.SecretID); err != nil {
			return Item{}, fmt.Errorf("removing replaced settings: %w", err)
		}
	}
	return Item{Integration: rec, Settings: in.Settings}, nil
}

// Delete removes an object and its encrypted settings inside tx. A channel
// that an alert rule still notifies cannot be deleted.
func (s *Service) Delete(ctx context.Context, tx store.Tx, kind, id string) error {
	r, err := tx.GetIntegration(ctx, kind, id)
	if err != nil {
		return err
	}
	if kind == store.IntegrationChannel {
		rules, err := s.list(ctx, tx, store.IntegrationAlertRule)
		if err != nil {
			return err
		}
		var users []string
		for _, rule := range rules {
			var d AlertDoc
			if json.Unmarshal(rule.Settings, &d) == nil && slices.Contains(d.ChannelIDs, id) {
				users = append(users, rule.Name)
			}
		}
		if len(users) > 0 {
			return fmt.Errorf("%w: the channel is used by alert rules %s", ErrInUse, strings.Join(users, ", "))
		}
	}
	if err := tx.DeleteIntegration(ctx, kind, id); err != nil {
		return err
	}
	if err := tx.DeleteSecret(ctx, r.SecretID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("removing settings: %w", err)
	}
	return nil
}

func (s *Service) validate(ctx context.Context, tx store.Tx, kind string, in Input) error {
	if !json.Valid(in.Settings) || len(in.Settings) == 0 || in.Settings[0] != '{' {
		return invalid("settings must be a JSON object")
	}
	switch kind {
	case store.IntegrationExporter:
		if !slices.Contains(s.Backend.ExporterTypes(), in.Type) {
			return invalid("unknown exporter type %q", in.Type)
		}
		switch in.Stream {
		case "events", "audit", "both":
		default:
			return invalid("stream must be events, audit or both")
		}
		if err := s.Backend.ValidateExporter(in.Type, in.Stream, in.Settings); err != nil {
			return invalid("%v", err)
		}
	case store.IntegrationChannel:
		if !slices.Contains(s.Backend.ChannelKinds(), in.Type) {
			return invalid("unknown channel type %q", in.Type)
		}
		if err := s.Backend.ValidateChannel(in.Type, in.Settings); err != nil {
			return invalid("%v", err)
		}
	case store.IntegrationAlertRule:
		if !slices.Contains(s.Backend.AlertKinds(), in.Type) {
			return invalid("unknown alert kind %q", in.Type)
		}
		var d AlertDoc
		if err := json.Unmarshal(in.Settings, &d); err != nil {
			return invalid("malformed alert rule settings")
		}
		if err := s.Backend.ValidateAlertRule(in.Type, d); err != nil {
			return invalid("%v", err)
		}
		return s.checkChannels(ctx, tx, d.ChannelIDs)
	default:
		return invalid("unknown kind %q", kind)
	}
	return nil
}

func (s *Service) checkChannels(ctx context.Context, tx store.Tx, ids []string) error {
	chans, err := tx.ListIntegrations(ctx, store.IntegrationChannel)
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(chans))
	for _, c := range chans {
		known[c.ID] = true
	}
	for _, id := range ids {
		if !known[id] {
			return invalid("notification channel %q does not exist", id)
		}
	}
	return nil
}

// Test checks a configuration without saving it. For an existing object, masked
// values are filled from the stored settings.
func (s *Service) Test(ctx context.Context, kind, existingID string, in Input) error {
	settings := in.Settings
	if existingID != "" {
		old, err := s.Get(ctx, kind, existingID)
		if err != nil {
			return err
		}
		if settings, err = UnmaskInto(old.Settings, in.Settings); err != nil {
			return err
		}
	} else if bytesContainMasked(settings) {
		return invalid("a masked value needs an existing object to take it from")
	}
	if !json.Valid(settings) {
		return invalid("settings must be a JSON object")
	}
	switch kind {
	case store.IntegrationExporter:
		if !slices.Contains(s.Backend.ExporterTypes(), in.Type) {
			return invalid("unknown exporter type %q", in.Type)
		}
		return s.Backend.TestExporter(ctx, in.Type, in.Stream, settings)
	case store.IntegrationChannel:
		if !slices.Contains(s.Backend.ChannelKinds(), in.Type) {
			return invalid("unknown channel type %q", in.Type)
		}
		return s.Backend.TestChannel(ctx, in.Type, settings)
	}
	return invalid("kind %q has no test", kind)
}

// Mask returns settings with every credential-looking string replaced by
// Masked. Alert rule documents hold no secrets and are returned as stored.
func Mask(kind string, settings json.RawMessage) json.RawMessage {
	if kind == store.IntegrationAlertRule {
		return settings
	}
	var v any
	if err := json.Unmarshal(settings, &v); err != nil {
		return json.RawMessage(`{}`)
	}
	out, err := json.Marshal(maskValue(v, false))
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return out
}

func maskValue(v any, secret bool) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			// Everything under a "headers" map is masked: custom headers
			// routinely carry bearer tokens.
			out[k] = maskValue(e, secret || secretKey.MatchString(k) || strings.EqualFold(k, "headers"))
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = maskValue(e, secret)
		}
		return out
	case string:
		if secret && t != "" {
			return Masked
		}
	}
	return v
}

func bytesContainMasked(b json.RawMessage) bool {
	return strings.Contains(string(b), `"`+Masked+`"`)
}

// UnmaskInto replaces Masked values in next with the value at the same path in
// prev. A masked value with nothing stored behind it is an error: accepting it
// would save the literal mask as the credential.
func UnmaskInto(prev, next json.RawMessage) (json.RawMessage, error) {
	if !bytesContainMasked(next) {
		return next, nil
	}
	var n, p any
	if err := json.Unmarshal(next, &n); err != nil {
		return nil, invalid("settings must be a JSON object")
	}
	if len(prev) > 0 {
		if err := json.Unmarshal(prev, &p); err != nil {
			return nil, fmt.Errorf("decoding stored settings: %w", err)
		}
	}
	merged, err := unmask(p, n, "settings")
	if err != nil {
		return nil, err
	}
	return json.Marshal(merged)
}

func unmask(prev, next any, path string) (any, error) {
	switch t := next.(type) {
	case map[string]any:
		pm, _ := prev.(map[string]any)
		out := make(map[string]any, len(t))
		for k, e := range t {
			v, err := unmask(pm[k], e, path+"."+k)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case []any:
		pa, _ := prev.([]any)
		out := make([]any, len(t))
		for i, e := range t {
			var pe any
			if i < len(pa) {
				pe = pa[i]
			}
			v, err := unmask(pe, e, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	case string:
		if t == Masked {
			ps, ok := prev.(string)
			if !ok {
				return nil, invalid("%s is masked but nothing is stored for it; send the real value", path)
			}
			return ps, nil
		}
	}
	return next, nil
}

// AlertState is the live state of one alert rule, for the dashboard.
type AlertState struct {
	RuleID        string
	Firing        bool
	Suppressed    uint64
	LastEvaluated time.Time
	LastFired     time.Time
	LastError     string
}
