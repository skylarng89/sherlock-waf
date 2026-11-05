package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/secrets"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

type fakeBackend struct {
	validateErr error
	tested      json.RawMessage
}

func (fakeBackend) ExporterTypes() []string { return []string{"webhook"} }
func (fakeBackend) ChannelKinds() []string  { return []string{"slack", "webhook"} }
func (fakeBackend) AlertKinds() []string    { return []string{"events_dropped"} }
func (b fakeBackend) ValidateExporter(string, string, json.RawMessage) error {
	return b.validateErr
}

func (b *fakeBackend) TestExporter(_ context.Context, _, _ string, s json.RawMessage) error {
	b.tested = s
	return nil
}

func (b fakeBackend) ValidateChannel(string, json.RawMessage) error               { return b.validateErr }
func (b *fakeBackend) TestChannel(context.Context, string, json.RawMessage) error { return nil }
func (b fakeBackend) ValidateAlertRule(string, AlertDoc) error                    { return b.validateErr }

func newService(t *testing.T) (*Service, *fakeBackend) {
	t.Helper()
	st, err := store.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "i.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	key, err := secrets.LoadKey(t.Context(), st, t.TempDir(), nil)
	require.NoError(t, err)
	b := &fakeBackend{}
	return &Service{Store: st, Secrets: secrets.New(key), Backend: b}, b
}

func put(t *testing.T, s *Service, kind, id string, in Input) (Item, error) {
	t.Helper()
	var it Item
	err := s.Store.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
		it, err = s.Put(ctx, tx, kind, id, in)
		return err
	})
	return it, err
}

func del(s *Service, kind, id string) error {
	return s.Store.Tx(context.Background(), func(ctx context.Context, tx store.Tx) error { return s.Delete(ctx, tx, kind, id) })
}

var hook = Input{
	Name: "SIEM", Type: "webhook", Stream: "events", Enabled: true,
	Settings: json.RawMessage(`{"url":"https://siem.example/in?token=abc","hmac_secret":"supersecret","headers":{"X-Api":"k1"},"batch":100}`),
}

func TestSettingsAreEncryptedAtRestAndMaskedForTheAPI(t *testing.T) {
	s, _ := newService(t)
	it, err := put(t, s, store.IntegrationExporter, "siem", hook)
	require.NoError(t, err)

	var raw store.Secret
	require.NoError(t, s.Store.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
		raw, err = tx.GetSecret(ctx, it.SecretID)
		return err
	}))
	assert.NotContains(t, string(raw.Ciphertext), "supersecret", "the secret is sealed, not stored in clear")

	got, err := s.Get(t.Context(), store.IntegrationExporter, "siem")
	require.NoError(t, err)
	assert.JSONEq(t, string(hook.Settings), string(got.Settings), "the service itself sees the real values")

	masked := string(Mask(store.IntegrationExporter, got.Settings))
	for _, leak := range []string{"supersecret", "token=abc", "k1"} {
		assert.NotContains(t, masked, leak)
	}
	assert.Contains(t, masked, `"batch":100`, "non-secret values stay visible")
}

func TestMaskedValueKeepsTheStoredOneOnUpdate(t *testing.T) {
	s, _ := newService(t)
	_, err := put(t, s, store.IntegrationExporter, "siem", hook)
	require.NoError(t, err)

	edit := hook
	edit.Name = "Renamed"
	edit.Settings = json.RawMessage(`{"url":"********","hmac_secret":"********","headers":{"X-Api":"********"},"batch":250}`)
	_, err = put(t, s, store.IntegrationExporter, "siem", edit)
	require.NoError(t, err)

	got, err := s.Get(t.Context(), store.IntegrationExporter, "siem")
	require.NoError(t, err)
	assert.JSONEq(t, `{"url":"https://siem.example/in?token=abc","hmac_secret":"supersecret","headers":{"X-Api":"k1"},"batch":250}`, string(got.Settings))
	assert.Equal(t, "Renamed", got.Name)
}

func TestMaskedValueWithNothingStoredIsRefused(t *testing.T) {
	s, _ := newService(t)
	in := hook
	in.Settings = json.RawMessage(`{"url":"********","hmac_secret":"x"}`)
	_, err := put(t, s, store.IntegrationExporter, "new", in)
	require.ErrorIs(t, err, ErrInvalid, "the literal mask must never become a credential")
}

func TestReplacingSettingsDeletesTheOldSecret(t *testing.T) {
	s, _ := newService(t)
	first, err := put(t, s, store.IntegrationExporter, "siem", hook)
	require.NoError(t, err)
	second, err := put(t, s, store.IntegrationExporter, "siem", hook)
	require.NoError(t, err)
	require.NotEqual(t, first.SecretID, second.SecretID)
	require.NoError(t, s.Store.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		_, err := tx.GetSecret(ctx, first.SecretID)
		assert.ErrorIs(t, err, store.ErrNotFound, "the replaced ciphertext does not linger")
		return nil
	}))
}

func TestValidation(t *testing.T) {
	s, b := newService(t)
	cases := map[string]struct {
		id string
		in func(Input) Input
	}{
		"bad id":       {"Bad ID", func(i Input) Input { return i }},
		"empty name":   {"ok", func(i Input) Input { i.Name = " "; return i }},
		"unknown type": {"ok", func(i Input) Input { i.Type = "carrier-pigeon"; return i }},
		"bad stream":   {"ok", func(i Input) Input { i.Stream = "all"; return i }},
		"not object":   {"ok", func(i Input) Input { i.Settings = json.RawMessage(`[1]`); return i }},
		"invalid json": {"ok", func(i Input) Input { i.Settings = json.RawMessage(`{`); return i }},
	}
	for name, c := range cases {
		_, err := put(t, s, store.IntegrationExporter, c.id, c.in(hook))
		assert.ErrorIs(t, err, ErrInvalid, name)
	}
	b.validateErr = errors.New("address is required")
	_, err := put(t, s, store.IntegrationExporter, "ok", hook)
	assert.ErrorContains(t, err, "address is required", "type validation errors reach the caller")
}

func TestAlertRulesNeedExistingChannelsAndBlockChannelDeletion(t *testing.T) {
	s, _ := newService(t)
	rule := Input{
		Name: "Drops", Type: "events_dropped", Enabled: true,
		Settings: json.RawMessage(`{"severity":"warning","cooldown_seconds":900,"channel_ids":["ops"],"params":{}}`),
	}
	_, err := put(t, s, store.IntegrationAlertRule, "drops", rule)
	require.ErrorIs(t, err, ErrInvalid, "unknown channel")

	_, err = put(t, s, store.IntegrationChannel, "ops", Input{Name: "Ops", Type: "slack", Enabled: true, Settings: json.RawMessage(`{"webhook_url":"https://hooks.example/x"}`)})
	require.NoError(t, err)
	_, err = put(t, s, store.IntegrationAlertRule, "drops", rule)
	require.NoError(t, err)

	err = del(s, store.IntegrationChannel, "ops")
	require.ErrorIs(t, err, ErrInUse)
	assert.ErrorContains(t, err, "Drops")
	require.NoError(t, del(s, store.IntegrationAlertRule, "drops"))
	require.NoError(t, del(s, store.IntegrationChannel, "ops"))
	assert.ErrorIs(t, del(s, store.IntegrationChannel, "ops"), store.ErrNotFound)
}

func TestTestFillsMaskedValuesFromTheStoredObject(t *testing.T) {
	s, b := newService(t)
	_, err := put(t, s, store.IntegrationExporter, "siem", hook)
	require.NoError(t, err)

	in := Input{Type: "webhook", Stream: "events", Settings: json.RawMessage(`{"url":"********","hmac_secret":"********"}`)}
	require.NoError(t, s.Test(t.Context(), store.IntegrationExporter, "siem", in))
	assert.True(t, strings.Contains(string(b.tested), "supersecret"))

	err = s.Test(t.Context(), store.IntegrationExporter, "", in)
	assert.ErrorIs(t, err, ErrInvalid, "an unsaved config cannot use masked values")
	assert.ErrorIs(t, s.Test(t.Context(), store.IntegrationExporter, "ghost", in), store.ErrNotFound)
}
