package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/alerts"
	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/exporters"
	"github.com/skylarng89/sherlock-waf/internal/exporters/builtin"
	"github.com/skylarng89/sherlock-waf/internal/integrations"
	"github.com/skylarng89/sherlock-waf/internal/notify"
	"github.com/skylarng89/sherlock-waf/internal/secrets"
	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// receiver collects request bodies posted to it.
type receiver struct {
	mu     sync.Mutex
	bodies []string
	srv    *httptest.Server
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies = append(r.bodies, string(b))
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

func (r *receiver) all() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.bodies, "\n")
}

type fakeSource struct {
	mu      sync.Mutex
	dropped uint64
}

func (f *fakeSource) bump() { f.mu.Lock(); f.dropped += 5; f.mu.Unlock() }
func (f *fakeSource) EventsDropped(context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dropped, nil
}

func (*fakeSource) BlocksBySite(context.Context, time.Time, time.Time) ([]alerts.SiteCount, error) {
	return nil, nil
}

func (*fakeSource) TopCountries(context.Context, string, time.Time, time.Time) ([]alerts.CountryCount, error) {
	return nil, nil
}
func (*fakeSource) CertExpiries(context.Context) ([]alerts.CertExpiry, error) { return nil, nil }
func (*fakeSource) FeedStatuses(context.Context) ([]alerts.FeedStatus, error) { return nil, nil }
func (*fakeSource) Upstreams(context.Context) ([]alerts.Upstream, error)      { return nil, nil }

func newRuntime(t *testing.T, bus *events.Bus, src alerts.Source) (*integrationRuntime, *integrations.Service) {
	t.Helper()
	st, err := store.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "i.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	key, err := secrets.LoadKey(t.Context(), st, t.TempDir(), nil)
	require.NoError(t, err)

	mgr := exporters.NewManager(t.Context(), bus, t.TempDir(), exporters.RunnerOptions{Poll: 5 * time.Millisecond, BackoffMin: time.Millisecond}, nil)
	for _, typ := range builtin.Types("test") {
		require.NoError(t, mgr.RegisterType(typ))
	}
	t.Cleanup(mgr.Stop)
	svc := &integrations.Service{Store: st, Secrets: secrets.New(key)}
	rt := newIntegrationRuntime(svc, mgr, src, nil)
	return rt, svc
}

func webhookSettings(t *testing.T, url string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{"url": url, "allow_http": true, "hmac_secret": testHMAC})
	require.NoError(t, err)
	return b
}

func putItem(t *testing.T, svc *integrations.Service, kind, id string, in integrations.Input) {
	t.Helper()
	require.NoError(t, svc.Store.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		_, err := svc.Put(ctx, tx, kind, id, in)
		return err
	}))
}

func TestStoredExporterReceivesEventsAndAuditRecords(t *testing.T) {
	bus := events.NewBus(256)
	rt, svc := newRuntime(t, bus, &fakeSource{})
	siem := newReceiver(t)
	putItem(t, svc, store.IntegrationExporter, "siem", integrations.Input{
		Name: "SIEM", Type: "webhook", Stream: "both", Enabled: true,
		Settings: webhookSettings(t, siem.srv.URL),
	})
	rt.Reload(t.Context())
	require.Len(t, rt.mgr.Status(), 1)

	bus.Publish(&events.Event{ID: "01EVENT", Schema: events.SchemaV1, TS: time.Now(), SiteID: "shop", Action: "block"})
	require.NoError(t, auditExporter{mgr: rt.mgr}.Deliver(t.Context(), extension.AuditRecord{ID: "01AUDIT", Seq: 1, At: time.Now(), Action: "config.apply", Hash: "h"}))

	require.Eventually(t, func() bool {
		all := siem.all()
		return strings.Contains(all, "01EVENT") && strings.Contains(all, "01AUDIT")
	}, 5*time.Second, 10*time.Millisecond)
	assert.Contains(t, siem.all(), "sherlock.audit.v1")
	assert.Contains(t, siem.all(), "sherlock.event.v1")

	// Disabling through the same path stops delivery.
	putItem(t, svc, store.IntegrationExporter, "siem", integrations.Input{
		Name: "SIEM", Type: "webhook", Stream: "both", Enabled: false,
		Settings: webhookSettings(t, siem.srv.URL),
	})
	rt.Reload(t.Context())
	assert.Empty(t, rt.mgr.Status())
}

func TestStoredAlertRuleReachesStoredChannel(t *testing.T) {
	src := &fakeSource{}
	rt, svc := newRuntime(t, events.NewBus(8), src)
	slack := newReceiver(t)
	putItem(t, svc, store.IntegrationChannel, "ops", integrations.Input{
		Name: "Ops", Type: "slack", Enabled: true,
		Settings: json.RawMessage(`{"url":"` + slack.srv.URL + `","allow_http":true}`),
	})
	putItem(t, svc, store.IntegrationAlertRule, "drops", integrations.Input{
		Name: "Events dropped", Type: "events_dropped", Enabled: true,
		Settings: json.RawMessage(`{"severity":"critical","cooldown_seconds":900,"channel_ids":["ops"],"params":{}}`),
	})

	rt.engine.EvaluateOnce(t.Context()) // baseline reading
	rt.engine.Wait()
	assert.Empty(t, slack.all(), "the first reading only sets the baseline")

	src.bump()
	rt.engine.EvaluateOnce(t.Context())
	rt.engine.Wait()
	require.Contains(t, slack.all(), "Events dropped")

	st := rt.alertStates()
	require.Len(t, st, 1)
	assert.Equal(t, "drops", st[0].RuleID)

	src.bump()
	rt.engine.EvaluateOnce(t.Context())
	rt.engine.Wait()
	assert.Equal(t, 1, slack.count(), "the cool-down suppresses the repeat")
}

func TestDisabledChannelIsSkippedAndMissingChannelErrors(t *testing.T) {
	rt, svc := newRuntime(t, events.NewBus(8), &fakeSource{})
	slack := newReceiver(t)
	putItem(t, svc, store.IntegrationChannel, "ops", integrations.Input{
		Name: "Ops", Type: "slack", Enabled: false,
		Settings: json.RawMessage(`{"url":"` + slack.srv.URL + `","allow_http":true}`),
	})
	require.NoError(t, rt.Notify(t.Context(), "ops", alertsMessage()))
	assert.Empty(t, slack.all())
	assert.Error(t, rt.Notify(t.Context(), "ghost", alertsMessage()))
}

// testHMAC is built at runtime so secret scanners do not flag a fixture.
var testHMAC = strings.Repeat("hmac-test-", 4)

func alertsMessage() notify.Message {
	return notify.Message{Title: "t", Body: "b", Severity: notify.SeverityWarning, At: time.Now()}
}
