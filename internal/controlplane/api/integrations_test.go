package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/integrations"
)

type stubBackend struct{ testErr error }

func (stubBackend) ExporterTypes() []string { return []string{"webhook"} }
func (stubBackend) ChannelKinds() []string  { return []string{"slack"} }
func (stubBackend) AlertKinds() []string    { return []string{"events_dropped"} }
func (stubBackend) ValidateExporter(_, _ string, s json.RawMessage) error {
	if !strings.Contains(string(s), `"url"`) {
		return errors.New("url is required")
	}
	return nil
}

func (b stubBackend) TestExporter(context.Context, string, string, json.RawMessage) error {
	return b.testErr
}
func (stubBackend) ValidateChannel(string, json.RawMessage) error { return nil }
func (b stubBackend) TestChannel(context.Context, string, json.RawMessage) error {
	return b.testErr
}
func (stubBackend) ValidateAlertRule(string, integrations.AlertDoc) error { return nil }

// testHMAC is built at runtime so secret scanners do not flag a fixture.
var testHMAC = strings.Repeat("hmac-test-", 4)

func exporterBody(url string) map[string]any {
	return map[string]any{
		"name": "SIEM", "type": "webhook", "stream": "events", "enabled": true,
		"settings": map[string]any{"url": url, "hmac_secret": testHMAC, "batch": 100},
	}
}

func TestExporterLifecycleMasksSecretsEverywhere(t *testing.T) {
	h := newHarnessWith(t, harnessOpts{integrations: stubBackend{}})
	admin, viewer := h.mint(h.admin, "full"), h.mint(h.view, "full")

	put := admin.do("PUT", "/exporters/siem", exporterBody("https://siem.example/hook?token=abc"))
	require.Equal(t, http.StatusOK, put.Status, string(put.Body))
	for _, leak := range []string{"token=abc", "hmac-test-"} {
		assert.NotContains(t, string(put.Body), leak, "the response never echoes a secret")
	}
	assert.Equal(t, 1, h.changed, "the runtime is told to reload")

	list := admin.do("GET", "/exporters", nil)
	require.Equal(t, http.StatusOK, list.Status)
	assert.NotContains(t, string(list.Body), "token=abc")
	assert.Contains(t, string(list.Body), `"batch":100`)
	assert.Contains(t, string(list.Body), integrations.Masked)

	assert.Equal(t, http.StatusOK, viewer.do("GET", "/exporters", nil).Status, "viewers may look")
	assert.Equal(t, http.StatusForbidden, viewer.do("PUT", "/exporters/siem", exporterBody("https://x.example")).Status)
	assert.Equal(t, http.StatusForbidden, viewer.do("DELETE", "/exporters/siem", nil).Status)
	assert.Equal(t, http.StatusForbidden, viewer.do("POST", "/exporters/test", map[string]any{"type": "webhook", "settings": map[string]any{}}).Status)

	// Sending the masked values back keeps the stored ones.
	edit := exporterBody("********")
	edit["settings"].(map[string]any)["hmac_secret"] = "********"
	edit["name"] = "SIEM 2"
	require.Equal(t, http.StatusOK, admin.do("PUT", "/exporters/siem", edit).Status)
	it, err := (&integrations.Service{Store: h.st, Secrets: h.secrets, Backend: stubBackend{}}).Get(t.Context(), "exporter", "siem")
	require.NoError(t, err)
	assert.Contains(t, string(it.Settings), "token=abc")

	// The audit trail records that it happened, not the settings.
	var details strings.Builder
	for _, e := range admin.do("GET", "/audit", nil).JSON(t)["items"].([]any) {
		b, _ := json.Marshal(e)
		details.Write(b)
	}
	assert.Contains(t, details.String(), "exporter.put")
	assert.NotContains(t, details.String(), "token=abc")
	assert.NotContains(t, details.String(), "hmac-test-")

	assert.Equal(t, http.StatusNoContent, admin.do("DELETE", "/exporters/siem", nil).Status)
	assert.Equal(t, http.StatusNotFound, admin.do("DELETE", "/exporters/siem", nil).Status)
}

func TestExporterValidation(t *testing.T) {
	h := newHarnessWith(t, harnessOpts{integrations: stubBackend{}})
	admin := h.mint(h.admin, "full")

	bad := exporterBody("")
	delete(bad["settings"].(map[string]any), "url")
	r := admin.do("PUT", "/exporters/siem", bad)
	assert.Equal(t, http.StatusUnprocessableEntity, r.Status)
	assert.Contains(t, string(r.Body), "url is required")

	unknown := exporterBody("https://x.example")
	unknown["type"] = "carrier-pigeon"
	assert.Equal(t, http.StatusUnprocessableEntity, admin.do("PUT", "/exporters/siem", unknown).Status)
	assert.Equal(t, http.StatusUnprocessableEntity, admin.do("PUT", "/exporters/Bad_ID", exporterBody("https://x.example")).Status, "the id pattern is part of the schema")
	assert.Equal(t, http.StatusUnprocessableEntity, admin.do("PUT", "/exporters/new", exporterBody("********")).Status, "a mask with nothing behind it is refused")
	assert.Zero(t, h.changed, "nothing changed, nothing reloaded")
}

func TestIntegrationTestEndpoint(t *testing.T) {
	h := newHarnessWith(t, harnessOpts{integrations: stubBackend{testErr: errors.New("connection refused")}})
	admin := h.mint(h.admin, "full")
	r := admin.do("POST", "/exporters/test", map[string]any{"type": "webhook", "settings": map[string]any{"url": "https://x.example"}})
	require.Equal(t, http.StatusOK, r.Status, "a failed check is a result, not an HTTP error")
	assert.Equal(t, false, r.JSON(t)["ok"])
	assert.Equal(t, "connection refused", r.JSON(t)["error"])

	r = admin.do("POST", "/exporters/test", map[string]any{"type": "webhook", "settings": map[string]any{"url": "********"}})
	assert.Equal(t, http.StatusUnprocessableEntity, r.Status, "masked values need a saved object")
	r = admin.do("POST", "/exporters/test", map[string]any{"id": "ghost", "type": "webhook", "settings": map[string]any{"url": "********"}})
	assert.Equal(t, http.StatusNotFound, r.Status)
}

func TestAlertRulesAndChannelsFlow(t *testing.T) {
	h := newHarnessWith(t, harnessOpts{integrations: stubBackend{}})
	admin := h.mint(h.admin, "full")
	rule := map[string]any{
		"name": "Drops", "kind": "events_dropped", "enabled": true, "severity": "warning",
		"cooldown_seconds": 900, "channel_ids": []string{"ops"}, "params": map[string]any{},
	}
	assert.Equal(t, http.StatusUnprocessableEntity, admin.do("PUT", "/alert-rules/drops", rule).Status, "unknown channel")

	ch := map[string]any{"name": "Ops", "type": "slack", "enabled": true, "settings": map[string]any{"webhook_url": "https://hooks.example/T/B/secret"}}
	put := admin.do("PUT", "/notification-channels/ops", ch)
	require.Equal(t, http.StatusOK, put.Status, string(put.Body))
	assert.NotContains(t, string(put.Body), "hooks.example", "a webhook URL is a credential")

	require.Equal(t, http.StatusOK, admin.do("PUT", "/alert-rules/drops", rule).Status)
	got := admin.do("GET", "/alert-rules", nil).JSON(t)["items"].([]any)
	require.Len(t, got, 1)
	assert.Equal(t, "warning", got[0].(map[string]any)["severity"])

	assert.Equal(t, http.StatusConflict, admin.do("DELETE", "/notification-channels/ops", nil).Status, "still used by a rule")
	require.Equal(t, http.StatusNoContent, admin.do("DELETE", "/alert-rules/drops", nil).Status)
	require.Equal(t, http.StatusNoContent, admin.do("DELETE", "/notification-channels/ops", nil).Status)

	types := admin.do("GET", "/integrations/types", nil).JSON(t)
	assert.Equal(t, []any{"webhook"}, types["exporters"])
	assert.Equal(t, http.StatusOK, admin.do("GET", "/alerts/status", nil).Status)
}

func TestIntegrationsAreUnavailableWhenNotConfigured(t *testing.T) {
	h := newHarness(t)
	assert.Equal(t, http.StatusServiceUnavailable, h.mint(h.admin, "full").do("GET", "/exporters", nil).Status)
}
