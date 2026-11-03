package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
	"github.com/skylarng89/sherlock-waf/internal/exporters"
	"github.com/skylarng89/sherlock-waf/internal/integrations"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// maxTestErrorLen keeps a failed connectivity check's message short; backends
// already keep credentials out of their errors.
const maxTestErrorLen = 300

func (h *handlers) integrationsService() (*integrations.Service, error) {
	if h.s.Integrations == nil {
		return nil, newProblem(503, "unavailable", "Unavailable", "Exporters and alerts are not enabled on this node.")
	}
	return h.s.Integrations, nil
}

// integrationErr maps the service's sentinels to problems.
func integrationErr(err error) error {
	switch {
	case errors.Is(err, integrations.ErrInvalid):
		return errUnprocessed(strings.TrimPrefix(err.Error(), integrations.ErrInvalid.Error()+": "))
	case errors.Is(err, integrations.ErrInUse):
		return errConflict(strings.TrimPrefix(err.Error(), integrations.ErrInUse.Error()+": "))
	case errors.Is(err, store.ErrConflict):
		return errConflict("An object with that id or name already exists.")
	}
	return err
}

func settingsJSON(m map[string]interface{}) (json.RawMessage, error) {
	if m == nil {
		return json.RawMessage(`{}`), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, errBadRequest("settings must be a JSON object")
	}
	return b, nil
}

func settingsMap(kind string, raw json.RawMessage) map[string]interface{} {
	out := map[string]interface{}{}
	_ = json.Unmarshal(integrations.Mask(kind, raw), &out)
	return out
}

// put runs the create-or-replace path shared by the three kinds, auditing the
// change in the same transaction. Audit details carry no settings.
func (h *handlers) putIntegration(ctx context.Context, action, kind, id string, in integrations.Input) (integrations.Item, error) {
	svc, err := h.integrationsService()
	if err != nil {
		return integrations.Item{}, err
	}
	var it integrations.Item
	err = h.audited(ctx, action, kind, id, map[string]any{"type": in.Type, "stream": in.Stream, "enabled": in.Enabled}, func(ctx context.Context, tx store.Tx) (err error) {
		it, err = svc.Put(ctx, tx, kind, id, in)
		return err
	})
	if err != nil {
		return integrations.Item{}, integrationErr(err)
	}
	h.integrationsChanged(ctx)
	return it, nil
}

func (h *handlers) deleteIntegration(ctx context.Context, action, kind, id string) error {
	svc, err := h.integrationsService()
	if err != nil {
		return err
	}
	if err := h.audited(ctx, action, kind, id, nil, func(ctx context.Context, tx store.Tx) error {
		return svc.Delete(ctx, tx, kind, id)
	}); err != nil {
		return integrationErr(err)
	}
	h.integrationsChanged(ctx)
	return nil
}

func (h *handlers) integrationsChanged(ctx context.Context) {
	if h.s.IntegrationsChanged != nil {
		h.s.IntegrationsChanged(context.WithoutCancel(ctx))
	}
}

func (h *handlers) testIntegration(ctx context.Context, kind string, b *apigen.TestIntegration) (apigen.TestResult, error) {
	svc, err := h.integrationsService()
	if err != nil {
		return apigen.TestResult{}, err
	}
	if b == nil {
		return apigen.TestResult{}, errBadRequest("A JSON body is required.")
	}
	settings, err := settingsJSON(b.Settings)
	if err != nil {
		return apigen.TestResult{}, err
	}
	in := integrations.Input{Type: b.Type, Settings: settings}
	if b.Stream != nil {
		in.Stream = string(*b.Stream)
	}
	id := ""
	if b.Id != nil {
		id = *b.Id
	}
	if err := svc.Test(ctx, kind, id, in); err != nil {
		if errors.Is(err, integrations.ErrInvalid) || errors.Is(err, store.ErrNotFound) {
			return apigen.TestResult{}, integrationErr(err)
		}
		msg := err.Error()
		if len(msg) > maxTestErrorLen {
			msg = msg[:maxTestErrorLen] + "…"
		}
		return apigen.TestResult{Ok: false, Error: &msg}, nil
	}
	return apigen.TestResult{Ok: true}, nil
}

func (h *handlers) ListIntegrationTypes(context.Context, apigen.ListIntegrationTypesRequestObject) (apigen.ListIntegrationTypesResponseObject, error) {
	svc, err := h.integrationsService()
	if err != nil {
		return nil, err
	}
	return apigen.ListIntegrationTypes200JSONResponse(apigen.IntegrationTypes{
		Exporters: svc.Backend.ExporterTypes(), Channels: svc.Backend.ChannelKinds(), AlertKinds: svc.Backend.AlertKinds(),
	}), nil
}

// --- exporters ---

func (h *handlers) exporterDTO(it integrations.Item, status map[string]exporters.Status) apigen.Exporter {
	d := apigen.Exporter{
		Id: it.ID, Name: it.Name, Type: it.Type, Stream: apigen.ExporterStream(it.Stream), Enabled: it.Enabled,
		Settings: settingsMap(it.Kind, it.Settings), CreatedAt: it.CreatedAt, UpdatedAt: it.UpdatedAt,
	}
	if st, ok := status[it.ID]; ok {
		d.Status = &apigen.ExporterStatus{
			Running: true, Sent: int64(st.Sent), SendFailures: int64(st.SendFailures), //nolint:gosec // counters stay far below 2^63
			Dropped: int64(st.Lagged + st.Discarded + st.SpoolDropped), Pending: st.Pending, SpoolBytes: st.SpoolBytes, //nolint:gosec // as above
			LastSuccess: ptrTime(st.LastSuccess), LastErrorAt: ptrTime(st.LastErrorAt),
		}
		if st.LastError != "" {
			e := st.LastError
			d.Status.LastError = &e
		}
	} else {
		d.Status = &apigen.ExporterStatus{Running: false}
	}
	return d
}

func (h *handlers) ListExporters(ctx context.Context, _ apigen.ListExportersRequestObject) (apigen.ListExportersResponseObject, error) {
	svc, err := h.integrationsService()
	if err != nil {
		return nil, err
	}
	items, err := svc.List(ctx, store.IntegrationExporter)
	if err != nil {
		return nil, err
	}
	var status map[string]exporters.Status
	if h.s.ExporterStatuses != nil {
		status = h.s.ExporterStatuses()
	}
	out := apigen.ExporterList{Items: make([]apigen.Exporter, 0, len(items))}
	for _, it := range items {
		out.Items = append(out.Items, h.exporterDTO(it, status))
	}
	return apigen.ListExporters200JSONResponse(out), nil
}

func (h *handlers) PutExporter(ctx context.Context, req apigen.PutExporterRequestObject) (apigen.PutExporterResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	settings, err := settingsJSON(b.Settings)
	if err != nil {
		return nil, err
	}
	it, err := h.putIntegration(ctx, "exporter.put", store.IntegrationExporter, req.Id, integrations.Input{
		Name: b.Name, Type: b.Type, Stream: string(b.Stream), Enabled: b.Enabled, Settings: settings,
	})
	if err != nil {
		return nil, err
	}
	var status map[string]exporters.Status
	if h.s.ExporterStatuses != nil {
		status = h.s.ExporterStatuses()
	}
	return apigen.PutExporter200JSONResponse(h.exporterDTO(it, status)), nil
}

func (h *handlers) DeleteExporter(ctx context.Context, req apigen.DeleteExporterRequestObject) (apigen.DeleteExporterResponseObject, error) {
	if err := h.deleteIntegration(ctx, "exporter.delete", store.IntegrationExporter, req.Id); err != nil {
		return nil, err
	}
	return apigen.DeleteExporter204Response{}, nil
}

func (h *handlers) TestExporter(ctx context.Context, req apigen.TestExporterRequestObject) (apigen.TestExporterResponseObject, error) {
	res, err := h.testIntegration(ctx, store.IntegrationExporter, req.Body)
	if err != nil {
		return nil, err
	}
	return apigen.TestExporter200JSONResponse(res), nil
}

// --- notification channels ---

func channelDTO(it integrations.Item) apigen.NotificationChannel {
	return apigen.NotificationChannel{
		Id: it.ID, Name: it.Name, Type: apigen.NotificationChannelType(it.Type), Enabled: it.Enabled,
		Settings: settingsMap(it.Kind, it.Settings), CreatedAt: it.CreatedAt, UpdatedAt: it.UpdatedAt,
	}
}

func (h *handlers) ListNotificationChannels(ctx context.Context, _ apigen.ListNotificationChannelsRequestObject) (apigen.ListNotificationChannelsResponseObject, error) {
	svc, err := h.integrationsService()
	if err != nil {
		return nil, err
	}
	items, err := svc.List(ctx, store.IntegrationChannel)
	if err != nil {
		return nil, err
	}
	out := apigen.NotificationChannelList{Items: make([]apigen.NotificationChannel, 0, len(items))}
	for _, it := range items {
		out.Items = append(out.Items, channelDTO(it))
	}
	return apigen.ListNotificationChannels200JSONResponse(out), nil
}

func (h *handlers) PutNotificationChannel(ctx context.Context, req apigen.PutNotificationChannelRequestObject) (apigen.PutNotificationChannelResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	settings, err := settingsJSON(b.Settings)
	if err != nil {
		return nil, err
	}
	it, err := h.putIntegration(ctx, "notification_channel.put", store.IntegrationChannel, req.Id, integrations.Input{
		Name: b.Name, Type: string(b.Type), Enabled: b.Enabled, Settings: settings,
	})
	if err != nil {
		return nil, err
	}
	return apigen.PutNotificationChannel200JSONResponse(channelDTO(it)), nil
}

func (h *handlers) DeleteNotificationChannel(ctx context.Context, req apigen.DeleteNotificationChannelRequestObject) (apigen.DeleteNotificationChannelResponseObject, error) {
	if err := h.deleteIntegration(ctx, "notification_channel.delete", store.IntegrationChannel, req.Id); err != nil {
		return nil, err
	}
	return apigen.DeleteNotificationChannel204Response{}, nil
}

func (h *handlers) TestNotificationChannel(ctx context.Context, req apigen.TestNotificationChannelRequestObject) (apigen.TestNotificationChannelResponseObject, error) {
	res, err := h.testIntegration(ctx, store.IntegrationChannel, req.Body)
	if err != nil {
		return nil, err
	}
	return apigen.TestNotificationChannel200JSONResponse(res), nil
}

// --- alert rules ---

func alertRuleDTO(it integrations.Item) apigen.AlertRule {
	var doc integrations.AlertDoc
	_ = json.Unmarshal(it.Settings, &doc)
	params := map[string]interface{}{}
	_ = json.Unmarshal(doc.Params, &params)
	ids := doc.ChannelIDs
	if ids == nil {
		ids = []string{}
	}
	return apigen.AlertRule{
		Id: it.ID, Name: it.Name, Kind: apigen.AlertRuleKind(it.Type), Enabled: it.Enabled,
		Severity: apigen.AlertRuleSeverity(doc.Severity), CooldownSeconds: doc.CooldownSeconds,
		ChannelIds: ids, Params: params, CreatedAt: it.CreatedAt, UpdatedAt: it.UpdatedAt,
	}
}

func (h *handlers) ListAlertRules(ctx context.Context, _ apigen.ListAlertRulesRequestObject) (apigen.ListAlertRulesResponseObject, error) {
	svc, err := h.integrationsService()
	if err != nil {
		return nil, err
	}
	items, err := svc.List(ctx, store.IntegrationAlertRule)
	if err != nil {
		return nil, err
	}
	out := apigen.AlertRuleList{Items: make([]apigen.AlertRule, 0, len(items))}
	for _, it := range items {
		out.Items = append(out.Items, alertRuleDTO(it))
	}
	return apigen.ListAlertRules200JSONResponse(out), nil
}

func (h *handlers) PutAlertRule(ctx context.Context, req apigen.PutAlertRuleRequestObject) (apigen.PutAlertRuleResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, errBadRequest("A JSON body is required.")
	}
	params, err := settingsJSON(b.Params)
	if err != nil {
		return nil, err
	}
	doc, err := json.Marshal(integrations.AlertDoc{
		Severity: string(b.Severity), CooldownSeconds: b.CooldownSeconds, ChannelIDs: b.ChannelIds, Params: params,
	})
	if err != nil {
		return nil, err
	}
	it, err := h.putIntegration(ctx, "alert_rule.put", store.IntegrationAlertRule, req.Id, integrations.Input{
		Name: b.Name, Type: string(b.Kind), Enabled: b.Enabled, Settings: doc,
	})
	if err != nil {
		return nil, err
	}
	return apigen.PutAlertRule200JSONResponse(alertRuleDTO(it)), nil
}

func (h *handlers) DeleteAlertRule(ctx context.Context, req apigen.DeleteAlertRuleRequestObject) (apigen.DeleteAlertRuleResponseObject, error) {
	if err := h.deleteIntegration(ctx, "alert_rule.delete", store.IntegrationAlertRule, req.Id); err != nil {
		return nil, err
	}
	return apigen.DeleteAlertRule204Response{}, nil
}

func (h *handlers) GetAlertStatus(context.Context, apigen.GetAlertStatusRequestObject) (apigen.GetAlertStatusResponseObject, error) {
	out := apigen.AlertStatusList{Items: []apigen.AlertStatus{}}
	if h.s.AlertStatuses != nil {
		for _, st := range h.s.AlertStatuses() {
			item := apigen.AlertStatus{
				RuleId: st.RuleID, Firing: st.Firing, Suppressed: int64(st.Suppressed), //nolint:gosec // counter
				LastEvaluated: ptrTime(st.LastEvaluated), LastFired: ptrTime(st.LastFired),
			}
			if st.LastError != "" {
				e := st.LastError
				item.LastError = &e
			}
			out.Items = append(out.Items, item)
		}
	}
	return apigen.GetAlertStatus200JSONResponse(out), nil
}
