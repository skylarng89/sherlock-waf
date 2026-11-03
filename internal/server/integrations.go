package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/alerts"
	"github.com/skylarng89/sherlock-waf/internal/exporters"
	"github.com/skylarng89/sherlock-waf/internal/exporters/format"
	"github.com/skylarng89/sherlock-waf/internal/integrations"
	"github.com/skylarng89/sherlock-waf/internal/notify"
	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// integrationRuntime connects the stored exporters, channels and alert rules to
// the running exporter manager and alert engine.
type integrationRuntime struct {
	svc    *integrations.Service
	mgr    *exporters.Manager
	engine *alerts.Engine
	log    *slog.Logger

	mu      sync.Mutex
	senders map[string]cachedSender
}

type cachedSender struct {
	updated time.Time
	sender  notify.Sender
}

func newIntegrationRuntime(svc *integrations.Service, mgr *exporters.Manager, src alerts.Source, log *slog.Logger) *integrationRuntime {
	rt := &integrationRuntime{svc: svc, mgr: mgr, log: log, senders: map[string]cachedSender{}}
	svc.Backend = rt
	rt.engine = alerts.New(alerts.Options{Source: src, Rules: rt.rules, Notifier: rt, Logger: log})
	return rt
}

// Reload applies the stored exporters. It runs at boot and after every change
// made through the API.
func (rt *integrationRuntime) Reload(ctx context.Context) {
	items, err := rt.svc.List(ctx, store.IntegrationExporter)
	if err != nil {
		rt.log.Error("loading exporters", "error", err)
		return
	}
	cfgs := make([]exporters.Config, 0, len(items))
	for _, it := range items {
		cfgs = append(cfgs, exporters.Config{
			ID: it.ID, Name: it.Name, Type: it.Type, Stream: it.Stream, Enabled: it.Enabled, Settings: it.Settings,
		})
	}
	if err := rt.mgr.Apply(cfgs); err != nil {
		rt.log.Error("applying exporters", "error", err)
	}
}

// --- integrations.Backend ---

func (rt *integrationRuntime) ExporterTypes() []string { return rt.mgr.Types() }
func (rt *integrationRuntime) ChannelKinds() []string  { return notify.Kinds() }
func (rt *integrationRuntime) AlertKinds() []string    { return alerts.Kinds() }

func (rt *integrationRuntime) ValidateExporter(typ, stream string, settings json.RawMessage) error {
	return rt.mgr.Validate(exporters.Config{ID: "validate", Type: typ, Stream: stream, Settings: settings})
}

func (rt *integrationRuntime) TestExporter(ctx context.Context, typ, stream string, settings json.RawMessage) error {
	return rt.mgr.Test(ctx, exporters.Config{ID: "test", Type: typ, Stream: stream, Settings: settings})
}

func (rt *integrationRuntime) ValidateChannel(kind string, settings json.RawMessage) error {
	return notify.Validate(kind, settings)
}

func (rt *integrationRuntime) TestChannel(ctx context.Context, kind string, settings json.RawMessage) error {
	return notify.Test(ctx, kind, settings)
}

func (rt *integrationRuntime) ValidateAlertRule(kind string, d integrations.AlertDoc) error {
	return alerts.ValidateRule(alerts.Rule{
		ID: "validate", Name: "validate", Enabled: true, Kind: kind, Params: d.Params,
		Severity: d.Severity, CooldownSeconds: d.CooldownSeconds, ChannelIDs: d.ChannelIDs,
	})
}

// --- alerts ---

func (rt *integrationRuntime) rules(ctx context.Context) ([]alerts.Rule, error) {
	items, err := rt.svc.List(ctx, store.IntegrationAlertRule)
	if err != nil {
		return nil, err
	}
	out := make([]alerts.Rule, 0, len(items))
	for _, it := range items {
		var d integrations.AlertDoc
		if err := json.Unmarshal(it.Settings, &d); err != nil {
			rt.log.Warn("skipping alert rule with unreadable settings", "rule", it.ID)
			continue
		}
		out = append(out, alerts.Rule{
			ID: it.ID, Name: it.Name, Enabled: it.Enabled, Kind: it.Type, Params: d.Params,
			Severity: d.Severity, CooldownSeconds: d.CooldownSeconds, ChannelIDs: d.ChannelIDs,
		})
	}
	return out, nil
}

// Notify implements alerts.Notifier: it resolves the channel at send time, so a
// channel edited or disabled in the dashboard applies to the next alert.
func (rt *integrationRuntime) Notify(ctx context.Context, channelID string, m notify.Message) error {
	it, err := rt.svc.Get(ctx, store.IntegrationChannel, channelID)
	if err != nil {
		return fmt.Errorf("looking up notification channel %q: %w", channelID, err)
	}
	if !it.Enabled {
		return nil
	}
	rt.mu.Lock()
	c, ok := rt.senders[channelID]
	rt.mu.Unlock()
	if !ok || !c.updated.Equal(it.UpdatedAt) {
		s, err := notify.New(it.Type, it.Settings)
		if err != nil {
			return fmt.Errorf("building notification channel %q: %w", channelID, err)
		}
		c = cachedSender{updated: it.UpdatedAt, sender: s}
		rt.mu.Lock()
		rt.senders[channelID] = c
		rt.mu.Unlock()
	}
	return c.sender.Send(ctx, m)
}

func (rt *integrationRuntime) alertStates() []integrations.AlertState {
	rs := rt.engine.Status()
	out := make([]integrations.AlertState, 0, len(rs))
	for _, r := range rs {
		errMsg := r.LastError
		if errMsg == "" {
			errMsg = r.LastNotifyError
		}
		out = append(out, integrations.AlertState{
			RuleID: r.RuleID, Firing: r.Firing, Suppressed: r.Suppressed,
			LastEvaluated: r.LastEvaluated, LastFired: r.LastFired, LastError: errMsg,
		})
	}
	return out
}

func (rt *integrationRuntime) exporterStates() map[string]exporters.Status {
	out := map[string]exporters.Status{}
	for _, s := range rt.mgr.Status() {
		out[s.ID] = s
	}
	return out
}

// auditExporter is the post-commit audit observer that feeds the audit stream
// to exporters. It only writes to each exporter's own spool, so a dead SIEM
// cannot fail or noticeably slow the audited operation.
type auditExporter struct{ mgr *exporters.Manager }

func (a auditExporter) Deliver(_ context.Context, rec extension.AuditRecord) error {
	body, err := json.Marshal(format.AuditDoc{
		Schema: format.AuditSchemaV1, ID: rec.ID, Seq: rec.Seq, At: rec.At,
		ActorType: rec.ActorType, ActorID: rec.ActorID, IP: rec.IP, Action: rec.Action,
		ObjectType: rec.ObjectType, ObjectID: rec.ObjectID, Details: rec.Details,
		PrevHash: rec.PrevHash, Hash: rec.Hash,
	})
	if err != nil {
		return fmt.Errorf("encoding audit record %s: %w", rec.ID, err)
	}
	a.mgr.Offer(extension.ExportRecord{ID: rec.ID, Stream: extension.StreamAudit, At: rec.At, Body: body})
	return nil
}
