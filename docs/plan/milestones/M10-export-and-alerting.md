# M10 · SIEM export and alerting

- Phase: 3 · Competitive and finance-ready
- Depends on: M7
- Ships: `v0.8.0`
- Read first: `docs/architecture/events.md`, `docs/architecture/extension-points.md` (ExporterType), PCI DSS 4.0 requirements 6.4.2 and 10.x (summary in `docs/product/vision.md`)

## Goal

Get Sherlock's events into the customer's SOC and alert people when something needs attention.

## Tasks

- [x] **M10-T1** Exporter framework: per-exporter subscriber with own buffer and cursor, retries with backoff, disk-backed spool (bounded) for outages, metrics per exporter, `ExporterType` extension point.
- [x] **M10-T2** Exporters: syslog (RFC 5424 over UDP/TCP/TLS) with CEF and JSON payload options; HTTPS webhook (JSON batch, HMAC signature header); OpenTelemetry logs (OTLP/HTTP and gRPC).
- [x] **M10-T3** Audit log export through the same exporters (separate stream flag).
- [x] **M10-T4** Alert rules: conditions (blocks per site > N in window, new country in top attackers, certificate expiring < N days, feed failure, events dropped > 0, upstream unhealthy), evaluation job every 30 s, deduplication and cool-down.
- [x] **M10-T5** Notification channels: SMTP email, generic webhook, Slack-compatible webhook, Microsoft Teams webhook.
- [x] **M10-T6** UI: Exporters page with test button and delivery stats; Alerts page; notification channels.
- [x] **M10-T7** Docs: integration guides for Splunk (syslog/CEF), Elastic (OTLP or webhook), Microsoft Sentinel (syslog via AMA), Graylog, Wazuh.

## Acceptance criteria

1. With the SIEM endpoint down for 10 minutes, no events are lost up to the spool size, and delivery resumes automatically.
2. A slow exporter does not increase request latency or event-store write latency (k6 + benchmark).
3. CEF output parses in a reference CEF parser test; OTLP output accepted by an OpenTelemetry Collector in CI.
4. Alert fires within 60 s of its condition and does not repeat during cool-down.

## Delivered

Documentation: [integrations/](../../integrations/README.md).

Decisions taken while building it:

- `sherlock-waf/docs` is the authoritative copy of the plan; the copy under `sherlock-plan/` was not used.
- `pkg/extension` gained a minimal `ExporterType` / `Exporter` / `ExporterTester` / `ErrPermanent` / `Host.AddExporterType` surface (public API change, reviewed by the owner).
- Delivery is at-least-once with a per-exporter disk spool. When the spool (256 MiB, fixed) is full the oldest 4 MiB segment is dropped and counted, not the newest.
- OTLP/HTTP uses the JSON encoding; OTLP/gRPC is hand-framed over `net/http` HTTP/2 with hand-encoded protobuf, so the core gained no gRPC or protobuf dependency.
- The audit stream is fed by the post-commit audit observer into each exporter's spool (`stream`: `events`, `audit`, `both`), with its own schema `sherlock.audit.v1`.
- Exporters, channels and alert rules share one `integrations` table; each object's settings are a single encrypted secret and are masked in the API.
- Alert state (de-duplication, cool-down) is in memory; a restart repeats still-true alerts once.
- Microsoft Teams is in scope and uses an Adaptive Card for a Teams Workflows webhook.

Known follow-ups:

- Acceptance 1 is covered by an automated outage test with a small bus ring and short timings, not by a 10-minute run against a real SIEM.
- Acceptance 2 (exporter slowness versus request and event-store write latency under k6 and `make bench`) has a unit test that `Publish` never blocks on a stuck exporter; a k6 and benchmark comparison is still to be added.
- Acceptance 3: the CEF parser round-trip test runs in CI; the OpenTelemetry Collector job (`otlp-collector`, build tag `otelcol`) has to be run once in CI to confirm the pinned image.
- The spool size per exporter is not configurable yet; no per-exporter retry or batch settings in the UI.
- No "resolved" alert notification and no persisted alert state.
- Vendor guides for Splunk, Graylog and Wazuh mark details to verify against the customer's product version.
