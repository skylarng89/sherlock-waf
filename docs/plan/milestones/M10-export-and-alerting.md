# M10 · SIEM export and alerting

- Phase: 3 · Competitive and finance-ready
- Depends on: M7
- Ships: `v0.8.0`
- Read first: `docs/architecture/events.md`, `docs/architecture/extension-points.md` (ExporterType), PCI DSS 4.0 requirements 6.4.2 and 10.x (summary in `docs/product/vision.md`)

## Goal

Get Sherlock's events into the customer's SOC and alert people when something needs attention.

## Tasks

- [ ] **M10-T1** Exporter framework: per-exporter subscriber with own buffer and cursor, retries with backoff, disk-backed spool (bounded) for outages, metrics per exporter, `ExporterType` extension point.
- [ ] **M10-T2** Exporters: syslog (RFC 5424 over UDP/TCP/TLS) with CEF and JSON payload options; HTTPS webhook (JSON batch, HMAC signature header); OpenTelemetry logs (OTLP/HTTP and gRPC).
- [ ] **M10-T3** Audit log export through the same exporters (separate stream flag).
- [ ] **M10-T4** Alert rules: conditions (blocks per site > N in window, new country in top attackers, certificate expiring < N days, feed failure, events dropped > 0, upstream unhealthy), evaluation job every 30 s, deduplication and cool-down.
- [ ] **M10-T5** Notification channels: SMTP email, generic webhook, Slack-compatible webhook, Microsoft Teams webhook.
- [ ] **M10-T6** UI: Exporters page with test button and delivery stats; Alerts page; notification channels.
- [ ] **M10-T7** Docs: integration guides for Splunk (syslog/CEF), Elastic (OTLP or webhook), Microsoft Sentinel (syslog via AMA), Graylog, Wazuh.

## Acceptance criteria

1. With the SIEM endpoint down for 10 minutes, no events are lost up to the spool size, and delivery resumes automatically.
2. A slow exporter does not increase request latency or event-store write latency (k6 + benchmark).
3. CEF output parses in a reference CEF parser test; OTLP output accepted by an OpenTelemetry Collector in CI.
4. Alert fires within 60 s of its condition and does not repeat during cool-down.
