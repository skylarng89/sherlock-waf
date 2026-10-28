# ADR-0007: In-process bounded event bus

- Status: Accepted
- Date: 2026-10-28

## Decision

Security events go from the data plane to a bounded in-memory ring buffer. Publishing never blocks; overflow drops the oldest event and counts it. A batch writer persists events; exporters and the live tail subscribe independently with their own buffers.

## Consequences

Traffic is never slowed by logging or by a slow SIEM (NFR-4). Under extreme attack, some event detail can be lost, but counters stay correct and the drop is visible as a metric and on the dashboard. A crash loses at most ~1 s of unwritten events.

## Alternatives considered

| Option | Why not |
| --- | --- |
| Write synchronously per request | Couples latency to disk |
| External queue (NATS, Kafka) | Extra dependency for self-hosters; can be added later as an exporter |
