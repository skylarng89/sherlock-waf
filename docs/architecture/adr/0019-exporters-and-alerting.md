# ADR-0019: Exporters, notification channels and alert rules

- Status: Proposed
- Date: 2026-11-03
- Deciders: Product owner (delegated the M10 design choices to the implementer; please review and accept)

## Context

M10 sends events and audit records to the customer's SOC and alerts people. ADR-0007 already fixed the event bus (bounded ring, per-subscriber cursors, `Publish` never blocks). Open questions were how to survive a SIEM outage longer than the ring holds, where to store operator-defined integrations that carry credentials, and how to keep the public extension surface small.

## Decision

1. **One pipeline per exporter**: bus subscription (live only) → bounded segmented disk spool → sender with exponential backoff and jitter. The spool cursor advances only after the destination accepts a batch, so delivery is **at-least-once**; records carry a stable `id` for receiver-side deduplication.
2. **Spool overflow drops the oldest segment** and counts the loss (`sherlock_exporter_dropped_total{reason="spool_full"}`). Newest data is the most valuable during an incident, and the bound keeps a dead SIEM from filling the disk. The default is 256 MiB per exporter and is configurable per exporter with the `spool_max_mb` setting (16 to 102400 MiB). Lowering it trims an existing backlog on the next append, and the trimmed records are counted as dropped.
3. **Permanent rejections** (`extension.ErrPermanent`, e.g. HTTP 4xx) discard the batch and count it, so one bad batch cannot block the queue.
4. **Integrations share one table** (`integrations`: exporter, channel, alert rule). The whole settings document is one encrypted secret (XChaCha20-Poly1305, `internal/secrets`). The API masks credential-looking values; a masked value sent back keeps the stored one.
5. **Public API addition** (`pkg/extension`): `ExporterType`, `Exporter`, `ExporterTester`, `ExportRecord`, `ErrPermanent`, `Host.AddExporterType`. Exporters exchange structs and a pre-serialised JSON body so the core can add fields.
6. **The audit stream** enters exporters through the existing post-commit `AuditSink` observer, written to each exporter's own spool; it does not use the event bus.
7. **OTLP/gRPC is hand-framed** over `net/http` HTTP/2 with hand-encoded protobuf, and OTLP/HTTP uses the JSON encoding. This adds no gRPC or protobuf module to the core.
8. **Alert state is in memory.** Rules are edge-triggered per subject with a cool-down; after a restart a still-true condition alerts once more. Rules and channels are read on every evaluation, so edits apply without a restart.

## Consequences

- A slow or dead SIEM costs the data plane nothing beyond a wake-up signal in `Publish` (benchmarked in `internal/exporters/bench_test.go`).
- Events can be duplicated after a crash between a successful send and the cursor write; receivers must deduplicate.
- A hard crash can lose about one second of spooled records (the spool is synced about once a second), the same window as the event writer.
- Disk use is bounded per exporter but multiplies with the number of exporters.
- Credential masking is heuristic (key-name based) and errs towards masking too much; an extension exporter with unusual key names should use names containing `secret`, `token`, `key`, `password` or `url`.
- Alert dedup state is lost on restart. If that proves noisy, persist a small state table later (backward-compatible).

## Alternatives considered

| Option | Why not |
|---|---|
| Spool in the SQL store | Couples exporter volume to the database that stores events; vacuum and lock contention |
| Block the writer on a slow exporter | Violates ADR-0007 and NFR-4 |
| Exactly-once delivery | Not achievable across the network without receiver cooperation; at-least-once plus ids is honest |
| One table per integration kind | Three near-identical tables and migrations for one lifecycle |
| gRPC and protobuf modules for OTLP | Large dependency tree in the security-sensitive core for one exporter option |
