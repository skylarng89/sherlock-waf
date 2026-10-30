# M2 · Events, metrics and test harness

- Phase: 1 · Foundation (gate milestone)
- Depends on: M1
- Ships: `v0.1.0` (first public preview, file-config only)
- Read first: `docs/architecture/events.md`, `docs/engineering/testing-strategy.md`, `docs/product/requirements.md` NFR-1/2/3/13, ADR-0007

## Goal

Every decision becomes a structured, redacted event; the node exposes metrics and health; and the full security and performance test harness runs in CI so every later milestone is measured.

## Tasks

- [ ] **M2-T1** `internal/events`: event v1 struct, JSON Schema generation to `docs/reference/event.schema.json`, redaction (events.md rules) with fuzz tests.
- [ ] **M2-T2** Bounded ring-buffer bus with non-blocking publish, drop-oldest, metrics; subscriber API.
- [ ] **M2-T3** Temporary sinks until the store exists: JSON lines file (`$DATA_DIR/events.jsonl`, rotated by size) and stdout.
- [ ] **M2-T4** Optional sampled access log (FR-EVT-3).
- [ ] **M2-T5** Prometheus metrics (`/metrics` on admin listener) with the series listed in operations/deployment.md that exist so far; `/healthz`, `/readyz`.
- [ ] **M2-T6** `test/e2e-compose`: Sherlock + OWASP Juice Shop + httpbin; `make e2e-up/down`.
- [ ] **M2-T7** go-ftw harness: config for Sherlock (log via events file), CRS tests at PL1 in CI (`ftw-smoke`), PL1–4 nightly; document known/expected failures with reasons in `test/ftw/overrides.yaml`.
- [ ] **M2-T8** nuclei (web vulnerability templates, tags `sqli,xss,rce,lfi,ssrf`) and ZAP baseline against Juice Shop in block mode, nightly; record detection rate baseline in `test/nuclei/BASELINE.md`.
- [ ] **M2-T9** k6 scripts: (a) latency: 1 KB GET at 200 rps for 2 min, report p50/p95/p99 added latency vs direct-to-upstream; (b) throughput ramp until p99 > 50 ms. Run nightly on the fixed runner; fail if NFR-1/NFR-2 budgets are missed.
- [ ] **M2-T10** Go benchmarks for `sherlock_core` and `sherlock_waf`, `benchstat` comparison job on PRs.
- [ ] **M2-T11** Expand benign corpus to ≥ 1,000 requests (forms, JSON APIs, uploads, unicode, long cookies) and a CI job asserting zero blocks at PL1.
- [ ] **M2-T12** First release through the pipeline: `release.yml` with GoReleaser, SBOM, cosign signing, container image. Tag `v0.1.0`.

## Acceptance criteria (Phase 1 gate)

1. go-ftw CRS suite at PL1 passes in CI, with every override justified.
2. k6 results recorded in `docs/plan/benchmarks.md`; NFR-1/2 met, or an ADR revises the budget with numbers.
3. Juice Shop nuclei/ZAP baseline recorded; each Juice Shop injection challenge category is detected at PL1 or listed as a known gap.
4. Events contain no unredacted password, token or PAN in a test that sends them in query, form and JSON bodies.
5. Publishing 1 million events in a tight loop with no subscriber never blocks request handling (benchmark) and drop metric is correct.
6. `v0.1.0` release artefacts verify with `cosign verify-blob`.
