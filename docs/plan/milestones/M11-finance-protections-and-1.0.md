# M11 · Finance protections, hardening and 1.0

- Phase: 3 · Competitive and finance-ready (gate milestone)
- Depends on: M8, M9, M10
- Ships: `v0.9.0` (feature complete), then `v1.0.0-rc.N`, then `v1.0.0`
- Read first: `docs/product/requirements.md` FR-FIN, `docs/security/threat-model.md` (all), `docs/release/versioning.md` (1.0 criteria)

## Goal

Ship the protections finance teams ask for, harden everything, pass an external pentest and freeze v1 contracts.

## Tasks

- [ ] **M11-T1** `sherlock_login` module: declared login endpoints; read username from form/JSON; observe upstream status for failures; velocity counters per IP, per username (hashed), per device fingerprint (hash of stable headers + TLS JA4 fingerprint if available from Caddy); actions challenge/block; events with `module=login`.
- [ ] **M11-T2** `sherlock_dlp` module: streaming response scanner for PAN (Luhn) and IBAN (mod-97) and custom patterns, with content-type allow-list and size limit; mask preserving last four; block option; never log matched values.
- [ ] **M11-T3** UI: Login protection and Data protection tabs; finance preset ("Fintech baseline") applying recommended settings to a site.
- [ ] **M11-T4** Hardening: extended fuzzing (body processors, config, exclusions), race-detector soak test 24 h, chaos test (kill upstream, fill disk, DB unavailable) with documented behaviour.
- [ ] **M11-T5** Freeze: API v1, config schema 1, event schema v1, `pkg/extension` v1. Review all names; breaking cleanup now or never.
- [ ] **M11-T6** External penetration test (vendor with web and WAF-bypass experience); fix critical/high; publish a summary letter.
- [ ] **M11-T7** Documentation complete: every feature, every config field (generated reference from schema), API reference (generated from OpenAPI), PCI DSS mapping guide (how Sherlock supports 6.4.2 and 10.x).
- [ ] **M11-T8** RC program with design partners (block mode 30 days); fix regressions; release `v1.0.0`.

## Acceptance criteria (Phase 3 gate)

1. Credential-stuffing simulation (k6, 50 usernames × 1,000 passwords from 200 IPs) is challenged/blocked within the configured thresholds while a normal user login succeeds.
2. A test page containing PANs in HTML and JSON is masked; no PAN appears in any event, log or export.
3. Pentest report: no open critical/high.
4. All 1.0 criteria in `docs/release/versioning.md` met.
