# M7 · MVP completion: explorer, analytics, install, updates

- Phase: 2 · MVP (gate milestone)
- Depends on: M4, M5, M6
- Ships: `v0.5.0` (MVP, first design-partner release)
- Read first: `docs/architecture/events.md`, `docs/operations/deployment.md`, `docs/release/release-process.md`, `docs/security/threat-model.md` T7, T12

## Goal

Everything a design partner needs: see and understand attacks, roll out from detect to block with evidence, install in minutes, update safely, back up and restore.

## Tasks

- [ ] **M7-T1** Attack explorer: filterable, paginated event table (site, action, rule, IP, country, path, time range, free text), saved filters in URL, live tail via SSE with pause.
- [ ] **M7-T2** Event detail page: request summary, findings with CRS rule description and links, anomaly score breakdown, client info, "similar events" count; all data rendered as text (XSS-safe; Playwright test with payloads).
- [ ] **M7-T3** Analytics: time series (requests, blocks, challenges by site), top rules, top IPs, top paths, top countries (ECharts, with table fallbacks for accessibility).
- [ ] **M7-T4** Would-block report (FR-FIN-3): for a detect-mode site and period, count and list requests that would have been blocked, grouped by rule and path; export CSV; one-click "switch to block" from the report.
- [ ] **M7-T5** System page: version info, CRS version and age, update available, backups list, health of feeds, disk usage, event drop counter.
- [ ] **M7-T6** Packaging: nfpm `.deb`/`.rpm` with systemd unit (hardening from deployment.md), `deploy/install/install.sh` (detects distro, verifies cosign signature, installs, starts, prints setup URL), Docker Compose example, container image runs as non-root with read-only root FS.
- [ ] **M7-T7** Updater: `sherlock update [--check|--bundle FILE]` and `POST /system/update/apply`; downloads release manifest, verifies cosign signature and checksums, backs up, swaps binary atomically, restarts via systemd (or prints instructions in containers).
- [ ] **M7-T8** Backup/restore commands and daily backup job (data-model.md).
- [ ] **M7-T9** Internal ASVS 5.0 L2 review of the control plane; findings fixed or ticketed with severity.
- [ ] **M7-T10** User docs: install guide per method, first site, detect-to-block rollout guide, backup/restore, upgrade.

## Acceptance criteria (Phase 2 gate)

1. Fresh Ubuntu 24.04 and Rocky Linux 9 VMs: install script to protected site in < 10 minutes (screen recording or log in PR).
2. Upgrade from `v0.4.0` to `v0.5.0` with `sherlock update` keeps config and events, with no proxied request errors under k6 load except connections longer than 30 s.
3. A tampered binary in the bundle is refused by the updater.
4. Attack explorer shows an event within 2 s of the request; filters return in < 500 ms on 1 million stored events in SQLite (benchmark recorded; Postgres guidance updated in ADR-0006 if needed).
5. Restore from backup on a fresh host reproduces sites, users and certificates.
6. No open critical/high findings from the ASVS review.
