# M1 · Data plane core

- Phase: 1 · Foundation
- Depends on: M0
- Ships: no release (internal milestone)
- Read first: ADR-0012, `docs/architecture/overview.md`, `docs/architecture/request-pipeline.md`, `docs/architecture/config-model.md`, ADR-0002, ADR-0003, ADR-0005, `docs/security/threat-model.md` (T1–T4, T17)

## Goal

`sherlock run --config sherlock.yaml` proxies traffic for multiple sites through Coraza with OWASP CRS, in `detect` or `block` mode, with automatic HTTPS. No database or API yet.

## Tasks

- [ ] **M1-T1** `internal/config`: Go structs for `schema_version`, `global` (subset: trusted_proxies, client_ip_headers, acme) and `sites` (id, name, hosts, path_prefix, mode, fail_mode, tls, upstreams, headers (security_headers only), waf (all fields except exclusions/custom_rules), block_page). Defaults, YAML load, validation returning `{path, code, message}` list. Unit and fuzz tests.
- [ ] **M1-T1b** Policy hierarchy (FR-POL-1/2/3, ADR-0012): `policy` block type used by `global.defaults`, `sites[].policy` and `sites[].endpoints[]`; merge rules and endpoint precedence in `internal/config/effective.go`; ambiguity validation; exhaustive table tests of merging.
- [ ] **M1-T2** `internal/compiler`: deterministic `config.Root` → Caddy JSON (apps: http servers on :80/:443, routes per site matching hosts/path, one subroute per endpoint ordered by precedence plus a site-default subroute, each with its effective policy, `sherlock_core` → `sherlock_waf` → `reverse_proxy`; tls automation policies; `admin.disabled=true`; HTTP→HTTPS redirect; unknown host → static 421). Golden tests in `testdata/`.
- [ ] **M1-T3** `internal/app`: start Caddy in-process with `caddy.Load`; graceful shutdown on SIGTERM; SIGHUP reloads the YAML file (validate → compile → load; keep old config on failure).
- [ ] **M1-T4** `internal/dataplane/core` module `sherlock_core`: client IP resolution (request-pipeline.md), ULID event ID, `Decision` in context, panic recovery with fail mode, `X-Sherlock-Event-Id` on terminated responses. For now, log decisions as JSON lines via slog.
- [ ] **M1-T5** `internal/dataplane/waf` module `sherlock_waf`: per-site `coraza.WAF` built at Provision from generated directives + embedded CRS (`coraza-coreruleset`), paranoia level and thresholds from config, request phases 1–2, findings captured into the decision, `detect` vs `block` semantics, body limits and partial processing, skip-inspection extensions.
- [ ] **M1-T6** Block page: embedded `html/template` (HTML) and RFC 9457 JSON by `Accept`; shows event ID only; no request echo.
- [ ] **M1-T7** `internal/policy`: client IP parsing and CIDR set (used by core; reused by ACL in M5), with tests.
- [ ] **M1-T8** `NOTICE` credits for Caddy, Coraza, coraza-caddy, coraza-coreruleset, CRS.
- [ ] **M1-T9** `docs/user/quickstart-file-config.md`: run Sherlock with a YAML file in front of a local app.

## Acceptance criteria

1. With `test/e2e-compose` (httpbin backend), `curl "http://site.localhost/get?id=1' OR '1'='1"` returns 403 with JSON body containing `event_id` when the site is in `block` mode, and 200 with a logged finding in `detect` mode.
2. A benign request set (`test/corpus/benign` initial 200 requests) produces zero blocks at PL1.
3. Two sites with different hosts and modes work simultaneously from one config.
4. Invalid YAML or invalid config is rejected with path-specific errors; on SIGHUP with a bad file, traffic continues on the old config.
5. A site with a global default of PL1, a site override of `block`, and an endpoint override of PL2 on `POST /login` produces PL2 only for that endpoint (golden test + live request test). Ambiguous endpoint definitions fail validation.
6. Compiler golden tests cover: one site, two sites, path prefix, TLS file mode, ACME mode, PL1–PL4.
7. Killing an upstream returns Caddy 502, not a panic; a forced panic in `sherlock_waf` (test build tag) follows `fail_mode`.
8. `go test -race ./...` passes.

## Out of scope

Database, API, dashboard, ACL, rate limits, events persistence, exclusions, response inspection.
