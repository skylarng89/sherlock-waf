# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions: [Semantic Versioning](https://semver.org/). Maintained by release-please from Conventional Commits.

## [Unreleased]

### Added

- Project plan and design documentation.
- Control-plane hardening (ASVS S-04 to S-09, B2): setup token verified before the argon2 run (no hashing for a wrong token); login limiter keyed on (IP, username) with a 20/min username ceiling and `auth.account_locked` once per lock; failed API-token presentations limited per IP (429 before lookup) and audited as coalesced `auth.token_failed` rows; API tokens capped at `SHERLOCK_API_TOKEN_MAX_DAYS` (default 365, `0` for no limit), 50 per account, an expires-soon badge and a create-form limit notice; `POST /system/update/apply` refused for API tokens; per-principal and per-IP request limiter with 429 and `Retry-After` and a `sherlock_api_throttled_total` metric; breached-password corpus (SecLists, 12+ characters, MIT, see NOTICE) with trailing-noise and leetspeak normalisation and a fuzz target; password changes compare-and-set on the verified hash (409 on a lost race).

### Fixed

- Audit rows written for unauthenticated callers (`auth.login_failed` for unknown users, `auth.login_throttled`) were refused by the audit table's actor check, so they were never stored (only an error log line was written); they are now recorded as the `system` actor `anonymous`.
- The CLI `token create` now applies the same token lifetime maximum as the API.
- Self-service account (ASVS S-01, S-03): `POST /auth/password` changes your own password (current password required, per-user attempt limit, other sessions end, audited). `GET /auth/sessions` and `DELETE /auth/sessions/{id}` list and sign out your other browser sessions (IDOR-safe: foreign ids are 404). At most five full sessions per user; a sixth evicts the oldest. New `session-full` permission. Dashboard Account page with the change-password form and the sessions table; e2e and axe coverage.
- Control-plane request validation against `api/openapi.yaml` (S-02, S-14): parameters, media type and JSON bodies are checked after authentication and before handlers, with 422 `errors[{path,code,message}]` for schema violations, 400 for malformed requests and 415 for an undeclared `Content-Type`. The data plane shares the validator (`internal/oapi`).
- False-positive tuning (M8): site-scoped exclusions compiled before CRS, propose-an-exclusion-from-an-event API with past-event impact and category warnings, custom SecLang rules validated in a throwaway engine with a strict allow-list, outbound (response) inspection with body limit and content-type filter, `blocking_paranoia_level` below `paranoia_level` with a predicted-blocks helper, searchable CRS rule catalogue with per-site state.
- API protection (M9, ADR-0018): `sherlock_api` module with OpenAPI 3.0/3.1 conformance (unknown path or method, parameter and body schema violations with JSON pointers), JWT validation (RS/PS/ES/EdDSA, JWKS fetched by a background job with rotation, HS only with a configured secret, `exp`/`nbf`/`iss`/`aud`, clock skew), mutual-TLS requirement per path with an uploaded CA bundle, rate-limit keys `jwt:<claim>`, `api_key:<header>` and `mtls_subject`, `/api-docs` and `/ca-bundles` endpoints, and a site API tab.
- Virtual-patch pack (ADR-0013): `rules/virtual-patches/` format, loader before CRS, `policy.stacks` and `policy.virtual_patches`, an initial pack of 20 rules for exploited CVEs with positive and negative tests, `covered-by-crs.yaml`, `GET /virtual-patches`, and the `kev-watch` triage workflow.
