# Control-plane API

## Principles

- **One public API.** The dashboard, CLI and automation all use `/api/v1`. No private endpoints for the UI.
- **Spec first.** `api/openapi.yaml` (OpenAPI 3.1) is written before handlers. Go request/response types are generated with `oapi-codegen` (types and strict server interface); the dashboard client is generated with `openapi-typescript` + `openapi-fetch`. CI fails if generated code is stale.
- **Stable from v1.0.** Before 1.0, breaking changes are allowed in minor releases with a changelog note. From 1.0, `/api/v1` only gets additive changes; breaking changes need `/api/v2`, with v1 kept for at least two minor releases.

## Conventions

| Topic | Rule |
| --- | --- |
| Format | JSON, `snake_case` fields, RFC 3339 UTC timestamps |
| IDs | User-chosen slugs for config objects (`sites/shop`); ULIDs for events, users, tokens, versions |
| Errors | `application/problem+json` (RFC 9457) with `type`, `title`, `status`, `detail`, and `errors: [{path, code, message}]` for validation |
| Pagination | Cursor-based: `?limit=50&cursor=…`, response `{items, next_cursor}` |
| Filtering events | Query params (`site`, `action`, `rule_id`, `ip`, `from`, `to`, `q`) |
| Concurrency | Config objects return `ETag` (config version). Writes require `If-Match`; mismatch returns 412 so two admins cannot overwrite each other |
| Idempotency | `POST` that creates accepts optional `Idempotency-Key` header |
| Rate limiting | Login: 5 attempts/min per IP and per username. API tokens: 600 req/min default |

## Authentication

| Method | Used by | Details |
| --- | --- | --- |
| Session cookie | Dashboard | `POST /api/v1/auth/login` (username + password) → `mfa_required` → `POST /api/v1/auth/mfa` (TOTP), or `mfa_enrol_required` → `POST /auth/mfa/enroll` (returns the seed once) → `POST /auth/mfa/enroll/confirm`. MFA is mandatory for every account. The pre-MFA session is partial (5 min, may only complete this step) and is destroyed when the full session is issued. Cookie `__Host-sherlock_session`: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, no `Domain`, 12 h absolute, 30 min idle. CSRF: double-submit token (cookie `__Host-sherlock_csrf`, readable by the dashboard) echoed in the `X-CSRF-Token` header for all non-GET session requests |
| API token | CLI, CI, Terraform | `Authorization: Bearer shk_<id>_<secret>`. Only the SHA-256 of the secret is stored (it carries 160 bits of entropy, so a fast hash is appropriate). Scopes: `read`, `write`, `events:read`, `admin`. A token's permissions are its scopes intersected with its owner's role, so demoting a user narrows their tokens. Tokens cannot create tokens (that needs a session). Optional expiry and CIDR restriction. No CSRF header needed (not ambient browser credentials) |

Login is throttled at 5 attempts per minute per IP and per username (unknown usernames included, so throttling does not reveal which exist); five consecutive failures lock the account for 1 minute, doubling to a 15-minute cap. Failures, locks, denials and successes are audited, never with credentials.

Roles (OSS): `admin`, `viewer`. Authorisation is checked in one middleware from a route→permission table read from the `x-sherlock-permission` extensions of the embedded OpenAPI spec (`api/openapi.yaml`), so no handler can forget it: a route with no permission, or an unknown permission name, stops the server starting. Special values: `public` (no authentication), `authenticated`, `session-any`, `session-partial` (sign-in steps). Enterprise replaces the authoriser through `extension.Authorizer`; authentication, CSRF and the sign-in rules above it are not replaceable, and an authoriser error denies.

Operational conventions: errors are RFC 9457 `application/problem+json` with a `request_id`; configuration bodies are decoded strictly (an unknown field is a 400); the control plane listens on `SHERLOCK_ADMIN_LISTEN` (default `127.0.0.1:9443`) over TLS 1.2+ with a self-signed ECDSA P-256 certificate generated at first start (or `SHERLOCK_ADMIN_TLS_CERT`/`_KEY`; its public-key SHA-256 is logged for pinning), optionally restricted by `SHERLOCK_ADMIN_ALLOWED_CIDRS`.

## Resources

| Method and path | Purpose | Permission | M |
| --- | --- | --- | --- |
| `POST /auth/login`, `/auth/mfa`, `/auth/mfa/enroll`, `/auth/mfa/enroll/confirm`, `/auth/logout` | Session sign-in steps | public / session | M3 |
| `GET /auth/me` | Current user, role, permissions | any | M3 |
| `GET /setup/status`, `POST /setup` | First-run wizard (only works while no user exists) | public, one-time | M4 |
| `GET /config` / `PUT /config` | Whole effective config (JSON or `Accept: application/yaml`) | viewer / admin | M3 |
| `POST /config/validate` | Validate without applying | admin | M3 |
| `GET /config/versions`, `GET /config/versions/{id}`, `POST /config/versions/{id}/rollback` | History, diff, rollback | viewer / admin | M3 |
| `GET/POST /sites`, `GET/PATCH/DELETE /sites/{site}` | Sites | viewer / admin | M3 |
| `GET/PUT /defaults` | Global policy defaults | viewer / admin | M3 |
| `GET/POST /sites/{site}/endpoints`, `GET/PATCH/DELETE …/{endpoint}` | Endpoint overrides | viewer / admin | M3 |
| `GET /sites/{site}/effective-policy?path=&method=` | Merged policy with source of each value; shows matched endpoint | viewer | M3 |
| `GET /virtual-patches?q&site&severity&kev&days` | Rule-pack catalogue: CVE, product, severity, KEV, state per site (`active`, `stack_not_declared`, `disabled`, `pack_off`), hit counts, CVEs covered by CRS, summary for the overview | viewer | M8 |
| `PUT /sites/{site}/virtual-patches/{patch}` | Switch one patch on or off for a site (audited) | admin | M8 |
| `GET/POST /sites/{site}/exclusions`, `DELETE …/{exclusion}` | Site-level WAF exclusions; creating is audited with the actor and source event; critical warnings need `acknowledge_warnings` | viewer / admin | M8 |
| `POST /sites/{site}/exclusions/propose` | Narrowest exclusion for an event (or a preview of an edited one): past-event impact and warnings; saves nothing | viewer (`events:read`) | M8 |
| `GET/PUT /sites/{site}/custom-rules`, `POST …/validate` | Custom SecLang rules (ids 10000-99999); validated by static allow-list and a throwaway Coraza compile before saving | viewer / admin | M8 |
| `GET /sites/{site}/paranoia-impact?target&from&to` | Predicted additional blocks if the blocking paranoia level is raised, from stored findings | viewer (`events:read`) | M8 |
| `GET /crs/rules?q&site&category&paranoia_level&direction&state&limit&offset` | CRS rule catalogue with descriptions, searchable, with per-site state | viewer | M8 |
| `GET/POST /sites/{site}/rate-limits`, `…/{name}` | Rate limits | viewer / admin | M5 |
| `GET/PUT /sites/{site}/openapi` | OpenAPI doc for API protection | viewer / admin | M9 |
| `GET/POST /certificates`, `DELETE /certificates/{id}` | Uploaded certs; ACME status | viewer / admin | M4 |
| `GET/POST /ip-lists`, `…/{name}` | IP lists | viewer / admin | M5 |
| `GET/DELETE /bans`, `POST /bans` | Active temporary bans | viewer / admin | M5 |
| `GET /events`, `GET /events/{id}` | Security events | viewer | M3, M7 |
| `GET /events/stream` | Server-sent events, live tail | viewer | M7 |
| `GET /analytics/summary`, `/analytics/timeseries`, `/analytics/top` | Dashboard charts (top IPs, rules, paths, countries) | viewer | M7 |
| `GET /reports/would-block` | Detect-mode rollout report (FR-FIN-3) | viewer | M7 |
| `GET/POST /exporters`, `…/{id}`, `POST …/{id}/test` | Event exporters | viewer / admin | M10 |
| `GET/POST /alerts`, `…/{id}` | Alert rules | viewer / admin | M10 |
| `GET/POST /users`, `PATCH/DELETE /users/{id}`, `POST /users/{id}/reset-mfa` | Users | admin | M3 |
| `GET/POST /tokens`, `DELETE /tokens/{id}` | API tokens (own; admin sees all) | any / admin | M3 |
| `GET /audit` | Audit log | admin | M3 |
| `GET /system/health`, `/system/info` | System | viewer | M7 |
| `GET /system/update` | Is a newer signed release available (verified, cached 5 min; 502 when the check fails) | viewer (`system:read`) | M7 |
| `POST /system/update/apply` | Download, verify (ADR-0017) and stage or install the latest release; never restarts; audited | admin (`system:update`; the `admin` token scope only) | M7 |
| `GET /system/backups` | The node's own backups, newest first | viewer (`system:read`) | M7 |
| `GET /setup/status`, `POST /setup/admin` | First-run setup: whether it is open; create the first admin with the one-time setup token | public (token-guarded, closes itself) | M4 |
| `POST /system/test-upstream` | Reachability check for an upstream (connect + `HEAD /`, no redirects, 3 s, no response content returned) | admin | M4 |
| `GET /stats/timeseries?from&to&step&site` | Event counts per bucket and action from the minute rollups (dense buckets, at most 2000) | viewer | M4 |
| `GET/POST /certificates`, `DELETE /certificates/{id}`, `GET /certificates/acme-status` | Uploaded certificates (PEM chain + key; key never returned; delete refused while a site uses it); certificate state per site host | viewer / admin | M4 |
| `GET /block-pages`, `PUT/DELETE /block-pages/{id}` | Custom block page templates (`html/template`; fields `.Status .Title .Detail .EventID`; validated by rendering once; delete refused while in use) | viewer / admin | M4 |
| `GET /healthz`, `/readyz` (no `/api/v1` prefix) | Probes | public | M2 |
| `GET /metrics` (no prefix, can be bound to separate address) | Prometheus | token or CIDR | M2 |

## Extension

Enterprise mounts extra routes under `/api/v1/ee/...` through `extension.APIRoutes`. The OSS OpenAPI document does not include them; Enterprise ships its own `openapi-ee.yaml` that references the core document.
