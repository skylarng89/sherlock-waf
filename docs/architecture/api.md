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
| Session cookie | Dashboard | `POST /api/v1/auth/login` (username + password) → `mfa_required` → `POST /api/v1/auth/mfa` (TOTP). Cookie `sherlock_session`: `HttpOnly`, `Secure`, `SameSite=Strict`, 12 h absolute, 30 min idle. CSRF: double-submit token in `X-CSRF-Token` header for all non-GET requests |
| API token | CLI, CI, Terraform | `Authorization: Bearer shk_<id>_<secret>`. Stored as SHA-256 hash. Scopes: `read`, `write`, `events:read`, `admin`. Optional expiry and CIDR restriction |

Roles (OSS): `admin`, `viewer`. Authorisation is checked in one middleware from a route→permission table generated from `x-sherlock-permission` extensions in the OpenAPI spec, so no handler can forget it. Enterprise replaces the authoriser through `extension.Authorizer`.

## Resources

| Method and path | Purpose | Permission | M |
| --- | --- | --- | --- |
| `POST /auth/login`, `/auth/mfa`, `/auth/logout` | Session | public / session | M3 |
| `GET /auth/me` | Current user, role, permissions | any | M3 |
| `GET /setup/status`, `POST /setup` | First-run wizard (only works while no user exists) | public, one-time | M4 |
| `GET /config` / `PUT /config` | Whole effective config (JSON or `Accept: application/yaml`) | viewer / admin | M3 |
| `POST /config/validate` | Validate without applying | admin | M3 |
| `GET /config/versions`, `GET /config/versions/{id}`, `POST /config/versions/{id}/rollback` | History, diff, rollback | viewer / admin | M3 |
| `GET/POST /sites`, `GET/PATCH/DELETE /sites/{site}` | Sites | viewer / admin | M3 |
| `GET/PUT /defaults` | Global policy defaults | viewer / admin | M3 |
| `GET/POST /sites/{site}/endpoints`, `GET/PATCH/DELETE …/{endpoint}` | Endpoint overrides | viewer / admin | M3 |
| `GET /sites/{site}/effective-policy?path=&method=` | Merged policy with source of each value; shows matched endpoint | viewer | M3 |
| `GET /virtual-patches`, `GET /virtual-patches/{id}` | Rule-pack catalogue: CVE, product, severity, state per site, hit counts | viewer | M8 |
| `GET/POST /sites/{site}/exclusions`, `…/{id}` | WAF exclusions | viewer / admin | M8 |
| `POST /sites/{site}/exclusions/from-event/{event_id}` | Suggest an exclusion from an event | admin | M8 |
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
| `GET /system/health`, `/system/info`, `/system/update`, `POST /system/update/apply`, `POST /system/backup` | System | viewer / admin | M7 |
| `GET /healthz`, `/readyz` (no `/api/v1` prefix) | Probes | public | M2 |
| `GET /metrics` (no prefix, can be bound to separate address) | Prometheus | token or CIDR | M2 |

## Extension

Enterprise mounts extra routes under `/api/v1/ee/...` through `extension.APIRoutes`. The OSS OpenAPI document does not include them; Enterprise ships its own `openapi-ee.yaml` that references the core document.
