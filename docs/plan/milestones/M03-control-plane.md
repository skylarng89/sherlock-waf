# M3 · Control plane foundation

- Phase: 2 · MVP
- Depends on: M2
- Ships: no release (dashboard comes in M4)
- Read first: `docs/architecture/api.md`, `docs/architecture/data-model.md`, `docs/architecture/extension-points.md`, ADR-0006, ADR-0009, `docs/security/threat-model.md` T5–T11, T15

## Goal

Configuration moves from a file into a store, managed through an authenticated, versioned REST API with history, rollback and audit. The file mode remains as `sherlock config apply -f`.

## Tasks

- [ ] **M3-T1** Store: goose migrations and sqlc queries for both dialects (tables: config_versions, sites, users, sessions, api_tokens, secrets, audit_log, events, event_rollups_1m, kv). `SHERLOCK_DB` DSN selection. Store test suite on SQLite and Postgres (testcontainers).
- [ ] **M3-T2** Node key and `internal/secrets` (XChaCha20-Poly1305), key from file or env.
- [ ] **M3-T3** `configsvc`: load latest applied version at boot; apply = validate → compile → `caddy.Load` → commit version + diff + audit; rollback; ETag/If-Match concurrency.
- [ ] **M3-T4** Event batch writer to the store + rollups; retention job. Remove the temporary JSONL sink or keep it as an option.
- [ ] **M3-T5** `api/openapi.yaml` for the M3 routes in api.md (auth, me, config, versions, global defaults, sites CRUD, endpoints CRUD, effective-policy, users, tokens, audit, events list/get, system/info). `x-sherlock-permission` on every operation. Generate server types (oapi-codegen strict server) and the TS client.
- [ ] **M3-T6** Admin listener (`SHERLOCK_ADMIN_LISTEN`) with TLS (self-signed generated at first start until an admin hostname with ACME is set), separate `http.Server`, strict security headers and CSP, request size limits, timeouts, CIDR allow-list.
- [ ] **M3-T7** Auth: argon2id passwords, login rate limiting and backoff, TOTP MFA (RFC 6238, mandatory for admin role), sessions per api.md, CSRF double-submit, API tokens with scopes/CIDR/expiry. Permission middleware from the spec's `x-sherlock-permission`.
- [ ] **M3-T8** Audit service writing hash-chained rows for logins, failed logins, every config change, user/token changes.
- [ ] **M3-T9** `pkg/extension` v0: `Extension`, `Host`, `Authorizer`, `AuthProvider`, `AuditSink`, `EventStore` interfaces with core defaults and a fake implementation used in tests. `cmd/sherlock` uses `extension.None()`.
- [ ] **M3-T10** CLI: `sherlock user create|reset-password|reset-mfa`, `sherlock config export|import|apply|validate`, `sherlock token create`.
- [ ] **M3-T11** API tests: every route × {anonymous, viewer, admin, token with each scope} × {valid, invalid input}.

## Acceptance criteria

1. Fresh start with an empty DB creates no user and no default password; `sherlock user create --admin` is required (or the M4 setup wizard).
2. A config change through the API takes effect within 1 s with no dropped in-flight requests (k6 running during reload shows zero errors).
3. Two concurrent writes with the same ETag: one succeeds, one gets 412.
4. Rollback to any earlier version works and is audited.
5. Viewer cannot call any write endpoint (test proves it for every route).
6. Admin login without MFA enrolment is forced into enrolment; 6 wrong passwords in a minute lock the account with backoff.
7. Restarting the control plane HTTP server (test hook) does not interrupt proxied traffic.
8. `GET /sites/{site}/effective-policy?path=…&method=…` returns the matched endpoint and every value's source level; tested for the M1 hierarchy fixtures.
9. `sherlock config export` → `import` on a fresh node reproduces identical compiled Caddy JSON.
