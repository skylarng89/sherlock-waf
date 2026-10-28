# Data model

## Stores

| Store | Engine | Holds |
| --- | --- | --- |
| Config store | SQLite (default, file `data/sherlock.db`, WAL mode) or Postgres 15+ | Config versions, users, tokens, secrets, audit log, certificates metadata, IP lists, bans |
| Event store | Same database by default, separate tables; Enterprise can switch to ClickHouse | Security events, aggregated counters |
| Files | `data/` directory | ACME certificates (Caddy storage), uploaded certs, GeoIP DB, feed caches, backups |

SQLite driver: `modernc.org/sqlite` (pure Go, keeps NFR-10 no-CGO). Postgres driver: `github.com/jackc/pgx/v5`. Queries are written in SQL and generated with `sqlc` for both dialects (`internal/store/sqlite`, `internal/store/postgres`) behind one Go interface. Migrations with `pressly/goose`, embedded, forward-only, one file per dialect per change.

## Tables

| Table | Key columns | Notes |
| --- | --- | --- |
| `config_versions` | `id` ULID, `created_at`, `author_id`, `source` (api, import, rollback, cli), `schema_version`, `snapshot` JSON, `diff` JSON, `applied` bool | The canonical config is the latest `applied` row. Normalised tables below are a projection for queries; the snapshot wins on conflict |
| `sites` | `id` slug, `name`, `mode`, `hosts` JSON, `updated_at` | Projection for listing and filtering |
| `users` | `id`, `username` unique, `password_hash` (argon2id), `role`, `mfa_secret_id`, `mfa_enabled`, `disabled`, `last_login_at`, `created_at` | |
| `sessions` | `id` hash, `user_id`, `created_at`, `last_seen_at`, `ip`, `user_agent`, `csrf_token_hash` | Expired rows purged hourly |
| `api_tokens` | `id`, `user_id`, `name`, `token_hash`, `scopes` JSON, `cidrs` JSON, `expires_at`, `last_used_at` | |
| `secrets` | `id`, `ciphertext`, `nonce`, `created_at` | XChaCha20-Poly1305 with the node key (`data/node.key`, 0600, generated at first start; or from `SHERLOCK_NODE_KEY` env / file for containers) |
| `audit_log` | `id` ULID, `at`, `actor_type` (user, token, system), `actor_id`, `ip`, `action`, `object_type`, `object_id`, `details` JSON, `prev_hash`, `hash` | OSS fills `hash` too (SHA-256 of row + `prev_hash`) so Enterprise can verify and sign the chain without migrating data |
| `certificates` | `id`, `name`, `subjects` JSON, `not_after`, `source` (upload, acme), `secret_id` for private key | ACME certs live in Caddy storage; this table mirrors status |
| `ip_lists` / `ip_list_entries` | `name`; `list_name`, `cidr`, `comment`, `expires_at` | |
| `bans` | `ip`, `site_id`, `reason`, `created_at`, `expires_at`, `source` (auto, manual, crowdsec) | Loaded into memory at start, changes pushed to the data plane |
| `events` | see [events.md](events.md) | Partitioned by day in Postgres; in SQLite, indexed on `(ts)`, `(site_id, ts)`, `(client_ip, ts)` |
| `event_rollups_1m` | `bucket`, `site_id`, `action`, `count` | Written by the batch writer for fast charts |
| `exporters`, `alert_rules`, `alert_state` | | M10 |
| `openapi_docs` | `id`, `site_id`, `content` (compressed), `sha256`, `uploaded_at` | M9 |
| `kv` | `key`, `value` | Small node state: install ID, last update check, feature flags |

## Retention

A job runs every 10 minutes: deletes events older than `retention_days` in batches of 10,000, deletes rollups older than 400 days, vacuums SQLite weekly (`PRAGMA incremental_vacuum`).

## Backups

`sherlock backup` writes a `.tar.zst` containing a consistent SQLite snapshot (`VACUUM INTO`) or a `pg_dump` invocation result, the `data/` directory minus caches, and a manifest with version and checksum. The node key is excluded unless `--include-key` is given (and then the archive must be encrypted with `--passphrase`).
