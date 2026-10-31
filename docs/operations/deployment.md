# Deployment and operations

## Sizing (initial guidance; calibrate in M2 and M7)

| Load | vCPU | RAM | Disk |
| --- | --- | --- | --- |
| Small (≤ 200 req/s, ≤ 10 sites) | 1 | 1 GB | 10 GB |
| Medium (≤ 2,000 req/s) | 2 | 4 GB | 40 GB |
| Large (> 2,000 req/s) | 4+ per node, several nodes | 8 GB | Postgres for events |

## Install methods

| Method | Command | Milestone |
| --- | --- | --- |
| Script (Debian/Ubuntu/RHEL family) | `curl -fsSL https://get.sherlockwaf.dev/install.sh \| sudo sh` (domain TBD; script verifies cosign signature before installing) | M7 |
| Packages | `.deb` / `.rpm` from GitHub Releases | M7 |
| Docker Compose | `deploy/compose/docker-compose.yml` | M7 |
| Kubernetes | Helm chart | M12 |

## Filesystem layout (packages)

| Path | Content |
| --- | --- |
| `/usr/bin/sherlock` | Binary |
| `/etc/sherlock/sherlock.env` | Bootstrap settings (listen addresses, data dir, DB DSN) |
| `/var/lib/sherlock/` | Data dir: DB, node key, certificates, feeds, backups (0700, user `sherlock`) |
| `/lib/systemd/system/sherlock.service` | Hardened unit: `User=sherlock`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/sherlock`, `NoNewPrivileges=yes`, `PrivateTmp=yes` |

## Bootstrap settings (environment)

| Setting | Default |
| --- | --- |
| `--data-dir` (flag; all commands) | the OS user data dir; packages and the unit use `/var/lib/sherlock` |
| `SHERLOCK_DATABASE_URL` (or `--database-url`) | SQLite file `<data-dir>/sherlock.db`; `postgres://…` selects PostgreSQL |
| `SHERLOCK_ADMIN_LISTEN` (or `run --listen`) | `127.0.0.1:9443` (the package unit keeps it on loopback; the Docker example sets `0.0.0.0:9443`) |
| `SHERLOCK_ADMIN_ALLOWED_CIDRS` | unset (no network restriction) |
| `SHERLOCK_ADMIN_TLS_CERT` / `SHERLOCK_ADMIN_TLS_KEY` | unset (self-signed identity in the data dir) |
| `run --http-port` / `run --https-port` (flags) | `80` / `443` |
| `SHERLOCK_NODE_KEY_FILE` / `SHERLOCK_NODE_KEY` | `<data-dir>/node.key` |
| `SHERLOCK_BACKUP`, `SHERLOCK_BACKUP_KEEP`, `SHERLOCK_BACKUP_PASSPHRASE_FILE` | daily, keep 7, unencrypted |
| `SHERLOCK_TURNSTILE_SECRET`, `SHERLOCK_HCAPTCHA_SECRET` | unset (bot-defence provider secrets) |
| `SHERLOCK_CROWDSEC_API_KEY` | unset (optional feeds) |
| `SHERLOCK_MAXMIND_ACCOUNT_ID`, `SHERLOCK_MAXMIND_LICENSE_KEY` | unset (optional; needed only for the MaxMind GeoIP provider) |
| `SHERLOCK_API_URL`, `SHERLOCK_TOKEN`, `SHERLOCK_TLS_PIN` | CLI client settings for `sherlock config … --server` |

There is no `SHERLOCK_DATA_DIR`, `SHERLOCK_DB`, `SHERLOCK_HTTP_LISTEN`, `SHERLOCK_NODE_NAME` or `SHERLOCK_LOG_LEVEL`.

Everything else is configuration in the store, managed via API/dashboard/YAML.

## Operating

- Health: `GET /healthz` (process up), `GET /readyz` (store reachable, data plane running, config applied).
- Metrics: `GET /metrics` on the admin listener (CIDR protected via `global.admin.allowed_cidrs`; the control plane adds token auth in M3). Key series: `sherlock_requests_total{site,action}`, `sherlock_request_duration_seconds`, `sherlock_waf_duration_seconds`, `sherlock_events_published_total`, `sherlock_events_dropped_total`, `sherlock_internal_errors_total`, `sherlock_requests_in_flight`, `sherlock_config_version_info`, `sherlock_crs_version_info`.

Upstream and certificate health (both read from snapshots that background jobs refresh, so a scrape causes no probes, disk reads or database queries):

- `sherlock_upstream_healthy{site,upstream}`: `1` when the last probe of the origin succeeded, `0` when it failed. The gauge has series only for sites that define `upstreams.targets`, one per target (`host:port`). Sherlock probes every 15 s, with at most eight probes in flight and a per-probe timeout of `upstreams.health_check.timeout` (default 2 s). With `upstreams.health_check.path` set, a probe is a GET of that path over the same scheme and TLS settings as traffic, and only a 2xx response counts as healthy; redirects are not followed. Without a path, a probe is a TCP connect only. This is Sherlock's own probe, not Caddy's internal pool state, which is not reachable without the disabled admin API. A value of `0` means the last probe failed, not that the origin is confirmed down.
- `sherlock_cert_expiry_seconds{site,host}`: seconds until the certificate that serves the host expires, refreshed every 60 s. A negative value means the certificate has already expired. Uploaded certificates use the stored `NotAfter`, and a host is only reported when the certificate covers it. ACME certificates are read from the copy Caddy stores under `$DATA_DIR/certificates/`. A host has no series until its certificate exists, and wildcard ACME hosts have none because Caddy stores them under a different name. Alert on the value falling below a threshold, such as 14 days (`1209600`), rather than on the series disappearing.

### Admin listener (since M2)

`global.admin.listen` (default `127.0.0.1:9444`, because the control plane uses 9443; `off` disables it) serves only `GET /metrics`, `/healthz` and `/readyz`, separate from proxied traffic. `/readyz` answers 503 until the first configuration has been applied and again while shutting down. `allowed_cidrs` limits who may connect (empty means anyone who can reach the port, so keep the default loopback bind or set a list when binding wider). It is plain HTTP until the control plane brings TLS (M3).

### Events on disk (since M2)

Until the event store exists (M3), security events are written as JSON lines, one event per line (schema: [event.schema.json](../reference/event.schema.json)):

- `$DATA_DIR/events.jsonl`, rotated by size (`global.events.sinks.file_max_mb`, default 100, keeping `file_keep`, default 5 rotated files), mode 0600;
- standard output (`global.events.sinks.stdout`, default on), interleaved with log lines (distinguish them by the `"schema":"sherlock.event.v1"` field);
- optionally `$DATA_DIR/access.jsonl`: a sampled log of *clean* requests (`global.events.access_log`, off by default), kept apart from security events.

The data directory defaults to `$XDG_DATA_HOME/sherlock` or `~/.local/share/sherlock`; override with `--data-dir`. Only whole lines are ever written, so a log shipper tailing the file never sees a truncated event.
- Backups: daily automatic to `$DATA_DIR/backups`, keep 7 (`SHERLOCK_BACKUP=off`, `SHERLOCK_BACKUP_KEEP=N`, `SHERLOCK_BACKUP_PASSPHRASE_FILE=<file>` to encrypt); copy off-host with your own tooling. Keep a separate copy of `node.key`. Details: [backup and restore](../user/backup-restore.md).
- Logs: JSON to stdout/journald.
- Upgrades: `sherlock update` (online) or `sherlock update --bundle sherlock-X.Y.Z-linux-amd64.tar.gz` (offline). Both verify the Ed25519-signed release manifest and the archive checksum, refuse downgrades, back up, swap the binary atomically and restart the unit (a binary that does not stay up is rolled back). Proxied connections that finish within 30 s drain on restart. The dashboard/API path (`POST /system/update/apply`) stages the verified update and the unit installs it as root at the next start. Containers update by pulling a new image. See [upgrade](../user/upgrade.md) and [ADR-0017](../architecture/adr/0017-update-verification.md).
