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
| Docker Compose | `deploy/docker/compose.yaml` | M7 |
| Kubernetes | Helm chart | M12 |

## Filesystem layout (packages)

| Path | Content |
| --- | --- |
| `/usr/bin/sherlock` | Binary |
| `/etc/sherlock/sherlock.env` | Bootstrap settings (listen addresses, data dir, DB DSN) |
| `/var/lib/sherlock/` | Data dir: DB, node key, certificates, feeds, backups (0700, user `sherlock`) |
| `/lib/systemd/system/sherlock.service` | Hardened unit: `User=sherlock`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/sherlock`, `NoNewPrivileges=yes`, `PrivateTmp=yes` |

## Bootstrap settings (environment)

| Variable | Default |
| --- | --- |
| `SHERLOCK_DATA_DIR` | `/var/lib/sherlock` |
| `SHERLOCK_DB` | `sqlite:///var/lib/sherlock/sherlock.db` or `postgres://…` |
| `SHERLOCK_ADMIN_LISTEN` | `0.0.0.0:9443` |
| `SHERLOCK_HTTP_LISTEN` / `SHERLOCK_HTTPS_LISTEN` | `:80` / `:443` |
| `SHERLOCK_NODE_NAME` | hostname |
| `SHERLOCK_NODE_KEY_FILE` | `$DATA_DIR/node.key` |
| `SHERLOCK_LOG_LEVEL` | `info` |

Everything else is configuration in the store, managed via API/dashboard/YAML.

## Operating

- Health: `GET /healthz` (process up), `GET /readyz` (store reachable, data plane running, config applied).
- Metrics: `GET /metrics` on the admin listener (CIDR protected via `global.admin.allowed_cidrs`; the control plane adds token auth in M3). Key series: `sherlock_requests_total{site,action}`, `sherlock_request_duration_seconds`, `sherlock_waf_duration_seconds`, `sherlock_events_published_total`, `sherlock_events_dropped_total`, `sherlock_internal_errors_total`, `sherlock_requests_in_flight`, `sherlock_config_version_info`, `sherlock_crs_version_info`. Not yet exposed (they need Caddy state the data plane does not publish): `sherlock_upstream_healthy{site,upstream}` and `sherlock_cert_expiry_seconds`.

### Admin listener (since M2)

`global.admin.listen` (default `127.0.0.1:9444`, because the control plane uses 9443; `off` disables it) serves only `GET /metrics`, `/healthz` and `/readyz`, separate from proxied traffic. `/readyz` answers 503 until the first configuration has been applied and again while shutting down. `allowed_cidrs` limits who may connect (empty means anyone who can reach the port, so keep the default loopback bind or set a list when binding wider). It is plain HTTP until the control plane brings TLS (M3).

### Events on disk (since M2)

Until the event store exists (M3), security events are written as JSON lines, one event per line (schema: [event.schema.json](../reference/event.schema.json)):

- `$DATA_DIR/events.jsonl`, rotated by size (`global.events.sinks.file_max_mb`, default 100, keeping `file_keep`, default 5 rotated files), mode 0600;
- standard output (`global.events.sinks.stdout`, default on), interleaved with log lines (distinguish them by the `"schema":"sherlock.event.v1"` field);
- optionally `$DATA_DIR/access.jsonl`: a sampled log of *clean* requests (`global.events.access_log`, off by default), kept apart from security events.

The data directory defaults to `$XDG_DATA_HOME/sherlock` or `~/.local/share/sherlock`; override with `--data-dir`. Only whole lines are ever written, so a log shipper tailing the file never sees a truncated event.
- Backups: daily automatic to `$DATA_DIR/backups`, keep 7; copy off-host with your own tooling.
- Logs: JSON to stdout/journald.
- Upgrades: `sherlock update` (online) or `sherlock update --bundle sherlock-X.Y.Z-linux-amd64.tar.gz` (offline). Both verify signatures, back up, migrate, restart with zero downtime for proxied connections that finish within 30 s.
