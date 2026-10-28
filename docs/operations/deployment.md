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
- Metrics: `GET /metrics` on the admin listener (token or CIDR protected). Key series: `sherlock_requests_total{site,action}`, `sherlock_request_duration_seconds`, `sherlock_waf_duration_seconds`, `sherlock_events_dropped_total`, `sherlock_upstream_healthy{site,upstream}`, `sherlock_config_version_info`, `sherlock_crs_version_info`, `sherlock_cert_expiry_seconds`.
- Backups: daily automatic to `$DATA_DIR/backups`, keep 7; copy off-host with your own tooling.
- Logs: JSON to stdout/journald.
- Upgrades: `sherlock update` (online) or `sherlock update --bundle sherlock-X.Y.Z-linux-amd64.tar.gz` (offline). Both verify signatures, back up, migrate, restart with zero downtime for proxied connections that finish within 30 s.
