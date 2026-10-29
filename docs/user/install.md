# Install Sherlock WAF

Pick one method. Every method ends the same way: a node with no users and no configuration, a control plane on `https://127.0.0.1:9443`, and nothing proxied until you add a site ([first site](first-site.md)).

| Method | Use it when | Updates |
| --- | --- | --- |
| [Install script](#install-script) | A Debian, Ubuntu or RHEL-family VM and you want one command | `sudo sherlock update` |
| [Packages](#packages-deb-and-rpm) | You manage hosts with apt, dnf or configuration management | `sudo sherlock update`, or install the next package |
| [Docker](#docker) | You run containers | Pull the new image |
| [From source](#from-source) | You build it yourself | `sudo sherlock update --bundle` or rebuild |

Requirements: Linux amd64 or arm64, 1 vCPU and 1 GB RAM for a small site (see [deployment](../operations/deployment.md) for sizing), ports 80 and 443 free for proxied traffic, and a way to reach port 9443 (loopback by default).

## Install script

```sh
curl --proto '=https' --tlsv1.2 -fsSLO https://github.com/skylarng89/sherlock-waf/releases/latest/download/install.sh
less install.sh                      # read it first
sudo sh install.sh                   # or: sudo sh install.sh --version v0.5.0
```

The script detects `dpkg` or `rpm`, downloads the package and `checksums.txt`, verifies the cosign signature of the checksums (keyless, the repository's release workflow identity), verifies the package's SHA-256, and only then installs. It stops on any verification failure. Without `cosign` installed it refuses to continue; install cosign, or pass `--allow-unsigned` and accept that the signature was not checked.

## Packages (deb and rpm)

Download `sherlock_<version>_linux_<arch>.deb` or `.rpm` and `checksums.txt` plus `checksums.txt.sigstore.json` from the [release page](https://github.com/skylarng89/sherlock-waf/releases), then verify and install:

```sh
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/skylarng89/sherlock-waf/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum -c --ignore-missing checksums.txt
sudo dpkg -i sherlock_*_linux_amd64.deb      # Debian, Ubuntu
sudo rpm -U  sherlock_*_linux_amd64.rpm      # RHEL, Rocky, Alma, Fedora
```

The package creates the `sherlock` user, `/var/lib/sherlock` (0700), `/etc/sherlock/sherlock.env`, and a hardened systemd unit (non-root, read-only system, only `CAP_NET_BIND_SERVICE`), then enables and starts it.

Settings go in `/etc/sherlock/sherlock.env`, then `sudo systemctl restart sherlock`:

| Variable | Meaning |
| --- | --- |
| `SHERLOCK_ADMIN_LISTEN` | Control plane address, default `127.0.0.1:9443`. Keep it on loopback or a private interface |
| `SHERLOCK_ADMIN_ALLOWED_CIDRS` | Only these networks may reach the control plane |
| `SHERLOCK_DATABASE_URL` | PostgreSQL instead of the default SQLite file |
| `SHERLOCK_NODE_KEY_FILE` | Keep the node key outside the data directory |
| `SHERLOCK_BACKUP`, `SHERLOCK_BACKUP_KEEP`, `SHERLOCK_BACKUP_PASSPHRASE_FILE` | Daily backup job: `off`, how many to keep (7), a file holding the passphrase that encrypts them |

Create the first administrator and look at the logs:

```sh
sudo -u sherlock sherlock user create --admin ada      # prompts for a 12+ character password
sudo journalctl -u sherlock -n 20                      # shows tls_spki_sha256, the control plane's key fingerprint
```

Or open `https://127.0.0.1:9443` and use the setup page with the one-time token in `/var/lib/sherlock/setup-token`. The certificate is self-signed; compare its fingerprint with `tls_spki_sha256` in the log before trusting it. Every account enrols an authenticator app at first sign-in.

To reach the control plane from another machine without exposing it, use an SSH tunnel: `ssh -L 9443:127.0.0.1:9443 host`.

## Docker

The image (`ghcr.io/skylarng89/sherlock-waf`) runs as a non-root user on a distroless base and works with a read-only root filesystem. Mount a volume for the data directory.

```sh
docker volume create sherlock-data
docker run -d --name sherlock --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  -p 80:80 -p 443:443 -p 127.0.0.1:9443:9443 \
  -v sherlock-data:/var/lib/sherlock \
  -e SHERLOCK_ADMIN_LISTEN=0.0.0.0:9443 \
  ghcr.io/skylarng89/sherlock-waf:<version> \
  run --data-dir /var/lib/sherlock
docker exec -it sherlock sherlock user create --admin ada --data-dir /var/lib/sherlock
```

A hardened Compose file with the same settings (non-root, read-only root filesystem, tmpfs, data volume, healthcheck) is at [`deploy/compose/docker-compose.yml`](../../deploy/compose/docker-compose.yml). Replace `<VERSION>` with a released tag, set `SHERLOCK_ADMIN_ALLOWED_CIDRS`, then run `docker compose up -d` and create the first admin with `docker compose exec sherlock sherlock user create --admin <name> --data-dir /var/lib/sherlock`. The image has no shell or curl, so its healthcheck runs `sherlock healthcheck`, which probes the node's own `/readyz` over loopback and exits non-zero when it is not ready. Point external monitoring at `https://<host>:9443/readyz`.

Notes:

- The image's default command runs the data plane from a YAML file only (`run --config /etc/sherlock/sherlock.yaml`). The command above overrides it to start the full node with the control plane.
- `-p 127.0.0.1:9443:9443` publishes the control plane on the host's loopback only. Add `SHERLOCK_ADMIN_ALLOWED_CIDRS` if you publish it wider.
- Pin the image by tag or digest rather than `latest`. Containers are updated by pulling a new image and recreating the container; `sherlock update` only checks inside a container. See [upgrade](upgrade.md).
- Back up the `sherlock-data` volume with `sherlock backup` ([backup and restore](backup-restore.md)), not by copying files from a running container.

## From source

```sh
make build                      # bin/sherlock, with the dashboard
sudo install -m 0755 bin/sherlock /usr/local/bin/sherlock
sherlock version
```

A build from source has no release signing key embedded, so `sherlock update` is disabled in it (it fails closed). Run it under your own service manager; the unit in `deploy/systemd/sherlock.service` is a good starting point.

## Check that it works

```sh
curl -sk https://127.0.0.1:9443/healthz        # ok
curl -sk https://127.0.0.1:9443/readyz         # 503 until the first configuration is applied
```

Next: [add your first site](first-site.md).
