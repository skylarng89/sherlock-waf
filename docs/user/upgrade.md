# Upgrade Sherlock WAF

Updates are signed. `sherlock update` accepts a release only if its manifest verifies against the release key built into your binary, the archive's SHA-256 matches, and the release is newer than the one you run. It refuses downgrades and anything it cannot verify, with no network needed for the verification itself. Background: [ADR-0017](../architecture/adr/0017-update-verification.md).

Read the release notes first, and take a backup if you want a copy beyond the automatic one (`sherlock backup`).

## Check for a new release

```sh
sherlock update --check
# running 0.4.0, latest release 0.5.0 (CRS 4.25.0)
# update available: run `sudo sherlock update`
```

The dashboard's system page shows the same through `GET /api/v1/system/update`.

## Update a host (online)

```sh
sudo sherlock update
```

It downloads and verifies the release, **backs up your data** (it stops if the backup fails), replaces the binary atomically (the old one is kept as `/usr/bin/sherlock.bak`), restarts `sherlock.service`, and waits until the service is up and stays up. If the new version does not start, it **puts the old binary back and restarts it**, then reports the failure. The database is migrated forward by the new version when it starts.

Proxied connections that finish within 30 seconds are not cut: the service drains on restart. Long-lived connections (WebSocket, streaming) are reset, so schedule updates accordingly.

Options: `--no-restart` swaps the binary and leaves the restart to you; `--skip-backup` skips the pre-update backup (not recommended); `--source https://mirror.example/release/` reads release files from your own mirror (the signature check still applies).

## Update offline (air-gapped)

On a machine with internet access download three files from the release page: `sherlock_<version>_linux_<arch>.tar.gz`, `release-manifest.json` and `release-manifest.json.sig`. Copy them into one directory on the host and run:

```sh
sudo sherlock update --bundle /srv/update/sherlock_0.5.0_linux_amd64.tar.gz
# manifest and signature are taken from the same directory, or pass --manifest FILE --signature FILE
```

A bundle whose archive was altered, truncated or swapped is refused with `archive checksum does not match the signed manifest`, and nothing on the host changes.

## Update from the dashboard or API

An administrator can run `POST /api/v1/system/update/apply` (permission `system:update`, held by admins and `admin`-scoped tokens). The service verifies the release and **stages** it; it does not restart itself. Restart when you are ready:

```sh
sudo systemctl restart sherlock      # the unit installs the staged update, as root, after verifying it again, then starts
```

The response and the system page tell you whether the update is `staged` or `installed`. Each apply, and each refusal, is in the audit log (`system.update`, `system.update_failed`).

## Roll back

If the new version misbehaves after a successful start:

```sh
sudo sherlock update --rollback      # restores /usr/bin/sherlock.bak and restarts
```

Rolling back swaps the binary only. The database has already been migrated: releases keep migrations compatible with the previous version for one release, but check the release notes; if they say otherwise, restore the pre-update backup instead ([backup and restore](backup-restore.md)).

## Containers

The binary inside an image is not replaced. `sherlock update --check` tells you what is available; to update, pull the new image tag and recreate the container with the same data volume:

```sh
docker pull ghcr.io/skylarng89/sherlock-waf:<new version>
docker stop sherlock && docker rm sherlock
docker run ... ghcr.io/skylarng89/sherlock-waf:<new version> run --data-dir /var/lib/sherlock    # same options as before
```

Back up the volume first, and keep the previous tag so you can go back.

## Packages

Installing a newer `.deb` or `.rpm` also upgrades (verify it as described in [install](install.md)); the package restarts the service. `sherlock update` is the same path with the verification built in.

## When an update is refused

| Message | Meaning |
| --- | --- |
| `manifest signature is invalid` | The manifest was not signed by the release key. Do not install it; report it |
| `archive checksum does not match the signed manifest` | The archive is damaged or tampered with. Download it again from a trusted source |
| `release is older than the running version` / `already running the latest version` | Nothing to do; downgrades are never performed by `update` |
| `below the release's min_upgrade_from` | Upgrade through the intermediate release named in the notes first |
| `this build has no release public key` | A source build: updates are disabled by design |
| `running in a container` | Pull the new image instead |
| `the installed binary's directory is not writable` | Run as root (`sudo`), or let the service stage it (API path) and restart |
