# Backup and restore

A node's state is its database, its node key, and a few files (ACME certificates and similar). `sherlock backup` captures all of it except the node key in one archive, while the server keeps running. `sherlock restore` brings it back on the same or a fresh host.

## What is in a backup

| Included | Not included |
| --- | --- |
| A consistent snapshot of the SQLite database: sites and configuration history, users, API tokens (hashes), sealed secrets, audit log, events | The node key (`node.key`), unless you ask for it (see below) |
| Data directory files: ACME certificates and account state, the control plane's TLS identity | Caches and runtime state: `geoip/`, `feeds/`, `locks/`, event JSONL files, the setup token, previous backups, staged updates |
| A manifest with the version, creation time and a SHA-256 for every file | `certs/`: uploaded certificates are rewritten from the database whenever the configuration compiles |

**The node key matters.** Secrets in the database (uploaded certificate private keys, authenticator seeds) are encrypted under it. A backup without the key restores everything, but those secrets cannot be read. Keep a copy of `node.key` (or the file `SHERLOCK_NODE_KEY_FILE` names) in your password manager or vault, separate from the backups.

Backups can hold sensitive material (ACME private keys in clear, the audit log, password hashes). Treat them like the node itself: files are mode 0600 in a 0700 directory, and you should encrypt them whenever they leave the host.

## Take a backup

```sh
sudo -u sherlock sherlock backup                       # <data-dir>/backups/sherlock-backup-<UTC time>.tar.gz
sudo -u sherlock sherlock backup --output /mnt/nas/sherlock-$(date +%F).tar.gz
printf '%s\n' "$PASSPHRASE" | sudo -u sherlock sherlock backup --passphrase-stdin      # encrypted archive
printf '%s\n' "$PASSPHRASE" | sudo -u sherlock sherlock backup --include-key --passphrase-stdin   # includes node.key; always encrypted
```

The passphrase is read from stdin or a prompt, never from a flag. An encrypted archive ends in `.tar.gz.enc`; without the passphrase it is unreadable, and a truncated or altered file fails to open.

### Automatic daily backups

SQLite nodes back up automatically: every 24 hours the server writes a backup to `<data-dir>/backups` and keeps the newest 7. Each is recorded in the audit log (`backup.create`). Tune it in `/etc/sherlock/sherlock.env`:

```sh
SHERLOCK_BACKUP=off                                       # turn the job off
SHERLOCK_BACKUP_KEEP=14                                   # how many to keep
SHERLOCK_BACKUP_PASSPHRASE_FILE=/etc/sherlock/backup.pass # encrypt scheduled backups (file readable only by sherlock)
```

If a passphrase file is configured but unreadable, the job stops rather than writing unencrypted backups. **Copy backups off the host** with your own tooling (rsync, object storage, your backup agent): a backup next to the disk it protects does not survive losing the disk.

List and check them:

```sh
sherlock backup list
sherlock backup verify /path/to/backup.tar.gz [--passphrase-stdin]
```

`verify` decrypts the archive, checks every checksum, runs SQLite's integrity and foreign-key checks and verifies the audit hash chain, without touching your data. Run it on a schedule against your off-host copies: an untested backup is a hope.

The dashboard's system page and `GET /api/v1/system/backups` list the node's own backups.

### PostgreSQL

Sherlock does not dump PostgreSQL itself. Dump the database with your own tooling and take the files with `--files-only`:

```sh
pg_dump --format=custom --file=sherlock-$(date +%F).dump "$SHERLOCK_DATABASE_URL"
sudo -u sherlock sherlock backup --files-only
```

To restore, run `pg_restore --clean --if-exists --dbname=<url> sherlock-….dump` for the database, then `sherlock restore` on the files archive (an archive without a database installs only the data files), and put the node key back. `sherlock restore` refuses a backup that holds a SQLite database on a node configured for PostgreSQL. Test the restore into a scratch database before you need it.

## Restore

Restore needs the server **stopped** (it takes the data-directory lock and refuses to run beside a live node).

```sh
sudo systemctl stop sherlock
sudo -u sherlock sherlock restore /path/to/backup.tar.gz [--passphrase-stdin]
# a backup without the node key: put node.key back (owner sherlock, mode 0600) before starting
sudo install -m 0600 -o sherlock -g sherlock /safe/place/node.key /var/lib/sherlock/node.key
sudo systemctl start sherlock
```

What restore does, in order: decrypts and unpacks into a staging directory inside the data directory; checks every checksum against the manifest and rejects any unsafe path; runs the database integrity and audit-chain checks on a copy; and only then installs. Nothing in your data directory changes if any check fails.

- On a **fresh host** (empty data directory) it just installs.
- If the data directory **already has a database**, restore refuses. Add `--force` to replace it: the old database and files are moved to `<data-dir>/pre-restore-<time>/`, not deleted.
- A restore is recorded in the restored audit log as `backup.restore`.
- Restore from a backup made by an **older** version works; the server migrates the database forward when it starts. A backup from a **newer** version than the binary is refused.

After starting, confirm: `curl -sk https://127.0.0.1:9443/readyz`, sign in, check that your sites, users and certificates are there, and run `sherlock audit verify`.

## A restore drill

Do this once a quarter on a scratch VM: install the same version, restore the latest off-host backup, put the node key back, start it, and sign in. Time it. That number is your real recovery time.
