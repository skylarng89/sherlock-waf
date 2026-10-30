# ADR-0017: Update verification, atomic swap and restart

- Status: Accepted (M7-T7)
- Date: 2026-10-29
- Deciders: owner (delegated: recommended option adopted)

## Context

`sherlock update` replaces the running binary, so it is the highest-value target in the product: a forged or replayed update is remote code execution on a security appliance, usually as root. The milestone text says "verifies cosign signature and checksums". Three constraints push against doing that inside the binary:

1. Keyless cosign verification needs the Sigstore trust root (Fulcio, Rekor), a TUF refresh and network access, and pulls a large dependency tree into the binary that verifies itself. It cannot run offline, which `--bundle` must.
2. An air-gapped or restricted host must be able to verify an update with nothing but the files it was given.
3. The control plane runs as an unprivileged user under `ProtectSystem=strict`, so it cannot write `/usr/bin/sherlock`. A privileged step has to exist, and it must not trust anything the unprivileged user can write.

## Decision

1. **Trust anchor.** One Ed25519 public key, committed in `internal/updater/release_key.pub` and embedded in the binary. It is the only thing the updater trusts. A source build carries the placeholder `UNSET`; the updater then refuses everything (`ErrNoReleaseKey`) instead of trusting an empty key. Editions that sign their own releases pass their key with `cli.WithReleaseKey`.
2. **Signed manifest.** Each release has `release-manifest.json` (schema, version, CRS version, `min_upgrade_from`, SHA-256 of every artefact; written by `scripts/release-manifest.sh`) and `release-manifest.json.sig`, a base64 Ed25519 signature over `"sherlock-release-manifest-v1\n" + manifest bytes`. The context prefix stops the key from validating a document signed for another purpose. The signature is checked before the manifest is parsed. The private key lives only in the release workflow secret `RELEASE_SIGNING_KEY` and is read from a file by `internal/updater/cmd/sign-manifest`.
3. **Checks, in order**, all of which must pass: manifest signature; schema 1; the running build has a release version (development builds cannot update); the release is **strictly newer** than the running version (downgrade and same-version refused); the running version is at least `min_upgrade_from`; the manifest lists an archive for this OS and architecture; the SHA-256 of the archive equals the manifest value (constant-time compare). Only then is the archive opened. The archive bytes are read into memory once and both hashed and unpacked from that copy, so a file swapped after the check cannot be installed.
4. **Offline and online are the same path.** `--bundle FILE` takes the release archive and finds `release-manifest.json` and `.sig` beside it (or via `--manifest` / `--signature`). Online mode fetches the same three files from the release URL. Online fetches use `internal/netx` (SSRF-safe: no loopback, private, link-local or metadata addresses; no proxy from the environment; size caps; https only) and never any other client.
5. **cosign stays in CI.** The workflow still cosign-signs `checksums.txt`, the SBOMs and `release-manifest.json` (keyless, GitHub OIDC). `install.sh` verifies those with cosign when it is installed. They are an independent, auditable signature for humans and for first install, but the updater does not need them: the Ed25519 chain is complete on its own.
6. **Atomic swap with backup and rollback.** The new binary is extracted from the archive's `sherlock` entry (regular file, size-capped, never written by name from the archive) to `<exe>.new` in the same directory and fsynced. It must pass a self-test (`<exe>.new version` reports the manifest version) before anything is replaced. The current binary is hard-linked (or copied) to `<exe>.bak`, then `rename(2)` replaces the executable, so the path never names a missing or partial file. `sherlock update --rollback` renames `.bak` back. A failed self-test or write leaves the old binary untouched.
7. **Data first.** Before swapping, the CLI writes a backup (ADR-0006, `sherlock backup`) because the new binary may migrate the database forward. A failed backup aborts the update unless `--skip-backup` is given. PostgreSQL nodes get a files-only backup and a reminder to `pg_dump`.
8. **Restart.** If systemd manages an active `sherlock.service`, the CLI restarts it, waits for `active` and for the unit to stay up three seconds, and on failure rolls the binary back and restarts again. Otherwise it prints what to do. In containers the binary inside an image is not replaced: `update` refuses to install and `--check` still works; operators pull a new image.
9. **API path.** `POST /system/update/apply` needs the new permission `system:update` (admin role and the `admin` token scope only; never read, write or events scopes). It downloads and verifies exactly as above, audits `system.update` (and `system.update_failed`, with the reason, for refusals), and then either installs (if the process can write the binary, for example a non-packaged install) or **stages** the verified bundle (manifest, signature and archive, unmodified) in `<data-dir>/updates/staged`. It never restarts the process.
10. **Privileged apply.** The packaged unit runs `ExecStartPre=-+/usr/bin/sherlock update --apply-staged` (the `+` runs it as root outside the sandbox, the `-` means a failure never blocks start-up). `--apply-staged` treats the staged directory as hostile, because the service user owns it: it re-verifies signature, version policy and checksum from scratch and installs from the verified in-memory copy. A tampered stage is deleted and refused. The worst an attacker who controls the service user can do is cause a replay of an older **validly signed** release that is still newer than the running one, which the version policy bounds.

## Consequences

- Verifying needs no network, no Sigstore and no new dependency (standard library `crypto/ed25519`).
- The release key is a long-lived secret. Compromise of `RELEASE_SIGNING_KEY` allows signing a malicious release; there is no revocation list inside the binary. Mitigations: the secret is only in the release workflow; rotation means shipping a release signed with the old key that embeds the new key (a key-rotation release must set `min_upgrade_from` so that old binaries step through it); the cosign signature on the same manifest gives humans a second, independent check. A key-rollover procedure has to be written before the first public release (follow-up).
- A user who cannot reach the update URL can still update from a bundle, and a tampered binary in a bundle is refused (Phase 2 acceptance criterion 3).
- Rolling an upgrade back does not roll the database back. Migrations are forward-only and are meant to stay backward-compatible for one release (expand, migrate, contract), so the previous binary should run on the migrated database for one version (verify this per release); the pre-update backup is the way back beyond that.
- API-triggered updates stage and wait for a restart. This costs one operator action, and in exchange the service keeps `ProtectSystem=strict` and the unprivileged user never writes an executable that root will run.
- No staged-update expiry exists yet: a staged bundle waits for the next start, where it is re-checked; if a newer release has been installed since, it is discarded as a downgrade.

## Alternatives considered

| Option | Why not |
|---|---|
| Verify cosign keyless bundles inside the binary | Needs the Sigstore trust root and network for freshness, large dependency set, not verifiable offline. Kept in CI as an extra. |
| Pinned cosign key pair instead of Ed25519 | Same trust model as Ed25519 but through a heavier library and a PEM/ECDSA format; no benefit here. |
| Trust `checksums.txt` fetched over HTTPS only | TLS protects the channel, not the artefact; a compromised mirror or release page would pass. |
| Let the service user write `/usr/bin` (drop `ProtectSystem`, or a writable bin dir) | Weakens the hardened unit and lets a compromised service user plant code that runs as root at the next restart. |
| Run the updater from a root `systemd` path unit watching the staged dir | Works, but adds two units and a long-lived privileged watcher; `ExecStartPre=+` reuses the restart the operator has to do anyway. |
| Re-exec the new binary in place and hand over sockets (zero-downtime) | Caddy's own reload does not cover a binary change; deferred to a later milestone. Connections that finish within `TimeoutStopSec` (30 s) drain on restart. |
