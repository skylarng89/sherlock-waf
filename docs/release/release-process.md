# Release process

## Branching

- **Trunk-based.** `main` is always releasable. Feature work on short-lived `mNN/...` branches, squash-merged.
- **Release branches** `release/X.Y` are cut only when a patch is needed for an older minor (after 1.0). Fixes land on `main` first, then are cherry-picked.

## Cadence

| Release type | When |
| --- | --- |
| Minor | End of each milestone that ships user-facing change (pre-1.0); roughly every 6 to 8 weeks after 1.0 |
| Patch | As needed: security fixes, CRS security updates (target ≤ 72 h after CRS release), Caddy/Coraza/Go security fixes, regressions |
| Emergency patch | Virtual patch for a newly exploited critical CVE: target ≤ 24 h after the rule is validated (FR-VP-6) |
| RC | `-rc.N` one to two weeks before a minor, announced to design partners |

## Steps (automated)

1. Conventional Commits on `main` → `release-please` keeps a release PR updated with version bump and `CHANGELOG.md`.
2. Merge the release PR when the milestone's acceptance criteria and the release checklist pass. This creates tag `vX.Y.Z`.
3. `release.yml` runs GoReleaser:
   - builds `sherlock` for linux/amd64 and linux/arm64 with `-trimpath`, `-buildvcs`, ldflags for version info, `CGO_ENABLED=0`;
   - builds the dashboard first (`make web`), embedded;
   - produces `.tar.gz`, `.deb`, `.rpm` (nfpm), checksums;
   - generates SPDX SBOMs (syft);
   - signs checksums, SBOMs and container image with cosign keyless (GitHub OIDC identity);
   - pushes multi-arch image `ghcr.io/skylarng89/sherlock-waf:X.Y.Z` (+ `X.Y`, `X`, `latest` for stable) based on `gcr.io/distroless/static-debian12:nonroot`;
   - publishes `release-manifest.json` (version, CRS version, checksums, minimum upgrade-from version), signed.
4. Docs site rebuilds from the tag.

## Release checklist (human, in the release PR)

- [ ] Nightly suite green on the release commit (ftw full, nuclei/ZAP, k6 budgets, upgrade test).
- [ ] CHANGELOG reviewed; breaking changes have migration notes.
- [ ] `docs/user` updated for new features.
- [ ] Upgrade tested from the previous two minors.
- [ ] Security-sensitive changes since last release listed and reviewed.
- [ ] Version matrix in `docs/release/versioning.md` examples still accurate.

## Verifying a release (users)

```bash
cosign verify-blob --certificate-identity-regexp 'https://github.com/skylarng89/sherlock-waf/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
```

`sherlock update` does not need cosign: it verifies `release-manifest.json` against the Ed25519 release key embedded in the binary, then the SHA-256 of the archive, and refuses unsigned, mismatched, older or too-old-to-upgrade releases ([ADR-0017](../architecture/adr/0017-update-verification.md)). The workflow signs the manifest with `RELEASE_SIGNING_KEY` (base64 Ed25519 seed, repository secret) using `go run ./internal/updater/cmd/sign-manifest`, and uploads `release-manifest.json`, `release-manifest.json.sig` and the cosign bundle.

### Release signing key (one-time setup, before the first public release)

```bash
(umask 077; head -c 32 /dev/urandom | base64 > release-seed.b64)   # keep offline; paste into the RELEASE_SIGNING_KEY secret
go run ./internal/updater/cmd/sign-manifest -public release-seed.b64 > internal/updater/release_key.pub   # commit this
```

Until `release_key.pub` holds a real key, every build refuses to update (fail closed). Rotating the key needs a release signed with the old key that embeds the new one.
