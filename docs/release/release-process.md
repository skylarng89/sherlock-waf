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

`sherlock update` performs the same verification automatically and refuses unsigned or mismatched artefacts.
