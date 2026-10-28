# CI/CD

GitHub Actions. Runners: `ubuntu-latest` for most jobs; a fixed-size runner (2 vCPU) for k6 so numbers are comparable.

## Workflows

| Workflow | Trigger | Jobs |
| --- | --- | --- |
| `ci.yml` | PR, push to `main` | `gen-drift` (run `make gen`, fail on diff) · `lint` · `test-go` (race detector on) · `test-store` (SQLite + Postgres service) · `test-web` · `build` (binary + web) · `ftw-smoke` · `benign-corpus` · `bench` (compare with `main` via `benchstat`) · `e2e-smoke` · `govulncheck` · `licenses` · `gitleaks` |
| `codeql.yml` | PR, weekly | CodeQL for Go and JavaScript/TypeScript |
| `nightly.yml` | Schedule 02:00 UTC | Full `ftw` PL1–4, nuclei + ZAP vs Juice Shop, k6 budgets, long fuzzing, full e2e; opens an issue on failure |
| `release.yml` | Tag `v*` | GoReleaser build, SBOM, cosign signing, container image, GitHub Release, docs publish |
| `release-please.yml` | Push to `main` | Maintains the release PR and changelog from Conventional Commits |
| `cla.yml` | PR | CLA Assistant check |

Branch protection on `main`: required checks = all `ci.yml` jobs + CodeQL + CLA; linear history; squash merge; at least one approving review (yours) for PRs from branches; CODEOWNERS for sensitive paths.

## Caching

Go build and module cache, pnpm store, Playwright browsers, CRS test files.

## Secrets used by CI

None for PRs. Release uses GitHub OIDC for keyless cosign signing and `GITHUB_TOKEN` for GHCR; no long-lived keys.

## Status after M0

`ci.yml` currently runs `lint`, `test-go` (Linux and macOS), `test-web`, `build` (Linux and macOS), `govulncheck`, `licenses` and `gitleaks`. The remaining jobs in the table are added by the milestone that introduces what they check (`gen-drift` in M1 with the first generator, `test-store` in M3, `ftw-smoke` and `bench` in M2, `e2e-smoke` in M2). Actions are pinned by commit SHA; Renovate keeps the pins current.

## Branch protection checklist (M0-T9, manual)

- [ ] Required status checks: every `ci.yml` job, `codeql`, and the `cla` check.
- [ ] Require linear history and squash merging; require one approving review; require review from CODEOWNERS.
- [ ] Create the `cla-signatures` branch (unprotected) that the CLA workflow writes signatures to.
- [ ] Enable private vulnerability reporting and Dependabot alerts.
