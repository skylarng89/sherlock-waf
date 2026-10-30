# M0 · Repository bootstrap

- Phase: 1 · Foundation
- Depends on: nothing
- Ships: no release
- Read first: `docs/engineering/repo-structure.md`, `docs/engineering/coding-standards.md`, `docs/engineering/ci-cd.md`, `docs/security/secure-development.md`, ADR-0004, ADR-0008, ADR-0010

## Goal

An empty but fully wired repository: `make check` runs lint, tests and builds a placeholder binary with an embedded placeholder dashboard, CI enforces it, and governance files are in place.

## Tasks

- [ ] **M0-T1** Go module `github.com/skylarng89/sherlock-waf`, `go 1.27` + toolchain line, `cmd/sherlock/main.go` printing version via `pkg/cli` (cobra) with `version` command; ldflags for version/commit/date.
- [ ] **M0-T2** `tools/tools.go` pinning golangci-lint (or use `go tool` directives), gofumpt, sqlc, oapi-codegen, goose, air, govulncheck, go-licenses. `Makefile` with every target from repo-structure.md (unimplemented ones print "not yet").
- [ ] **M0-T3** `web/` scaffold: Vite 8 + Vue 3.5 + TS strict + Pinia + Vue Router + Tailwind v4 (`@tailwindcss/vite`) + OpenVue + Tabler webfont + vue-echarts + vue-i18n + Vitest + ESLint flat config + Prettier. One placeholder page that renders an OpenVue button, a Tabler icon and an ECharts chart in light and dark mode. pnpm.
- [ ] **M0-T4** `internal/webui` embedding `web/dist`; `sherlock run` serves it on `:9443` (plain HTTP for now) to prove the embed works.
- [ ] **M0-T5** Lint and format configs: `.golangci.yml` (linters from coding-standards.md), `.editorconfig`, `.gitleaks.toml`, pre-commit config (optional for contributors).
- [ ] **M0-T6** GitHub Actions `ci.yml` with jobs `lint`, `test-go`, `test-web`, `build`, `govulncheck`, `licenses`, `gitleaks`; `codeql.yml`; `renovate.json` (group Go, web, Actions; weekly; automerge patch for dev deps only).
- [ ] **M0-T7** `.goreleaser.yaml` producing linux amd64/arm64 archives in snapshot mode (`make release-snapshot`); release workflows added but only triggered on tags.
- [ ] **M0-T8** Governance: `LICENSE` (AGPL-3.0 full text), `NOTICE`, `CLA.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `CHANGELOG.md`, issue and PR templates, `CODEOWNERS`. CLA Assistant app configured (`cla.yml`).
- [ ] **M0-T9** Branch protection on `main` configured per ci-cd.md (manual step in GitHub settings; document in `docs/engineering/ci-cd.md` that it is done).

## Acceptance criteria

1. `make setup && make check` passes on a clean clone on Linux and macOS.
2. `make build && ./bin/sherlock version` prints the version line; `./bin/sherlock run` serves the placeholder dashboard.
3. CI on a PR runs all listed jobs and blocks merge on failure.
4. `make release-snapshot` produces two archives with a working binary each.
5. A PR from a second GitHub account is blocked until the CLA is signed.

## Out of scope

Any proxy or WAF functionality.

## Notes

- Do not add dependencies beyond those listed; each later milestone adds what it needs.
- Choose the exact latest stable versions on the day and pin them; record them in the PR description.
