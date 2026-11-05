# Coding standards

## Go

- Go version: pinned in `go.mod` (`go 1.27`, `toolchain go1.27.x`). Update with Renovate.
- Format with `gofumpt`, imports with `goimports`. Lint with `golangci-lint` (enabled: `govet`, `staticcheck`, `errcheck`, `gosec`, `revive`, `bodyclose`, `noctx`, `sqlclosecheck`, `exhaustive`, `gocritic`, `misspell`, `nilerr`, `contextcheck`).
- Errors: wrap with `fmt.Errorf("doing x: %w", err)`; sentinel errors in the package that owns them; no `panic` outside `main` and impossible states.
- Context: every function doing I/O takes `ctx context.Context` first.
- Logging: `log/slog` only, structured keys in `snake_case`, logger passed in, never global.
- Concurrency: prefer channels for pipelines, `sync.Mutex` for state; `atomic.Pointer` for hot-swapped read-mostly data (feeds, compiled policies). Every goroutine has an owner that stops it on shutdown.
- Packages are small and named for what they provide (`ratelimit`, not `utils`).
- Public API (`pkg/...`) has doc comments on every exported identifier.
- Tests: table-driven, `t.Parallel()` where safe, `testify/require` allowed; no sleeps for synchronisation.

## TypeScript / Vue

- `strict: true`, no `any` (lint error), no non-null assertions except in tests.
- `<script setup lang="ts">` Single File Components; Composition API only.
- Components: PascalCase files; pages in `pages/` named `XxxPage.vue`.
- State: Pinia stores per domain (`useSitesStore`), server data fetched through composables wrapping the generated client; no direct `fetch`.
- Styling: Tailwind utility classes; OpenVue components in unstyled or themed mode configured once in `main.ts`; design tokens as CSS variables in `styles/main.css`, light and dark themes.
- Icons: Tabler webfont classes (`<i class="ti ti-shield-check" aria-hidden="true" />`) with an accessible label on the control.
- Accessibility: every interactive element keyboard reachable; form fields have labels; colour is never the only signal; check with `@axe-core/playwright` in e2e.
- Internationalisation: all strings through `vue-i18n` from M4 (English only at first), so translation is possible later.

## Commits and branches

- Conventional Commits: `feat(waf): add exclusion by tag`, `fix(api): …`, `docs(adr): …`, `chore(deps): …`. Scope = top-level area (`waf`, `acl`, `ratelimit`, `bot`, `api`, `ui`, `store`, `config`, `compiler`, `events`, `release`, `docs`).
- Branch names: `m<NN>/<short-task>` for milestone work, e.g. `m05/sliding-window`.
- Breaking changes: `feat(api)!:` plus `BREAKING CHANGE:` footer.
- Small PRs: one task (or a few tightly coupled tasks) per PR; squash-merge.
