# Repository structure

Target layout once M0 is done. Folders appear as milestones need them; do not create empty packages early.

```
sherlock-waf/
├── README.md
├── LICENSE                       # AGPL-3.0 full text
├── NOTICE                        # third-party credits (Caddy, Coraza, coraza-caddy, CRS)
├── CLA.md  CONTRIBUTING.md  SECURITY.md  CODE_OF_CONDUCT.md  CHANGELOG.md
├── Makefile                      # the only entry point for build/test tasks
├── go.mod  go.sum
├── .golangci.yml  .editorconfig  .gitignore  .gitleaks.toml
├── renovate.json
├── .goreleaser.yaml
├── .github/
│   ├── workflows/                # ci.yml, nightly.yml, release.yml, codeql.yml, cla.yml
│   ├── ISSUE_TEMPLATE/
│   ├── pull_request_template.md
│   └── CODEOWNERS
├── api/
│   └── openapi.yaml              # source of truth for /api/v1
├── cmd/
│   └── sherlock/main.go
├── pkg/                          # PUBLIC Go API (semver-governed)
│   ├── cli/                      # cobra commands shared with sherlock-ee
│   └── extension/                # interfaces for Enterprise
├── internal/
│   ├── app/                      # wiring: start store, control plane, data plane; shutdown
│   ├── config/                   # model, defaults, validation, YAML, migrate/
│   ├── compiler/                 # config → Caddy JSON (+ testdata golden files)
│   ├── dataplane/
│   │   ├── core/  acl/  ratelimit/  bot/  apiguard/  login/  waf/  dlp/
│   │   └── pages/                # embedded block/challenge templates
│   ├── policy/                   # pure logic: ipset, sliding window, tokens, luhn, redaction
│   ├── events/                   # schema, bus, writer, redaction
│   ├── controlplane/
│   │   ├── api/                  # generated server interface + handlers
│   │   ├── auth/  users/  audit/  configsvc/  eventsvc/  analytics/
│   │   ├── exporters/  alerts/  feeds/  jobs/  updater/  backup/
│   ├── store/
│   │   ├── migrations/{sqlite,postgres}/
│   │   ├── queries/{sqlite,postgres}/
│   │   └── sqlite/  postgres/    # sqlc output
│   ├── logging/                  # slog setup with redaction
│   ├── secrets/                  # node key, encrypt/decrypt
│   └── webui/                    # embed.FS of web/dist
├── web/                          # Vue dashboard (pnpm)
│   ├── package.json  vite.config.ts  tsconfig.json  eslint.config.js
│   ├── src/
│   │   ├── main.ts  App.vue  router/  stores/  api/ (generated client)
│   │   ├── components/  (Sk* wrappers, charts/, layout/)
│   │   ├── pages/  (overview, sites, events, analytics, settings, setup, ...)
│   │   ├── composables/  extensions.ts  styles/main.css
│   └── e2e/                      # Playwright
├── rules/
│   └── virtual-patches/          # SV-<year>-<n>.conf rules + metadata.yaml per rule (CVE, product, refs, tests)
├── test/
│   ├── ftw/                      # go-ftw config and Sherlock-specific test cases
│   ├── nuclei/                   # nuclei templates and config (incl. one template per virtual patch)
│   ├── k6/                       # load and latency scripts with budgets
│   ├── corpus/benign/            # benign traffic samples for false-positive checks
│   └── e2e-compose/              # docker compose: sherlock + Juice Shop + httpbin
├── deploy/
│   ├── docker/                   # Dockerfile, compose.yaml example
│   ├── systemd/sherlock.service
│   ├── install/install.sh
│   └── helm/sherlock/            # from M12
├── docs/                         # design docs (this folder) + user docs in docs/user/
└── tools/                        # tools.go pins for sqlc, oapi-codegen, goose, etc.
```

## Make targets (stable interface for humans and CI)

| Target | Does |
| --- | --- |
| `make setup` | Install toolchain deps (Go tools pinned in `tools/`, pnpm install) |
| `make gen` | Run sqlc, oapi-codegen, openapi-typescript, JSON-schema generation |
| `make build` | Build web then Go binary into `bin/sherlock` |
| `make run` | Run locally with `dev/config.yaml` and data in `.dev-data/` |
| `make test` | Go unit tests + web unit tests |
| `make test-integration` | Store tests on SQLite and Postgres (testcontainers) |
| `make ftw` | Build, start Sherlock + backend, run go-ftw CRS regression |
| `make e2e` | Compose stack + Playwright |
| `make bench` | Go benchmarks; `make k6` latency/throughput budget |
| `make lint` | golangci-lint, eslint, vue-tsc, prettier --check, gitleaks |
| `make check` | `gen` drift check + lint + test (what CI runs on every PR) |
