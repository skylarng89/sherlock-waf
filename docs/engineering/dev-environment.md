# Development environment

## Prerequisites

| Tool | Version |
| --- | --- |
| Go | 1.27.x (Caddy 2.11 needs ≥ 1.26) |
| Node.js | 22 LTS or 24 LTS |
| pnpm | 12.x (pinned in `web/package.json` `packageManager`) |
| Docker + Compose v2 | recent |
| make, git | |
| VS Code with Go, Vue (Volar), ESLint, Tailwind CSS IntelliSense extensions | |

## First run

```bash
git clone https://github.com/skylarng89/sherlock-waf && cd sherlock-waf
make setup
make gen
make run            # dashboard on https://localhost:9443, proxy on :8080/:8443
make e2e-up         # optional: Juice Shop behind Sherlock on http://juice.localhost:8080
```

`dev/config.yaml` defines a `juice` site pointing at the compose Juice Shop, in block mode, with ACME off and a local self-signed certificate.

## Hot reload

- Web: `pnpm -C web dev` proxies `/api` to the Go server, so UI changes reload instantly.
- Go: `make run` uses `air` (pinned in `tools/`) to rebuild on change.

## Useful commands

```bash
make ftw             # CRS regression against a local build
make k6              # latency budget check
go test ./internal/policy/... -run TestSlidingWindow -v
pnpm -C web test
```
