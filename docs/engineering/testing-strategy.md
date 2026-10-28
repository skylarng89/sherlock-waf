# Testing strategy

| Layer | Tool | What | When |
| --- | --- | --- | --- |
| Unit (Go) | `go test` | `internal/policy`, `config`, `compiler`, services | Every PR |
| Golden files | `go test` + `testdata/*.yaml → *.caddy.json` | Compiler determinism and output | Every PR; update with `make golden` |
| Fuzz | Go native fuzzing | Config YAML parser, redaction, Luhn, JWT parsing, SecLang validator | 60 s per target per PR; 30 min nightly |
| Store | `go test` + testcontainers Postgres | Every query on both dialects | Every PR |
| API | `go test` + `httptest` | Each route × role × happy/forbidden/invalid | Every PR |
| CRS regression | `go-ftw` against the built binary | Full CRS test suite at PL1–PL4; Sherlock-specific cases in `test/ftw` | Every PR (PL1 subset), nightly (all) |
| Virtual patches | nuclei template or go-ftw case per rule (positive) + benign corpus (negative) | Every rule blocks its exploit and nothing benign | Every PR touching `rules/`; nightly all |
| Attack replay | nuclei, OWASP ZAP baseline | Juice Shop behind Sherlock in block mode; expected detection list | Nightly |
| False positives | Benign corpus replay (`test/corpus/benign`: real-world-like requests, JSON APIs, file uploads) | Zero blocks at PL1 | Every PR |
| Performance | Go benchmarks; k6 | Module micro-benchmarks (10% regression gate); latency/throughput budgets NFR-1/2 | Benchmarks every PR; k6 nightly on a fixed 2 vCPU runner |
| Web unit | Vitest | Composables, stores, form validation | Every PR |
| E2E | Playwright + axe | Setup wizard, add site, see blocked attack, create exclusion, roles | Every PR (smoke), nightly (full) |
| Upgrade | Script | Install previous release, create data, upgrade to current, verify | Release pipeline |

Coverage targets: `internal/policy` 90%, other Go packages 75%, enforced per package in CI from M3. Coverage is a floor, not a goal.

## Juice Shop test bed

`test/e2e-compose/compose.yaml` runs Sherlock, OWASP Juice Shop, `httpbin` and a Postgres. `make e2e-up` brings it up locally with Sherlock in block mode on `juice.localhost`. All attack tests run against it.

## Definition of done (every task)

- Acceptance criteria in the milestone file pass, with tests that would fail without the change.
- `make check` passes.
- User-facing docs in `docs/user/` updated.
- If a design doc is now wrong, it is updated in the same PR.
