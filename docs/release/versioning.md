# Versioning

Sherlock has several things that carry versions. Each has its own rule.

| Thing | Scheme | Rule |
| --- | --- | --- |
| Product / binary / container | SemVer `MAJOR.MINOR.PATCH` | One version for the whole monorepo (Go server, dashboard, API, CLI) |
| Go module `github.com/skylarng89/sherlock-waf` | Same tag as product | `pkg/...` is the public API. From v1.0 a breaking change to `pkg/` requires a new major version (`/v2` module path) |
| REST API | Path version `/api/v1` | Additive changes only within v1 after 1.0. Deprecations announced one minor release ahead with `Deprecation` and `Sunset` headers |
| Config schema | Integer `schema_version` | Increments only on breaking change; automatic migration on import and upgrade |
| Event schema | `sherlock.event.vN` | New version needs dual-write for one minor release |
| Database schema | goose migration number | Forward-only; every release can migrate from the previous two minors |
| CRS | Embedded, shown in `sherlock version` and the dashboard | CRS update = Sherlock patch release (minor if CRS minor changes behaviour noticeably) |
| Virtual-patch rule pack | `YYYY.MM.N` shown next to CRS | Ships in releases; a pack-only update is a Sherlock patch release |
| Helm chart | Own SemVer, `appVersion` = Sherlock version | From M12 |

## Pre-1.0

- `0.MINOR.PATCH`. Each completed milestone that changes user-facing behaviour ships as a minor release (`0.1.0` after M2, `0.2.0` after M4, … see [../plan/roadmap.md](../plan/roadmap.md)).
- Breaking changes are allowed in minors but MUST be listed under "Breaking" in the changelog with migration notes.
- Pre-releases: `0.5.0-rc.1` for design partners before each minor from M5 on.

## 1.0 criteria

Status as of the freeze (M11-T5). A criterion is only ticked when its evidence exists.

- [ ] All Phase 3 milestones complete. M8, M9 and M10 are done; M11 is feature complete once its remaining tasks land.
- [ ] External pentest critical/high findings fixed. **Not started**: the vendor engagement (M11-T6) is the owner's; the preparation pack is in [../security/pentest/](../security/pentest/).
- [x] API, config schema v1 and event schema v1 frozen (see below).
- [ ] At least 3 design partners ran a release candidate in `block` mode for 30 days. **Not started**: the programme (M11-T8) is the owner's; see [rc-program/](rc-program/).

## The 1.0 contract

From `v1.0.0` these are frozen. Within a major version they only grow; anything else needs a new major version (and for Go packages a `/v2` module path).

| Surface | What is frozen | How it is enforced |
| --- | --- | --- |
| REST API `/api/v1` | Paths, methods, parameters, request and response schemas, status codes and the permission of every operation in [api/openapi.yaml](../../api/openapi.yaml), `info.version` 1.0.0. New fields, endpoints and optional parameters are additions. | The embedded spec is the contract the server validates against; `make gen` and the `gen-drift` CI job keep the generated server, the web client and [the API reference](../reference/api-reference.md) in step with it. A start-up check refuses an operation without a permission. |
| Deprecation | A deprecated operation stays for at least one minor release after it is announced and answers with `Deprecation: true`, `Sunset: <HTTP-date>` and, when set, `Link: <migration notes>; rel="deprecation"`. | An operation marked `deprecated: true` must carry `x-sherlock-sunset` (RFC 3339), checked at start-up and by a unit test; headers are added by the API guard. No operation is deprecated at 1.0. |
| Config schema | `schema_version: 1`: every key, its type and meaning in [the configuration reference](../reference/config-reference.md) and [config.schema.json](../reference/config.schema.json). New optional keys are additions; removing or re-typing a key is a new schema version with automatic migration. | The reference is generated from the Go types and fails the build if a key lacks a description; unknown keys are rejected by the loader. |
| Event schema | `sherlock.event.v1` ([event.schema.json](../reference/event.schema.json)). New optional fields are additions; a new version dual-writes for one minor release. | Generated from the Go type; drift fails CI. |
| `pkg/extension` | Every exported identifier, signature and field of the package. | `TestAPIGuard` compares the exported surface with `pkg/extension/testdata/api.txt`; changing it is a visible golden-file edit (`go test ./pkg/extension -run APIGuard -update`). |
| `pkg/cli` | `Execute`, `NewRootCommand` (the returned `*cobra.Command` and so the cobra major version), `BuildInfo`, `Option`, `WithExtensions`, `WithReleaseKey`, `WithUI`. | `TestAPIGuard` with `pkg/cli/testdata/api.txt`. |
| Command line | The commands and flags documented in `docs/user` (`run`, `version`, `user`, `token`, `config`, `audit`, `secrets`, `update`, `backup`, `restore`, `healthcheck`, `hash-password`). New commands and flags are additions. | Command tests in `pkg/cli`; a removed or renamed flag is a breaking change listed in the changelog. |
| Database schema | Forward-only goose migrations; every release migrates from the previous two minors. | The store conformance suite and migration tests in `internal/store` (SQLite and PostgreSQL). The upgrade-from-the-previous-two-minors check is a release-checklist item and is not automated yet. |

Not frozen: anything under `internal/`, the dashboard's internal routes and components, and log line formats. Metric names are stable but may gain labels; a removed metric is announced in the changelog.

Breaking changes made before the freeze are listed under "Breaking (before 1.0)" in [CHANGELOG.md](../../CHANGELOG.md).

## Version information

`sherlock version` prints:

```
sherlock 1.2.3 (commit 1a2b3c4, built 2026-11-02T10:00:00Z, go1.27.3 linux/amd64)
caddy v2.11.7 · coraza v3.x.y · crs 4.30.0 · config schema 1 · api v1
```

The same data is in `GET /api/v1/system/info` and the dashboard footer.
