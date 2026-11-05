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

- All Phase 3 milestones complete.
- External pentest critical/high findings fixed.
- API, config schema v1 and event schema v1 frozen.
- At least 3 design partners ran a release candidate in `block` mode for 30 days.

## Version information

`sherlock version` prints:

```
sherlock 1.2.3 (commit 1a2b3c4, built 2026-11-02T10:00:00Z, go1.27.3)
caddy 2.11.7 · coraza 3.x.y · crs 4.30.0 · config schema 1 · api v1 · edition community
```

The same data is in `GET /api/v1/system/info` and the dashboard footer.
