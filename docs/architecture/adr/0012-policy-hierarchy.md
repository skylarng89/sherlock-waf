# ADR-0012: Global, site and endpoint policy hierarchy

- Status: Accepted
- Date: 2026-10-28

## Context

Sherlock protects whole websites and individual API endpoints. Users need organisation-wide defaults (e.g. a global per-IP rate limit, paranoia level 1 everywhere) and narrow overrides (stricter rules and bot challenge on `/login`, a bigger body limit on an upload endpoint, inspection off for `/healthz`). Bolting this on after the config schema is frozen at v1.0 would be a breaking change.

## Decision

- One `policy` block type, used at three levels: `global.defaults`, `sites[].policy`, `sites[].endpoints[].policy`.
- Field-level inheritance with the merge rules in `docs/architecture/config-model.md`; explicit `opt_out` to drop a global named item.
- Deterministic endpoint precedence; ambiguous overlaps fail validation.
- Effective policies are resolved at **compile time** into per-endpoint Caddy subroutes; no runtime merging.
- `GET /sites/{site}/effective-policy` and a dashboard "effective policy" view show every value with its source.

## Consequences

- The model is in place from M1; each feature milestone adds its fields to the policy block, not to the site.
- Compiled config grows with the number of endpoints (one subroute each). Validation caps endpoints at 500 per site initially; revisit with measurements.
- Debuggability depends on the effective-policy view, so it is part of M3/M4, not an afterthought.

## Alternatives considered

| Option | Why not |
| --- | --- |
| Per-site settings with ad-hoc path matches per feature (the original plan) | Inconsistent across features, no global layer, hard to explain |
| Runtime merging per request | Slower and harder to test than compile-time resolution |
