# ADR-0005: Sherlock-owned config model compiled to Caddy JSON

- Status: Accepted
- Date: 2026-10-28

## Context

Caddy JSON is powerful but low-level, and it changes with Caddy versions. Users, the API and the dashboard need a stable, domain-specific model (sites, modes, exclusions, rate limits).

## Decision

Define the model in `internal/config` (see `docs/architecture/config-model.md`), version it with `schema_version`, and compile it deterministically to Caddy JSON in `internal/compiler`. Caddy JSON is an implementation detail and is never exposed in the API.

## Consequences

- We can upgrade Caddy without breaking users.
- GitOps via YAML export/import is natural.
- The compiler needs golden-file tests: every fixture config has an expected Caddy JSON output.
