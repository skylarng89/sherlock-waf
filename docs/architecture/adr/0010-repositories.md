# ADR-0010: Public monorepo plus private Enterprise repo

- Status: Accepted
- Date: 2026-10-28

## Decision

`github.com/skylarng89/sherlock-waf` (public) contains Go server, dashboard, API spec, deployment files and docs, versioned and released together. `github.com/skylarng89/sherlock-waf-enterprise` (private) imports the core Go module and core web source (git submodule pinned to the same tag).

## Consequences

One PR can change data plane, API and UI together, which suits milestone-at-a-time work. Paid code cannot leak into the AGPL repo by accident.
