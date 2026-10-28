# ADR-0004: Go, single static binary

- Status: Accepted
- Date: 2026-10-28

## Decision

All server code is Go (1.27.x at time of writing; minimum = Caddy's minimum). Build with `CGO_ENABLED=0` for linux/amd64 and linux/arm64. The dashboard is built with Vite and embedded with `embed.FS`. One binary, `sherlock`, provides server and CLI.

## Consequences

Trivial install and upgrade (replace one file), small container image (distroless/static), easy reproducible builds. The pure-Go SQLite driver is slower than the CGO one; acceptable for the config store and moderate event volumes, and Postgres is available.
