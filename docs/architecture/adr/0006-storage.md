# ADR-0006: SQLite by default, Postgres optional

- Status: Accepted
- Date: 2026-10-28

## Decision

SQLite (`modernc.org/sqlite`, WAL) is the default for zero-dependency installs. Postgres 15+ is supported for larger installs and is required for Enterprise clustering. SQL is written once per dialect and generated with `sqlc`; migrations with `goose`, embedded, forward-only. Events live in the same database by default with daily retention; Enterprise can move events to ClickHouse via `extension.EventStore`.

## Consequences

Two dialects to test: CI runs the store test suite against both. Event volume on SQLite is bounded; documented guidance: switch to Postgres above ~5 million stored events or more than 3 sites with heavy traffic (to be measured in M7).
