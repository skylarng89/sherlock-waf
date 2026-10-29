# ADR-0015: One set of queries, run on both databases

- Status: Accepted
- Date: 2026-10-29

## Context

ADR-0006 and `data-model.md` describe `sqlc` generating separate packages for
SQLite and PostgreSQL (`internal/store/sqlite`, `internal/store/postgres`) behind
one Go interface. With about 70 queries that means two copies of every query and
two copies of the glue that adapts each generated package's row and parameter
types to the domain types, which is where drift between dialects would creep in.

## Decision

- Queries are written **once** in `internal/store/queries/`, in the subset of SQL
  that both engines accept, and generated from the PostgreSQL dialect into
  `internal/store/db` (`sqlc.yaml`).
- They run unchanged on PostgreSQL (pgx stdlib driver). For SQLite, a thin
  wrapper rewrites the `$n` placeholders sqlc emits to SQLite's numbered `?n`
  (`rebindDBTX`).
- **Migrations remain one file per dialect** (`internal/store/{postgres,sqlite}/migrations`),
  identical apart from `BYTEA`/`BLOB`; a test asserts both directories contain the
  same migration names.
- A conformance suite (`internal/store/storetest`) runs the same tests on both
  engines. CI runs it against a real PostgreSQL service and fails, rather than
  skips, if one is not available (`SHERLOCK_REQUIRE_PG=1`).

Portability rules for the schema and queries: timestamps are `BIGINT` unix
microseconds set from Go; ids are text; enumerations are `TEXT` plus `CHECK`;
booleans are `0/1` integers; JSON is `TEXT` so hashed bytes are read back exactly;
no `::` casts (use `CAST`), no `now()`, no arrays, no `ILIKE`, no `FOR UPDATE`.
Optional filters use `CAST(narg AS type) IS NULL OR ...`.

## Consequences

- No query or adapter duplication, so dialect drift in queries cannot happen
  silently; a query that only one engine accepts fails the suite.
- We give up PostgreSQL-only features (partitioning, `jsonb`, advisory locks) in
  the shared path. Daily partitioning of `events` is deferred; retention uses
  batched deletes (M7 revisits it with measurements).
- A failed statement aborts the whole transaction on PostgreSQL but not on SQLite.
  Code must never continue a transaction after a failed statement; the suite
  asserts expected failures in transactions of their own.
- `sqlc` is still the only way SQL enters the code base (project rule), and
  `make gen` regenerates it; CI fails if generated code is stale.

## Alternatives considered

| Option | Why not |
| --- | --- |
| Two sqlc targets (the original plan) | Doubles the queries and the adapters; the drift risk it was meant to remove is created by it. |
| Hand-written `database/sql` with a rebind helper | Violates the project rule that SQL goes through sqlc. |
| An ORM | Hides the SQL we need to audit and review. |
