# CRS regression with go-ftw

Runs the OWASP CRS test suite (the YAML tests shipped in
`coraza-coreruleset`, 4,674 tests for CRS 4.25.0) against a built Sherlock and
reads the matched rule IDs from Sherlock's own `events.jsonl`, so every run
also exercises the event pipeline.

```sh
make ftw            # paranoia level 1 (CI: ftw-smoke)
make ftw PL=3       # one level
make ftw-all        # levels 1 to 4 (nightly)
```

`test/ftw/run.sh` builds Sherlock with the `sherlock_testhooks` tag, starts a
trivial backend (`test/ftw/backend`) and Sherlock, writes a go-ftw config, and
runs go-ftw. Nothing outside a temp directory is touched; set `FTW_KEEP=1` to
keep it for inspection.

## What differs from production

Only in the `sherlock_testhooks` build, and only what the CRS project's own
regression environment also does:

- a rule that logs the `X-CRS-Test` marker header go-ftw uses to find each test
  in the log,
- `tx.crs_validate_utf8_encoding=1` and `tx.enforce_bodyproc_urlencoded=1`
  (optional CRS checks that are off by default),
- anomaly thresholds of 10000, set in the generated config, so nothing is
  blocked and tests judge **detection** by rule ID. Blocking is covered by
  Sherlock's own block-mode tests and the e2e smoke test.

## Which tests run

Tests for rules of a higher paranoia level cannot fire at a lower one, so
`test/ftw/plfilter` selects only tests whose rule is at or below the level under
test (from the `paranoia-level/N` tags in the rule files).

| Level | Tests selected |
| --- | --- |
| PL1 | 2,752 |
| PL2 | 4,059 |
| PL3 | 4,596 |
| PL4 | 4,663 |

## Overrides (`overrides.yaml`)

Every ignored test has a reason, and ids are listed exactly so a new failure in
the same rule still fails the run. They fall into a few groups, all verified
against Sherlock's real behaviour:

| Group | Why the test cannot pass |
| --- | --- |
| Response rules (950–956, 980) | Only `REQUEST-*` CRS files are loaded; response inspection is out of scope until a later milestone. |
| Missing/foreign/IP `Host` (920270–920350, 922130, 931130, 943110 …) | Sherlock routes by `Host` and answers `421` for any unconfigured host, so the WAF never sees the request. By design. |
| Header names with `_` or `.` (933110, 933220, 944140) | Caddy 2.11 drops them by default (GHSA-f59h-q822-g45g, GHSA-49wc-4hcv-v58q); neither the WAF nor the upstream sees them, so there is no bypass to detect. |
| Optional length limits (920360–920410) | Disabled by default in CRS; Sherlock does not expose the limits until WAF tuning (M8). |
| Protocol edge cases (920430, 920610 …) | Go's HTTP server rejects or parses these before the handler chain; the expected status comes from Apache's parser. |
| `logdata` text (933120, 932200, 932207, 932300, 931130-24) | Tests assert on ModSecurity's `logdata` string; Sherlock events carry `target` and `matched` as separate fields. |
| Methods (911100-6, 920100-4/5) | Sherlock allows PUT/PATCH/DELETE (REST) and rejects CONNECT (reverse proxy). |
| Tool mismatch (921140-1) | go-ftw 2.6 refuses a raw CR/LF in a header value. |

## A known harness flake

Roughly 0.1–0.3% of tests (a different handful each run, never in isolation)
fail with go-ftw's *"start marker not found while collecting marked lines"*,
while the event file on disk is complete and correctly ordered. Causes found and
fixed along the way: half-written lines (the file sink now only ever writes whole
lines), event ordering under load (requests wait for the previous one to finish
publishing in the test build), and the PAN masker corrupting marker UUIDs. What
remains looks like go-ftw reading a line while the kernel is still making a
write visible.

So failed tests are re-run, up to `FTW_ATTEMPTS` (default 3) attempts in total,
and **only tests that fail on every attempt count**. Tests that recovered are
printed ("recovered on retry"), never hidden. A real failure fails every attempt.
Run with `FTW_ATTEMPTS=1` to see the raw flake rate.
