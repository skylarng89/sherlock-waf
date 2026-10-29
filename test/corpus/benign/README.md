# Benign request corpus

200 ordinary requests (browsing, search, forms, JSON APIs) that must never be
blocked at paranoia level 1. One JSON object per line:
`{"method", "path", "content_type", "body"}`.

`internal/dataplane/waf/corpus_test.go` replays the file against a block-mode
`sherlock_waf` at PL1. A request that fails here is either a false positive to
investigate (add an exclusion or open a CRS issue) or not benign and should be
removed with a note. Never loosen the test to make it pass.

## Regenerating

`python3 generate.py` rewrites `requests.jsonl` and `known-false-positives.jsonl`
deterministically (no randomness, no clock). Edit the generator, never the output.

## Known false positives

`known-false-positives.jsonl` holds benign requests that CRS currently blocks at
PL1. A test asserts they are still blocked, so fixing one (an exclusion in M8, a
CRS update) makes the test fail until the entry is moved into `requests.jsonl`.
Current entries: GraphQL selections containing a field named `url` (CRS 932370).
