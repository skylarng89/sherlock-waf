# Benign request corpus

200 ordinary requests (browsing, search, forms, JSON APIs) that must never be
blocked at paranoia level 1. One JSON object per line:
`{"method", "path", "content_type", "body"}`.

`internal/dataplane/waf/corpus_test.go` replays the file against a block-mode
`sherlock_waf` at PL1. A request that fails here is either a false positive to
investigate (add an exclusion or open a CRS issue) or not benign and should be
removed with a note. Never loosen the test to make it pass.
