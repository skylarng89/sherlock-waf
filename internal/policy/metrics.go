package policy

import "sync/atomic"

// InternalErrors counts recovered internal failures in data plane modules
// (exported as sherlock_internal_errors_total once the metrics endpoint exists).
var InternalErrors atomic.Uint64
