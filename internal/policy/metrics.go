package policy

import "sync/atomic"

// InternalErrors counts recovered internal failures in data plane modules
// (exported as sherlock_internal_errors_total once the metrics endpoint exists).
var InternalErrors atomic.Uint64

// InFlight counts requests currently inside sherlock_core, from entry until
// their event has been published (sherlock_requests_in_flight).
var InFlight atomic.Int64
