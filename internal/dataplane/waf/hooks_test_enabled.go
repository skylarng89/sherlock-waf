//go:build sherlock_testhooks

package waf

import (
	"net/http"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

// Test-only behaviour, compiled out of every other build.
func init() {
	// The CRS regression run (go-ftw) locates each test in the event log
	// through marker requests carrying a unique X-CRS-Test header. This rule
	// records the header, and the settings below mirror the CRS project's own
	// regression environment: optional checks that are off by default in
	// production.
	extraDirectives = strings.Join([]string{
		`SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" "id:999999,phase:1,pass,t:none,log,severity:7,msg:'X-CRS-Test %{MATCHED_VAR}'"`,
		`SecAction "id:900950,phase:1,pass,t:none,nolog,setvar:tx.crs_validate_utf8_encoding=1,setvar:tx.enforce_bodyproc_urlencoded=1"`,
	}, "\n")

	testHook = func(r *http.Request) {
		// A request carrying this header forces a panic inside inspection so the
		// fail-mode path can be tested end to end.
		if r.Header.Get("X-Sherlock-Test-Panic") != "" {
			panic("forced panic (sherlock_testhooks build)")
		}
		// An event is published just after its response is sent, so under load
		// the next request can overtake it. go-ftw needs start marker, test and
		// end marker events in that order and runs one request at a time, so wait
		// until the previous request has finished publishing (only this one is
		// left in flight). Bounded, so a stuck request cannot hang the run.
		for deadline := time.Now().Add(2 * time.Second); policy.InFlight.Load() > 1 && time.Now().Before(deadline); {
			time.Sleep(50 * time.Microsecond)
		}
	}
}
