//go:build sherlock_testhooks

package waf

import "net/http"

// Test-only: a request carrying this header forces a panic inside the WAF
// inspection stage. Compiled out of release builds.
func init() {
	testHook = func(r *http.Request) {
		if r.Header.Get("X-Sherlock-Test-Panic") != "" {
			panic("forced panic (sherlock_testhooks build)")
		}
	}
}
