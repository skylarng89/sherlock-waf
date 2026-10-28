//go:build sherlock_testhooks

package app

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestForcedPanicFollowsFailModeLive is the live half of acceptance criterion
// 7: a panic inside sherlock_waf (forced by the testhooks build tag) must
// follow the site's fail_mode and never crash the process.
func TestForcedPanicFollowsFailModeLive(t *testing.T) {
	up := upstreamServer(t)
	port := launch(t, fmt.Sprintf(`
schema_version: 1
sites:
  - id: closed
    hosts: [closed.localhost]
    tls: { mode: none }
    policy: { mode: block, fail_mode: closed }
    upstreams: { targets: ["%[1]s"] }
  - id: open
    hosts: [open.localhost]
    tls: { mode: none }
    policy: { mode: block, fail_mode: open }
    upstreams: { targets: ["%[1]s"] }
`, up))
	panicHdr := map[string]string{"X-Sherlock-Test-Panic": "1"}

	r := send(t, port, http.MethodGet, "closed.localhost", "/get", panicHdr)
	assert.Equal(t, http.StatusServiceUnavailable, r.status, "fail_mode closed answers 503")
	assert.NotEmpty(t, r.header.Get("X-Sherlock-Event-Id"))

	r = send(t, port, http.MethodGet, "open.localhost", "/get", panicHdr)
	assert.Equal(t, http.StatusOK, r.status, "fail_mode open proxies the request")

	r = send(t, port, http.MethodGet, "closed.localhost", "/get", nil)
	assert.Equal(t, http.StatusOK, r.status, "process is still healthy after the panics")
}
