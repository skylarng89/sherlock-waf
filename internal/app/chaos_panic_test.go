//go:build chaos && sherlock_testhooks

package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

// TestChaosWAFPanicFollowsFailMode: a panic inside WAF inspection (forced by the
// sherlock_testhooks build) follows the site's fail_mode: closed answers 503 with
// the block page, open proxies the request. Either way the event carries a core
// finding, sherlock_internal_errors_total counts it and the process stays healthy.
//
// A panic anywhere else in the chain is recovered by sherlock_core and answered
// with 503 whatever the fail mode; that path has no injection point in a running
// node and is covered by TestDownstreamPanicIsRecovered in internal/dataplane/core.
func TestChaosWAFPanicFollowsFailMode(t *testing.T) {
	stdout := &syncBuffer{}
	closed, open := uniqueSite("chaos-closed"), uniqueSite("chaos-open")
	up := upstreamServer(t)
	port, _ := chaosLaunch(t, fmt.Sprintf(`
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
sites:
  - id: %[1]s
    hosts: [closed.localhost]
    tls: { mode: none }
    policy: { mode: block, fail_mode: closed }
    upstreams: { targets: ["%[3]s"] }
  - id: %[2]s
    hosts: [open.localhost]
    tls: { mode: none }
    policy: { mode: block, fail_mode: open }
    upstreams: { targets: ["%[3]s"] }
`, closed, open, up), WithEventsOutput(stdout))
	c := chaosClient()
	panicHdr := map[string]string{"X-Sherlock-Test-Panic": "1"}
	errors0 := policy.InternalErrors.Load()

	rc := mustGet(t, c, port, "closed.localhost", "/get", panicHdr)
	assert.Equal(t, http.StatusServiceUnavailable, rc.status, "fail_mode closed answers 503")
	idClosed := rc.header.Get("X-Sherlock-Event-Id")
	assert.NotEmpty(t, idClosed)
	assert.NotContains(t, rc.body, "forced panic", "the panic text never reaches the client")

	ro := mustGet(t, c, port, "open.localhost", "/get", panicHdr)
	assert.Equal(t, http.StatusOK, ro.status, "fail_mode open proxies the request uninspected")
	assert.Equal(t, "ok", ro.body)

	assert.Equal(t, errors0+2, policy.InternalErrors.Load(), "each panic is one internal error")
	assert.Equal(t, http.StatusOK, mustGet(t, c, port, "closed.localhost", "/get", nil).status, "the node is healthy after the panics")
	assert.Equal(t, http.StatusForbidden, mustGet(t, c, port, "closed.localhost", "/?id=1%27%20OR%20%271%27%3D%271", nil).status, "and still inspects")

	// Both events carry a core finding naming the WAF failure.
	require.Eventually(t, func() bool {
		return strings.Count(stdout.String(), "waf internal error") >= 2
	}, 10*time.Second, 50*time.Millisecond)
	seen := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(stdout.String()), "\n") {
		var ev struct {
			ID       string `json:"id"`
			SiteID   string `json:"site_id"`
			Findings []struct {
				Module  string `json:"module"`
				Message string `json:"message"`
			} `json:"findings"`
		}
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		for _, f := range ev.Findings {
			if f.Module == "core" && strings.Contains(f.Message, "waf internal error") {
				seen[ev.SiteID] = true
				if ev.SiteID == closed {
					assert.Equal(t, idClosed, ev.ID, "the event id in the 503 response matches the stored event")
				}
			}
		}
	}
	assert.True(t, seen[closed], "the closed site's event has a core finding")
	assert.True(t, seen[open], "the open site's event has a core finding")
}
