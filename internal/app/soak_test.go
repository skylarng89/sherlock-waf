//go:build soak

package app

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

// TestSoak drives the whole data plane with a steady mix of benign, hostile and
// oversized requests for SOAK_DURATION (a Go duration, default 30s; the 24 h
// release soak runs from .github/workflows/soak.yml) and checks that nothing
// leaks or breaks: no 5xx, no recovered internal error, bounded goroutines and
// bounded heap. Run it with the race detector:
//
//	SOAK_DURATION=30s go test -race -tags soak -run TestSoak -timeout 0 ./internal/app
func TestSoak(t *testing.T) {
	dur := 30 * time.Second
	if v := os.Getenv("SOAK_DURATION"); v != "" {
		d, err := time.ParseDuration(v)
		require.NoError(t, err, "SOAK_DURATION")
		dur = d
	}
	// The race detector and the rule engine make each request slow, so a modest
	// worker count keeps the node busy without turning the run into a queue.
	workers := min(runtime.GOMAXPROCS(0), 8)

	up := upstreamServer(t)
	site := uniqueSite("soak")
	port := launch(t, fmt.Sprintf(`
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
sites:
  - id: %s
    hosts: [soak.localhost]
    tls: { mode: none }
    policy:
      mode: block
      rate_limits: [{ name: per-ip, key: ip, limit: 1000000, window: 1m }]
    upstreams: { targets: ["%s"] }
`, site, up))

	client := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: workers}}
	t.Cleanup(client.CloseIdleConnections)

	benign := []string{"/", "/products?id=42&sort=name", "/static/app.js", "/api/items/17"}
	hostile := []string{"/?q=%27%20OR%201%3D1--", "/?x=%3Cscript%3Ealert(1)%3C/script%3E", "/../../etc/passwd", "/?file=php://input"}
	bigBody := strings.Repeat("a", 64<<10)

	var sent, blocked, bad atomic.Int64
	var firstBad atomic.Value
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				var (
					method = http.MethodGet
					target string
					body   io.Reader
				)
				switch i % 10 {
				case 0, 1, 2, 3, 4, 5:
					target = benign[(i+w)%len(benign)]
				case 6, 7:
					target = hostile[(i+w)%len(hostile)]
				case 8:
					method, target, body = http.MethodPost, "/api/items", strings.NewReader(`{"name":"widget","qty":3}`)
				default:
					method, target, body = http.MethodPost, "/upload", strings.NewReader(bigBody)
				}
				req, err := http.NewRequestWithContext(t.Context(), method, fmt.Sprintf("http://127.0.0.1:%d%s", port, target), body)
				if err != nil {
					return
				}
				req.Host = "soak.localhost"
				resp, err := client.Do(req)
				if err != nil {
					if t.Context().Err() != nil {
						return
					}
					bad.Add(1)
					firstBad.CompareAndSwap(nil, err.Error())
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				sent.Add(1)
				switch {
				case resp.StatusCode == http.StatusForbidden:
					blocked.Add(1)
				case resp.StatusCode >= 500:
					bad.Add(1)
					firstBad.CompareAndSwap(nil, fmt.Sprintf("%s %s -> %d", method, target, resp.StatusCode))
				}
			}
		})
	}

	// Sample the process once a minute (every 2s for short runs); the first
	// quarter is warm-up (caches, pools, the rule engine), the rest is judged.
	type sample struct {
		goroutines int
		heap       uint64
	}
	var samples []sample
	every := min(time.Minute, max(dur/15, 2*time.Second))
	tick := time.NewTicker(every)
	defer tick.Stop()
	deadline := time.After(dur)
loop:
	for {
		select {
		case <-tick.C:
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			samples = append(samples, sample{runtime.NumGoroutine(), m.HeapInuse})
		case <-deadline:
			break loop
		}
	}
	close(stop)
	wg.Wait()

	require.NotEmpty(t, samples, "SOAK_DURATION is too short to sample")
	assert.Zero(t, bad.Load(), "no transport error or 5xx under load; first: %v", firstBad.Load())
	assert.Zero(t, policy.InternalErrors.Load(), "no recovered internal failure in a data plane module")
	assert.Positive(t, blocked.Load(), "hostile requests were blocked")
	t.Logf("soak %s: %d requests (%d blocked), %d workers, %d samples", dur, sent.Load(), blocked.Load(), workers, len(samples))

	if len(samples) >= 4 {
		warm := samples[len(samples)/4]
		last := samples[len(samples)-1]
		assert.LessOrEqual(t, last.goroutines, warm.goroutines+50, "goroutines grew from %d to %d", warm.goroutines, last.goroutines)
		assert.LessOrEqual(t, last.heap, warm.heap*2+64<<20, "heap in use grew from %d to %d bytes", warm.heap, last.heap)
	}
}
