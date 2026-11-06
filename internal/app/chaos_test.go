//go:build chaos

package app

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/eventwriter"
	"github.com/skylarng89/sherlock-waf/internal/metrics"
	"github.com/skylarng89/sherlock-waf/internal/policy"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// Chaos tests: each one breaks a dependency under a running node and asserts
// the behaviour docs/operations/failure-modes.md promises, with bounded waits.
//
//	go test -race -tags 'chaos sherlock_testhooks' -count=1 -run Chaos -timeout 20m ./internal/app

// chaosLaunch is launch with options. It returns the HTTP port and the data
// directory (events.jsonl and access.jsonl live there).
func chaosLaunch(t *testing.T, cfg string, options ...Option) (int, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sherlock.yaml")
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0o600))
	port := freePort(t)
	dataDir := filepath.Join(dir, "data")
	opts := append([]Option{WithEventsOutput(io.Discard)}, options...)
	a := New(path, compiler.Options{HTTPPort: port, HTTPSPort: freePort(t), DataDir: dataDir}, slog.New(slog.DiscardHandler), opts...)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, make(chan os.Signal)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(30 * time.Second):
			t.Error("Run did not return after context cancel")
		}
	})
	require.Eventually(t, func() bool {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 20*time.Second, 50*time.Millisecond)
	return port, dataDir
}

// chaosClient never reuses connections, so goroutine and descriptor counts
// measure the node and not the client's idle pool.
func chaosClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
}

type chaosReply struct {
	status  int
	body    string
	elapsed time.Duration
	header  http.Header
}

// chaosGet returns an error instead of failing, so workers can call it.
func chaosGet(ctx context.Context, c *http.Client, port int, host, target string, hdr map[string]string) (chaosReply, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, target), nil)
	if err != nil {
		return chaosReply{}, err
	}
	req.Host = host
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return chaosReply{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return chaosReply{status: resp.StatusCode, body: string(b), elapsed: time.Since(start), header: resp.Header}, nil
}

func mustGet(t *testing.T, c *http.Client, port int, host, target string, hdr map[string]string) chaosReply {
	t.Helper()
	r, err := chaosGet(t.Context(), c, port, host, target, hdr)
	require.NoError(t, err)
	return r
}

func openFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// settle waits for goroutines that are winding down.
func settle() (goroutines, fds int) {
	for range 20 {
		runtime.GC()
		time.Sleep(100 * time.Millisecond)
	}
	return runtime.NumGoroutine(), openFDs()
}

// captureSlog sends the process-wide slog default (where the event sinks and
// Caddy-side modules report) to a buffer for the test.
func captureSlog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// killableServer is an upstream that can be stopped and started again on the
// same address.
type killableServer struct {
	t    *testing.T
	addr string
	mu   sync.Mutex
	srv  *http.Server
}

func newKillableServer(t *testing.T) *killableServer {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	k := &killableServer{t: t, addr: ln.Addr().String()}
	k.serve(ln)
	t.Cleanup(k.stop)
	return k
}

func (k *killableServer) serve(ln net.Listener) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }), ReadHeaderTimeout: 5 * time.Second}
	go func(s *http.Server) { _ = s.Serve(ln) }(k.srv)
}

func (k *killableServer) stop() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.srv != nil {
		_ = k.srv.Close()
		k.srv = nil
	}
}

func (k *killableServer) start() {
	var ln net.Listener
	require.Eventually(k.t, func() bool {
		var err error
		ln, err = (&net.ListenConfig{}).Listen(k.t.Context(), "tcp", k.addr)
		return err == nil
	}, 10*time.Second, 50*time.Millisecond, "rebinding %s", k.addr)
	k.serve(ln)
}

// TestChaosUpstreamOutage: an origin dies and comes back. Sherlock answers 5xx
// quickly without hanging, keeps inspecting and keeps serving other sites, and
// recovers by itself without leaking goroutines, descriptors or internal errors.
func TestChaosUpstreamOutage(t *testing.T) {
	origin := newKillableServer(t)
	stable := upstreamServer(t)
	a, b := uniqueSite("chaos-a"), uniqueSite("chaos-b")
	port, _ := chaosLaunch(t, fmt.Sprintf(`
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
sites:
  - id: %s
    hosts: [a.localhost]
    tls: { mode: none }
    policy: { mode: block }
    upstreams: { targets: ["%s"] }
  - id: %s
    hosts: [b.localhost]
    tls: { mode: none }
    policy: { mode: block }
    upstreams: { targets: ["%s"] }
`, a, origin.addr, b, stable))
	c := chaosClient()
	attack := "/?id=1%27%20OR%20%271%27%3D%271"

	require.Equal(t, http.StatusOK, mustGet(t, c, port, "a.localhost", "/", nil).status)
	goroutines0, fds0 := settle()
	errors0 := policy.InternalErrors.Load()

	origin.stop()
	for range 10 {
		r := mustGet(t, c, port, "a.localhost", "/", nil)
		assert.Equal(t, http.StatusBadGateway, r.status, "a refused connection is a 502 from the proxy")
		assert.Less(t, r.elapsed, 5*time.Second, "a refused connection does not hang the request")
		assert.Equal(t, http.StatusOK, mustGet(t, c, port, "b.localhost", "/", nil).status, "other sites are unaffected")
	}
	assert.Equal(t, http.StatusForbidden, mustGet(t, c, port, "a.localhost", attack, nil).status, "attacks are still blocked while the origin is down")

	origin.start()
	require.Eventually(t, func() bool {
		r, err := chaosGet(t.Context(), c, port, "a.localhost", "/", nil)
		return err == nil && r.status == http.StatusOK
	}, 15*time.Second, 100*time.Millisecond, "the site recovers without a reload")

	goroutines1, fds1 := settle()
	assert.LessOrEqual(t, goroutines1, goroutines0+25, "goroutines: %d before the outage, %d after", goroutines0, goroutines1)
	if fds0 >= 0 {
		assert.LessOrEqual(t, fds1, fds0+25, "open descriptors: %d before the outage, %d after", fds0, fds1)
	}
	assert.Equal(t, errors0, policy.InternalErrors.Load(), "an origin outage is not an internal error")
}

// TestChaosEventFileSinkFailure: the event file cannot rotate (its rotation
// target is a non-empty directory). The data plane keeps answering at normal
// speed, the failure is logged, and the stdout sink, which is independent,
// still receives every event.
func TestChaosEventFileSinkFailure(t *testing.T) {
	logs := captureSlog(t)
	stdout := &syncBuffer{}
	site := uniqueSite("chaos-disk")
	port, dataDir := chaosLaunch(t, fmt.Sprintf(`
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
  trusted_proxies: ["127.0.0.0/8"]
  client_ip_headers: ["X-Forwarded-For"]
  ip_lists: [{ name: bad, cidrs: ["198.51.100.0/24"] }]
  events: { sinks: { stdout: true, file: true, file_max_mb: 1, file_keep: 1 } }
sites:
  - id: %s
    hosts: [disk.localhost]
    tls: { mode: none }
    upstreams: { targets: ["%s"] }
    policy: { mode: block, acl: { deny_lists: [bad] } }
`, site, upstreamServer(t)), WithEventsOutput(stdout))

	// events.jsonl.1 is where the first rotation renames the file to. A
	// directory with content there makes the rename fail on any filesystem.
	blocker := filepath.Join(dataDir, "events.jsonl.1")
	require.NoError(t, os.MkdirAll(blocker, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(blocker, "keep"), []byte("x"), 0o600))

	c := chaosClient()
	var sent atomic.Int64
	var slowest atomic.Int64
	burst := func() {
		var wg sync.WaitGroup
		for w := range 8 {
			wg.Go(func() {
				for i := range 40 {
					r, err := chaosGet(t.Context(), c, port, "disk.localhost", fmt.Sprintf("/x%d-%d", w, i), map[string]string{"X-Forwarded-For": "198.51.100.7"})
					if assert.NoError(t, err) {
						assert.Equal(t, http.StatusForbidden, r.status)
						sent.Add(1)
						for old := slowest.Load(); int64(r.elapsed) > old && !slowest.CompareAndSwap(old, int64(r.elapsed)); old = slowest.Load() {
						}
					}
				}
			})
		}
		wg.Wait()
	}
	// Until the file reaches 1 MiB nothing rotates: keep sending until the sink
	// reports the failed rotation, bounded by a request budget.
	require.Eventually(t, func() bool {
		burst()
		return strings.Contains(logs.String(), "event file rotation failed") && sent.Load() >= 320
	}, 90*time.Second, 10*time.Millisecond, "the failed rotation is logged; sent %d requests", sent.Load())
	assert.Contains(t, logs.String(), "rotating", "the log names the rotation that failed")
	assert.Less(t, time.Duration(slowest.Load()), 3*time.Second, "no request waited for the failing sink")

	total := int(sent.Load())
	require.Eventually(t, func() bool { return strings.Count(stdout.String(), `"site_id":"`+site+`"`) >= total },
		20*time.Second, 100*time.Millisecond, "the independent stdout sink still received every event (%d)", total)

	// The file sink keeps appending to the current file while rotation is blocked
	// and rotates again once the obstruction is gone.
	require.NoError(t, os.RemoveAll(blocker))
	size := func() int64 {
		fi, err := os.Stat(filepath.Join(dataDir, "events.jsonl"))
		if err != nil {
			return -1
		}
		return fi.Size()
	}
	before := size()
	require.Eventually(t, func() bool { burst(); time.Sleep(1100 * time.Millisecond); return size() > before || size() < before },
		30*time.Second, time.Millisecond, "the file sink writes again once the rotation target is repaired")
}

// TestChaosEventStoreLocked: the database is locked for longer than the busy
// timeout. Requests are unaffected, the writer fails and retries, the backlog is
// capped oldest-first and counted, and everything that survived is stored once
// the lock is released.
func TestChaosEventStoreLocked(t *testing.T) {
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "chaos.db")
	st, err := store.OpenSQLite(ctx, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	writerLogs := &syncBuffer{}
	// The hook runs on the app's start goroutine; atomics give the test its
	// happens-before edge.
	var (
		wrPtr  atomic.Pointer[eventwriter.Writer]
		busPtr atomic.Pointer[events.Bus]
	)
	hook := func(pctx context.Context, b *events.Bus) func() {
		w := eventwriter.New(b, st, slog.New(slog.NewTextHandler(writerLogs, nil)), eventwriter.Options{FlushEvery: 200 * time.Millisecond})
		busPtr.Store(b)
		wrPtr.Store(w)
		done := make(chan struct{})
		go func() { defer close(done); w.Run(pctx) }()
		return func() { <-done }
	}
	site := uniqueSite("chaos-db")
	port, _ := chaosLaunch(t, fmt.Sprintf(`
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
  trusted_proxies: ["127.0.0.0/8"]
  client_ip_headers: ["X-Forwarded-For"]
  ip_lists: [{ name: bad, cidrs: ["198.51.100.0/24"] }]
sites:
  - id: %s
    hosts: [db.localhost]
    tls: { mode: none }
    upstreams: { targets: ["%s"] }
    policy: { mode: block, acl: { deny_lists: [bad] } }
`, site, upstreamServer(t)), WithSecurityBusHook(hook))

	wr, bus := wrPtr.Load(), busPtr.Load()
	require.NotNil(t, wr)
	require.NotNil(t, bus)
	c := chaosClient()
	denied := func(n int) (slowest time.Duration) {
		for i := range n {
			r := mustGet(t, c, port, "db.localhost", fmt.Sprintf("/d%d", i), map[string]string{"X-Forwarded-For": "198.51.100.9"})
			require.Equal(t, http.StatusForbidden, r.status)
			slowest = max(slowest, r.elapsed)
		}
		return slowest
	}
	// Store transactions take the write lock when they begin (so they cannot fail
	// halfway), which means even a store read waits behind the lock. A plain
	// read-only connection counts rows without it (WAL readers never block).
	reader, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })
	count := func() (n int) {
		require.NoError(t, reader.QueryRowContext(ctx, "SELECT count(*) FROM events").Scan(&n))
		return n
	}

	// Healthy first: a request becomes a stored event.
	denied(5)
	require.Eventually(t, func() bool { return count() == 5 }, 15*time.Second, 100*time.Millisecond)

	// A second connection takes the write lock and holds it.
	locker, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(100)&_txlock=immediate")
	require.NoError(t, err)
	t.Cleanup(func() { _ = locker.Close() })
	lock, err := locker.BeginTx(ctx, nil)
	require.NoError(t, err)
	released := false
	release := func() {
		if !released {
			released = true
			require.NoError(t, lock.Rollback())
		}
	}
	t.Cleanup(release)

	assert.Less(t, denied(20), 3*time.Second, "no request waited for the locked database")
	require.Eventually(t, func() bool { return wr.Failed() > 0 }, 30*time.Second, 100*time.Millisecond,
		"a write that exceeds the 5 s busy timeout fails and is counted")
	assert.Contains(t, writerLogs.String(), "writing events")
	require.NoError(t, st.Ping(ctx), "the lock is not an outage: the pool still answers")

	// More events than the backlog cap (8 batches of 500) while the writer is stalled.
	for i := range 6000 {
		bus.Publish(&events.Event{ID: fmt.Sprintf("chaos-%06d", i), Schema: events.SchemaV1, TS: time.Now().UTC(), SiteID: site, Action: "block", Mode: "block"})
	}
	require.Eventually(t, func() bool { return wr.Dropped() > 0 }, 30*time.Second, 100*time.Millisecond, "events beyond the backlog cap are dropped and counted")
	assert.Contains(t, writerLogs.String(), "event store unavailable; dropping the oldest events")
	assert.Less(t, denied(10), 3*time.Second, "requests are still not delayed while the writer is stalled")

	before := count()
	stored := wr.Stored()
	release()
	require.Eventually(t, func() bool { return wr.Stored() > stored }, 30*time.Second, 100*time.Millisecond, "the writer resumes without a restart")
	assert.Greater(t, count(), before, "the backlog that survived is written once the lock is gone")
}

// TestChaosEventBusOverload: events are published far faster than a slow
// subscriber reads them. Publish never blocks, requests are never delayed, and
// the overwritten events are counted in sherlock_events_dropped_total.
func TestChaosEventBusOverload(t *testing.T) {
	var busPtr atomic.Pointer[events.Bus]
	hook := func(_ context.Context, b *events.Bus) func() {
		_ = b.Subscribe(true) // a consumer that never reads: its unread events are what overflow
		busPtr.Store(b)
		return nil
	}
	port, _ := chaosLaunch(t, fmt.Sprintf(`
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
sites:
  - id: %s
    hosts: [flood.localhost]
    tls: { mode: none }
    upstreams: { targets: ["%s"] }
    policy: { mode: "off" }
`, uniqueSite("chaos-flood"), upstreamServer(t)), WithSecurityBusHook(hook))
	bus := busPtr.Load()
	require.NotNil(t, bus)

	droppedBefore := metricSum(t, "sherlock_events_dropped_total")
	var flooding atomic.Bool
	flooding.Store(true)
	var published atomic.Int64
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; flooding.Load(); i++ {
			bus.Publish(&events.Event{ID: fmt.Sprintf("flood-%d", i), Schema: events.SchemaV1, TS: time.Now().UTC(), SiteID: "flood", Action: "allow", Mode: "off"})
			published.Add(1)
		}
	})

	c := chaosClient()
	var slowest time.Duration
	require.Eventually(t, func() bool {
		r := mustGet(t, c, port, "flood.localhost", "/", nil)
		slowest = max(slowest, r.elapsed)
		assert.Equal(t, http.StatusOK, r.status)
		return published.Load() > 3*events.DefaultBusCapacity
	}, 60*time.Second, time.Millisecond, "the flood passes three times the ring capacity")
	flooding.Store(false)
	wg.Wait()

	assert.Less(t, slowest, 2*time.Second, "no request waited for the overloaded bus")
	assert.Positive(t, bus.Dropped(), "the unread events were overwritten")
	assert.Greater(t, metricSum(t, "sherlock_events_dropped_total"), droppedBefore, "the loss is visible in sherlock_events_dropped_total")
}

// metricSum adds every sample of a metric family from the process registry.
func metricSum(t *testing.T, name string) float64 {
	t.Helper()
	mfs, err := metrics.Registry.Gather()
	require.NoError(t, err)
	var sum float64
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			switch {
			case m.GetCounter() != nil:
				sum += m.GetCounter().GetValue()
			case m.GetGauge() != nil:
				sum += m.GetGauge().GetValue()
			}
		}
	}
	return sum
}
