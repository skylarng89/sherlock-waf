package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
)

// Caddy is process-global, so these tests share one running app and run in
// sequence inside a single parent test.

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port //nolint:errcheck,forcetypeassert // always TCP
}

const configTemplate = `
schema_version: 1
sites:
  - id: strict
    hosts: [strict.localhost]
    tls: { mode: none }
    policy: { mode: %s }
    upstreams: { targets: ["%s"] }
  - id: lenient
    hosts: [lenient.localhost]
    tls: { mode: none }
    policy: { mode: detect }
    upstreams: { targets: ["%s"] }
`

func writeConfig(t *testing.T, path, strictMode, upstream string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, fmt.Appendf(nil, configTemplate, strictMode, upstream, upstream), 0o600))
}

type reply struct {
	status int
	header http.Header
	body   string
}

func get(t *testing.T, port int, host, target string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, target), nil)
	require.NoError(t, err)
	req.Host = host
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return reply{status: resp.StatusCode, header: resp.Header, body: string(b)}
}

func TestDataPlaneEndToEnd(t *testing.T) {
	logs := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream:"+html.EscapeString(r.URL.Path))
	}))
	upstreamAddr := strings.TrimPrefix(upstream.URL, "http://")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sherlock.yaml")
	writeConfig(t, cfgPath, "block", upstreamAddr)

	port := freePort(t)
	appLogs := &syncBuffer{}
	a := New(cfgPath, compiler.Options{HTTPPort: port, HTTPSPort: freePort(t), DataDir: filepath.Join(dir, "data")}, slog.New(slog.NewTextHandler(appLogs, nil)))
	hup := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, hup) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err, "graceful shutdown")
		case <-time.After(15 * time.Second):
			t.Error("Run did not return after context cancel")
		}
	})
	require.Eventually(t, func() bool {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 20*time.Second, 50*time.Millisecond, "data plane must start listening")

	sqli := "/get?id=" + url.QueryEscape("1' OR '1'='1")

	t.Run("benign request is proxied (AC2 shape)", func(t *testing.T) {
		r := get(t, port, "strict.localhost", "/get?id=1")
		assert.Equal(t, http.StatusOK, r.status)
		assert.Equal(t, "upstream:/get", r.body)
		assert.Equal(t, "nosniff", r.header.Get("X-Content-Type-Options"))
	})

	t.Run("AC1 block mode returns 403 with event_id", func(t *testing.T) {
		r := get(t, port, "strict.localhost", sqli)
		assert.Equal(t, http.StatusForbidden, r.status)
		var p map[string]any
		require.NoError(t, json.Unmarshal([]byte(r.body), &p))
		assert.NotEmpty(t, p["event_id"])
		assert.Equal(t, p["event_id"], r.header.Get("X-Sherlock-Event-Id"))
	})

	t.Run("AC1/AC3 detect mode proxies and logs a finding, simultaneously with block site", func(t *testing.T) {
		r := get(t, port, "lenient.localhost", sqli)
		assert.Equal(t, http.StatusOK, r.status)
		assert.Equal(t, "upstream:/get", r.body)

		var found bool
		for line := range strings.SplitSeq(logs.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) != nil || m["msg"] != "decision" {
				continue
			}
			if m["site_id"] == "lenient" && m["action"] == "log" && m["findings"] != nil {
				found = true
			}
		}
		assert.True(t, found, "expected a decision log line with a finding for the detect-mode site")
	})

	t.Run("unknown host gets 421", func(t *testing.T) {
		r := get(t, port, "nobody.localhost", "/")
		assert.Equal(t, http.StatusMisdirectedRequest, r.status)
	})

	t.Run("AC4 bad config on SIGHUP keeps the old config", func(t *testing.T) {
		require.NoError(t, os.WriteFile(cfgPath, []byte("schema_version: 1\nsites:\n  - id: Broken Site\n"), 0o600))
		hup <- syscall.SIGHUP
		require.Eventually(t, func() bool { return strings.Contains(appLogs.String(), "reload failed") },
			5*time.Second, 10*time.Millisecond, "the failed reload must be reported")

		r := get(t, port, "strict.localhost", sqli)
		assert.Equal(t, http.StatusForbidden, r.status, "old block-mode config must still be live")
		r = get(t, port, "strict.localhost", "/get?id=1")
		assert.Equal(t, http.StatusOK, r.status)
		assert.Equal(t, "upstream:/get", r.body)

		err := a.Reload()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "/sites/0/id", "error must carry the JSON-pointer path")
	})

	t.Run("good config on SIGHUP is applied", func(t *testing.T) {
		writeConfig(t, cfgPath, "detect", upstreamAddr)
		hup <- syscall.SIGHUP
		require.Eventually(t, func() bool {
			r := get(t, port, "strict.localhost", sqli)
			return r.status == http.StatusOK
		}, 10*time.Second, 100*time.Millisecond, "strict site must switch to detect after reload")
	})

	t.Run("AC7 killed upstream returns 502, not a panic", func(t *testing.T) {
		upstream.Close()
		r := get(t, port, "lenient.localhost", "/get?id=1")
		assert.Equal(t, http.StatusBadGateway, r.status)
	})
}

func TestStartRejectsInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte("schema_version: 1\nbogus: true\n"), 0o600))
	a := New(path, compiler.Options{}, nil)
	err := a.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/bogus")
	require.Error(t, a.Reload(), "reload before start is refused")
	require.NoError(t, a.Stop(), "stop on a stopped app is a no-op")
}
