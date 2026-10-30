package app

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/events"
)

func post(t *testing.T, port int, host, target, contentType, body string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d%s", port, target), strings.NewReader(body))
	require.NoError(t, err)
	req.Host = host
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer abc.def.ghi-SECRET")
	req.Header.Set("Cookie", "session=COOKIE-SECRET")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return reply{status: resp.StatusCode, header: resp.Header, body: string(b)}
}

func readEvents(t *testing.T, path string) []events.Event {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test temp path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	var out []events.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e events.Event
		require.NoError(t, json.Unmarshal(sc.Bytes(), &e))
		out = append(out, e)
	}
	return out
}

// TestEventsContainNoSecrets is acceptance criterion 4 of M2: passwords,
// tokens and card numbers sent in the query, a form body and a JSON body must
// not appear anywhere in the recorded events, even with body excerpts on.
func TestEventsContainNoSecrets(t *testing.T) {
	up := upstreamServer(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sherlock.yaml")
	require.NoError(t, os.WriteFile(cfgPath, fmt.Appendf(nil, `
schema_version: 1
global:
  admin: { listen: "off" }
  events:
    body_excerpt: true
    sinks: { stdout: false }
sites:
  - id: shop
    hosts: [shop.localhost]
    tls: { mode: none }
    policy: { mode: block }
    upstreams: { targets: ["%s"] }
`, up), 0o600))

	port := freePort(t)
	dataDir := filepath.Join(dir, "data")
	a := New(cfgPath, compiler.Options{HTTPPort: port, HTTPSPort: freePort(t), DataDir: dataDir}, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, make(chan os.Signal)) }()
	require.Eventually(t, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port)) //nolint:noctx,bodyclose,gosec // readiness probe
		if err == nil {
			_ = resp.Body.Close()
		}
		return err == nil
	}, 20*time.Second, 50*time.Millisecond)

	const (
		canaryA = "Tr0ub4dor&3-CANARY"
		canaryB = "tok_live_9f8e7d6c5b4a"
		pan     = "4111111111111111"
		sqli    = "1' OR '1'='1"
	)
	// Every request is an attack so an event is recorded; the secrets ride along.
	q := url.Values{"id": {sqli}, "password": {canaryA}, "api_token": {canaryB}, "note": {"card " + pan}}
	assert.Equal(t, http.StatusForbidden, post(t, port, "shop.localhost", "/q?"+q.Encode(), "text/plain", "x").status)

	form := url.Values{"id": {sqli}, "passwd": {canaryA}, "token": {canaryB}, "card_number": {pan}, "memo": {pan}}
	assert.Equal(t, http.StatusForbidden, post(t, port, "shop.localhost", "/form", "application/x-www-form-urlencoded", form.Encode()).status)

	body, err := json.Marshal(map[string]any{"id": sqli, "password": canaryA, "auth": map[string]string{"token": canaryB}, "card": pan, "memo": "pay " + pan})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, post(t, port, "shop.localhost", "/json", "application/json", string(body)).status)

	cancel()
	require.NoError(t, <-done)

	evs := readEvents(t, filepath.Join(dataDir, "events.jsonl"))
	require.Len(t, evs, 3, "one event per attack")
	raw, err := os.ReadFile(filepath.Join(dataDir, "events.jsonl")) //nolint:gosec // test temp path
	require.NoError(t, err)
	for _, secret := range []string{canaryA, "Tr0ub4dor", canaryB, pan, "COOKIE-SECRET", "abc.def.ghi-SECRET"} {
		assert.NotContains(t, string(raw), secret, "event stream leaked %q", secret)
	}
	assert.Contains(t, string(raw), "[PAN:****1111]", "cards are masked, not just dropped")
	assert.Contains(t, string(raw), "[REDACTED]")
	var withBody int
	for _, e := range evs {
		if e.Request.BodyExcerpt != "" {
			withBody++
		}
	}
	assert.GreaterOrEqual(t, withBody, 2, "form and JSON bodies produce redacted excerpts")
}

func TestEventsFileAndAccessLog(t *testing.T) {
	up := upstreamServer(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sherlock.yaml")
	require.NoError(t, os.WriteFile(cfgPath, fmt.Appendf(nil, `
schema_version: 1
global:
  admin: { listen: "off" }
  events:
    node_name: test-node
    access_log: { enabled: true, sample_rate: 1 }
    sinks: { stdout: false }
sites:
  - id: shop
    hosts: [shop.localhost]
    tls: { mode: none }
    policy: { mode: block }
    upstreams: { targets: ["%s"] }
`, up), 0o600))

	port := freePort(t)
	dataDir := filepath.Join(dir, "data")
	a := New(cfgPath, compiler.Options{HTTPPort: port, HTTPSPort: freePort(t), DataDir: dataDir}, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, make(chan os.Signal)) }()
	require.Eventually(t, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port)) //nolint:noctx,bodyclose,gosec // readiness probe
		if err == nil {
			_ = resp.Body.Close()
		}
		return err == nil
	}, 20*time.Second, 50*time.Millisecond)

	assert.Equal(t, http.StatusOK, send(t, port, http.MethodGet, "shop.localhost", "/clean", nil).status)
	assert.Equal(t, http.StatusForbidden, send(t, port, http.MethodGet, "shop.localhost", "/x?id="+url.QueryEscape("1' OR '1'='1"), nil).status)
	cancel()
	require.NoError(t, <-done)

	sec := readEvents(t, filepath.Join(dataDir, "events.jsonl"))
	require.Len(t, sec, 1, "the clean request is not a security event")
	assert.Equal(t, "block", sec[0].Action)
	assert.Equal(t, "test-node", sec[0].Node)

	acc := readEvents(t, filepath.Join(dataDir, "access.jsonl"))
	require.Len(t, acc, 1, "only the clean request is in the access log")
	assert.Equal(t, "allow", acc[0].Action)
	assert.Equal(t, "/clean", acc[0].Request.Path)
	assert.Equal(t, 200, acc[0].Response.Status)
	assert.Equal(t, int64(2), acc[0].Response.Bytes, `upstream writes "ok"`)
}
