package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/metrics"
)

// Public test values; none is a real account. Built by concatenation so secret
// scanners do not flag the file.
const (
	dlpVisa   = "4111" + "1111" + "1111" + "1111"
	dlpVisaSp = "4111 1111 1111 1111"
	dlpAmex   = "3782 822463 10005"
	dlpIBAN   = "GB82WEST12345698765432"
)

var dlpSecrets = []string{dlpVisa, dlpVisaSp, dlpAmex, dlpIBAN, "4111", "WEST1234", "1111 1111", "822463"}

const (
	dlpHTML = "<h1>Your cards</h1><p>Visa " + dlpVisa + "</p><p>Amex " + dlpAmex + "</p><p>Account " + dlpIBAN + "</p>"
	dlpJSON = `{"cards":[{"pan":"` + dlpVisa + `","spaced":"` + dlpVisaSp + `","number":` + dlpVisa + `}],"iban":"` + dlpIBAN + `"}`
)

func dlpOrigin(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ct := dlpHTML, "text/html; charset=utf-8"
		if strings.HasSuffix(r.URL.Path, "/json") {
			body, ct = dlpJSON, "application/json"
		}
		if strings.HasSuffix(r.URL.Path, "/clean") {
			body = `{"order":8841,"total":129.90}`
			ct = "application/json"
		}
		w.Header().Set("Content-Type", ct)
		if strings.HasSuffix(r.URL.Path, "/gz") && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write([]byte(body))
			_ = zw.Close()
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", fmt.Sprint(buf.Len()))
			_, _ = w.Write(buf.Bytes())
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

type dlpReply struct {
	status int
	header http.Header
	body   []byte
}

func dlpGet(t *testing.T, port int, host, target string, hdr ...string) dlpReply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, target), nil)
	require.NoError(t, err)
	req.Host = host
	req.Header.Set("Accept", "text/html")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return dlpReply{status: resp.StatusCode, header: resp.Header, body: b}
}

func dlpGunzip(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	require.NoError(t, err)
	out, err := io.ReadAll(zr)
	require.NoError(t, err)
	return string(out)
}

func assertNoSecrets(t *testing.T, where, text string) {
	t.Helper()
	for _, s := range dlpSecrets {
		assert.NotContains(t, text, s, "%s leaked %q", where, s)
	}
}

// TestDLPLive is acceptance criterion 2 of M11: pages with card numbers and
// IBANs, as HTML and JSON, come out masked (or blocked), and no value appears in
// any event, log line or exporter-bound record. It also covers the three actions,
// detect mode, a compressed response and a clean response.
func TestDLPLive(t *testing.T) {
	origin := dlpOrigin(t)
	bank, watch := uniqueSite("bank"), uniqueSite("watch")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sherlock.yaml")
	require.NoError(t, os.WriteFile(cfgPath, fmt.Appendf(nil, `
schema_version: 1
global:
  admin: { listen: "off" }
  events:
    access_log: { enabled: true, sample_rate: 1 }
    sinks: { stdout: true }
sites:
  - id: %[1]s
    hosts: [bank.localhost]
    tls: { mode: none }
    policy:
      mode: block
      dlp: { enabled: true, detect: [pan, iban], action: mask }
    upstreams: { targets: ["%[3]s"] }
    endpoints:
      - id: blocked
        match: { path_prefix: /block }
        policy: { dlp: { action: block } }
      - id: logged
        match: { path_prefix: /log }
        policy: { dlp: { action: log } }
  - id: %[2]s
    hosts: [watch.localhost]
    tls: { mode: none }
    policy:
      mode: detect
      dlp: { enabled: true, detect: [pan, iban], action: block }
    upstreams: { targets: ["%[3]s"] }
`, bank, watch, origin), 0o600))

	var (
		stdout, logs syncBuffer
		busMu        sync.Mutex
		busRecords   []string
	)
	port := freePort(t)
	dataDir := filepath.Join(dir, "data")
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	hook := func(ctx context.Context, bus *events.Bus) func() {
		sub := bus.Subscribe(false)
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer sub.Close()
			buf := make([]*events.Event, 64)
			for sub.Wait(ctx) {
				for _, e := range buf[:sub.Read(buf)] {
					b, _ := json.Marshal(e)
					busMu.Lock()
					busRecords = append(busRecords, string(b))
					busMu.Unlock()
				}
			}
		}()
		return func() { <-done }
	}
	a := New(cfgPath, compiler.Options{HTTPPort: port, HTTPSPort: freePort(t), DataDir: dataDir}, logger,
		WithEventsOutput(&stdout), WithSecurityBusHook(hook))
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

	// mask: HTML and JSON come out masked, with the same length and valid JSON.
	r := dlpGet(t, port, "bank.localhost", "/account")
	require.Equal(t, http.StatusOK, r.status)
	assert.Equal(t, "<h1>Your cards</h1><p>Visa ************1111</p><p>Amex **** ****** *0005</p><p>Account GB****************5432</p>", string(r.body))
	assert.Equal(t, fmt.Sprint(len(dlpHTML)), r.header.Get("Content-Length"))
	assertNoSecrets(t, "masked HTML", string(r.body))

	r = dlpGet(t, port, "bank.localhost", "/account/json", "Accept", "application/json")
	require.Equal(t, http.StatusOK, r.status)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(r.body, &doc), string(r.body))
	assertNoSecrets(t, "masked JSON", string(r.body))
	assert.Contains(t, string(r.body), "************1111")

	// compressed: decoded, masked, re-encoded with a matching length.
	r = dlpGet(t, port, "bank.localhost", "/account/gz", "Accept-Encoding", "gzip")
	require.Equal(t, http.StatusOK, r.status)
	assert.Equal(t, "gzip", r.header.Get("Content-Encoding"))
	assert.Equal(t, fmt.Sprint(len(r.body)), r.header.Get("Content-Length"))
	assertNoSecrets(t, "masked gzip body", dlpGunzip(t, r.body))

	// a client that prefers br is served a body that could be scanned.
	r = dlpGet(t, port, "bank.localhost", "/account/gz", "Accept-Encoding", "br")
	assert.Empty(t, r.header.Get("Content-Encoding"))
	assertNoSecrets(t, "masked body for a br client", string(r.body))

	// block: the origin's page never reaches the client.
	r = dlpGet(t, port, "bank.localhost", "/block/account")
	assert.Equal(t, http.StatusBadGateway, r.status)
	assertNoSecrets(t, "blocked response", string(r.body))
	assert.NotEmpty(t, r.header.Get("X-Sherlock-Event-Id"))

	// log: delivered unchanged, but recorded.
	r = dlpGet(t, port, "bank.localhost", "/log/account")
	assert.Equal(t, dlpHTML, string(r.body))

	// detect mode: nothing is ever changed, even with action block.
	r = dlpGet(t, port, "watch.localhost", "/account")
	assert.Equal(t, http.StatusOK, r.status)
	assert.Equal(t, dlpHTML, string(r.body))

	// clean responses are untouched and produce no finding.
	r = dlpGet(t, port, "bank.localhost", "/account/clean", "Accept", "application/json")
	assert.JSONEq(t, `{"order":8841,"total":129.90}`, string(r.body))

	time.Sleep(200 * time.Millisecond) // events are published just after the response
	cancel()
	require.NoError(t, <-done)

	raw, err := os.ReadFile(filepath.Join(dataDir, "events.jsonl")) //nolint:gosec // test temp path
	require.NoError(t, err)
	assertNoSecrets(t, "events file", string(raw))
	assertNoSecrets(t, "stdout events", stdout.String())
	assertNoSecrets(t, "log output", logs.String())
	busMu.Lock()
	bus := strings.Join(busRecords, "\n")
	busMu.Unlock()
	assertNoSecrets(t, "exporter-bound records", bus)

	// the findings themselves are there, with counts and no values.
	for _, want := range []string{`"module":"dlp"`, `"rule_id":"pan"`, `"rule_id":"iban"`, "card numbers found in the response", "detect mode, response unchanged", "response blocked", "logged, response unchanged"} {
		assert.Contains(t, bus, want)
		assert.Contains(t, string(raw), want)
	}

	mfs, err := metrics.Registry.Gather()
	require.NoError(t, err)
	seen := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "sherlock_dlp_matches_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["site"] == bank || labels["site"] == watch {
				seen[labels["site"]+"/"+labels["detector"]+"/"+labels["action"]] += m.GetCounter().GetValue()
			}
		}
	}
	assert.Positive(t, seen[bank+"/pan/mask"])
	assert.Positive(t, seen[bank+"/iban/mask"])
	assert.Positive(t, seen[bank+"/pan/block"])
	assert.Positive(t, seen[bank+"/pan/log"])
	assert.Positive(t, seen[watch+"/pan/log"], "detect mode counts the match as log")
}
