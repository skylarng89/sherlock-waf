package syslog

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/exporters/exptest"
	"github.com/skylarng89/sherlock-waf/internal/exporters/format"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

func eventRec(id string) extension.ExportRecord {
	ev := events.Event{
		ID: id, Schema: events.SchemaV1, TS: time.Date(2026, 11, 3, 10, 0, 0, 123456000, time.UTC), Node: "waf-01",
		SiteID: "shop", Action: "block", Client: events.Client{IP: "198.51.100.7"},
		Request:  events.Request{Method: "GET", Host: "shop.example", Path: "/x"},
		Findings: []events.Finding{{Module: "waf", RuleID: "942100", Severity: "critical", Message: "SQLi"}},
	}
	b, _ := json.Marshal(ev)
	return extension.ExportRecord{ID: id, Stream: extension.StreamEvents, At: ev.TS, Body: b}
}

func settingsJSON(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

func newExporter(t *testing.T, m map[string]any) extension.Exporter {
	t.Helper()
	e, err := Type{Version: "9.9"}.New(settingsJSON(t, m))
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })
	return e
}

var rfc5424 = regexp.MustCompile(`^<(\d+)>1 (\S+) (\S+) (\S+) - (\S+) - (.*)$`)

func TestUDPCEF(t *testing.T) {
	pc := exptest.ListenPacket(t)
	e := newExporter(t, map[string]any{"network": "udp", "address": pc.LocalAddr().String(), "hostname": "waf-01"})

	require.NoError(t, e.Send(t.Context(), []extension.ExportRecord{eventRec("e1")}))
	buf := make([]byte, 65535)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	require.NoError(t, err)

	m := rfc5424.FindStringSubmatch(string(buf[:n]))
	require.NotNil(t, m, string(buf[:n]))
	assert.Equal(t, strconv.Itoa(16*8+2), m[1], "local0.crit")
	assert.Equal(t, "2026-11-03T10:00:00.123456Z", m[2])
	assert.Equal(t, "waf-01", m[3])
	assert.Equal(t, "sherlock", m[4])
	assert.Equal(t, "event", m[5])
	want, err := format.CEF(eventRec("e1"), "9.9")
	require.NoError(t, err)
	assert.Equal(t, want, m[6])
}

func TestUDPTruncatesOnRuneBoundary(t *testing.T) {
	msg := []byte(strings.Repeat("é", 10)) // 2 bytes each
	assert.Equal(t, []byte(strings.Repeat("é", 2)), truncate(msg, 5))
	assert.Equal(t, msg, truncate(msg, 100))
	assert.Len(t, truncate([]byte(strings.Repeat("a", UDPMaxMessage+10)), UDPMaxMessage), UDPMaxMessage)
}

// tcpSink accepts connections and records raw bytes.
type tcpSink struct {
	ln   net.Listener
	mu   sync.Mutex
	data []byte
}

func newSink(t *testing.T, ln net.Listener) *tcpSink {
	s := &tcpSink{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 4096)
				for {
					n, err := c.Read(b)
					s.mu.Lock()
					s.data = append(s.data, b[:n]...)
					s.mu.Unlock()
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return s
}

func (s *tcpSink) bytes() string { s.mu.Lock(); defer s.mu.Unlock(); return string(s.data) }

// octetFrames splits RFC 6587 octet-counted frames.
func octetFrames(t *testing.T, raw string) []string {
	t.Helper()
	var out []string
	r := bufio.NewReader(strings.NewReader(raw))
	for {
		lenStr, err := r.ReadString(' ')
		if err == io.EOF {
			return out
		}
		require.NoError(t, err)
		n, err := strconv.Atoi(strings.TrimSpace(lenStr))
		require.NoError(t, err)
		b := make([]byte, n)
		_, err = io.ReadFull(r, b)
		require.NoError(t, err)
		out = append(out, string(b))
	}
}

func TestTCPOctetCountingBatch(t *testing.T) {
	ln := exptest.Listen(t)
	sink := newSink(t, ln)
	e := newExporter(t, map[string]any{"network": "tcp", "address": ln.Addr().String(), "format": "json"})

	require.NoError(t, e.Send(t.Context(), []extension.ExportRecord{eventRec("e1"), eventRec("e2")}))
	require.Eventually(t, func() bool { return len(octetFrames(t, sink.bytes())) == 2 }, 5*time.Second, 10*time.Millisecond)
	frames := octetFrames(t, sink.bytes())
	for i, f := range frames {
		m := rfc5424.FindStringSubmatch(f)
		require.NotNil(t, m, f)
		var ev events.Event
		require.NoError(t, json.Unmarshal([]byte(m[6]), &ev))
		assert.Equal(t, fmt.Sprintf("e%d", i+1), ev.ID, "order is kept")
	}
}

func TestTCPNewlineFramingAndAudit(t *testing.T) {
	ln := exptest.Listen(t)
	sink := newSink(t, ln)
	e := newExporter(t, map[string]any{"network": "tcp", "address": ln.Addr().String(), "framing": "newline", "facility": 4, "app_name": "sh"})

	doc, _ := json.Marshal(format.AuditDoc{Schema: format.AuditSchemaV1, ID: "a1", Action: "auth.login_failed", ActorID: "u1"})
	require.NoError(t, e.Send(t.Context(), []extension.ExportRecord{{ID: "a1", Stream: extension.StreamAudit, At: time.Now(), Body: doc}}))
	require.Eventually(t, func() bool { return strings.HasSuffix(sink.bytes(), "\n") }, 5*time.Second, 10*time.Millisecond)
	line := strings.TrimSuffix(sink.bytes(), "\n")
	m := rfc5424.FindStringSubmatch(line)
	require.NotNil(t, m, line)
	assert.Equal(t, strconv.Itoa(4*8+4), m[1], "auth.warning for a failed login")
	assert.Equal(t, "sh", m[4])
	assert.Equal(t, "audit", m[5])
	assert.Contains(t, m[6], "CEF:0|Sherlock|Sherlock WAF|9.9|audit.auth.login_failed|")
}

func TestTCPReconnectsAfterPeerClose(t *testing.T) {
	ln := exptest.Listen(t)
	var conns sync.WaitGroup
	got := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer conns.Done()
				b, _ := io.ReadAll(io.LimitReader(c, 4096))
				got <- string(b)
			}()
			// the first connection is closed by the server right away
		}
	}()
	defer ln.Close()
	e := newExporter(t, map[string]any{"network": "tcp", "address": ln.Addr().String()})
	require.NoError(t, e.(extension.ExporterTester).Test(t.Context()))
	exp := e.(*exporter)
	exp.mu.Lock()
	_ = exp.conn.Close() // simulate the peer going away: our side is dead too
	exp.mu.Unlock()
	require.NoError(t, e.Send(t.Context(), []extension.ExportRecord{eventRec("e1")}), "a dead connection is replaced, not reused")
	_ = e.Close()
	var all string
	for range 2 {
		select {
		case s := <-got:
			all += s
		case <-time.After(5 * time.Second):
			t.Fatal("timed out")
		}
	}
	assert.Contains(t, all, "CEF:0")
}

func TestDownDestinationIsTransient(t *testing.T) {
	ln := exptest.Listen(t)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	e := newExporter(t, map[string]any{"network": "tcp", "address": addr})
	err := e.Send(t.Context(), []extension.ExportRecord{eventRec("e1")})
	require.Error(t, err)
	assert.NotErrorIs(t, err, extension.ErrPermanent, "an outage must be retried")
}

func TestContextDeadlineHonoured(t *testing.T) {
	ln := exptest.Listen(t) // accepts via the kernel backlog, never reads
	e := newExporter(t, map[string]any{"network": "tcp", "address": ln.Addr().String()})
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	big := eventRec("e1")
	batch := make([]extension.ExportRecord, 4000)
	for i := range batch {
		batch[i] = big
	}
	start := time.Now()
	err := e.Send(ctx, batch)
	assert.Less(t, time.Since(start), 3*time.Second)
	if err != nil {
		assert.NotErrorIs(t, err, extension.ErrPermanent)
	}
}

func TestTLS(t *testing.T) {
	ca := exptest.NewCA(t)
	leaf := ca.Issue(t, false)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{leaf.TLS}, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	sink := newSink(t, ln)

	e := newExporter(t, map[string]any{"network": "tls", "address": ln.Addr().String(), "tls": map[string]any{"ca_pem": ca.PEM, "server_name": "localhost"}})
	require.NoError(t, e.Send(t.Context(), []extension.ExportRecord{eventRec("e1")}))
	require.Eventually(t, func() bool { return len(octetFrames(t, sink.bytes())) == 1 }, 5*time.Second, 10*time.Millisecond)

	// Without the CA the handshake must fail: there is no skip-verify.
	bad := newExporter(t, map[string]any{"network": "tls", "address": ln.Addr().String()})
	err = bad.Send(t.Context(), []extension.ExportRecord{eventRec("e2")})
	require.Error(t, err)
	assert.NotErrorIs(t, err, extension.ErrPermanent)
}

func TestTLSClientCertificate(t *testing.T) {
	ca := exptest.NewCA(t)
	server := ca.Issue(t, false)
	client := ca.Issue(t, true)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{server.TLS}, MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.Pool(),
	})
	require.NoError(t, err)
	sink := newSink(t, ln)
	e := newExporter(t, map[string]any{"network": "tls", "address": ln.Addr().String(), "tls": map[string]any{
		"ca_pem": ca.PEM, "server_name": "localhost", "client_cert_pem": client.CertPEM, "client_key_pem": client.KeyPEM,
	}})
	require.NoError(t, e.(extension.ExporterTester).Test(t.Context()))
	require.Eventually(t, func() bool { return len(octetFrames(t, sink.bytes())) == 1 }, 5*time.Second, 10*time.Millisecond)
}

func TestValidate(t *testing.T) {
	ca := exptest.NewCA(t)
	ok := func(m map[string]any) map[string]any {
		base := map[string]any{"network": "tcp", "address": "siem.example:514"}
		for k, v := range m {
			base[k] = v
		}
		return base
	}
	cases := map[string]struct {
		cfg  map[string]any
		fail bool
	}{
		"minimal tcp":                         {ok(nil), false},
		"udp":                                 {ok(map[string]any{"network": "udp"}), false},
		"tls with ca":                         {ok(map[string]any{"network": "tls", "tls": map[string]any{"ca_pem": ca.PEM}}), false},
		"no network":                          {map[string]any{"address": "a:1"}, true},
		"bad network":                         {ok(map[string]any{"network": "sctp"}), true},
		"no port":                             {ok(map[string]any{"address": "siem.example"}), true},
		"port zero":                           {ok(map[string]any{"address": "siem.example:0"}), true},
		"port too big":                        {ok(map[string]any{"address": "siem.example:70000"}), true},
		"empty host":                          {ok(map[string]any{"address": ":514"}), true},
		"bad format":                          {ok(map[string]any{"format": "xml"}), true},
		"facility out of range":               {ok(map[string]any{"facility": 24}), true},
		"negative facility":                   {ok(map[string]any{"facility": -1}), true},
		"app name with space":                 {ok(map[string]any{"app_name": "my app"}), true},
		"app name too long":                   {ok(map[string]any{"app_name": strings.Repeat("a", 49)}), true},
		"hostname with space":                 {ok(map[string]any{"hostname": "a b"}), true},
		"framing on udp":                      {ok(map[string]any{"network": "udp", "framing": "octet"}), true},
		"bad framing":                         {ok(map[string]any{"framing": "crlf"}), true},
		"tls settings on tcp":                 {ok(map[string]any{"tls": map[string]any{"server_name": "x"}}), true},
		"garbage ca":                          {ok(map[string]any{"network": "tls", "tls": map[string]any{"ca_pem": "nope"}}), true},
		"client cert without key":             {ok(map[string]any{"network": "tls", "tls": map[string]any{"client_cert_pem": ca.PEM}}), true},
		"unknown field (skip-verify attempt)": {ok(map[string]any{"network": "tls", "tls": map[string]any{"insecure_skip_verify": true}}), true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := Type{}.Validate(settingsJSON(t, c.cfg))
			if c.fail {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
	assert.Error(t, Type{}.Validate(json.RawMessage(`not json`)))
}

func TestErrorsDoNotLeakKeyMaterial(t *testing.T) {
	ca := exptest.NewCA(t)
	client := ca.Issue(t, true)
	_, err := Type{}.New(settingsJSON(t, map[string]any{"network": "tls", "address": "a:1", "tls": map[string]any{
		"client_cert_pem": client.CertPEM, "client_key_pem": "-----BEGIN EC " + "PRIVATE KEY-----\nsecret-material\n-----END EC " + "PRIVATE KEY-----",
	}}))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secret-material")
}
