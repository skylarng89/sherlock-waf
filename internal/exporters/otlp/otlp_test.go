package otlp

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/exporters/exptest"
	"github.com/skylarng89/sherlock-waf/internal/exporters/format"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

func cfg(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

func eventRec(id string) extension.ExportRecord {
	ev := events.Event{
		ID: id, Schema: events.SchemaV1, TS: time.Unix(1700000000, 5), SiteID: "shop", Action: "block",
		Client:   events.Client{IP: "198.51.100.7", Country: "NG"},
		Request:  events.Request{Method: "POST", Host: "shop.example", Path: "/login"},
		Response: events.Response{Status: 403},
		Findings: []events.Finding{{Module: "waf", RuleID: "942100", Severity: "error"}, {Module: "waf", RuleID: "949110", Severity: "warning"}},
	}
	b, _ := json.Marshal(ev)
	return extension.ExportRecord{ID: id, Stream: extension.StreamEvents, At: ev.TS, Body: b}
}

func auditRec() extension.ExportRecord {
	b, _ := json.Marshal(format.AuditDoc{Schema: format.AuditSchemaV1, ID: "a1", Action: "config.apply", ActorID: "u1", ObjectType: "config", ObjectID: "v2", IP: "10.0.0.1"})
	return extension.ExportRecord{ID: "a1", Stream: extension.StreamAudit, At: time.Unix(1700000001, 0), Body: b}
}

func newExp(t *testing.T, m map[string]any) extension.Exporter {
	t.Helper()
	e, err := Type{Version: "1.2"}.New(cfg(t, m))
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.Close() })
	return e
}

// attrMap flattens an OTLP/JSON attribute list for assertions.
func attrMap(t *testing.T, kvs []any) map[string]any {
	t.Helper()
	out := map[string]any{}
	for _, kv := range kvs {
		m := kv.(map[string]any)
		out[m["key"].(string)] = m["value"]
	}
	return out
}

func TestHTTPJSONShape(t *testing.T) {
	var path, ct, ua, tokenHdr string
	var doc map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ct, ua, tokenHdr = r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("User-Agent"), r.Header.Get("Api-Token")
		b, _ := io.ReadAll(r.Body)
		require.NoError(t, json.Unmarshal(b, &doc))
		_, _ = w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"nope"}}`))
	}))
	defer srv.Close()
	e := newExp(t, map[string]any{
		"endpoint": srv.URL, "allow_http": true, "headers": map[string]string{"Api-Token": "tok"},
		"resource_attributes": map[string]string{"deployment.environment": "prod", "service.name": "custom"},
	})

	require.NoError(t, e.Send(t.Context(), []extension.ExportRecord{eventRec("e1"), auditRec()}), "partial success is not an error")
	assert.Equal(t, "/v1/logs", path)
	assert.Equal(t, "application/json", ct)
	assert.Equal(t, "Sherlock-WAF/1.2", ua)
	assert.Equal(t, "tok", tokenHdr)

	rl := doc["resourceLogs"].([]any)
	require.Len(t, rl, 1)
	r0 := rl[0].(map[string]any)
	res := attrMap(t, r0["resource"].(map[string]any)["attributes"].([]any))
	assert.Equal(t, map[string]any{"stringValue": "custom"}, res["service.name"], "user attributes override defaults")
	assert.Equal(t, map[string]any{"stringValue": "1.2"}, res["service.version"])
	assert.Equal(t, map[string]any{"stringValue": "prod"}, res["deployment.environment"])

	sl := r0["scopeLogs"].([]any)[0].(map[string]any)
	assert.Equal(t, "sherlock-waf", sl["scope"].(map[string]any)["name"])
	recs := sl["logRecords"].([]any)
	require.Len(t, recs, 2)

	ev := recs[0].(map[string]any)
	assert.Equal(t, "1700000000000000005", ev["timeUnixNano"], "64-bit integers are JSON strings")
	assert.IsType(t, "", ev["observedTimeUnixNano"])
	assert.EqualValues(t, 17, ev["severityNumber"], "error maps to ERROR")
	assert.Equal(t, "ERROR", ev["severityText"])
	var body events.Event
	require.NoError(t, json.Unmarshal([]byte(ev["body"].(map[string]any)["stringValue"].(string)), &body))
	assert.Equal(t, "e1", body.ID, "the whole event is the body")
	at := attrMap(t, ev["attributes"].([]any))
	assert.Equal(t, map[string]any{"stringValue": "e1"}, at["sherlock.event.id"])
	assert.Equal(t, map[string]any{"stringValue": "shop"}, at["sherlock.site_id"])
	assert.Equal(t, map[string]any{"stringValue": "block"}, at["sherlock.action"])
	assert.Equal(t, map[string]any{"stringValue": "198.51.100.7"}, at["client.address"])
	assert.Equal(t, map[string]any{"intValue": "403"}, at["http.response.status_code"])
	assert.Equal(t, map[string]any{"arrayValue": map[string]any{"values": []any{
		map[string]any{"stringValue": "942100"}, map[string]any{"stringValue": "949110"},
	}}}, at["sherlock.rule_ids"])

	au := recs[1].(map[string]any)
	assert.EqualValues(t, 9, au["severityNumber"])
	aa := attrMap(t, au["attributes"].([]any))
	assert.Equal(t, map[string]any{"stringValue": "config.apply"}, aa["sherlock.audit.action"])
	assert.Equal(t, map[string]any{"stringValue": "audit"}, aa["sherlock.stream"])
}

func TestHTTPGzipAndEndpointPath(t *testing.T) {
	var enc, path string
	var doc map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enc, path = r.Header.Get("Content-Encoding"), r.URL.Path
		zr, err := gzip.NewReader(r.Body)
		require.NoError(t, err)
		b, _ := io.ReadAll(zr)
		require.NoError(t, json.Unmarshal(b, &doc))
	}))
	defer srv.Close()
	for in, want := range map[string]string{srv.URL: "/v1/logs", srv.URL + "/otel/": "/otel/v1/logs", srv.URL + "/x/v1/logs": "/x/v1/logs"} {
		e := newExp(t, map[string]any{"endpoint": in, "allow_http": true, "compression": "gzip"})
		require.NoError(t, e.Send(t.Context(), []extension.ExportRecord{eventRec("e1")}))
		assert.Equal(t, "gzip", enc)
		assert.Equal(t, want, path)
		assert.NotEmpty(t, doc["resourceLogs"])
	}
}

func TestHTTPStatusClassification(t *testing.T) {
	for code, class := range map[int]string{
		200: "ok", 202: "ok", 408: "transient", 429: "transient", 500: "transient", 502: "transient", 503: "transient", 504: "transient",
		400: "permanent", 401: "permanent", 403: "permanent", 404: "permanent", 413: "permanent", 307: "permanent",
	} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
			defer srv.Close()
			err := newExp(t, map[string]any{"endpoint": srv.URL, "allow_http": true}).Send(t.Context(), []extension.ExportRecord{eventRec("e")})
			switch class {
			case "ok":
				assert.NoError(t, err)
			case "transient":
				require.Error(t, err)
				assert.NotErrorIs(t, err, extension.ErrPermanent)
			default:
				assert.ErrorIs(t, err, extension.ErrPermanent)
			}
		})
	}
}

func TestHTTPTLSPrivateCA(t *testing.T) {
	ca := exptest.NewCA(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.Issue(t, false).TLS}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	require.NoError(t, newExp(t, map[string]any{"endpoint": srv.URL, "tls": map[string]any{"ca_pem": ca.PEM}}).Send(t.Context(), []extension.ExportRecord{eventRec("e")}))
	err := newExp(t, map[string]any{"endpoint": srv.URL}).Send(t.Context(), []extension.ExportRecord{eventRec("e")})
	require.Error(t, err)
	assert.NotErrorIs(t, err, extension.ErrPermanent)
}

func TestTestExportsAMarkedRecord(t *testing.T) {
	var doc map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &doc)
	}))
	defer srv.Close()
	require.NoError(t, newExp(t, map[string]any{"endpoint": srv.URL, "allow_http": true}).(extension.ExporterTester).Test(t.Context()))
	lr := doc["resourceLogs"].([]any)[0].(map[string]any)["scopeLogs"].([]any)[0].(map[string]any)["logRecords"].([]any)
	require.Len(t, lr, 1)
	assert.Equal(t, "test", attrMap(t, lr[0].(map[string]any)["attributes"].([]any))["sherlock.stream"].(map[string]any)["stringValue"])
}

func TestContextTimeoutAndNoLeaks(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	e := newExp(t, map[string]any{"endpoint": srv.URL + "/path-token-123?key=SECRETKEY", "allow_http": true, "headers": map[string]string{"Authorization": "Bearer HEADERSECRET"}})
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := e.Send(ctx, []extension.ExportRecord{eventRec("e")})
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.NotErrorIs(t, err, extension.ErrPermanent)
	for _, leak := range []string{"path-token-123", "SECRETKEY", "HEADERSECRET"} {
		assert.NotContains(t, err.Error(), leak)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer srv.Close()
	require.Error(t, newExp(t, map[string]any{"endpoint": srv.URL, "allow_http": true}).Send(t.Context(), []extension.ExportRecord{eventRec("e")}))
	assert.False(t, hit.Load())
}

// --- gRPC ---

type grpcServer struct {
	addr     string
	got      chan []byte
	headers  chan http.Header
	status   atomic.Int32
	trailers atomic.Bool // false: answer "trailers-only" in the header block
}

func startGRPC(t *testing.T, tlsConf *tls.Config) *grpcServer {
	t.Helper()
	s := &grpcServer{got: make(chan []byte, 4), headers: make(chan http.Header, 4)}
	s.trailers.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc(grpcMethod, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.got <- b
		s.headers <- r.Header.Clone()
		w.Header().Set("Content-Type", "application/grpc")
		if s.trailers.Load() {
			w.Header().Set("Trailer", "Grpc-Status")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte{0, 0, 0, 0, 0})
			w.Header().Set("Grpc-Status", strconv.Itoa(int(s.status.Load())))
			return
		}
		w.Header().Set("Grpc-Status", strconv.Itoa(int(s.status.Load())))
		w.WriteHeader(http.StatusOK)
	})
	ln := exptest.Listen(t)
	srv := &http.Server{Handler: mux, Protocols: new(http.Protocols), ReadHeaderTimeout: time.Second}
	srv.Protocols.SetHTTP2(true)
	if tlsConf == nil {
		srv.Protocols.SetUnencryptedHTTP2(true)
	} else {
		srv.TLSConfig = tlsConf
		ln = tls.NewListener(ln, tlsConf)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	s.addr = ln.Addr().String()
	return s
}

// pbField is one decoded protobuf field.
type pbField struct {
	num  int
	wire int
	v    uint64 // varint / fixed
	b    []byte // length-delimited
}

func pbFields(t *testing.T, b []byte) []pbField {
	t.Helper()
	var out []pbField
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		require.Positive(t, n)
		b = b[n:]
		f := pbField{num: int(tag >> 3), wire: int(tag & 7)}
		switch f.wire {
		case 0:
			f.v, n = binary.Uvarint(b)
			require.Positive(t, n)
			b = b[n:]
		case 1:
			require.GreaterOrEqual(t, len(b), 8)
			f.v = binary.LittleEndian.Uint64(b)
			b = b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			require.Positive(t, n)
			b = b[n:]
			require.GreaterOrEqual(t, uint64(len(b)), l)
			f.b, b = b[:l], b[l:]
		default:
			t.Fatalf("unexpected wire type %d", f.wire)
		}
		out = append(out, f)
	}
	return out
}

func first(fs []pbField, num int) pbField {
	for _, f := range fs {
		if f.num == num {
			return f
		}
	}
	return pbField{}
}

func all(fs []pbField, num int) (out []pbField) {
	for _, f := range fs {
		if f.num == num {
			out = append(out, f)
		}
	}
	return out
}

func TestGRPCCleartextPayload(t *testing.T) {
	srv := startGRPC(t, nil)
	e := newExp(t, map[string]any{"endpoint": "http://" + srv.addr, "protocol": "grpc", "allow_http": true, "headers": map[string]string{"Api-Token": "tok"}})
	require.NoError(t, e.Send(t.Context(), []extension.ExportRecord{eventRec("e1")}))

	frame := <-srv.got
	hdr := <-srv.headers
	assert.Equal(t, "application/grpc", hdr.Get("Content-Type"))
	assert.Equal(t, "trailers", hdr.Get("Te"))
	assert.Equal(t, "tok", hdr.Get("Api-Token"))
	require.GreaterOrEqual(t, len(frame), 5)
	assert.Zero(t, frame[0], "uncompressed")
	assert.EqualValues(t, len(frame)-5, binary.BigEndian.Uint32(frame[1:5]), "length prefix matches")

	rl := pbFields(t, first(pbFields(t, frame[5:]), 1).b) // ResourceLogs
	resAttrs := all(pbFields(t, first(rl, 1).b), 1)
	keys := map[string]string{}
	for _, kv := range resAttrs {
		f := pbFields(t, kv.b)
		keys[string(first(f, 1).b)] = string(first(pbFields(t, first(f, 2).b), 1).b)
	}
	assert.Equal(t, "sherlock-waf", keys["service.name"])
	assert.Equal(t, "1.2", keys["service.version"])

	sl := pbFields(t, first(rl, 2).b)
	assert.Equal(t, "sherlock-waf", string(first(pbFields(t, first(sl, 1).b), 1).b), "scope name")
	lrs := all(sl, 2)
	require.Len(t, lrs, 1)
	lr := pbFields(t, lrs[0].b)
	assert.Equal(t, uint64(1700000000000000005), first(lr, 1).v, "time_unix_nano")
	assert.EqualValues(t, 17, first(lr, 2).v, "severity_number")
	assert.Equal(t, "ERROR", string(first(lr, 3).b))
	var body events.Event
	require.NoError(t, json.Unmarshal(first(pbFields(t, first(lr, 5).b), 1).b, &body))
	assert.Equal(t, "e1", body.ID)
	attrs := map[string]pbField{}
	for _, kv := range all(lr, 6) {
		f := pbFields(t, kv.b)
		attrs[string(first(f, 1).b)] = first(f, 2)
	}
	assert.Equal(t, "e1", string(first(pbFields(t, attrs["sherlock.event.id"].b), 1).b))
	assert.EqualValues(t, 403, first(pbFields(t, attrs["http.response.status_code"].b), 3).v, "int_value")
	arr := pbFields(t, first(pbFields(t, attrs["sherlock.rule_ids"].b), 5).b)
	assert.Len(t, all(arr, 1), 2, "array_value holds both rule ids")
	assert.NotZero(t, first(lr, 11).v, "observed_time_unix_nano")
}

func TestGRPCStatusClassification(t *testing.T) {
	srv := startGRPC(t, nil)
	e := newExp(t, map[string]any{"endpoint": "http://" + srv.addr, "protocol": "grpc", "allow_http": true})
	for code, class := range map[int32]string{
		0: "ok", 1: "transient", 2: "transient", 4: "transient", 8: "transient", 10: "transient", 13: "transient", 14: "transient",
		3: "permanent", 7: "permanent", 12: "permanent", 16: "permanent",
	} {
		srv.status.Store(code)
		for _, trailers := range []bool{true, false} {
			srv.trailers.Store(trailers)
			err := e.Send(t.Context(), []extension.ExportRecord{eventRec("e")})
			<-srv.got
			<-srv.headers
			switch class {
			case "ok":
				assert.NoError(t, err, "code %d trailers=%v", code, trailers)
			case "transient":
				require.Error(t, err, "code %d", code)
				assert.NotErrorIs(t, err, extension.ErrPermanent, "code %d", code)
			default:
				assert.ErrorIs(t, err, extension.ErrPermanent, "code %d", code)
			}
		}
	}
}

func TestGRPCOverTLS(t *testing.T) {
	ca := exptest.NewCA(t)
	srv := startGRPC(t, &tls.Config{Certificates: []tls.Certificate{ca.Issue(t, false).TLS}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}})
	// A bare host:port means TLS for grpc.
	e := newExp(t, map[string]any{"endpoint": srv.addr, "protocol": "grpc", "tls": map[string]any{"ca_pem": ca.PEM}})
	require.NoError(t, e.(extension.ExporterTester).Test(t.Context()))
	assert.NotEmpty(t, <-srv.got)
}

func TestGRPCDownIsTransient(t *testing.T) {
	ln := exptest.Listen(t)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	err := newExp(t, map[string]any{"endpoint": "http://" + addr, "protocol": "grpc", "allow_http": true}).Send(t.Context(), []extension.ExportRecord{eventRec("e")})
	require.Error(t, err)
	assert.NotErrorIs(t, err, extension.ErrPermanent)
}

func TestValidate(t *testing.T) {
	ca := exptest.NewCA(t)
	good := func(m map[string]any) map[string]any {
		base := map[string]any{"endpoint": "https://collector.example:4318"}
		for k, v := range m {
			base[k] = v
		}
		return base
	}
	cases := map[string]struct {
		cfg  map[string]any
		fail bool
	}{
		"https http":          {good(nil), false},
		"grpc bare host":      {map[string]any{"endpoint": "collector.example:4317", "protocol": "grpc"}, false},
		"grpc cleartext":      {map[string]any{"endpoint": "http://10.0.0.5:4317", "protocol": "grpc", "allow_http": true}, false},
		"gzip":                {good(map[string]any{"compression": "gzip"}), false},
		"private ca":          {good(map[string]any{"tls": map[string]any{"ca_pem": ca.PEM}}), false},
		"resource attrs":      {good(map[string]any{"resource_attributes": map[string]string{"a": "b"}}), false},
		"no endpoint":         {map[string]any{}, true},
		"http without opt-in": {good(map[string]any{"endpoint": "http://collector.example:4318"}), true},
		"grpc bare http":      {map[string]any{"endpoint": "http://c:4317", "protocol": "grpc"}, true},
		"bad protocol":        {good(map[string]any{"protocol": "thrift"}), true},
		"bad compression":     {good(map[string]any{"compression": "zstd"}), true},
		"gzip on grpc":        {map[string]any{"endpoint": "c:4317", "protocol": "grpc", "compression": "gzip"}, true},
		"userinfo":            {good(map[string]any{"endpoint": "https://u:p@collector.example"}), true}, //nolint:gosec // fake credentials in a rejection test
		"metadata literal":    {good(map[string]any{"endpoint": "https://169.254.169.254"}), true},
		"unspecified":         {good(map[string]any{"endpoint": "https://0.0.0.0:4318"}), true},
		"ftp":                 {good(map[string]any{"endpoint": "ftp://collector.example"}), true},
		"bad header name":     {good(map[string]any{"headers": map[string]string{"bad name": "v"}}), true},
		"header injection":    {good(map[string]any{"headers": map[string]string{"X-A": "v\nX-B: w"}}), true},
		"reserved header":     {good(map[string]any{"headers": map[string]string{"Content-Type": "text/plain"}}), true},
		"garbage ca":          {good(map[string]any{"tls": map[string]any{"ca_pem": "nope"}}), true},
		"empty resource attr": {good(map[string]any{"resource_attributes": map[string]string{"": "b"}}), true},
		"unknown field":       {good(map[string]any{"insecure_skip_verify": true}), true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := Type{}.Validate(cfg(t, c.cfg))
			if c.fail {
				require.Error(t, err)
				assert.False(t, strings.Contains(err.Error(), "u:p"), "credentials are never echoed")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
