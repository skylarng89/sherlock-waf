// Package otlp exports records as OpenTelemetry logs over OTLP/HTTP (JSON) or
// OTLP/gRPC.
package otlp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/netx"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

const (
	scopeName      = "sherlock-waf"
	logsPath       = "/v1/logs"
	grpcMethod     = "/opentelemetry.proto.collector.logs.v1.LogsService/Export"
	requestTimeout = 30 * time.Second
	maxHeaders     = 20
	maxHeaderValue = 4096
	maxResAttrs    = 32
	maxResponse    = 64 << 10
)

// Type builds OTLP exporters. Version is reported as service.version and as the
// instrumentation scope version.
type Type struct{ Version string }

// Name implements extension.ExporterType.
func (Type) Name() string { return "otlp" }

type settings struct {
	Endpoint    string            `json:"endpoint"`
	Protocol    string            `json:"protocol"`
	Headers     map[string]string `json:"headers"`
	Compression string            `json:"compression"`
	AllowHTTP   bool              `json:"allow_http"`
	TLS         struct {
		CAPEM string `json:"ca_pem"`
	} `json:"tls"`
	ResourceAttributes map[string]string `json:"resource_attributes"`
}

var headerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)

func reserved(name string) bool {
	switch strings.ToLower(name) {
	case "content-type", "content-length", "content-encoding", "host", "te", "user-agent", "grpc-encoding":
		return true
	}
	return false
}

type config struct {
	settings
	target *url.URL // gRPC: scheme://host:port; HTTP: full logs URL
}

func parse(raw json.RawMessage) (config, error) {
	var s settings
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return config{}, fmt.Errorf("otlp settings: %w", err)
	}
	c := config{settings: s}
	switch s.Protocol {
	case "":
		c.Protocol = "http"
	case "http", "grpc":
	default:
		return c, errors.New("otlp: protocol must be http or grpc")
	}
	switch s.Compression {
	case "", "none", "gzip":
	default:
		return c, errors.New("otlp: compression must be none or gzip")
	}
	if c.Protocol == "grpc" && c.Compression == "gzip" {
		return c, errors.New("otlp: compression applies to the http protocol only")
	}
	ep := s.Endpoint
	if ep != "" && !strings.Contains(ep, "://") && c.Protocol == "grpc" {
		ep = "https://" + ep // a bare host:port is the usual gRPC form
	}
	u, err := url.Parse(ep)
	if err != nil || u.Hostname() == "" {
		return c, errors.New("otlp: endpoint must be an absolute URL (or host:port for grpc)") // not echoed: it may hold a token
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && s.AllowHTTP:
	case u.Scheme == "http":
		return c, errors.New("otlp: endpoint must use https (set allow_http only for a trusted network)")
	default:
		return c, errors.New("otlp: endpoint scheme must be https")
	}
	if u.User != nil {
		return c, errors.New("otlp: credentials in the endpoint are not accepted; use headers")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && netx.Blocked(ip, true) {
		return c, fmt.Errorf("otlp: destination address %s is not allowed", ip)
	}
	if c.Protocol == "http" && !strings.HasSuffix(u.Path, logsPath) {
		u.Path = strings.TrimSuffix(u.Path, "/") + logsPath
	}
	c.target = u
	if len(s.Headers) > maxHeaders {
		return c, fmt.Errorf("otlp: at most %d custom headers", maxHeaders)
	}
	for k, v := range s.Headers {
		switch {
		case !headerName.MatchString(k):
			return c, errors.New("otlp: invalid header name")
		case reserved(k):
			return c, fmt.Errorf("otlp: header %q is set by Sherlock", k)
		case len(v) > maxHeaderValue || strings.ContainsAny(v, "\r\n\x00"):
			return c, fmt.Errorf("otlp: invalid value for header %q", k)
		}
	}
	if len(s.ResourceAttributes) > maxResAttrs {
		return c, fmt.Errorf("otlp: at most %d resource attributes", maxResAttrs)
	}
	for k := range s.ResourceAttributes {
		if k == "" {
			return c, errors.New("otlp: resource attribute names must not be empty")
		}
	}
	if s.TLS.CAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(s.TLS.CAPEM)) {
		return c, errors.New("otlp: tls.ca_pem holds no certificate")
	}
	return c, nil
}

// Validate implements extension.ExporterType.
func (Type) Validate(raw json.RawMessage) error {
	_, err := parse(raw)
	return err
}

// New implements extension.ExporterType.
func (t Type) New(raw json.RawMessage) (extension.Exporter, error) {
	c, err := parse(raw)
	if err != nil {
		return nil, err
	}
	// Private and loopback destinations are normal for a collector; link-local
	// (cloud metadata) stays blocked on the dialled address.
	client := netx.NewClient(netx.Options{AllowPrivate: true, Timeout: requestTimeout})
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if tr, ok := client.Transport.(*http.Transport); ok {
		if c.TLS.CAPEM != "" {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM([]byte(c.TLS.CAPEM))
			tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
		if c.Protocol == "grpc" {
			// gRPC needs HTTP/2, also in cleartext for a collector on a trusted network.
			tr.ForceAttemptHTTP2 = true
			tr.Protocols = new(http.Protocols)
			tr.Protocols.SetHTTP2(true)
			tr.Protocols.SetUnencryptedHTTP2(true)
		}
	}
	res := []attr{strAttr("service.name", "sherlock-waf"), strAttr("service.version", t.Version)}
	if h, err := os.Hostname(); err == nil {
		res = append(res, strAttr("host.name", h))
	}
	for k, v := range c.ResourceAttributes {
		replaced := false
		for i := range res {
			if res[i].key == k {
				res[i].val, replaced = value{s: v}, true
			}
		}
		if !replaced {
			res = append(res, strAttr(k, v))
		}
	}
	return &exporter{cfg: c, client: client, res: res, version: t.Version, now: time.Now, ua: "Sherlock-WAF/" + t.Version}, nil
}

type exporter struct {
	cfg     config
	client  *http.Client
	res     []attr
	version string
	ua      string
	now     func() time.Time
}

var (
	_ extension.Exporter       = (*exporter)(nil)
	_ extension.ExporterTester = (*exporter)(nil)
)

// Send implements extension.Exporter.
func (e *exporter) Send(ctx context.Context, batch []extension.ExportRecord) error {
	if len(batch) == 0 {
		return nil
	}
	observed := e.now()
	lrs := make([]logRecord, len(batch))
	for i, r := range batch {
		lrs[i] = toLogRecord(r, observed)
	}
	return e.export(ctx, lrs)
}

// Test implements extension.ExporterTester. It exports one clearly marked
// informational record, because an empty request proves little: collectors
// validate auth and pipelines on real data.
func (e *exporter) Test(ctx context.Context) error {
	now := e.now()
	return e.export(ctx, []logRecord{{
		timeNano: now.UnixNano(), observedNano: now.UnixNano(), sevNum: 9, sevText: "INFO",
		body: "Sherlock exporter connectivity test", attrs: []attr{strAttr("sherlock.stream", "test")},
	}})
}

func (e *exporter) export(ctx context.Context, lrs []logRecord) error {
	if e.cfg.Protocol == "grpc" {
		return e.exportGRPC(ctx, marshalProto(e.res, e.version, lrs))
	}
	body, err := marshalJSON(e.res, e.version, lrs)
	if err != nil {
		return fmt.Errorf("encoding otlp batch: %w", err)
	}
	return e.exportHTTP(ctx, body)
}

func (e *exporter) host() string { return e.cfg.target.Host }

func (e *exporter) newRequest(ctx context.Context, target string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, body)
	if err != nil {
		return nil, fmt.Errorf("building otlp request for %s: %w", e.host(), errors.Unwrap(err))
	}
	for k, v := range e.cfg.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", e.ua)
	return req, nil
}

func (e *exporter) do(req *http.Request) (*http.Response, error) {
	res, err := e.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the *url.Error text embeds the full URL
		}
		return nil, fmt.Errorf("sending to otlp endpoint %s: %w", e.host(), err)
	}
	return res, nil
}

func (e *exporter) exportHTTP(ctx context.Context, body []byte) error {
	var payload io.Reader = bytes.NewReader(body)
	if e.cfg.Compression == "gzip" {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(body)
		if err := zw.Close(); err != nil {
			return fmt.Errorf("compressing otlp batch: %w", err)
		}
		payload = &buf
	}
	req, err := e.newRequest(ctx, e.cfg.target.String(), payload)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.cfg.Compression == "gzip" {
		req.Header.Set("Content-Encoding", "gzip")
	}
	res, err := e.do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	// A 200 may carry partial_success with rejected records. Retrying would
	// resend the accepted ones, so it counts as delivered; the collector already
	// reported the rejects on its side.
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponse))
	return e.classifyHTTP(res.StatusCode)
}

func (e *exporter) classifyHTTP(code int) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500:
		return fmt.Errorf("otlp endpoint %s answered %d", e.host(), code)
	}
	return fmt.Errorf("otlp endpoint %s rejected the batch with %d: %w", e.host(), code, extension.ErrPermanent)
}

// gRPC status codes (google.rpc.Code) Sherlock distinguishes.
const (
	grpcOK               = 0
	grpcInvalidArgument  = 3
	grpcNotFound         = 5
	grpcPermissionDenied = 7
	grpcFailedPrecond    = 9
	grpcOutOfRange       = 11
	grpcUnimplemented    = 12
	grpcUnauthenticated  = 16
	grpcAlreadyExists    = 6
)

func (e *exporter) exportGRPC(ctx context.Context, msg []byte) error {
	frame := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(frame[1:], uint32(len(msg))) //nolint:gosec // a batch is far below 4 GiB
	frame = append(frame, msg...)

	target := e.cfg.target.Scheme + "://" + e.cfg.target.Host + grpcMethod
	req, err := e.newRequest(ctx, target, bytes.NewReader(frame))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Grpc-Accept-Encoding", "identity")
	res, err := e.do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponse)) // trailers are complete only after the body is read
	if res.StatusCode != http.StatusOK {
		return e.classifyHTTP(res.StatusCode)
	}
	status := res.Trailer.Get("Grpc-Status")
	if status == "" {
		status = res.Header.Get("Grpc-Status") // "trailers-only" responses
	}
	code, err := strconv.Atoi(status)
	if err != nil {
		return fmt.Errorf("otlp endpoint %s sent no grpc status", e.host())
	}
	if code == grpcOK {
		return nil
	}
	// The grpc-message is left out: servers sometimes echo request detail.
	switch code {
	case grpcInvalidArgument, grpcNotFound, grpcAlreadyExists, grpcPermissionDenied, grpcFailedPrecond, grpcOutOfRange, grpcUnimplemented, grpcUnauthenticated:
		return fmt.Errorf("otlp endpoint %s rejected the batch with grpc status %d: %w", e.host(), code, extension.ErrPermanent)
	}
	return fmt.Errorf("otlp endpoint %s failed with grpc status %d", e.host(), code)
}

// Close implements extension.Exporter.
func (e *exporter) Close() error {
	e.client.CloseIdleConnections()
	return nil
}
