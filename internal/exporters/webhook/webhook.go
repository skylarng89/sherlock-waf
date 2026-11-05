// Package webhook exports records as signed JSON batches over HTTPS.
//
// Request format: POST with Content-Type application/json and the body
//
//	{"schema":"sherlock.export.v1","records":[{"id","stream","at","body"}, ...]}
//
// X-Sherlock-Timestamp carries the Unix time in seconds and X-Sherlock-Signature
// is "sha256=" plus the hex HMAC-SHA256, keyed with hmac_secret, of the string
// "<timestamp>.<body>". Including the timestamp lets a receiver reject replays.
// X-Sherlock-Delivery is a random id per HTTP attempt; deduplicate on the record
// ids instead, because a retried batch is a new delivery.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/netx"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// SchemaV1 is the batch envelope's schema value.
const SchemaV1 = "sherlock.export.v1"

const (
	minSecretBytes = 32
	maxHeaders     = 20
	maxHeaderValue = 4096
	maxRetryAfter  = 5 * time.Minute
	requestTimeout = 30 * time.Second
	drainLimit     = 64 << 10
)

// Type builds webhook exporters. Version goes in the User-Agent.
type Type struct{ Version string }

// Name implements extension.ExporterType.
func (Type) Name() string { return "webhook" }

type settings struct {
	URL        string            `json:"url"`
	HMACSecret string            `json:"hmac_secret"`
	Headers    map[string]string `json:"headers"`
	AllowHTTP  bool              `json:"allow_http"`
	TLS        struct {
		CAPEM string `json:"ca_pem"`
	} `json:"tls"`
}

var headerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)

// reserved headers belong to the exporter; letting a setting override them
// would break signing or framing.
func reserved(name string) bool {
	n := strings.ToLower(name)
	return n == "content-type" || n == "content-length" || n == "host" || n == "user-agent" || strings.HasPrefix(n, "x-sherlock-")
}

func parse(raw json.RawMessage) (settings, *url.URL, error) {
	var s settings
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, nil, fmt.Errorf("webhook settings: %w", err)
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return s, nil, errors.New("webhook: url must be an absolute http(s) URL") // not echoed: it may carry a token
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && s.AllowHTTP:
	case u.Scheme == "http":
		return s, nil, errors.New("webhook: url must use https (set allow_http only for a trusted network)")
	default:
		return s, nil, errors.New("webhook: url scheme must be https")
	}
	if u.User != nil {
		return s, nil, errors.New("webhook: credentials in the url are not accepted; use headers")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && netx.Blocked(ip, true) {
		return s, nil, fmt.Errorf("webhook: destination address %s is not allowed", ip)
	}
	if len(s.HMACSecret) < minSecretBytes {
		return s, nil, fmt.Errorf("webhook: hmac_secret must be at least %d bytes", minSecretBytes)
	}
	if len(s.Headers) > maxHeaders {
		return s, nil, fmt.Errorf("webhook: at most %d custom headers", maxHeaders)
	}
	for k, v := range s.Headers {
		switch {
		case !headerName.MatchString(k):
			return s, nil, errors.New("webhook: invalid header name")
		case reserved(k):
			return s, nil, fmt.Errorf("webhook: header %q is set by Sherlock", k)
		case len(v) > maxHeaderValue || strings.ContainsAny(v, "\r\n\x00"):
			return s, nil, fmt.Errorf("webhook: invalid value for header %q", k)
		}
	}
	if s.TLS.CAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(s.TLS.CAPEM)) {
		return s, nil, errors.New("webhook: tls.ca_pem holds no certificate")
	}
	return s, u, nil
}

// Validate implements extension.ExporterType.
func (Type) Validate(raw json.RawMessage) error {
	_, _, err := parse(raw)
	return err
}

// New implements extension.ExporterType.
func (t Type) New(raw json.RawMessage) (extension.Exporter, error) {
	s, u, err := parse(raw)
	if err != nil {
		return nil, err
	}
	// Loopback and private ranges are allowed because SIEMs are usually internal;
	// netx still refuses link-local (cloud metadata) and unspecified addresses
	// on the address actually dialled.
	client := netx.NewClient(netx.Options{AllowPrivate: true, Timeout: requestTimeout})
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if s.TLS.CAPEM != "" {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(s.TLS.CAPEM))
		if tr, ok := client.Transport.(*http.Transport); ok {
			tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
	}
	return &exporter{s: s, target: u.String(), host: u.Host, client: client, ua: "Sherlock-WAF/" + t.Version, now: time.Now}, nil
}

type exporter struct {
	s      settings
	target string
	host   string // the only part of the URL that may appear in errors
	client *http.Client
	ua     string
	now    func() time.Time

	mu      sync.Mutex
	retryAt time.Time // set from Retry-After
}

var (
	_ extension.Exporter       = (*exporter)(nil)
	_ extension.ExporterTester = (*exporter)(nil)
)

type wireRecord struct {
	ID     string          `json:"id"`
	Stream string          `json:"stream"`
	At     time.Time       `json:"at"`
	Body   json.RawMessage `json:"body"`
}

type envelope struct {
	Schema  string       `json:"schema"`
	Test    bool         `json:"test,omitempty"`
	Records []wireRecord `json:"records"`
}

// Send implements extension.Exporter.
func (e *exporter) Send(ctx context.Context, batch []extension.ExportRecord) error {
	env := envelope{Schema: SchemaV1, Records: make([]wireRecord, 0, len(batch))}
	for _, r := range batch {
		if json.Valid(r.Body) { // an undecodable body can never be delivered; skipping it unblocks the queue
			env.Records = append(env.Records, wireRecord{ID: r.ID, Stream: r.Stream, At: r.At, Body: r.Body})
		}
	}
	if len(env.Records) == 0 {
		return nil
	}
	return e.post(ctx, env)
}

// Test implements extension.ExporterTester: it posts an empty batch flagged
// "test": true, which exercises DNS, TLS, the signature and the receiver's auth.
func (e *exporter) Test(ctx context.Context) error {
	return e.post(ctx, envelope{Schema: SchemaV1, Test: true, Records: []wireRecord{}})
}

func (e *exporter) post(ctx context.Context, env envelope) error {
	e.mu.Lock()
	wait := e.retryAt.Sub(e.now())
	e.mu.Unlock()
	if wait > 0 {
		return fmt.Errorf("webhook %s asked us to retry after %s", e.host, wait.Round(time.Second))
	}
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("encoding webhook batch: %w", err)
	}
	ts := strconv.FormatInt(e.now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(e.s.HMACSecret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	var delivery [16]byte
	_, _ = rand.Read(delivery[:])

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building webhook request for %s: %w", e.host, errors.Unwrap(err))
	}
	for k, v := range e.s.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", e.ua)
	req.Header.Set("X-Sherlock-Timestamp", ts)
	req.Header.Set("X-Sherlock-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Sherlock-Delivery", hex.EncodeToString(delivery[:]))

	res, err := e.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the *url.Error text embeds the full URL
		}
		return fmt.Errorf("posting to webhook %s: %w", e.host, err)
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, drainLimit)) // lets the connection be reused

	switch code := res.StatusCode; {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500:
		if d := retryAfter(res.Header.Get("Retry-After"), e.now()); d > 0 {
			e.mu.Lock()
			e.retryAt = e.now().Add(d)
			e.mu.Unlock()
		}
		return fmt.Errorf("webhook %s answered %d", e.host, code)
	default:
		return fmt.Errorf("webhook %s rejected the batch with %d: %w", e.host, code, extension.ErrPermanent)
	}
}

// retryAfter parses a Retry-After header (seconds or HTTP date), capped.
func retryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.Atoi(v); err == nil {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, 0), maxRetryAfter)
}

// Close implements extension.Exporter.
func (e *exporter) Close() error {
	e.client.CloseIdleConnections()
	return nil
}
