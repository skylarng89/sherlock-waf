// Package syslog exports records as RFC 5424 syslog messages over UDP, TCP or
// TLS, with a CEF or JSON payload.
package syslog

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/skylarng89/sherlock-waf/internal/exporters/format"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// UDPMaxMessage caps one UDP datagram's message. RFC 5424 asks receivers to
// handle 2048 bytes; 8192 stays under common MTU-fragmented limits while
// keeping most CEF lines whole. Longer messages are cut on a rune boundary.
const UDPMaxMessage = 8192

const (
	dialTimeout   = 10 * time.Second
	writeTimeout  = 10 * time.Second
	defaultFacil  = 16 // local0
	maxFacility   = 23
	maxAppName    = 48
	maxHostname   = 255
	syslogVersion = "1"
)

// Type builds syslog exporters. Version is the Sherlock version in CEF headers.
type Type struct{ Version string }

// Name implements extension.ExporterType.
func (Type) Name() string { return "syslog" }

type tlsSettings struct {
	CAPEM         string `json:"ca_pem"`
	ServerName    string `json:"server_name"`
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
}

type settings struct {
	Network  string      `json:"network"`
	Address  string      `json:"address"`
	Format   string      `json:"format"`
	Facility *int        `json:"facility"`
	AppName  string      `json:"app_name"`
	Hostname string      `json:"hostname"`
	Framing  string      `json:"framing"`
	TLS      tlsSettings `json:"tls"`
}

type config struct {
	settings
	facility int
	tlsConf  *tls.Config
}

func parse(raw json.RawMessage) (config, error) {
	var s settings
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return config{}, fmt.Errorf("syslog settings: %w", err)
	}
	c := config{settings: s, facility: defaultFacil}
	switch s.Network {
	case "udp", "tcp", "tls":
	default:
		return c, errors.New("syslog: network must be udp, tcp or tls")
	}
	host, port, err := net.SplitHostPort(s.Address)
	if err != nil || host == "" {
		return c, errors.New("syslog: address must be host:port")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return c, errors.New("syslog: address port must be 1-65535")
	}
	switch s.Format {
	case "":
		c.Format = "cef"
	case "cef", "json":
	default:
		return c, errors.New("syslog: format must be cef or json")
	}
	if s.Facility != nil {
		if *s.Facility < 0 || *s.Facility > maxFacility {
			return c, errors.New("syslog: facility must be 0-23")
		}
		c.facility = *s.Facility
	}
	if c.AppName == "" {
		c.AppName = "sherlock"
	}
	if !headerToken(c.AppName, maxAppName) {
		return c, errors.New("syslog: app_name must be 1-48 printable ASCII characters without spaces")
	}
	if c.Hostname != "" && !headerToken(c.Hostname, maxHostname) {
		return c, errors.New("syslog: hostname must be printable ASCII without spaces")
	}
	switch {
	case s.Framing == "" && s.Network != "udp":
		c.Framing = "octet"
	case s.Framing != "" && s.Network == "udp":
		return c, errors.New("syslog: framing applies to tcp and tls only")
	case s.Framing != "" && s.Framing != "octet" && s.Framing != "newline":
		return c, errors.New("syslog: framing must be octet or newline")
	}
	if s.Network == "tls" {
		if c.tlsConf, err = tlsConfig(s.TLS, host); err != nil {
			return c, err
		}
	} else if s.TLS != (tlsSettings{}) {
		return c, errors.New("syslog: tls settings apply to network tls only")
	}
	return c, nil
}

// headerToken reports whether s is usable as an RFC 5424 HOSTNAME or APP-NAME
// (PRINTUSASCII, no space).
func headerToken(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

func tlsConfig(t tlsSettings, host string) (*tls.Config, error) {
	conf := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if t.ServerName != "" {
		conf.ServerName = t.ServerName
	}
	if t.CAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(t.CAPEM)) {
			return nil, errors.New("syslog: tls.ca_pem holds no certificate")
		}
		conf.RootCAs = pool
	}
	if (t.ClientCertPEM == "") != (t.ClientKeyPEM == "") {
		return nil, errors.New("syslog: tls.client_cert_pem and tls.client_key_pem go together")
	}
	if t.ClientCertPEM != "" {
		pair, err := tls.X509KeyPair([]byte(t.ClientCertPEM), []byte(t.ClientKeyPEM))
		if err != nil {
			return nil, errors.New("syslog: tls client certificate and key do not match or are not valid PEM")
		}
		conf.Certificates = []tls.Certificate{pair}
	}
	return conf, nil
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
	if c.Hostname == "" {
		c.Hostname = "-"
		if h, err := os.Hostname(); err == nil && headerToken(h, maxHostname) {
			c.Hostname = h
		}
	}
	return &exporter{cfg: c, version: t.Version}, nil
}

type exporter struct {
	cfg     config
	version string

	mu   sync.Mutex
	conn net.Conn
}

var (
	_ extension.Exporter       = (*exporter)(nil)
	_ extension.ExporterTester = (*exporter)(nil)
)

// Send implements extension.Exporter. A record that cannot be rendered is
// skipped: retrying it would never succeed and would block everything behind it.
func (e *exporter) Send(ctx context.Context, batch []extension.ExportRecord) error {
	msgs := make([][]byte, 0, len(batch))
	for _, rec := range batch {
		if m, err := e.render(rec); err == nil {
			msgs = append(msgs, m)
		}
	}
	return e.write(ctx, msgs)
}

// Test implements extension.ExporterTester. UDP cannot confirm delivery; for
// TCP and TLS a successful connect and write is a real check.
func (e *exporter) Test(ctx context.Context) error {
	msg := e.frame5424(time.Now(), 6, "test", "Sherlock exporter connectivity test")
	return e.write(ctx, [][]byte{msg})
}

func (e *exporter) render(rec extension.ExportRecord) ([]byte, error) {
	var payload string
	if e.cfg.Format == "json" {
		var buf bytes.Buffer
		if err := json.Compact(&buf, rec.Body); err != nil {
			return nil, err
		}
		payload = buf.String()
	} else {
		line, err := format.CEF(rec, e.version)
		if err != nil {
			return nil, err
		}
		payload = line
	}
	at := rec.At
	if at.IsZero() {
		at = time.Now()
	}
	msgID := "event"
	if rec.Stream == extension.StreamAudit {
		msgID = "audit"
	}
	return e.frame5424(at, format.SyslogSeverity(rec), msgID, payload), nil
}

// frame5424 builds the message without transport framing.
func (e *exporter) frame5424(at time.Time, severity int, msgID, payload string) []byte {
	pri := e.cfg.facility*8 + severity
	// Line breaks would end the message early on newline framing and in many
	// collectors; both payload formats already escape them.
	payload = strings.NewReplacer("\r", " ", "\n", " ").Replace(payload)
	msg := "<" + strconv.Itoa(pri) + ">" + syslogVersion + " " +
		at.UTC().Format("2006-01-02T15:04:05.000000Z") + " " + e.cfg.Hostname + " " + e.cfg.AppName + " - " + msgID + " - " + payload
	return []byte(msg)
}

func (e *exporter) write(ctx context.Context, msgs [][]byte) error {
	if len(msgs) == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn != nil && e.cfg.Network != "udp" && !alive(e.conn) {
		_ = e.conn.Close()
		e.conn = nil
	}
	if e.conn == nil {
		conn, err := e.dial(ctx)
		if err != nil {
			return fmt.Errorf("connecting to syslog %s: %w", e.cfg.Address, err)
		}
		e.conn = conn
	}
	deadline := time.Now().Add(writeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = e.conn.SetWriteDeadline(deadline)
	// Cancellation without a deadline must also interrupt a blocked write.
	stop := context.AfterFunc(ctx, func() { _ = e.conn.SetWriteDeadline(time.Now()) })
	defer stop()

	var err error
	if e.cfg.Network == "udp" {
		for _, m := range msgs {
			if _, err = e.conn.Write(truncate(m, UDPMaxMessage)); err != nil {
				break
			}
		}
	} else {
		var buf bytes.Buffer
		for _, m := range msgs {
			if e.cfg.Framing == "newline" {
				buf.Write(m)
				buf.WriteByte('\n')
			} else {
				buf.WriteString(strconv.Itoa(len(m)))
				buf.WriteByte(' ')
				buf.Write(m)
			}
		}
		_, err = e.conn.Write(buf.Bytes())
	}
	if err != nil {
		_ = e.conn.Close()
		e.conn = nil // reconnect on the next attempt
		return fmt.Errorf("writing to syslog %s: %w", e.cfg.Address, err)
	}
	return nil
}

// alive detects a connection the peer has already closed. A write to such a
// connection usually succeeds once before failing, which would silently lose a
// batch the spool believes was delivered.
func alive(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(time.Millisecond))
	var b [1]byte
	_, err := c.Read(b[:])
	_ = c.SetReadDeadline(time.Time{})
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (e *exporter) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout}
	if e.cfg.Network == "tls" {
		return (&tls.Dialer{NetDialer: d, Config: e.cfg.tlsConf}).DialContext(ctx, "tcp", e.cfg.Address)
	}
	return d.DialContext(ctx, e.cfg.Network, e.cfg.Address)
}

// truncate cuts msg to at most limit bytes without splitting a UTF-8 sequence.
func truncate(msg []byte, limit int) []byte {
	if len(msg) <= limit {
		return msg
	}
	n := limit
	for n > 0 && !utf8.RuneStart(msg[n]) {
		n--
	}
	return msg[:n]
}

// Close implements extension.Exporter.
func (e *exporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn == nil {
		return nil
	}
	err := e.conn.Close()
	e.conn = nil
	return err
}
