package notify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/netip"
	"net/smtp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/netx"
)

const (
	maxRecipients  = 20
	defaultTimeout = 15
	maxTimeout     = 60
)

// SMTP transport security.
const (
	SecurityStartTLS = "starttls"
	SecurityTLS      = "tls"
	SecurityNone     = "none"
)

type smtpSettings struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Security       string   `json:"security"`
	AllowInsecure  bool     `json:"allow_insecure"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	From           string   `json:"from"`
	To             []string `json:"to"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}

type smtpSender struct {
	s       smtpSettings
	from    *mail.Address
	to      []*mail.Address
	timeout time.Duration
}

func newSMTP(raw json.RawMessage) (Sender, error) {
	var s smtpSettings
	if err := decodeStrict(raw, &s); err != nil {
		return nil, err
	}
	if s.Security == "" {
		s.Security = SecurityStartTLS
	}
	switch s.Security {
	case SecurityStartTLS, SecurityTLS:
	case SecurityNone:
		if !s.AllowInsecure {
			return nil, fmt.Errorf("%w: security \"none\" sends mail in clear text; set allow_insecure to accept that", ErrInvalid)
		}
	default:
		return nil, fmt.Errorf("%w: security must be starttls, tls or none", ErrInvalid)
	}
	if s.Port == 0 {
		s.Port = map[string]int{SecurityStartTLS: 587, SecurityTLS: 465, SecurityNone: 25}[s.Security]
	}
	if s.Port < 1 || s.Port > 65535 {
		return nil, fmt.Errorf("%w: port must be 1-65535", ErrInvalid)
	}
	if s.Host == "" || len(s.Host) > 253 || strings.ContainsAny(s.Host, " \r\n\x00/@") {
		return nil, fmt.Errorf("%w: host is required", ErrInvalid)
	}
	if (s.Username != "" || s.Password != "") && s.Security == SecurityNone {
		return nil, fmt.Errorf("%w: authentication needs tls or starttls; credentials are never sent in clear text", ErrInvalid)
	}
	if strings.ContainsAny(s.Username+s.Password, "\r\n\x00") {
		return nil, fmt.Errorf("%w: username and password must not contain control characters", ErrInvalid)
	}
	from, err := parseAddress(s.From)
	if err != nil {
		return nil, fmt.Errorf("%w: from: %s", ErrInvalid, err)
	}
	if len(s.To) == 0 || len(s.To) > maxRecipients {
		return nil, fmt.Errorf("%w: to needs 1-%d recipients", ErrInvalid, maxRecipients)
	}
	to := make([]*mail.Address, 0, len(s.To))
	for _, a := range s.To {
		addr, err := parseAddress(a)
		if err != nil {
			return nil, fmt.Errorf("%w: to: %s", ErrInvalid, err)
		}
		to = append(to, addr)
	}
	if s.TimeoutSeconds == 0 {
		s.TimeoutSeconds = defaultTimeout
	}
	if s.TimeoutSeconds < 1 || s.TimeoutSeconds > maxTimeout {
		return nil, fmt.Errorf("%w: timeout_seconds must be 1-%d", ErrInvalid, maxTimeout)
	}
	return &smtpSender{s: s, from: from, to: to, timeout: time.Duration(s.TimeoutSeconds) * time.Second}, nil
}

// parseAddress rejects anything that could smuggle a header or an SMTP command:
// control characters are refused before parsing, and the parsed form must be a
// single address.
func parseAddress(raw string) (*mail.Address, error) {
	if raw == "" || len(raw) > 320 {
		return nil, fmt.Errorf("an email address is required")
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return nil, fmt.Errorf("address contains a control character")
		}
	}
	a, err := mail.ParseAddress(raw)
	if err != nil {
		return nil, fmt.Errorf("not a valid address")
	}
	if strings.ContainsAny(a.Address, "<>,;\"") {
		return nil, fmt.Errorf("not a valid address")
	}
	return a, nil
}

func (s *smtpSender) Send(ctx context.Context, m Message) error {
	n := normalise(m)
	msg := s.compose(n)
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	conn, err := s.dial(ctx)
	if err != nil {
		return fmt.Errorf("smtp channel %s: connecting: %w", s.s.Host, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	c, err := smtp.NewClient(conn, s.s.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp channel %s: greeting: %w", s.s.Host, err)
	}
	defer c.Close()

	if s.s.Security == SecurityStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp channel %s: server does not offer STARTTLS", s.s.Host)
		}
		if err := c.StartTLS(s.tlsConfig()); err != nil {
			return fmt.Errorf("smtp channel %s: starttls: %w", s.s.Host, err)
		}
	}
	if s.s.Username != "" {
		// The connection is TLS here, so PLAIN is safe; net/smtp also refuses it otherwise.
		if err := c.Auth(smtp.PlainAuth("", s.s.Username, s.s.Password, s.s.Host)); err != nil {
			return fmt.Errorf("smtp channel %s: authentication failed", s.s.Host)
		}
	}
	if err := c.Mail(s.from.Address); err != nil {
		return fmt.Errorf("smtp channel %s: sender refused: %w", s.s.Host, err)
	}
	for _, r := range s.to {
		if err := c.Rcpt(r.Address); err != nil {
			return fmt.Errorf("smtp channel %s: recipient refused: %w", s.s.Host, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp channel %s: data: %w", s.s.Host, err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp channel %s: writing message: %w", s.s.Host, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp channel %s: message rejected: %w", s.s.Host, err)
	}
	_ = c.Quit()
	return nil
}

func (s *smtpSender) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: s.s.Host, MinVersion: tls.VersionTLS12}
}

func (s *smtpSender) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: s.timeout,
		// Private relays are normal; link-local (cloud metadata) is not.
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || netx.Blocked(ap.Addr(), true) {
				return netx.ErrBlockedAddress
			}
			return nil
		},
	}
	addr := net.JoinHostPort(s.s.Host, strconv.Itoa(s.s.Port))
	if s.s.Security == SecurityTLS {
		return (&tls.Dialer{NetDialer: d, Config: s.tlsConfig()}).DialContext(ctx, "tcp", addr)
	}
	return d.DialContext(ctx, "tcp", addr)
}

// compose builds the RFC 5322 message. Every header value is built from
// validated addresses or from text with control characters already removed, and
// the subject is MIME-encoded, so no field can add a header line.
func (s *smtpSender) compose(n normalised) []byte {
	var b strings.Builder
	tos := make([]string, len(s.to))
	for i, a := range s.to {
		tos[i] = a.String()
	}
	subject := "[Sherlock " + strings.ToUpper(n.Severity) + "] " + n.Title
	b.WriteString("From: " + s.from.String() + "\r\n")
	b.WriteString("To: " + strings.Join(tos, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("Date: " + n.At.Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n\r\n")

	var text strings.Builder
	text.WriteString(n.Title + "\r\n")
	if n.Body != "" {
		text.WriteString("\r\n" + strings.ReplaceAll(n.Body, "\n", "\r\n") + "\r\n")
	}
	if n.RuleName != "" {
		text.WriteString("\r\nRule: " + n.RuleName + "\r\n")
	}
	for _, f := range n.Fields {
		text.WriteString(f.Key + ": " + f.Value + "\r\n")
	}
	enc := base64.StdEncoding.EncodeToString([]byte(text.String()))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return []byte(b.String())
}
