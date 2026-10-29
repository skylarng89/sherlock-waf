package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/config"
)

// remote talks to a running node's API with a bearer token. A self-signed
// control-plane certificate is trusted only by pinning its public-key hash,
// which the server logs at start-up, never by switching verification off.
type remote struct {
	base  string
	token string
	hc    *http.Client
}

func newRemote(server, token, pin string) (*remote, error) {
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("--server must be an https URL, got %q", server)
	}
	if token == "" {
		return nil, errors.New("--token is required with --server")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin != "" {
		want := strings.ToLower(strings.ReplaceAll(pin, ":", ""))
		tc.InsecureSkipVerify = true //nolint:gosec // replaced by the SPKI pin check below
		// VerifyConnection (not VerifyPeerCertificate) so the pin is also enforced on resumed sessions.
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server presented no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if hex.EncodeToString(sum[:]) != want {
				return errors.New("server certificate does not match --tls-pin")
			}
			return nil
		}
	}
	return &remote{
		base: strings.TrimRight(server, "/") + "/api/v1", token: token,
		hc: &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}},
	}, nil
}

func (r *remote) do(ctx context.Context, method, path string, body []byte, hdr map[string]string) (int, http.Header, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.base+path, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := r.hc.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("calling %s %s: %w", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	return res.StatusCode, res.Header, b, err
}

// problemError renders a problem+json body for the terminal.
func problemError(status int, body []byte) error {
	var p struct {
		Title  string         `json:"title"`
		Detail string         `json:"detail"`
		Errors []config.Error `json:"errors"`
	}
	if json.Unmarshal(body, &p) != nil || p.Title == "" {
		return fmt.Errorf("server answered %d", status)
	}
	msg := fmt.Sprintf("%s (%d): %s", p.Title, status, p.Detail)
	for _, e := range p.Errors {
		msg += fmt.Sprintf("\n  %s: %s", e.Path, e.Message)
	}
	return errors.New(msg)
}

// exportConfig returns the live configuration and its ETag.
func (r *remote) exportConfig(ctx context.Context) (*config.Root, string, error) {
	status, hdr, body, err := r.do(ctx, http.MethodGet, "/config", nil, nil)
	if err != nil {
		return nil, "", err
	}
	if status == http.StatusNotFound {
		return nil, "", nil
	}
	if status != http.StatusOK {
		return nil, "", problemError(status, body)
	}
	root, err := config.FromSnapshot(body)
	return root, hdr.Get("ETag"), err
}

// putConfig replaces the configuration. etag may be empty only on a node that has none.
func (r *remote) putConfig(ctx context.Context, root *config.Root, etag string) (string, error) {
	body, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("encoding configuration: %w", err)
	}
	hdr := map[string]string{}
	if etag != "" {
		hdr["If-Match"] = etag
	}
	status, h, resp, err := r.do(ctx, http.MethodPut, "/config", body, hdr)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", problemError(status, resp)
	}
	return h.Get("ETag"), nil
}
