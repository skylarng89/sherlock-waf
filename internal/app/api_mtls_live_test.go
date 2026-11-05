package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/events"
)

const (
	mtlsHost       = "mtls.example.test"
	mtlsCABundleID = "clients-ca"
)

const mtlsConfig = `
schema_version: 1
global:
  admin: { listen: "off" }
  events:
    sinks: { stdout: false }
sites:
  - id: bank
    hosts: [mtls.example.test]
    tls: { mode: file, cert_file: %q, key_file: %q }
    upstreams: { targets: ["%s"] }
    policy:
      mode: block
      rate_limits:
        - { name: per-subject, key: mtls_subject, limit: 2, window: 1m, match: { paths: ["/payments"] } }
      api:
        enabled: true
        mtls:
          ca_cert_id: clients-ca
          required_paths: ["/payments"]
`

// liveTLSApp is a running data plane with an HTTPS listener.
type liveTLSApp struct {
	HTTPS   int
	DataDir string
	stop    func() error
}

// Stop shuts the app down and returns its Run error. It is idempotent, so a
// test can stop early to read the event log and still rely on the cleanup.
func (a *liveTLSApp) Stop() error { return a.stop() }

// launchTLS starts the data plane with CA bundles resolved by cas. The HTTPS
// port is ready when a TCP connection to it succeeds.
func launchTLS(t *testing.T, dir, cfg string, cas func(id string) (string, error)) *liveTLSApp {
	t.Helper()
	path := filepath.Join(dir, "sherlock.yaml")
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0o600))

	httpsPort := freePort(t)
	dataDir := filepath.Join(dir, "data")
	a := New(path, compiler.Options{HTTPPort: freePort(t), HTTPSPort: httpsPort, DataDir: dataDir, CABundles: cas}, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, make(chan os.Signal)) }()

	var once sync.Once
	var runErr error
	stop := func() error {
		once.Do(func() {
			cancel()
			select {
			case runErr = <-done:
			case <-time.After(15 * time.Second):
				runErr = fmt.Errorf("Run did not return after context cancel")
			}
		})
		return runErr
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("app stopped with error: %v", err)
		}
	})
	require.Eventually(t, func() bool {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort))
		if err == nil {
			_ = c.Close()
		}
		return err == nil
	}, 20*time.Second, 50*time.Millisecond)
	return &liveTLSApp{HTTPS: httpsPort, DataDir: dataDir, stop: stop}
}

// mtlsClient dials the local HTTPS listener while presenting SNI and verifying
// the server against serverCAs. Each client has its own transport so client
// certificates never leak between cases.
func mtlsClient(t *testing.T, port int, serverCAs *x509.CertPool, clientCert *tls.Certificate) *http.Client {
	t.Helper()
	cfg := &tls.Config{RootCAs: serverCAs, ServerName: mtlsHost, MinVersion: tls.VersionTLS12} //nolint:gosec // MinVersion 1.2 is the product floor
	if clientCert != nil {
		// Always present the certificate: Go otherwise sends nothing when the
		// server's CA list does not name its issuer, which would hide the
		// handshake failure this helper exists to exercise.
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return clientCert, nil }
	}
	tr := &http.Transport{
		TLSClientConfig:   cfg,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func doHTTPS(t *testing.T, c *http.Client, method, target string) (int, error) {
	t.Helper()
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(`{"amount":1}`)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, "https://"+mtlsHost+target, body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// mtlsRun numbers the invocations in this process. The rate limiter is
// process-wide, so each run needs subjects its buckets have not seen.
var mtlsRun atomic.Int64

// TestAPIMutualTLSLive exercises client certificate enforcement through the
// real Caddy listener: required paths, open paths and untrusted CAs.
func TestAPIMutualTLSLive(t *testing.T) {
	dir := t.TempDir()
	clientsCA := newTestCA(t, "Sherlock test clients")
	rogueCA := newTestCA(t, "Rogue CA")
	serverCert := clientsCA.issue(t, "server", []string{mtlsHost}, x509.ExtKeyUsageServerAuth)
	certPath, keyPath := writeCertFiles(t, dir, serverCert)
	serverCAs := x509.NewCertPool()
	serverCAs.AddCert(clientsCA.cert)

	up := upstreamServer(t)
	cfg := fmt.Sprintf(mtlsConfig, certPath, keyPath, up)
	app := launchTLS(t, dir, cfg, func(id string) (string, error) {
		if id != mtlsCABundleID {
			return "", fmt.Errorf("unknown CA bundle %q", id)
		}
		return clientsCA.pem, nil
	})

	run := mtlsRun.Add(1)
	tppA := clientsCA.issue(t, fmt.Sprintf("tpp-a-%d", run), nil, x509.ExtKeyUsageClientAuth)
	noCert := mtlsClient(t, app.HTTPS, serverCAs, nil)

	t.Run("valid client certificate on a required path reaches the upstream", func(t *testing.T) {
		code, err := doHTTPS(t, mtlsClient(t, app.HTTPS, serverCAs, &tppA), http.MethodPost, "/payments")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, code)
	})

	t.Run("no client certificate on a required path is refused", func(t *testing.T) {
		code, err := doHTTPS(t, noCert, http.MethodPost, "/payments")
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, code)
	})

	t.Run("no client certificate on an open path is allowed", func(t *testing.T) {
		code, err := doHTTPS(t, noCert, http.MethodGet, "/healthz")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, code)
	})

	t.Run("client certificate from an untrusted CA fails the handshake", func(t *testing.T) {
		rogue := rogueCA.issue(t, "intruder", nil, x509.ExtKeyUsageClientAuth)
		_, err := doHTTPS(t, mtlsClient(t, app.HTTPS, serverCAs, &rogue), http.MethodGet, "/healthz")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate")
	})

	t.Run("each client subject has its own rate-limit bucket", func(t *testing.T) {
		tppB := clientsCA.issue(t, fmt.Sprintf("tpp-b-%d", run), nil, x509.ExtKeyUsageClientAuth)
		clientA := mtlsClient(t, app.HTTPS, serverCAs, &tppA)
		clientB := mtlsClient(t, app.HTTPS, serverCAs, &tppB)
		// tpp-a already spent one of its two requests in the valid-cert case.
		code, err := doHTTPS(t, clientA, http.MethodPost, "/payments")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, code, "tpp-a second request")
		code, err = doHTTPS(t, clientA, http.MethodPost, "/payments")
		require.NoError(t, err)
		assert.Equal(t, http.StatusTooManyRequests, code, "tpp-a is over its limit")
		code, err = doHTTPS(t, clientB, http.MethodPost, "/payments")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, code, "tpp-b has its own bucket")
	})

	require.NoError(t, app.Stop())
	evs := readEvents(t, filepath.Join(app.DataDir, "events.jsonl"))
	assert.True(t, hasFinding(evs, "api.mtls"), "the refused request must record finding api.mtls")
}

func hasFinding(evs []events.Event, rule string) bool {
	for _, e := range evs {
		for _, f := range e.Findings {
			if f.RuleID == rule {
				return true
			}
		}
	}
	return false
}
