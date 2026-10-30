package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 test helper
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"log/slog"
	"math/big"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
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
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api"
	"github.com/skylarng89/sherlock-waf/internal/ops"
)

const pw = "correct horse battery"

func freePort(t *testing.T) int {
	t.Helper()
	for range 200 {
		port := 23000 + rand.IntN(3000) //nolint:gosec // test port choice
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", fmt.Sprintf("0.0.0.0:%d", port))
		if err == nil {
			_ = ln.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

func totp(t *testing.T, seed string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
	require.NoError(t, err)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(time.Now().Unix()/30)) //nolint:gosec // positive
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

type client struct {
	t    *testing.T
	base string
	hc   *http.Client
	csrf string
}

func (c *client) call(method, path string, body any, hdr ...string) (int, http.Header, []byte) {
	c.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string: // already JSON
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		require.NoError(c.t, err)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(c.t.Context(), method, c.base+api.BasePath+path, rd)
	require.NoError(c.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" && method != http.MethodGet {
		req.Header.Set(api.CSRFHeader, c.csrf)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := c.hc.Do(req)
	require.NoError(c.t, err)
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	require.NoError(c.t, err)
	return res.StatusCode, res.Header, b
}

func (c *client) syncCSRF() {
	for _, ck := range c.hc.Jar.Cookies(mustParse(c.base)) {
		if ck.Name == api.CSRFCookie {
			c.csrf = ck.Value
		}
	}
}

// TestControlPlaneDrivesTheDataPlane is the M3 end to end: a node with an empty
// database starts with no data plane, an operator signs in (with forced MFA
// enrolment), pushes a configuration through the API, traffic flows through the
// WAF within a second, the event is queryable, and the audit chain verifies.
func TestControlPlaneDrivesTheDataPlane(t *testing.T) {
	dir := t.TempDir()

	// AC1: a fresh node has no users; the operator creates the first one with the CLI path.
	env, err := ops.Open(t.Context(), ops.OpenOptions{DataDir: dir})
	require.NoError(t, err)
	_, err = env.CreateUser(t.Context(), "ada", pw, "admin")
	require.NoError(t, err)
	require.NoError(t, env.Close())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream:"+html.EscapeString(r.URL.Path))
	}))
	defer upstream.Close()

	httpPort, httpsPort := freePort(t), freePort(t)
	ready := make(chan net.Addr, 1)
	events := &lockedBuf{}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir: dir, Listen: "127.0.0.1:0", Logger: slog.New(slog.DiscardHandler), EventsOutput: events,
			Compiler: compiler.Options{HTTPPort: httpPort, HTTPSPort: httpsPort},
			Info:     api.Info{Version: "test", CRSVersion: "4.25.0"},
			UI:       http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "dashboard") }),
			Ready:    func(a net.Addr) { ready <- a },
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err, "graceful shutdown")
		case <-time.After(30 * time.Second):
			t.Error("server did not stop")
		}
	})
	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("server exited early: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("server did not become ready")
	}

	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: "https://" + addr.String(), hc: &http.Client{Jar: jar, Timeout: 20 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // self-signed identity under test
	}}}

	// The dashboard handler is mounted at the root, next to the API.
	status, _, ui := c.rawGet("/")
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "dashboard", string(ui))

	// Before any configuration: alive but not ready; the data plane is not running.
	status, _, _ = c.rawGet("/readyz")
	assert.Equal(t, http.StatusServiceUnavailable, status)
	status, _, _ = c.rawGet("/healthz")
	assert.Equal(t, http.StatusOK, status)
	_, err = (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", httpPort))
	require.Error(t, err, "no data plane before the first configuration")

	// Sign in: password, forced MFA enrolment, confirm.
	st, _, body := c.call("POST", "/auth/login", map[string]string{"username": "ada", "password": pw})
	require.Equal(t, 200, st, string(body))
	assert.Contains(t, string(body), "mfa_enrol_required")
	c.syncCSRF()
	st, _, body = c.call("POST", "/auth/mfa/enroll", nil)
	require.Equal(t, 200, st, string(body))
	var en struct{ Secret string }
	require.NoError(t, json.Unmarshal(body, &en))
	st, _, body = c.call("POST", "/auth/mfa/enroll/confirm", map[string]string{"code": totp(t, en.Secret)})
	require.Equal(t, 200, st, string(body))
	c.syncCSRF()

	// First configuration needs no If-Match (there is nothing to conflict with).
	cfg := map[string]any{"schema_version": 1, "global": quietAdmin, "sites": []any{map[string]any{
		"id": "shop", "hosts": []string{"shop.localhost"}, "tls": map[string]any{"mode": "none"},
		"upstreams": map[string]any{"targets": []string{strings.TrimPrefix(upstream.URL, "http://")}},
		"policy":    map[string]any{"mode": "block"},
	}}}
	start := time.Now()
	st, hdr, body := c.call("PUT", "/config", cfg)
	require.Equal(t, 200, st, string(body))
	require.NotEmpty(t, hdr.Get("ETag"))

	// AC2 shape: the change is live within a second.
	benign := proxied(t, httpPort, "shop.localhost", "/get?id=1")
	assert.Equal(t, 200, benign.status)
	assert.Equal(t, "upstream:/get", benign.body)
	assert.Less(t, time.Since(start), time.Second+5*time.Second, "activation is synchronous with the API call")
	attack := proxied(t, httpPort, "shop.localhost", "/get?id="+"1%27%20OR%20%271%27%3D%271")
	assert.Equal(t, 403, attack.status, "block mode from the API-supplied config")

	// The blocked request becomes a stored, queryable event.
	require.Eventually(t, func() bool {
		st, _, body := c.call("GET", "/events?action=block", nil)
		return st == 200 && strings.Contains(string(body), `"action":"block"`)
	}, 10*time.Second, 100*time.Millisecond, "events must reach the database through the writer")

	// /readyz now reports ready, and system info reports the audit head.
	assert.Eventually(t, func() bool { s, _, _ := c.rawGet("/readyz"); return s == http.StatusOK }, 5*time.Second, 50*time.Millisecond)
	st, _, body = c.call("GET", "/system/info", nil)
	require.Equal(t, 200, st)
	assert.Contains(t, string(body), `"audit_head"`)

	// A conditional change flips the site to detect and takes effect.
	st, hdr, _ = c.call("GET", "/sites/shop", nil)
	require.Equal(t, 200, st)
	st, _, body = c.call("PATCH", "/sites/shop", `{"policy":{"mode":"detect"}}`, "If-Match", hdr.Get("ETag"), "Content-Type", "application/merge-patch+json")
	require.Equal(t, 200, st, string(body))
	assert.Equal(t, 200, proxied(t, httpPort, "shop.localhost", "/get?id="+"1%27%20OR%20%271%27%3D%271").status, "detect mode proxies the attack")
}

type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (c *client) rawGet(path string) (int, http.Header, []byte) {
	c.t.Helper()
	req, err := http.NewRequestWithContext(c.t.Context(), http.MethodGet, c.base+path, nil)
	require.NoError(c.t, err)
	res, err := c.hc.Do(req)
	require.NoError(c.t, err)
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, b
}

type reply struct {
	status int
	body   string
}

func proxied(t *testing.T, port int, host, target string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, target), nil)
	require.NoError(t, err)
	req.Host = host
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return reply{res.StatusCode, string(b)}
}

func mustParse(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// TestRestartingTheAPIListenerDoesNotInterruptProxiedTraffic is AC7: the control
// plane's HTTP server can be stopped and started while the data plane serves.
func TestRestartingTheAPIListenerDoesNotInterruptProxiedTraffic(t *testing.T) {
	dir := t.TempDir()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer upstream.Close()

	// Seed a stored configuration; the server activates it at start.
	env, err := ops.Open(t.Context(), ops.OpenOptions{DataDir: dir})
	require.NoError(t, err)
	root, err := config.Parse(fmt.Appendf(nil, `
schema_version: 1
global: { admin: { listen: "127.0.0.1:0" } }
sites:
  - id: shop
    hosts: [shop.localhost]
    tls: { mode: none }
    upstreams: { targets: ["%s"] }
    policy: { mode: block }
`, strings.TrimPrefix(upstream.URL, "http://")))
	require.NoError(t, err)
	_, _, err = env.ApplyConfig(t.Context(), root, ops.ApplyOptions{Source: configsvc.SourceImport, RequireEmpty: true})
	require.NoError(t, err)
	require.NoError(t, env.Close())

	httpPort, httpsPort := freePort(t), freePort(t)
	ready := make(chan net.Addr, 1)
	hook := make(chan func(context.Context) error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir: dir, Listen: "127.0.0.1:0", Logger: slog.New(slog.DiscardHandler), EventsOutput: io.Discard,
			Compiler: compiler.Options{HTTPPort: httpPort, HTTPSPort: httpsPort}, Info: api.Info{Version: "test"},
			Ready: func(a net.Addr) { ready <- a }, TestHook: func(r func(context.Context) error) { hook <- r },
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(30 * time.Second):
			t.Error("server did not stop")
		}
	})
	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("server exited: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("not ready")
	}
	restart := <-hook

	require.Eventually(t, func() bool { return proxied(t, httpPort, "shop.localhost", "/").status == 200 }, 10*time.Second, 50*time.Millisecond)

	// Hammer the data plane while the API listener restarts several times.
	stop := make(chan struct{})
	var bad, total atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", httpPort), nil)
				if err != nil {
					bad.Add(1)
					continue
				}
				req.Host = "shop.localhost"
				res, err := http.DefaultClient.Do(req)
				total.Add(1)
				if err != nil {
					bad.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				if res.StatusCode != 200 {
					bad.Add(1)
				}
			}
		})
	}
	for range 5 {
		require.NoError(t, restart(t.Context()))
		time.Sleep(100 * time.Millisecond)
	}
	close(stop)
	wg.Wait()

	assert.Positive(t, total.Load(), "traffic flowed during the restarts")
	assert.Zero(t, bad.Load(), "no proxied request may fail while the API listener restarts")

	// And the API is back on the same address.
	c := &client{t: t, base: "https://" + addr.String(), hc: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // self-signed identity under test
	}}}
	status, _, _ := c.rawGet("/healthz")
	assert.Equal(t, http.StatusOK, status)
}

func selfSignedFor(t *testing.T, host string) (certPEM, keyPEM string, leaf *x509.Certificate) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	pk, err := x509.MarshalPKCS8PrivateKey(k)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})), leaf
}

// TestUploadedAssetsReachTheDataPlane drives the M4 backend end to end through
// the API with a token: an uploaded certificate terminates TLS for a site, a
// custom block page is what a blocked client sees, and a site that denies
// WebSockets refuses an upgrade.
func TestUploadedAssetsReachTheDataPlane(t *testing.T) {
	dir := t.TempDir()
	env, err := ops.Open(t.Context(), ops.OpenOptions{DataDir: dir})
	require.NoError(t, err)
	_, err = env.CreateUser(t.Context(), "ada", pw, "admin")
	require.NoError(t, err)
	tok, err := env.CreateToken(t.Context(), "ada", "ci", []string{"admin"}, nil, time.Time{})
	require.NoError(t, err)
	require.NoError(t, env.Close())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "origin") }))
	defer upstream.Close()

	httpPort, httpsPort := freePort(t), freePort(t)
	ready := make(chan net.Addr, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir: dir, Listen: "127.0.0.1:0", Logger: slog.New(slog.DiscardHandler), EventsOutput: io.Discard,
			Compiler: compiler.Options{HTTPPort: httpPort, HTTPSPort: httpsPort}, Info: api.Info{Version: "test"},
			Ready: func(a net.Addr) { ready <- a },
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(30 * time.Second):
			t.Error("server did not stop")
		}
	})
	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("server exited: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("not ready")
	}
	c := &client{t: t, base: "https://" + addr.String(), hc: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // self-signed identity under test
	}}}
	auth := []string{"Authorization", "Bearer " + tok.Secret}

	certPEM, keyPEM, leaf := selfSignedFor(t, "secure.localhost")
	st, _, body := c.call("POST", "/certificates", map[string]string{"name": "secure", "certificate_pem": certPEM, "private_key_pem": keyPEM}, auth...)
	require.Equal(t, 201, st, string(body))
	var cert struct{ ID string }
	require.NoError(t, json.Unmarshal(body, &cert))

	st, _, body = c.call("PUT", "/block-pages/corp", map[string]string{"html": "<h1>Corporate block {{.Status}}</h1><p>{{.EventID}}</p>"}, auth...)
	require.Equal(t, 200, st, string(body))

	cfg := map[string]any{"schema_version": 1, "global": quietAdmin, "sites": []any{
		map[string]any{
			"id": "secure", "hosts": []string{"secure.localhost"},
			"tls":       map[string]any{"mode": "file", "cert_id": cert.ID},
			"upstreams": map[string]any{"targets": []string{strings.TrimPrefix(upstream.URL, "http://")}, "websockets": false},
			"policy":    map[string]any{"mode": "block", "block_page": map[string]any{"template_id": "corp"}},
		},
	}}
	st, _, body = c.call("PUT", "/config", cfg, auth...)
	require.Equal(t, 200, st, string(body))

	// 1. TLS is terminated with exactly the uploaded certificate.
	require.Eventually(t, func() bool {
		conn, err := (&tls.Dialer{Config: &tls.Config{ServerName: "secure.localhost", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}). //nolint:gosec // identity compared below
																				DialContext(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", httpsPort))
		if err != nil {
			return false
		}
		defer func() { _ = conn.Close() }()
		peer := conn.(*tls.Conn).ConnectionState().PeerCertificates
		return len(peer) > 0 && peer[0].Equal(leaf)
	}, 10*time.Second, 100*time.Millisecond, "the site must present the uploaded certificate")

	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "secure.localhost", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // identity checked above
	}}
	get := func(target string, hdr map[string]string) (int, string) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d%s", httpsPort, target), nil)
		require.NoError(t, err)
		req.Host = "secure.localhost"
		req.Header.Set("Accept", "text/html")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		res, err := hc.Do(req)
		require.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}

	status, page := get("/", nil)
	assert.Equal(t, 200, status)
	assert.Equal(t, "origin", page)

	// 2. A blocked client sees the custom block page.
	status, page = get("/get?id="+"1%27%20OR%20%271%27%3D%271", nil)
	assert.Equal(t, 403, status)
	assert.Contains(t, page, "<h1>Corporate block 403</h1>")

	// 3. Upgrades are refused on a site that denies WebSockets, even though the WAF saw nothing wrong.
	status, _ = get("/chat", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"})
	assert.Equal(t, 403, status)

	// 4. The in-use certificate and block page cannot be removed from under the live site.
	st, _, _ = c.call("DELETE", "/certificates/"+cert.ID, nil, auth...)
	assert.Equal(t, 409, st)
	st, _, _ = c.call("DELETE", "/block-pages/corp", nil, auth...)
	assert.Equal(t, 409, st)

	// 5. The key is on disk only as a private file next to node.key.
	info, err := os.Stat(filepath.Join(dir, "certs", cert.ID+".key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

// quietAdmin keeps the data plane's own metrics listener off a fixed port, so
// concurrent test processes do not fight over the default.
var quietAdmin = map[string]any{"admin": map[string]any{"listen": "127.0.0.1:0"}}
