package cli_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api"
	"github.com/skylarng89/sherlock-waf/internal/ops"
	"github.com/skylarng89/sherlock-waf/internal/server"
)

func freePort(t *testing.T) int {
	t.Helper()
	for range 200 {
		p := 26000 + rand.IntN(3000) //nolint:gosec // test port choice
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", fmt.Sprintf("0.0.0.0:%d", p))
		if err == nil {
			_ = ln.Close()
			return p
		}
	}
	t.Fatal("no free port")
	return 0
}

func spkiPin(t *testing.T, certPath string) string {
	t.Helper()
	raw, err := os.ReadFile(certPath) //nolint:gosec // test path
	require.NoError(t, err)
	blk, _ := pem.Decode(raw)
	require.NotNil(t, blk)
	c, err := x509.ParseCertificate(blk.Bytes)
	require.NoError(t, err)
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// TestConfigImportThroughTheAPIOfARunningNode drives `config import|apply|export
// --server --token --tls-pin` against a real server, which the offline path
// refuses to do (it holds the data dir).
func TestConfigImportThroughTheAPIOfARunningNode(t *testing.T) {
	dir := t.TempDir()
	env, err := ops.Open(t.Context(), ops.OpenOptions{DataDir: dir})
	require.NoError(t, err)
	_, err = env.CreateUser(t.Context(), "ada", pw, "admin")
	require.NoError(t, err)
	ct, err := env.CreateToken(t.Context(), "ada", "ci", []string{"admin"}, nil, time.Time{})
	require.NoError(t, err)
	viewerTok, err := env.CreateToken(t.Context(), "ada", "ro", []string{"read"}, nil, time.Time{})
	require.NoError(t, err)
	require.NoError(t, env.Close())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer upstream.Close()

	httpPort, httpsPort := freePort(t), freePort(t)
	ready := make(chan net.Addr, 1)
	srvCtx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- server.Run(srvCtx, server.Options{
			DataDir: dir, Listen: "127.0.0.1:0", Logger: slog.New(slog.DiscardHandler), EventsOutput: io.Discard,
			Compiler: compiler.Options{HTTPPort: httpPort, HTTPSPort: httpsPort},
			Info:     api.Info{Version: "test"}, Ready: func(a net.Addr) { ready <- a },
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
	pin := spkiPin(t, filepath.Join(dir, "admin-tls.crt"))
	srv := "https://" + addr.String()

	file := filepath.Join(t.TempDir(), "sherlock.yaml")
	require.NoError(t, os.WriteFile(file, []byte(strings.Replace(sample, "127.0.0.1:9", strings.TrimPrefix(upstream.URL, "http://"), 1)), 0o600))

	// Without the pin the self-signed certificate is not trusted.
	r := run(t, dir, "", "config", "import", file, "--server", srv, "--token", ct.Secret)
	require.Error(t, r.err, "an unpinned self-signed certificate must not verify")
	r = run(t, dir, "", "config", "import", file, "--server", srv, "--token", ct.Secret, "--tls-pin", strings.Repeat("ab", 32))
	require.Error(t, r.err, "a wrong pin must not verify")
	assert.Contains(t, r.err.Error(), "tls-pin")

	r = run(t, dir, "", "config", "import", file, "--server", srv, "--token", ct.Secret, "--tls-pin", pin)
	require.NoError(t, r.err, r.errOut)
	assert.Contains(t, r.out, "applied; live version")
	r = run(t, dir, "", "config", "import", file, "--server", srv, "--token", ct.Secret, "--tls-pin", pin)
	assert.ErrorContains(t, r.err, "already has a configuration")

	// A read-only token cannot change configuration, and the refusal is readable.
	r = run(t, dir, "", "config", "apply", file, "--server", srv, "--token", viewerTok.Secret, "--tls-pin", pin)
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "Forbidden")

	r = run(t, dir, "", "config", "apply", file, "--server", srv, "--token", ct.Secret, "--tls-pin", pin, "--expect-version", "01STALE")
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "412")

	r = run(t, dir, "", "config", "export", "--server", srv, "--token", viewerTok.Secret, "--tls-pin", pin)
	require.NoError(t, r.err, r.errOut)
	assert.Contains(t, r.out, "id: shop")
}
