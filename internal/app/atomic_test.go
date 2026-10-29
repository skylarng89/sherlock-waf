package app

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/events"
)

// TestRejectedConfigChangesNothingObservable: a configuration that validates
// but that Caddy refuses to load (a TLS certificate file that does not exist)
// must not move the admin listener, swap the event publisher or disturb the
// site that is serving. Before activate was made two-phase, those side effects
// happened before caddy.Load.
func TestRejectedConfigChangesNothingObservable(t *testing.T) {
	up := upstreamServer(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sherlock.yaml")
	good := fmt.Sprintf(`
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
  events: { node_name: before, sinks: { stdout: false, file: false } }
sites:
  - id: shop
    hosts: [shop.localhost]
    tls: { mode: none }
    policy: { mode: block }
    upstreams: { targets: ["%s"] }
`, up)
	require.NoError(t, os.WriteFile(cfgPath, []byte(good), 0o600))

	port := freePort(t)
	a := New(cfgPath, compiler.Options{HTTPPort: port, HTTPSPort: freePort(t), DataDir: filepath.Join(dir, "data")}, nil)
	require.NoError(t, a.Start(t.Context()))
	defer func() { require.NoError(t, a.Stop(t.Context())) }()

	adminBefore := a.AdminAddr().String()
	pubBefore := events.Default()
	require.NotNil(t, pubBefore)

	// Valid YAML, but Caddy cannot load the certificate; it also asks for a new
	// admin address and a different node name.
	bad := fmt.Sprintf(`
schema_version: 1
global:
  admin: { listen: "127.0.0.1:%d" }
  events: { node_name: after, sinks: { stdout: false, file: false } }
sites:
  - id: shop
    hosts: [shop.localhost]
    tls: { mode: none }
    policy: { mode: block }
    upstreams: { targets: ["%s"] }
  - id: secure
    hosts: [secure.localhost]
    tls: { mode: file, cert_file: /nonexistent/cert.pem, key_file: /nonexistent/key.pem }
    upstreams: { targets: ["%s"] }
`, freePort(t), up, up)
	require.NoError(t, os.WriteFile(cfgPath, []byte(bad), 0o600))
	err := a.Reload(t.Context())
	require.Error(t, err, "Caddy must refuse the missing certificate")

	assert.Equal(t, adminBefore, a.AdminAddr().String(), "admin listener must not have moved")
	assert.Same(t, pubBefore, events.Default(), "event publisher must not have been swapped")
	assert.Equal(t, "before", events.Default().Node)

	// The new admin address must not be left bound.
	u := a.admin.Addr().String()
	assert.Equal(t, adminBefore, u)

	// And the old site still serves.
	r := send(t, port, http.MethodGet, "shop.localhost", "/ok", nil)
	assert.Equal(t, http.StatusOK, r.status)
	code, _ := adminGet(t, adminBefore, http.MethodGet, "/readyz")
	assert.Equal(t, http.StatusOK, code)
}

func TestFirstConfigRejectedLeavesNothingRunning(t *testing.T) {
	up := upstreamServer(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sherlock.yaml")
	require.NoError(t, os.WriteFile(cfgPath, fmt.Appendf(nil, `
schema_version: 1
global:
  admin: { listen: "127.0.0.1:0" }
  events: { sinks: { stdout: false, file: true } }
sites:
  - id: secure
    hosts: [secure.localhost]
    tls: { mode: file, cert_file: /nonexistent/cert.pem, key_file: /nonexistent/key.pem }
    upstreams: { targets: ["%s"] }
`, up), 0o600))

	a := New(cfgPath, compiler.Options{HTTPPort: freePort(t), HTTPSPort: freePort(t), DataDir: filepath.Join(dir, "data")}, nil)
	require.Error(t, a.Start(t.Context()))

	assert.Nil(t, a.AdminAddr(), "no admin listener may survive a rejected first config")
	assert.Nil(t, events.Default(), "no publisher may survive a rejected first config")
	assert.False(t, a.ready.Load())
}
