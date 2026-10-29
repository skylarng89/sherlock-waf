package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runHealthcheck(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newHealthcheckCommand()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(t.Context())
	return out.String(), err
}

func TestHealthcheck(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")

	out, err := runHealthcheck(t, "--listen", addr)
	require.NoError(t, err)
	assert.Equal(t, "ready\n", out)

	status = http.StatusServiceUnavailable
	_, err = runHealthcheck(t, "--listen", addr)
	assert.ErrorContains(t, err, "not ready")

	_, err = runHealthcheck(t, "--listen", "203.0.113.5:9443")
	assert.ErrorContains(t, err, "only probes the local node")
}
