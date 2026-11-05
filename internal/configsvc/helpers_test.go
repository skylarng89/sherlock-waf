package configsvc

import (
	"fmt"
	"math/rand/v2"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/store"
)

func newEnvNow() time.Time { return time.Now().UTC() }

// pgStore opens the PostgreSQL test database in an isolated schema.
func pgStore(t *testing.T, dsn string) store.Store {
	t.Helper()
	schema := fmt.Sprintf("t_%x", rand.Uint64()) //nolint:gosec // unique test schema name
	admin, err := store.Open(t.Context(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	require.NoError(t, execPG(t, dsn, "CREATE SCHEMA "+schema))
	t.Cleanup(func() { _ = execPG(t, dsn, "DROP SCHEMA "+schema+" CASCADE") })
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	s, err := store.Open(t.Context(), u.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}
