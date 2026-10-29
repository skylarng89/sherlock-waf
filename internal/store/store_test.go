package store_test

import (
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/internal/store/storetest"
)

func TestSQLite(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		s, err := store.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "sherlock.db"))
		require.NoError(t, err)
		assert.Equal(t, store.SQLite, s.Dialect())
		return s
	})
}

func TestSQLiteInMemory(t *testing.T) {
	s, err := store.Open(t.Context(), ":memory:")
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	require.NoError(t, s.Ping(t.Context()))
}

// TestPostgres runs the same suite against PostgreSQL when SHERLOCK_TEST_PG_DSN
// is set, each test in its own schema. CI sets SHERLOCK_REQUIRE_PG=1 so a missing
// database fails the build instead of silently skipping.
func TestPostgres(t *testing.T) {
	dsn := os.Getenv("SHERLOCK_TEST_PG_DSN")
	if dsn == "" {
		if os.Getenv("SHERLOCK_REQUIRE_PG") != "" {
			t.Fatal("SHERLOCK_REQUIRE_PG is set but SHERLOCK_TEST_PG_DSN is not")
		}
		t.Skip("SHERLOCK_TEST_PG_DSN not set; PostgreSQL conformance not run")
	}
	storetest.Run(t, func(t *testing.T) store.Store {
		schema := fmt.Sprintf("t_%x", rand.Uint64()) //nolint:gosec // unique test schema name
		admin, err := store.Open(t.Context(), dsn)
		require.NoError(t, err)
		// Create an isolated schema, then reconnect with it as the search_path.
		require.NoError(t, execRaw(t, dsn, "CREATE SCHEMA "+schema))
		t.Cleanup(func() {
			_ = execRaw(t, dsn, "DROP SCHEMA "+schema+" CASCADE")
			_ = admin.Close()
		})
		u, err := url.Parse(dsn)
		require.NoError(t, err)
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		s, err := store.Open(t.Context(), u.String())
		require.NoError(t, err)
		assert.Equal(t, store.Postgres, s.Dialect())
		return s
	})
}

func TestMigrationsStayInStep(t *testing.T) {
	pg, err := store.MigrationVersions(store.Postgres)
	require.NoError(t, err)
	lite, err := store.MigrationVersions(store.SQLite)
	require.NoError(t, err)
	require.NotEmpty(t, pg)
	assert.Equal(t, pg, lite, "every migration must exist for both dialects under the same name")
}

func TestOpenRejectsEmptyAndBadDSN(t *testing.T) {
	_, err := store.Open(t.Context(), "")
	require.Error(t, err)
	_, err = store.Open(t.Context(), "postgres://127.0.0.1:1/none?connect_timeout=1")
	require.Error(t, err)
	assert.False(t, strings.Contains(err.Error(), "password"))
}
