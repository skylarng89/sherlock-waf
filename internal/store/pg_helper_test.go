package store_test

import (
	"database/sql"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// execRaw runs one statement on a throwaway connection (test schema management).
func execRaw(t *testing.T, dsn, stmt string) error {
	t.Helper()
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.ExecContext(t.Context(), stmt)
	return err
}
