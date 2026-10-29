package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
)

// ErrNotSQLite is returned by SQLite-only maintenance on another engine.
var ErrNotSQLite = errors.New("store: this operation is only available on SQLite; use pg_dump for PostgreSQL")

// SnapshotSQLite writes a transactionally consistent copy of a live SQLite
// database to dest (VACUUM INTO: readers and the writer keep running, the copy
// is compact and has no WAL). dest must not exist.
func SnapshotSQLite(ctx context.Context, s Store, dest string) error {
	ss, ok := s.(*sqlStore)
	if !ok || ss.dialect != SQLite {
		return ErrNotSQLite
	}
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("snapshot destination %s already exists", dest)
	}
	if _, err := ss.db.ExecContext(ctx, "VACUUM INTO ?", dest); err != nil {
		_ = os.Remove(dest)
		return fmt.Errorf("snapshotting sqlite: %w", err)
	}
	return nil
}

// CheckSQLiteFile opens a database file read-only (no migrations, no writes)
// and runs SQLite's integrity and foreign-key checks.
func CheckSQLiteFile(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer db.Close()
	var res string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&res); err != nil {
		return fmt.Errorf("integrity check: %w", err)
	}
	if res != "ok" {
		return fmt.Errorf("integrity check failed: %s", res)
	}
	rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("foreign key check: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("foreign key check failed: dangling references")
	}
	return rows.Err()
}
