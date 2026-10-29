package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/skylarng89/sherlock-waf/internal/store/db"
)

//go:embed postgres/migrations/*.sql
var postgresMigrations embed.FS

//go:embed sqlite/migrations/*.sql
var sqliteMigrations embed.FS

// MigrationVersions lists the migration file names of a dialect (sorted), so a
// test can assert both dialects stay in step.
func MigrationVersions(d Dialect) ([]string, error) {
	fsys, dir := migrationFS(d)
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s migrations: %w", d, err)
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names, nil
}

func migrationFS(d Dialect) (embed.FS, string) {
	if d == Postgres {
		return postgresMigrations, "postgres/migrations"
	}
	return sqliteMigrations, "sqlite/migrations"
}

// sqlStore is the Store implementation shared by both engines.
type sqlStore struct {
	db      *sql.DB
	dialect Dialect
	rebind  bool // rewrite $n placeholders to ?n (SQLite)
}

// Open connects to the database named by dsn and applies pending migrations.
//
//	postgres://user:pass@host/db?sslmode=verify-full   PostgreSQL 15+
//	sqlite:///var/lib/sherlock/sherlock.db             SQLite file (also: a bare path)
func Open(ctx context.Context, dsn string) (Store, error) {
	switch {
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return openPostgres(ctx, dsn)
	case strings.HasPrefix(dsn, "sqlite://"):
		u, err := url.Parse(dsn)
		if err != nil {
			return nil, fmt.Errorf("parsing sqlite dsn: %w", err)
		}
		path := u.Path
		if u.Host != "" && u.Host != "localhost" {
			path = u.Host + u.Path // sqlite://relative/path.db
		}
		return OpenSQLite(ctx, path)
	case dsn == "":
		return nil, fmt.Errorf("empty database dsn")
	default:
		return OpenSQLite(ctx, dsn)
	}
}

func openPostgres(ctx context.Context, dsn string) (Store, error) {
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening postgres: %w", err)
	}
	conn.SetMaxOpenConns(20)
	return finishOpen(ctx, &sqlStore{db: conn, dialect: Postgres})
}

// OpenSQLite opens (creating if needed) a SQLite database file in WAL mode.
// ":memory:" gives a private in-memory database (tests); it is limited to one connection.
func OpenSQLite(ctx context.Context, path string) (Store, error) {
	q := url.Values{}
	for _, p := range []string{"busy_timeout(5000)", "journal_mode(WAL)", "foreign_keys(1)", "synchronous(NORMAL)"} {
		q.Add("_pragma", p)
	}
	// Writers take the write lock at BEGIN, so a read-then-write transaction
	// cannot fail halfway with SQLITE_BUSY on lock upgrade.
	q.Set("_txlock", "immediate")
	dsn := "file:" + path + "?" + q.Encode()
	if path == ":memory:" {
		dsn = "file::memory:?cache=private&" + q.Encode()
	}
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}
	if path == ":memory:" {
		conn.SetMaxOpenConns(1)
	} else {
		conn.SetMaxOpenConns(8)
	}
	return finishOpen(ctx, &sqlStore{db: conn, dialect: SQLite, rebind: true})
}

func finishOpen(ctx context.Context, s *sqlStore) (Store, error) {
	if err := s.db.PingContext(ctx); err != nil {
		_ = s.db.Close()
		return nil, fmt.Errorf("connecting to %s: %w", s.dialect, err)
	}
	if err := s.migrate(ctx); err != nil {
		_ = s.db.Close()
		return nil, err
	}
	return s, nil
}

func (s *sqlStore) migrate(ctx context.Context) error {
	fsys, dir := migrationFS(s.dialect)
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		return fmt.Errorf("locating migrations: %w", err)
	}
	gd := goose.DialectSQLite3
	if s.dialect == Postgres {
		gd = goose.DialectPostgres
	}
	p, err := goose.NewProvider(gd, s.db, sub)
	if err != nil {
		return fmt.Errorf("creating migration provider: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("applying %s migrations: %w", s.dialect, err)
	}
	return nil
}

func (s *sqlStore) Dialect() Dialect { return s.dialect }

func (s *sqlStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *sqlStore) Close() error { return s.db.Close() }

// Tx implements Store.
func (s *sqlStore) Tx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	var dbtx db.DBTX = tx
	if s.rebind {
		dbtx = rebindDBTX{tx}
	}
	if err := fn(ctx, sqlTx{q: db.New(dbtx)}); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", mapErr(err))
	}
	return nil
}

// placeholder matches the $n parameters sqlc emits for PostgreSQL. No query in
// internal/store/queries contains a literal dollar sign.
var placeholder = regexp.MustCompile(`\$(\d+)`)

// rebindDBTX lets the PostgreSQL-flavoured queries run on SQLite by rewriting
// $n to ?n (SQLite's numbered parameter, which may repeat).
type rebindDBTX struct{ inner db.DBTX }

func rewrite(q string) string { return placeholder.ReplaceAllString(q, "?$1") }

func (r rebindDBTX) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return r.inner.ExecContext(ctx, rewrite(q), args...)
}

func (r rebindDBTX) PrepareContext(ctx context.Context, q string) (*sql.Stmt, error) {
	return r.inner.PrepareContext(ctx, rewrite(q))
}

func (r rebindDBTX) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return r.inner.QueryContext(ctx, rewrite(q), args...)
}

func (r rebindDBTX) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return r.inner.QueryRowContext(ctx, rewrite(q), args...)
}

// SQLProvider is implemented by stores that expose their *sql.DB, which the
// extension host hands to extensions for their own "ee_"-prefixed tables.
type SQLProvider interface{ SQLDB() *sql.DB }

// SQLDB returns the underlying connection pool.
func (s *sqlStore) SQLDB() *sql.DB { return s.db }
