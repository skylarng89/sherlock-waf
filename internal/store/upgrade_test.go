package store_test

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

// The automated N-2 check (docs/release/versioning.md: every release migrates
// from the previous two minors). Two parts:
//
//   - TestUpgradeFromTheFirstSchema builds a database at the OLDEST schema
//     version, fills every table that exists then, and applies the migrations one
//     version at a time, checking after each step that nothing was lost. Every
//     released schema is one of the steps, so every upgrade path is covered.
//   - TestConfigSnapshotsOfPreviousReleasesStillLoad decodes the configuration
//     snapshot each earlier release stored. Each release adds a fixture under
//     testdata/upgrade/<version>/ (see the README there).

//go:embed sqlite/migrations/*.sql
var upgradeSQLite embed.FS

//go:embed postgres/migrations/*.sql
var upgradePostgres embed.FS

//go:embed testdata/upgrade
var upgradeFixtures embed.FS

// upgradeEngine is one database engine under test.
type upgradeEngine struct {
	name    string
	dialect goose.Dialect
	migs    fs.FS
	raw     *sql.DB
	blob    func(hex string) string                     // SQL literal for a binary value
	reopen  func(t *testing.T) store.Store              // the real store on the same database
	checkDB func(t *testing.T, db *sql.DB, step string) // engine-specific integrity checks
}

func sqliteUpgradeEngine(t *testing.T) *upgradeEngine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "upgrade.db")
	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	sub, err := fs.Sub(upgradeSQLite, "sqlite/migrations")
	require.NoError(t, err)
	return &upgradeEngine{
		name: "sqlite", dialect: goose.DialectSQLite3, migs: sub, raw: raw,
		blob: func(h string) string { return "X'" + h + "'" },
		reopen: func(t *testing.T) store.Store {
			s, err := store.OpenSQLite(t.Context(), path)
			require.NoError(t, err)
			return s
		},
		checkDB: func(t *testing.T, db *sql.DB, step string) {
			var res string
			require.NoError(t, db.QueryRowContext(t.Context(), "PRAGMA integrity_check").Scan(&res), step)
			assert.Equal(t, "ok", res, "integrity_check after %s", step)
			rows, err := db.QueryContext(t.Context(), "PRAGMA foreign_key_check")
			require.NoError(t, err, step)
			defer func() { _ = rows.Close() }()
			assert.False(t, rows.Next(), "foreign_key_check reports a dangling reference after %s", step)
		},
	}
}

func postgresUpgradeEngine(t *testing.T, dsn string) *upgradeEngine {
	t.Helper()
	schema := fmt.Sprintf("up_%x", rand.Uint64()) //nolint:gosec // unique test schema name
	require.NoError(t, execRaw(t, dsn, "CREATE SCHEMA "+schema))
	t.Cleanup(func() { _ = execRaw(t, dsn, "DROP SCHEMA "+schema+" CASCADE") })
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	raw, err := sql.Open("pgx", u.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	sub, err := fs.Sub(upgradePostgres, "postgres/migrations")
	require.NoError(t, err)
	return &upgradeEngine{
		name: "postgres", dialect: goose.DialectPostgres, migs: sub, raw: raw,
		blob: func(h string) string { return `'\x` + h + `'` },
		reopen: func(t *testing.T) store.Store {
			s, err := store.Open(t.Context(), u.String())
			require.NoError(t, err)
			return s
		},
		checkDB: func(t *testing.T, db *sql.DB, step string) {
			var n int
			require.NoError(t, db.QueryRowContext(t.Context(), "SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema()").Scan(&n), step)
			assert.Positive(t, n, "tables exist after %s", step)
		},
	}
}

func forEachUpgradeEngine(t *testing.T, fn func(t *testing.T, e *upgradeEngine)) {
	t.Run("sqlite", func(t *testing.T) { fn(t, sqliteUpgradeEngine(t)) })
	dsn := os.Getenv("SHERLOCK_TEST_PG_DSN")
	if dsn == "" {
		if os.Getenv("SHERLOCK_REQUIRE_PG") != "" {
			t.Fatal("SHERLOCK_REQUIRE_PG is set but SHERLOCK_TEST_PG_DSN is not")
		}
		return
	}
	t.Run("postgres", func(t *testing.T) { fn(t, postgresUpgradeEngine(t, dsn)) })
}

func lit(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

const upgradeBase = int64(1_700_000_000_000_000) // microseconds

// seedFirstSchema fills every table that exists at migration 00001 through raw
// SQL, as an old node would have, and returns the audit head it left.
func seedFirstSchema(t *testing.T, e *upgradeEngine, snapshot []byte) store.AuditEntry {
	t.Helper()
	ctx := t.Context()
	exec := func(stmt string) {
		_, err := e.raw.ExecContext(ctx, stmt)
		require.NoError(t, err, stmt)
	}
	exec(fmt.Sprintf(`INSERT INTO config_versions (id, parent_id, created_at, author_type, author_id, source, schema_version, snapshot, diff, applied)
		VALUES ('v1', '', %d, 'system', 'node', 'boot', 1, %s, '{}', 1)`, upgradeBase, lit(string(snapshot))))
	exec(`UPDATE config_head SET version_id = 'v1' WHERE id = 1`)
	exec(fmt.Sprintf(`INSERT INTO sites (id, name, mode, hosts, updated_at) VALUES ('shop', 'Shop', 'block', '["shop.example.com"]', %d)`, upgradeBase))
	exec(fmt.Sprintf(`INSERT INTO secrets (id, purpose, key_id, nonce, ciphertext, created_at) VALUES ('sec1', 'mfa', 1, %s, %s, %d)`,
		e.blob("000102030405060708090a0b0c0d0e0f1011121314151617"), e.blob("deadbeefcafe"), upgradeBase))
	exec(fmt.Sprintf(`INSERT INTO users (id, username, password_hash, role, mfa_secret_id, mfa_enabled, created_at)
		VALUES ('u-admin', 'ada', '$argon2id$stub', 'admin', 'sec1', 1, %d), ('u-view', 'vic', '$argon2id$stub', 'viewer', '', 0, %d)`, upgradeBase, upgradeBase))
	exec(fmt.Sprintf(`INSERT INTO sessions (id, user_id, stage, created_at, last_seen_at, expires_at, ip, user_agent, csrf_token_hash)
		VALUES ('sess1', 'u-admin', 'full', %d, %d, %d, '192.0.2.1', 'ua', 'csrfhash')`, upgradeBase, upgradeBase, upgradeBase+3_600_000_000))
	exec(fmt.Sprintf(`INSERT INTO api_tokens (id, user_id, name, token_hash, scopes, cidrs, created_at)
		VALUES ('tok1', 'u-admin', 'ci', 'tokhash', '["read"]', '[]', %d)`, upgradeBase))
	exec(fmt.Sprintf(`INSERT INTO events (id, ts, site_id, action, mode, client_ip, method, host, path, status, rule_ids, body)
		VALUES ('evt1', %d, 'shop', 'block', 'block', '198.51.100.7', 'GET', 'shop.example.com', '/x', 403, '["942100"]', '{"id":"evt1"}')`, upgradeBase))
	exec(fmt.Sprintf(`INSERT INTO event_rollups_1m (bucket, site_id, action, count) VALUES (%d, 'shop', 'block', 3)`, upgradeBase/60_000_000))
	exec(`INSERT INTO kv (key, value) VALUES ('node.id', 'node-1')`)

	// A valid two-entry audit chain, hashed exactly as the audit service does.
	var head store.AuditEntry
	for i, action := range []string{"config.apply", "user.create"} {
		entry := store.AuditEntry{
			Seq: int64(i + 1), ID: fmt.Sprintf("aud%d", i+1), At: time.UnixMicro(upgradeBase + int64(i)).UTC(),
			ActorType: "system", ActorID: "node", IP: "", Action: action, ObjectType: "config", ObjectID: "v1",
			Details: []byte(`{}`), PrevHash: head.Hash,
		}
		entry.Hash = audit.Hash(entry)
		exec(fmt.Sprintf(`INSERT INTO audit_log (seq, id, at, actor_type, actor_id, ip, action, object_type, object_id, details, prev_hash, hash)
			VALUES (%d, %s, %d, 'system', 'node', '', %s, 'config', 'v1', '{}', %s, %s)`,
			entry.Seq, lit(entry.ID), entry.At.UnixMicro(), lit(action), lit(entry.PrevHash), lit(entry.Hash)))
		head = entry
	}
	exec(fmt.Sprintf(`UPDATE audit_head SET seq = %d, hash = %s WHERE id = 1`, head.Seq, lit(head.Hash)))
	return head
}

// seededCounts is what must survive every migration step.
var seededCounts = map[string]int{
	"config_versions": 1, "config_head": 1, "sites": 1, "secrets": 1, "users": 2, "sessions": 1,
	"api_tokens": 1, "audit_log": 2, "events": 1, "event_rollups_1m": 1, "kv": 1,
}

func assertSeededRows(t *testing.T, e *upgradeEngine, step string, head store.AuditEntry) {
	t.Helper()
	ctx := t.Context()
	for table, want := range seededCounts {
		var n int
		require.NoError(t, e.raw.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&n), "%s after %s", table, step)
		assert.Equal(t, want, n, "%s rows after %s", table, step)
	}
	var version, hash string
	var seq int64
	require.NoError(t, e.raw.QueryRowContext(ctx, "SELECT version_id FROM config_head WHERE id = 1").Scan(&version))
	assert.Equal(t, "v1", version, "config head after %s", step)
	require.NoError(t, e.raw.QueryRowContext(ctx, "SELECT seq, hash FROM audit_head WHERE id = 1").Scan(&seq, &hash))
	assert.Equal(t, head.Seq, seq, "audit head seq after %s", step)
	assert.Equal(t, head.Hash, hash, "audit head hash after %s", step)
	e.checkDB(t, e.raw, step)
}

func TestUpgradeFromTheFirstSchema(t *testing.T) {
	snapshot, err := upgradeFixtures.ReadFile("testdata/upgrade/v0.1.0/snapshot.json")
	require.NoError(t, err)

	forEachUpgradeEngine(t, func(t *testing.T, e *upgradeEngine) {
		ctx := t.Context()
		p, err := goose.NewProvider(e.dialect, e.raw, e.migs)
		require.NoError(t, err)

		// Version 1 only: the oldest schema a supported upgrade starts from.
		res, err := p.UpByOne(ctx)
		require.NoError(t, err)
		require.EqualValues(t, 1, res.Source.Version)
		head := seedFirstSchema(t, e, snapshot)
		assertSeededRows(t, e, "migration 1", head)

		steps := 1
		for {
			res, err := p.UpByOne(ctx)
			if errors.Is(err, goose.ErrNoNextVersion) {
				break
			}
			require.NoError(t, err)
			steps++
			assertSeededRows(t, e, fmt.Sprintf("migration %d (%s)", res.Source.Version, res.Source.Path), head)
		}
		all, err := fs.ReadDir(e.migs, ".")
		require.NoError(t, err)
		require.Equal(t, len(all), steps, "every migration file was applied one by one")

		// The real store opens the upgraded database (a no-op migration) and reads
		// what the old node wrote.
		s := e.reopen(t)
		defer func() { _ = s.Close() }()
		auditor := audit.New(nil)

		require.NoError(t, s.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			u, err := tx.UserByID(ctx, "u-admin")
			require.NoError(t, err)
			assert.Equal(t, "ada", u.Username)
			assert.True(t, u.MFAEnabled)
			sessions, err := tx.ListUserSessions(ctx, "u-admin")
			require.NoError(t, err)
			assert.Len(t, sessions, 1)
			tokens, err := tx.ListTokensByUser(ctx, "u-admin")
			require.NoError(t, err)
			assert.Len(t, tokens, 1)

			headID, err := tx.ConfigHead(ctx)
			require.NoError(t, err)
			assert.Equal(t, "v1", headID)
			cv, err := tx.GetConfigVersion(ctx, headID)
			require.NoError(t, err)
			assert.JSONEq(t, string(snapshot), string(cv.Snapshot))
			_, err = config.FromSnapshot(cv.Snapshot)
			require.NoError(t, err, "the stored snapshot loads with the current build")
			sites, err := tx.ListSites(ctx)
			require.NoError(t, err)
			assert.Len(t, sites, 1)

			ev, err := tx.GetEvent(ctx, "evt1")
			require.NoError(t, err)
			assert.Equal(t, 403, ev.Status)
			assert.Empty(t, ev.Country, "an event written before the country column reads back with an empty country")
			v, err := tx.GetKV(ctx, "node.id")
			require.NoError(t, err)
			assert.Equal(t, "node-1", v)
			return nil
		}))

		// The seeded hash chain verifies, and a new entry chains onto its head.
		rep, err := audit.Verify(ctx, s)
		require.NoError(t, err)
		require.Nil(t, rep.Problem, "the chain written by the old node is intact")
		assert.Equal(t, 2, rep.Entries)

		var appended store.AuditEntry
		require.NoError(t, s.Tx(ctx, func(ctx context.Context, tx store.Tx) (err error) {
			appended, err = auditor.Append(ctx, tx, audit.Input{ActorType: audit.ActorSystem, ActorID: "node", Action: "system.upgraded", ObjectType: "system", ObjectID: "node"})
			return err
		}))
		assert.EqualValues(t, 3, appended.Seq)
		assert.Equal(t, head.Hash, appended.PrevHash, "the new entry points at the seeded head")
		rep, err = audit.Verify(ctx, s)
		require.NoError(t, err)
		require.Nil(t, rep.Problem)
		assert.Equal(t, 3, rep.Entries)

		// Tables added by later migrations work on the upgraded database.
		require.NoError(t, s.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			require.NoError(t, tx.PutBan(ctx, store.Ban{
				ID: "ban1", IP: "203.0.113.9", Source: "manual", Reason: "test", CreatedBy: "u-admin",
				CreatedAt: time.UnixMicro(upgradeBase).UTC(), Until: time.UnixMicro(upgradeBase).Add(time.Hour).UTC(),
			}))
			bans, err := tx.ListActiveBans(ctx, time.UnixMicro(upgradeBase).UTC())
			require.NoError(t, err)
			assert.Len(t, bans, 1)
			require.NoError(t, tx.PutBlockPage(ctx, store.BlockPage{ID: "default", HTML: "<p>blocked</p>", UpdatedAt: time.UnixMicro(upgradeBase).UTC()}))
			return nil
		}))
	})
}

// TestConfigSnapshotsOfPreviousReleasesStillLoad decodes every stored fixture:
// a snapshot written by an earlier release, and the YAML it came from. They must
// load with this build, validate, and resolve to the same effective policy.
func TestConfigSnapshotsOfPreviousReleasesStillLoad(t *testing.T) {
	releases, err := fs.ReadDir(upgradeFixtures, "testdata/upgrade")
	require.NoError(t, err)
	found := 0
	for _, r := range releases {
		if !r.IsDir() {
			continue
		}
		found++
		t.Run(r.Name(), func(t *testing.T) {
			dir := "testdata/upgrade/" + r.Name()
			snap, err := upgradeFixtures.ReadFile(dir + "/snapshot.json")
			require.NoError(t, err)
			src, err := upgradeFixtures.ReadFile(dir + "/config.yaml")
			require.NoError(t, err)

			fromSnap, err := config.FromSnapshot(snap)
			require.NoError(t, err, "the snapshot %s stored must load unchanged", r.Name())
			fromYAML, err := config.Parse(src)
			require.NoError(t, err, "the configuration file %s accepted must still parse", r.Name())

			require.Len(t, fromSnap.Sites, len(fromYAML.Sites))
			for i := range fromSnap.Sites {
				a, err := json.Marshal(fromSnap.EffectivePolicy(&fromSnap.Sites[i], nil))
				require.NoError(t, err)
				b, err := json.Marshal(fromYAML.EffectivePolicy(&fromYAML.Sites[i], nil))
				require.NoError(t, err)
				assert.JSONEq(t, string(b), string(a), "site %s resolves to the same policy from the snapshot and from the file", fromSnap.Sites[i].ID)
			}
		})
	}
	require.NotZero(t, found, "at least one release fixture exists")
}
