// Package storetest is the conformance suite every store.Store backend must
// pass. The same tests run on SQLite and PostgreSQL, which is what keeps the
// single set of queries honest on both.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/store"
)

// Factory returns a fresh, empty store for one test.
type Factory func(t *testing.T) store.Store

// stubHash stands in for a password hash; the store treats it as opaque text.
var stubHash = "$" + "argon2id" + "$stub"

var base = time.Date(2026, 10, 28, 12, 0, 0, 123456000, time.UTC) // microsecond precision

// Run executes the suite against stores produced by newStore.
func Run(t *testing.T, newStore Factory) {
	for name, fn := range map[string]func(*testing.T, store.Store){
		"migrations are idempotent":    testMigrations,
		"kv":                           testKV,
		"config versions and head":     testConfig,
		"head compare-and-set race":    testHeadRace,
		"sites projection":             testSites,
		"secrets keep binary intact":   testSecrets,
		"users and login throttling":   testUsers,
		"mfa step replay protection":   testMFAStep,
		"sessions":                     testSessions,
		"tokens":                       testTokens,
		"deleting a user cascades":     testCascade,
		"audit head and ordering":      testAudit,
		"concurrent audit writers":     testAuditConcurrent,
		"events and filters":           testEvents,
		"event retention and rollups":  testRetention,
		"transactions roll back":       testRollback,
		"text round-trips exactly":     testText,
		"timestamps keep microseconds": testTimestamps,
		"certificates":                 testCertificates,
		"block pages":                  testBlockPages,
		"api assets":                   testAPIAssets,
		"endpoint counts":              testEndpointCounts,
		"bans":                         testBans,
		"event filters":                testEventFilters,
		"top events":                   testTopEvents,
	} {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			t.Cleanup(func() { _ = s.Close() })
			fn(t, s)
		})
	}
}

func tx(t *testing.T, s store.Store, fn func(ctx context.Context, tx store.Tx) error) {
	t.Helper()
	require.NoError(t, s.Tx(t.Context(), fn))
}

// failsWith runs fn in its OWN transaction and returns its error. A failed
// statement aborts the whole transaction on PostgreSQL (SQLite lets it carry
// on), so every expected failure is asserted in a transaction of its own; the
// same rule applies to production code.
func failsWith(t *testing.T, s store.Store, fn func(ctx context.Context, tx store.Tx) error) error {
	t.Helper()
	return s.Tx(t.Context(), fn)
}

func testMigrations(t *testing.T, s store.Store) {
	require.NoError(t, s.Ping(t.Context()))
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		head, err := tx.ConfigHead(ctx)
		require.NoError(t, err)
		assert.Empty(t, head, "no version applied yet")
		seq, hash, err := tx.AuditHead(ctx)
		require.NoError(t, err)
		assert.Zero(t, seq)
		assert.Empty(t, hash)
		n, err := tx.CountUsers(ctx)
		require.NoError(t, err)
		assert.Zero(t, n, "a fresh database has no users and no default password")
		return nil
	})
}

func testKV(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.GetKV(ctx, "install_id")
		assert.ErrorIs(t, err, store.ErrNotFound)
		require.NoError(t, tx.SetKV(ctx, "install_id", "a"))
		require.NoError(t, tx.SetKV(ctx, "install_id", "b"))
		v, err := tx.GetKV(ctx, "install_id")
		require.NoError(t, err)
		assert.Equal(t, "b", v)
		require.NoError(t, tx.DeleteKV(ctx, "install_id"))
		_, err = tx.GetKV(ctx, "install_id")
		assert.ErrorIs(t, err, store.ErrNotFound)
		return nil
	})
}

func version(id, parent string, at time.Time) store.ConfigVersion {
	return store.ConfigVersion{
		ID: id, ParentID: parent, CreatedAt: at, AuthorType: "user", AuthorID: "u1", Source: "api", SchemaVersion: 1,
		Snapshot: []byte(`{"schema_version":1,"sites":[]}`), Diff: []byte(`{"added":["shop"]}`), Applied: true,
	}
}

func testConfig(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		v1 := version("01A", "", base)
		v2 := version("01B", "01A", base.Add(time.Second))
		v3 := version("01C", "01B", base.Add(2*time.Second))
		for _, v := range []store.ConfigVersion{v1, v2, v3} {
			require.NoError(t, tx.InsertConfigVersion(ctx, v))
		}

		got, err := tx.GetConfigVersion(ctx, "01B")
		require.NoError(t, err)
		assert.Equal(t, v2, got, "a version round-trips exactly, including snapshot bytes and time")
		_, err = tx.GetConfigVersion(ctx, "missing")
		assert.ErrorIs(t, err, store.ErrNotFound)

		ok, err := tx.CompareAndSetConfigHead(ctx, "", "01A")
		require.NoError(t, err)
		assert.True(t, ok)
		ok, err = tx.CompareAndSetConfigHead(ctx, "", "01B")
		require.NoError(t, err)
		assert.False(t, ok, "head is no longer empty")
		ok, err = tx.CompareAndSetConfigHead(ctx, "01A", "01C")
		require.NoError(t, err)
		assert.True(t, ok)
		head, err := tx.ConfigHead(ctx)
		require.NoError(t, err)
		assert.Equal(t, "01C", head)

		page1, err := tx.ListConfigVersions(ctx, store.Cursor{}, 2)
		require.NoError(t, err)
		require.Len(t, page1, 2)
		assert.Equal(t, []string{"01C", "01B"}, []string{page1[0].ID, page1[1].ID}, "newest first")
		page2, err := tx.ListConfigVersions(ctx, store.Cursor{Time: page1[1].CreatedAt, ID: page1[1].ID}, 2)
		require.NoError(t, err)
		require.Len(t, page2, 1)
		assert.Equal(t, "01A", page2[0].ID)
		return nil
	})
}

func testHeadRace(t *testing.T, s store.Store) {
	// A duplicate version id is a conflict (own transaction: see failsWith).
	require.NoError(t, s.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		return tx.InsertConfigVersion(ctx, version("dup", "", base))
	}))
	err := failsWith(t, s, func(ctx context.Context, tx store.Tx) error {
		return tx.InsertConfigVersion(ctx, version("dup", "", base))
	})
	assert.ErrorIs(t, err, store.ErrConflict)

	// Two writers both try to move the head away from "": exactly one wins.
	const writers = 8
	var wg sync.WaitGroup
	wins := make(chan string, writers)
	for i := range writers {
		wg.Go(func() {
			id := "v" + strconv.Itoa(i)
			err := s.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
				if err := tx.InsertConfigVersion(ctx, version(id, "", base)); err != nil {
					return err
				}
				ok, err := tx.CompareAndSetConfigHead(ctx, "", id)
				if err != nil {
					return err
				}
				if !ok {
					return errLost
				}
				return nil
			})
			if err == nil {
				wins <- id
			} else if !errors.Is(err, errLost) {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	wg.Wait()
	close(wins)
	var winners []string
	for w := range wins {
		winners = append(winners, w)
	}
	require.Len(t, winners, 1, "exactly one compare-and-set may win: %v", winners)
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		head, err := tx.ConfigHead(ctx)
		require.NoError(t, err)
		assert.Equal(t, winners[0], head)
		return nil
	})
}

var errLost = errors.New("lost the race")

func testSites(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		require.NoError(t, tx.ReplaceSites(ctx, []store.Site{
			{ID: "shop", Name: "Shop", Mode: "block", Hosts: []byte(`["shop.example.com"]`), UpdatedAt: base},
			{ID: "blog", Name: "Blog", Mode: "detect", Hosts: []byte(`["blog.example.com"]`), UpdatedAt: base},
		}))
		require.NoError(t, tx.ReplaceSites(ctx, []store.Site{{ID: "api", Name: "API", Mode: "block", Hosts: []byte(`[]`), UpdatedAt: base}}))
		got, err := tx.ListSites(ctx)
		require.NoError(t, err)
		require.Len(t, got, 1, "replace swaps the whole projection")
		assert.Equal(t, "api", got[0].ID)
		return nil
	})
}

func testSecrets(t *testing.T, s store.Store) {
	nonce := append(bytes.Repeat([]byte{0}, 12), bytes.Repeat([]byte{0xff}, 12)...) // NUL and 0xFF bytes
	ct := []byte{0, 1, 2, 0, 0xfe, 0xff, 0, '\n', '\'', '"'}
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		sec := store.Secret{ID: "s1", Purpose: "totp", KeyID: 1, Nonce: nonce, Ciphertext: ct, CreatedAt: base}
		require.NoError(t, tx.InsertSecret(ctx, sec))
		got, err := tx.GetSecret(ctx, "s1")
		require.NoError(t, err)
		assert.Equal(t, sec, got, "binary values must round-trip exactly")

		sec.KeyID, sec.Ciphertext = 2, []byte("rotated")
		require.NoError(t, tx.UpdateSecret(ctx, sec))
		got, _ = tx.GetSecret(ctx, "s1")
		assert.Equal(t, 2, got.KeyID)
		assert.ErrorIs(t, tx.UpdateSecret(ctx, store.Secret{ID: "nope"}), store.ErrNotFound)

		n, err := tx.CountSecrets(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		require.NoError(t, tx.DeleteSecret(ctx, "s1"))
		_, err = tx.GetSecret(ctx, "s1")
		assert.ErrorIs(t, err, store.ErrNotFound)
		return nil
	})
}

func user(id, name string) store.User {
	return store.User{ID: id, Username: name, PasswordHash: stubHash, Role: store.RoleViewer, CreatedAt: base}
}

func testUsers(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		require.NoError(t, tx.CreateUser(ctx, user("u1", "alice")))

		u, err := tx.UserByUsername(ctx, "alice")
		require.NoError(t, err)
		assert.Equal(t, store.RoleViewer, u.Role)
		assert.False(t, u.MFAEnabled)
		assert.True(t, u.LockedUntil.IsZero())
		_, err = tx.UserByUsername(ctx, "nobody")
		assert.ErrorIs(t, err, store.ErrNotFound)

		lock := base.Add(time.Minute)
		require.NoError(t, tx.RecordLoginFailure(ctx, "u1", 6, lock))
		u, _ = tx.UserByID(ctx, "u1")
		assert.Equal(t, 6, u.FailedCount)
		assert.True(t, u.LockedUntil.Equal(lock))

		require.NoError(t, tx.SetUserPassword(ctx, "u1", "$argon2id$new"))
		u, _ = tx.UserByID(ctx, "u1")
		assert.Equal(t, "$argon2id$new", u.PasswordHash)
		assert.Zero(t, u.FailedCount, "a password reset clears the failure counter")
		assert.True(t, u.LockedUntil.IsZero(), "and the lock")

		require.NoError(t, tx.RecordLoginSuccess(ctx, "u1", base))
		u, _ = tx.UserByID(ctx, "u1")
		assert.True(t, u.LastLoginAt.Equal(base))

		require.NoError(t, tx.SetUserRole(ctx, "u1", store.RoleAdmin))
		require.NoError(t, tx.SetUserDisabled(ctx, "u1", true))
		u, _ = tx.UserByID(ctx, "u1")
		assert.Equal(t, store.RoleAdmin, u.Role)
		assert.True(t, u.Disabled)
		assert.ErrorIs(t, tx.SetUserRole(ctx, "missing", store.RoleAdmin), store.ErrNotFound)

		us, err := tx.ListUsers(ctx)
		require.NoError(t, err)
		assert.Len(t, us, 1)
		return nil
	})
}

func testUserConstraints(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error { return tx.CreateUser(ctx, user("u1", "alice")) })
	assert.ErrorIs(t, failsWith(t, s, func(ctx context.Context, tx store.Tx) error {
		return tx.CreateUser(ctx, user("u2", "alice"))
	}), store.ErrConflict, "usernames are unique")
	assert.ErrorIs(t, failsWith(t, s, func(ctx context.Context, tx store.Tx) error {
		return tx.CreateUser(ctx, user("u1", "bob"))
	}), store.ErrConflict, "ids are unique")
	bad := user("u3", "carol")
	bad.Role = "root"
	assert.Error(t, failsWith(t, s, func(ctx context.Context, tx store.Tx) error {
		return tx.CreateUser(ctx, bad)
	}), "the role CHECK constraint rejects unknown roles")
}

func testMFAStep(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		require.NoError(t, tx.CreateUser(ctx, user("u1", "alice")))
		require.NoError(t, tx.SetUserMFA(ctx, "u1", "sec1", true))
		ok, err := tx.AdvanceMFAStep(ctx, "u1", 100)
		require.NoError(t, err)
		assert.True(t, ok)
		ok, _ = tx.AdvanceMFAStep(ctx, "u1", 100)
		assert.False(t, ok, "the same TOTP step must not be accepted twice")
		ok, _ = tx.AdvanceMFAStep(ctx, "u1", 99)
		assert.False(t, ok, "nor an older one")
		ok, _ = tx.AdvanceMFAStep(ctx, "u1", 101)
		assert.True(t, ok)

		require.NoError(t, tx.SetUserMFA(ctx, "u1", "", false))
		u, _ := tx.UserByID(ctx, "u1")
		assert.False(t, u.MFAEnabled)
		assert.Zero(t, u.MFALastStep, "re-enrolment resets the replay step")
		return nil
	})
}

func testSessions(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		require.NoError(t, tx.CreateUser(ctx, user("u1", "alice")))
		sess := store.Session{
			ID: "h1", UserID: "u1", Stage: store.StageFull, CreatedAt: base, LastSeenAt: base,
			ExpiresAt: base.Add(12 * time.Hour), IP: "192.0.2.1", UserAgent: "ua", CSRFTokenHash: "c",
		}
		require.NoError(t, tx.CreateSession(ctx, sess))
		got, err := tx.GetSession(ctx, "h1")
		require.NoError(t, err)
		assert.Equal(t, sess, got)

		require.NoError(t, tx.TouchSession(ctx, "h1", base.Add(time.Minute)))
		got, _ = tx.GetSession(ctx, "h1")
		assert.True(t, got.LastSeenAt.Equal(base.Add(time.Minute)))

		idle := sess
		idle.ID, idle.LastSeenAt = "idle", base.Add(-time.Hour)
		old := sess
		old.ID, old.ExpiresAt = "old", base.Add(-time.Minute)
		require.NoError(t, tx.CreateSession(ctx, idle))
		require.NoError(t, tx.CreateSession(ctx, old))
		n, err := tx.DeleteExpiredSessions(ctx, base, base.Add(-30*time.Minute))
		require.NoError(t, err)
		assert.Equal(t, 2, n, "absolute-expired and idle sessions are purged")
		_, err = tx.GetSession(ctx, "h1")
		require.NoError(t, err)

		require.NoError(t, tx.DeleteSession(ctx, "h1"))
		_, err = tx.GetSession(ctx, "h1")
		assert.ErrorIs(t, err, store.ErrNotFound)
		return nil
	})
}

func testSessionConstraints(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error { return tx.CreateUser(ctx, user("u1", "alice")) })
	sess := store.Session{ID: "h2", UserID: "u1", Stage: "admin", CreatedAt: base, LastSeenAt: base, ExpiresAt: base, IP: "i", UserAgent: "u", CSRFTokenHash: "c"}
	assert.Error(t, failsWith(t, s, func(ctx context.Context, tx store.Tx) error { return tx.CreateSession(ctx, sess) }), "the stage CHECK constraint")
	sess.Stage, sess.UserID = store.StageFull, "ghost"
	assert.Error(t, failsWith(t, s, func(ctx context.Context, tx store.Tx) error { return tx.CreateSession(ctx, sess) }),
		"a session for a missing user is rejected: foreign keys are enforced on every engine")
}

func testTokens(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		require.NoError(t, tx.CreateUser(ctx, user("u1", "alice")))
		require.NoError(t, tx.CreateUser(ctx, user("u2", "bob")))
		tok := store.Token{
			ID: "t1", UserID: "u1", Name: "ci", TokenHash: "hash", Scopes: []byte(`["read"]`),
			CIDRs: []byte(`["10.0.0.0/8"]`), ExpiresAt: base.Add(24 * time.Hour), CreatedAt: base,
		}
		require.NoError(t, tx.CreateToken(ctx, tok))
		require.NoError(t, tx.CreateToken(ctx, store.Token{ID: "t2", UserID: "u2", Name: "x", TokenHash: "h2", Scopes: []byte(`[]`), CIDRs: []byte(`[]`), CreatedAt: base.Add(time.Second)}))
		got, err := tx.GetToken(ctx, "t1")
		require.NoError(t, err)
		assert.Equal(t, tok, got)
		mine, err := tx.ListTokensByUser(ctx, "u1")
		require.NoError(t, err)
		assert.Len(t, mine, 1)
		all, err := tx.ListTokens(ctx)
		require.NoError(t, err)
		assert.Equal(t, []string{"t2", "t1"}, []string{all[0].ID, all[1].ID}, "newest first")
		require.NoError(t, tx.TouchToken(ctx, "t1", base.Add(time.Hour)))
		got, _ = tx.GetToken(ctx, "t1")
		assert.True(t, got.LastUsedAt.Equal(base.Add(time.Hour)))
		require.NoError(t, tx.DeleteToken(ctx, "t1"))
		assert.ErrorIs(t, tx.DeleteToken(ctx, "t1"), store.ErrNotFound)
		return nil
	})
}

func testCascade(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		require.NoError(t, tx.CreateUser(ctx, user("u1", "alice")))
		require.NoError(t, tx.CreateSession(ctx, store.Session{ID: "h", UserID: "u1", Stage: store.StageFull, CreatedAt: base, LastSeenAt: base, ExpiresAt: base, IP: "i", UserAgent: "u", CSRFTokenHash: "c"}))
		require.NoError(t, tx.CreateToken(ctx, store.Token{ID: "t", UserID: "u1", Name: "n", TokenHash: "h", Scopes: []byte(`[]`), CIDRs: []byte(`[]`), CreatedAt: base}))
		require.NoError(t, tx.DeleteUser(ctx, "u1"))
		_, err := tx.GetSession(ctx, "h")
		assert.ErrorIs(t, err, store.ErrNotFound, "foreign keys must be enforced on every engine")
		_, err = tx.GetToken(ctx, "t")
		assert.ErrorIs(t, err, store.ErrNotFound)
		assert.ErrorIs(t, tx.DeleteUser(ctx, "u1"), store.ErrNotFound)
		return nil
	})
}

func appendAudit(ctx context.Context, tx store.Tx, id string) (int64, string, error) {
	seq, prev, err := tx.BumpAuditHead(ctx)
	if err != nil {
		return 0, "", err
	}
	hash := fmt.Sprintf("h%d", seq)
	if err := tx.InsertAudit(ctx, store.AuditEntry{
		Seq: seq, ID: id, At: base, ActorType: "user", ActorID: "u1", IP: "i",
		Action: "test", ObjectType: "o", ObjectID: "1", Details: []byte(`{}`), PrevHash: prev, Hash: hash,
	}); err != nil {
		return 0, "", err
	}
	return seq, prev, tx.SetAuditHeadHash(ctx, hash)
}

func testAudit(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		for i := 1; i <= 5; i++ {
			seq, prev, err := appendAudit(ctx, tx, "a"+strconv.Itoa(i))
			require.NoError(t, err)
			assert.EqualValues(t, i, seq, "sequence numbers are gap-free")
			if i == 1 {
				assert.Empty(t, prev)
			} else {
				assert.Equal(t, fmt.Sprintf("h%d", i-1), prev, "each entry chains to the previous hash")
			}
		}
		seq, hash, err := tx.AuditHead(ctx)
		require.NoError(t, err)
		assert.EqualValues(t, 5, seq)
		assert.Equal(t, "h5", hash)

		desc, err := tx.ListAudit(ctx, 0, 3)
		require.NoError(t, err)
		require.Len(t, desc, 3)
		assert.EqualValues(t, 5, desc[0].Seq)
		more, err := tx.ListAudit(ctx, desc[2].Seq, 10)
		require.NoError(t, err)
		assert.Len(t, more, 2)

		asc, err := tx.ListAuditAfter(ctx, 2, 10)
		require.NoError(t, err)
		require.Len(t, asc, 3)
		assert.EqualValues(t, 3, asc[0].Seq)
		assert.Equal(t, base, asc[0].At)
		return nil
	})
}

func testAuditConcurrent(t *testing.T, s store.Store) {
	// Writers contend for the audit head. Whatever the engine, the result must
	// be a single gap-free chain where every entry points at its predecessor.
	const writers, each = 8, 10
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			for i := range each {
				err := s.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
					_, _, err := appendAudit(ctx, tx, fmt.Sprintf("w%d-%d", w, i))
					return err
				})
				if err != nil {
					t.Errorf("writer %d: %v", w, err)
					return
				}
			}
		})
	}
	wg.Wait()
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		all, err := tx.ListAuditAfter(ctx, 0, 1000)
		require.NoError(t, err)
		require.Len(t, all, writers*each)
		prev := ""
		for i, e := range all {
			assert.EqualValues(t, i+1, e.Seq)
			assert.Equal(t, prev, e.PrevHash, "entry %d", e.Seq)
			prev = e.Hash
		}
		return nil
	})
}

func testEvents(t *testing.T, s store.Store) {
	mk := func(id string, at time.Time, site, action, ip string, rules ...string) store.EventRow {
		return store.EventRow{
			ID: id, TS: at, SiteID: site, Action: action, Mode: "block", ClientIP: ip, Method: "GET",
			Host: "h", Path: "/p", Status: 403, RuleIDs: rules, Body: []byte(`{"id":"` + id + `"}`),
		}
	}
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		evs := []store.EventRow{
			mk("e1", base, "shop", "block", "192.0.2.1", "942100", "949110"),
			mk("e2", base.Add(time.Second), "shop", "log", "192.0.2.2", "941100"),
			mk("e3", base.Add(2*time.Second), "blog", "block", "192.0.2.1", "9421000"),
			mk("e4", base.Add(3*time.Second), "shop", "block", "192.0.2.3"),
		}
		for _, e := range evs {
			require.NoError(t, tx.InsertEvent(ctx, e))
		}
		require.NoError(t, tx.InsertEvent(ctx, evs[0]), "re-inserting the same id is a no-op (at-least-once delivery)")
		n, _ := tx.CountEvents(ctx)
		assert.Equal(t, 4, n)

		got, err := tx.GetEvent(ctx, "e1")
		require.NoError(t, err)
		assert.Equal(t, evs[0], got)
		_, err = tx.GetEvent(ctx, "zz")
		assert.ErrorIs(t, err, store.ErrNotFound)

		ids := func(f store.EventFilter) []string {
			rows, err := tx.ListEvents(ctx, f, store.Cursor{}, 100)
			require.NoError(t, err)
			out := make([]string, len(rows))
			for i, r := range rows {
				out[i] = r.ID
			}
			return out
		}
		assert.Equal(t, []string{"e4", "e3", "e2", "e1"}, ids(store.EventFilter{}), "newest first")
		assert.Equal(t, []string{"e4", "e2", "e1"}, ids(store.EventFilter{SiteID: "shop"}))
		assert.Equal(t, []string{"e4", "e3", "e1"}, ids(store.EventFilter{Action: "block"}))
		assert.Equal(t, []string{"e3", "e1"}, ids(store.EventFilter{ClientIP: "192.0.2.1"}))
		assert.Equal(t, []string{"e1"}, ids(store.EventFilter{RuleID: "942100"}), "rule filter matches whole ids only")
		assert.Equal(t, []string{"e3"}, ids(store.EventFilter{RuleID: "9421000"}))
		assert.Equal(t, []string{"e3", "e2"}, ids(store.EventFilter{From: base.Add(time.Second), To: base.Add(3 * time.Second)}), "from inclusive, to exclusive")
		assert.Equal(t, []string{"e1"}, ids(store.EventFilter{SiteID: "shop", Action: "block", ClientIP: "192.0.2.1"}))

		p1, err := tx.ListEvents(ctx, store.EventFilter{}, store.Cursor{}, 2)
		require.NoError(t, err)
		p2, err := tx.ListEvents(ctx, store.EventFilter{}, store.Cursor{Time: p1[1].TS, ID: p1[1].ID}, 2)
		require.NoError(t, err)
		assert.Equal(t, []string{"e4", "e3"}, []string{p1[0].ID, p1[1].ID})
		assert.Equal(t, []string{"e2", "e1"}, []string{p2[0].ID, p2[1].ID})
		return nil
	})
}

func testRetention(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		for i := range 25 {
			require.NoError(t, tx.InsertEvent(ctx, store.EventRow{
				ID: fmt.Sprintf("e%02d", i), TS: base.Add(time.Duration(i) * time.Second),
				SiteID: "s", Action: "block", Mode: "block", ClientIP: "i", Method: "GET", Host: "h", Path: "/", Status: 403, Body: []byte(`{}`),
			}))
		}
		cutoff := base.Add(20 * time.Second)
		n, err := tx.DeleteEventsBefore(ctx, cutoff, 10)
		require.NoError(t, err)
		assert.Equal(t, 10, n, "deletion is batched")
		n, _ = tx.DeleteEventsBefore(ctx, cutoff, 10)
		assert.Equal(t, 10, n)
		n, _ = tx.DeleteEventsBefore(ctx, cutoff, 10)
		assert.Zero(t, n)
		left, _ := tx.CountEvents(ctx)
		assert.Equal(t, 5, left)

		minute := base.Truncate(time.Minute)
		require.NoError(t, tx.AddRollup(ctx, store.Rollup{Bucket: minute, SiteID: "s", Action: "block", Count: 3}))
		require.NoError(t, tx.AddRollup(ctx, store.Rollup{Bucket: minute, SiteID: "s", Action: "block", Count: 4}))
		require.NoError(t, tx.AddRollup(ctx, store.Rollup{Bucket: minute, SiteID: "s", Action: "log", Count: 1}))
		require.NoError(t, tx.AddRollup(ctx, store.Rollup{Bucket: minute.Add(time.Minute), SiteID: "s", Action: "block", Count: 9}))
		rs, err := tx.ListRollups(ctx, minute, minute.Add(time.Minute))
		require.NoError(t, err)
		require.Len(t, rs, 2)
		assert.EqualValues(t, 7, rs[0].Count, "counts for the same bucket accumulate")
		del, err := tx.DeleteRollupsBefore(ctx, minute.Add(time.Minute))
		require.NoError(t, err)
		assert.Equal(t, 2, del)
		return nil
	})
}

func testRollback(t *testing.T, s store.Store) {
	boom := errors.New("boom")
	err := s.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		require.NoError(t, tx.SetKV(ctx, "k", "v"))
		require.NoError(t, tx.CreateUser(ctx, user("u1", "alice")))
		return boom
	})
	require.ErrorIs(t, err, boom)

	assert.PanicsWithValue(t, "kaboom", func() {
		_ = s.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
			_ = tx.SetKV(ctx, "p", "v")
			panic("kaboom")
		})
	})

	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.GetKV(ctx, "k")
		assert.ErrorIs(t, err, store.ErrNotFound, "an error rolls the whole transaction back")
		_, err = tx.GetKV(ctx, "p")
		assert.ErrorIs(t, err, store.ErrNotFound, "so does a panic")
		n, _ := tx.CountUsers(ctx)
		assert.Zero(t, n)
		return nil
	})
}

func testText(t *testing.T, s store.Store) {
	weird := "O'Brien \"quoted\" \\ back\\slash ; DROP TABLE users; -- 日本語 😀 \t tab $1 ?1 %s"
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		require.NoError(t, tx.SetKV(ctx, "weird", weird))
		got, err := tx.GetKV(ctx, "weird")
		require.NoError(t, err)
		assert.Equal(t, weird, got, "values are bound parameters, never interpolated; $1 inside a value must survive")

		v := version("01W", "", base)
		v.Snapshot = []byte("{\n  \"b\": 1,\n  \"a\": 2\n}\n")
		require.NoError(t, tx.InsertConfigVersion(ctx, v))
		gv, _ := tx.GetConfigVersion(ctx, "01W")
		assert.Equal(t, v.Snapshot, gv.Snapshot, "snapshot bytes (key order, whitespace) are preserved: the audit hash depends on it")
		return nil
	})
}

func testTimestamps(t *testing.T, s store.Store) {
	at := time.Date(2026, 10, 28, 12, 34, 56, 654321000, time.UTC)
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		require.NoError(t, tx.CreateUser(ctx, store.User{ID: "u", Username: "t", PasswordHash: "h", Role: store.RoleAdmin, CreatedAt: at}))
		u, err := tx.UserByID(ctx, "u")
		require.NoError(t, err)
		assert.True(t, u.CreatedAt.Equal(at), "%v != %v", u.CreatedAt, at)
		assert.Equal(t, 654321000, u.CreatedAt.Nanosecond())
		assert.Equal(t, time.UTC, u.CreatedAt.Location())
		return nil
	})
}

func cert(id, name, secretID string) store.Certificate {
	return store.Certificate{
		ID: id, Name: name, Hosts: []string{"a.example.test", "*.b.example.test"}, NotBefore: base, NotAfter: base.Add(90 * 24 * time.Hour),
		Issuer: "CN=Test CA", Fingerprint: "ab12", ChainPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", KeySecretID: secretID, CreatedAt: base,
	}
}

func testCertificates(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		require.NoError(t, tx.InsertSecret(ctx, store.Secret{ID: "k1", Purpose: "certificate_key", KeyID: 1, Nonce: []byte{1}, Ciphertext: []byte{2}, CreatedAt: base}))
		require.NoError(t, tx.InsertSecret(ctx, store.Secret{ID: "k2", Purpose: "certificate_key", KeyID: 1, Nonce: []byte{1}, Ciphertext: []byte{2}, CreatedAt: base}))
		require.NoError(t, tx.InsertCertificate(ctx, cert("c2", "zeta", "k2")))
		require.NoError(t, tx.InsertCertificate(ctx, cert("c1", "alpha", "k1")))

		got, err := tx.GetCertificate(ctx, "c1")
		require.NoError(t, err)
		assert.Equal(t, cert("c1", "alpha", "k1"), got, "every field, including the host list and microsecond times, round-trips")

		all, err := tx.ListCertificates(ctx)
		require.NoError(t, err)
		require.Len(t, all, 2)
		assert.Equal(t, []string{"alpha", "zeta"}, []string{all[0].Name, all[1].Name}, "ordered by name")
		return nil
	})
	assert.ErrorIs(t, failsWith(t, s, func(ctx context.Context, tx store.Tx) error {
		return tx.InsertCertificate(ctx, cert("c3", "alpha", "k2"))
	}), store.ErrConflict, "names are unique")
	assert.Error(t, failsWith(t, s, func(ctx context.Context, tx store.Tx) error {
		return tx.InsertCertificate(ctx, cert("c4", "other", "no-such-secret"))
	}), "the private key must exist")
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		require.NoError(t, tx.DeleteCertificate(ctx, "c1"))
		assert.ErrorIs(t, tx.DeleteCertificate(ctx, "c1"), store.ErrNotFound)
		_, err := tx.GetCertificate(ctx, "c1")
		assert.ErrorIs(t, err, store.ErrNotFound)
		return nil
	})
}

func testEndpointCounts(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		mk := func(id, site, method, path string, rules ...string) store.EventRow {
			return store.EventRow{
				ID: id, TS: base, SiteID: site, Action: "log", Mode: "detect", ClientIP: "192.0.2.1",
				Method: method, Host: "h", Path: path, Status: 200, RuleIDs: rules, Body: []byte(`{}`),
			}
		}
		for _, e := range []store.EventRow{
			mk("c1", "bank", "POST", "/pay", "api.schema"),
			mk("c2", "bank", "POST", "/pay", "api.schema", "api.jwt"),
			mk("c3", "bank", "GET", "/old", "api.unknown_endpoint"),
			mk("c4", "other", "POST", "/pay", "api.schema"),
			mk("c5", "bank", "POST", "/pay", "api.schema2"),
		} {
			require.NoError(t, tx.InsertEvent(ctx, e))
		}
		got, err := tx.CountEventsByEndpoint(ctx, "bank", "api.schema", base.Add(-time.Hour), base.Add(time.Hour), 10)
		require.NoError(t, err)
		assert.Equal(t, []store.EndpointCount{{Method: "POST", Path: "/pay", Count: 2}}, got, "exact rule id, one site")
		return nil
	})
}

func testBlockPages(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		html := "<h1>Blocked \u00e9 ' \" </h1>\n{{.EventID}}"
		require.NoError(t, tx.PutBlockPage(ctx, store.BlockPage{ID: "corp", HTML: html, UpdatedAt: base}))
		require.NoError(t, tx.PutBlockPage(ctx, store.BlockPage{ID: "alt", HTML: "x", UpdatedAt: base}))
		got, err := tx.GetBlockPage(ctx, "corp")
		require.NoError(t, err)
		assert.Equal(t, store.BlockPage{ID: "corp", HTML: html, UpdatedAt: base}, got)

		later := base.Add(time.Hour + 123*time.Microsecond)
		require.NoError(t, tx.PutBlockPage(ctx, store.BlockPage{ID: "corp", HTML: "v2", UpdatedAt: later}))
		got, err = tx.GetBlockPage(ctx, "corp")
		require.NoError(t, err)
		assert.Equal(t, store.BlockPage{ID: "corp", HTML: "v2", UpdatedAt: later}, got, "put replaces")

		all, err := tx.ListBlockPages(ctx)
		require.NoError(t, err)
		require.Len(t, all, 2)
		assert.Equal(t, "alt", all[0].ID)

		require.NoError(t, tx.DeleteBlockPage(ctx, "alt"))
		assert.ErrorIs(t, tx.DeleteBlockPage(ctx, "alt"), store.ErrNotFound)
		_, err = tx.GetBlockPage(ctx, "alt")
		assert.ErrorIs(t, err, store.ErrNotFound)
		return nil
	})
}

func testAPIAssets(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		doc := store.OpenAPIDoc{ID: "pay", Name: "Payments", Version: "3.1", SHA256: "ab", Body: `{"openapi":"3.1.0"}`, UpdatedAt: base}
		require.NoError(t, tx.PutOpenAPIDoc(ctx, doc))
		got, err := tx.GetOpenAPIDoc(ctx, "pay")
		require.NoError(t, err)
		assert.Equal(t, doc, got)
		doc.Body, doc.UpdatedAt = `{"openapi":"3.1.1"}`, base.Add(time.Hour)
		require.NoError(t, tx.PutOpenAPIDoc(ctx, doc))
		all, err := tx.ListOpenAPIDocs(ctx)
		require.NoError(t, err)
		require.Equal(t, []store.OpenAPIDoc{doc}, all, "put replaces")
		require.NoError(t, tx.DeleteOpenAPIDoc(ctx, "pay"))
		assert.ErrorIs(t, tx.DeleteOpenAPIDoc(ctx, "pay"), store.ErrNotFound)

		ca := store.CABundle{ID: "bank-ca", Name: "Bank CA", Subjects: []string{"CN=Bank Root"}, Fingerprint: "cd", PEM: "pem", NotAfter: base.Add(24 * time.Hour), CreatedAt: base}
		require.NoError(t, tx.InsertCABundle(ctx, ca))
		assert.ErrorIs(t, tx.InsertCABundle(ctx, ca), store.ErrConflict)
		gotCA, err := tx.GetCABundle(ctx, "bank-ca")
		require.NoError(t, err)
		assert.Equal(t, ca, gotCA)
		cas, err := tx.ListCABundles(ctx)
		require.NoError(t, err)
		assert.Len(t, cas, 1)
		require.NoError(t, tx.DeleteCABundle(ctx, "bank-ca"))
		_, err = tx.GetCABundle(ctx, "bank-ca")
		assert.ErrorIs(t, err, store.ErrNotFound)
		return nil
	})
}

func testBans(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		mk := func(id, ip, site string, until time.Duration) store.Ban {
			return store.Ban{ID: id, IP: ip, SiteID: site, Source: store.BanManual, Reason: "r", CreatedBy: "u1", CreatedAt: base, Until: base.Add(until)}
		}
		require.NoError(t, tx.PutBan(ctx, mk("b1", "203.0.113.1", "", time.Hour)))
		require.NoError(t, tx.PutBan(ctx, mk("b2", "203.0.113.1", "shop", 2*time.Hour)))
		require.NoError(t, tx.PutBan(ctx, mk("b3", "2001:db8::1", "", time.Minute)))
		require.NoError(t, tx.PutBan(ctx, mk("b4", "203.0.113.9", "", -time.Minute)))

		got, err := tx.GetBan(ctx, "b2")
		require.NoError(t, err)
		assert.Equal(t, mk("b2", "203.0.113.1", "shop", 2*time.Hour), got)

		// The same (ip, site) replaces the row: extending a ban is an upsert.
		ext := mk("b5", "203.0.113.1", "", 3*time.Hour)
		ext.Source = store.BanAuto
		require.NoError(t, tx.PutBan(ctx, ext))
		_, err = tx.GetBan(ctx, "b1")
		assert.NoError(t, err, "the surviving row keeps its original id")
		got, _ = tx.GetBan(ctx, "b1")
		assert.Equal(t, store.BanAuto, got.Source)
		assert.Equal(t, base.Add(3*time.Hour), got.Until)

		active, err := tx.ListActiveBans(ctx, base)
		require.NoError(t, err)
		ids := []string{}
		for _, b := range active {
			ids = append(ids, b.ID)
		}
		assert.Equal(t, []string{"b3", "b2", "b1"}, ids, "expired bans are excluded; soonest to expire first")

		n, err := tx.DeleteExpiredBans(ctx, base)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
		require.NoError(t, tx.DeleteBan(ctx, "b3"))
		assert.ErrorIs(t, tx.DeleteBan(ctx, "b3"), store.ErrNotFound)
		return nil
	})
	assert.Error(t, failsWith(t, s, func(ctx context.Context, tx store.Tx) error {
		return tx.PutBan(ctx, store.Ban{ID: "x", IP: "1.1.1.1", Source: "weird", Reason: "r", CreatedBy: "u", CreatedAt: base, Until: base})
	}), "unknown ban sources are refused by the schema")
}

func testEventFilters(t *testing.T, s store.Store) {
	mk := func(id string, off int, f func(*store.EventRow)) store.EventRow {
		e := store.EventRow{
			ID: id, TS: base.Add(time.Duration(off) * time.Second), SiteID: "shop", Action: "block", Mode: "block",
			ClientIP: "192.0.2.1", Method: "GET", Host: "Shop.Example.Test", Path: "/index", Status: 403, Body: []byte(`{}`),
		}
		f(&e)
		return e
	}
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		for _, e := range []store.EventRow{
			mk("f1", 1, func(e *store.EventRow) { e.Country, e.Path, e.RuleIDs = "NL", "/Search/Items", []string{"942100"} }),
			mk("f2", 2, func(e *store.EventRow) { e.Country, e.Method, e.Status, e.Mode = "DE", "POST", 200, "detect" }),
			mk("f3", 3, func(e *store.EventRow) { e.Country, e.Path = "", "/100%_done" }),
			mk("f4", 4, func(e *store.EventRow) { e.Country, e.ClientIP = "NL", "198.51.100.7" }),
		} {
			require.NoError(t, tx.InsertEvent(ctx, e))
		}
		ids := func(f store.EventFilter) []string {
			rows, err := tx.ListEvents(ctx, f, store.Cursor{}, 100)
			require.NoError(t, err)
			out := []string{}
			for _, r := range rows {
				out = append(out, r.ID)
			}
			return out
		}
		got, err := tx.GetEvent(ctx, "f1")
		require.NoError(t, err)
		assert.Equal(t, "NL", got.Country, "country round-trips")

		assert.Equal(t, []string{"f4", "f1"}, ids(store.EventFilter{Country: "NL"}))
		assert.Equal(t, []string{"f2"}, ids(store.EventFilter{Method: "POST"}))
		assert.Equal(t, []string{"f2"}, ids(store.EventFilter{Status: 200}))
		assert.Equal(t, []string{"f2"}, ids(store.EventFilter{Mode: "detect"}))
		assert.Equal(t, []string{"f1"}, ids(store.EventFilter{Text: "search/items"}), "path text is case-insensitive")
		assert.Equal(t, []string{"f4", "f3", "f2", "f1"}, ids(store.EventFilter{Text: "shop.example"}), "host text, case-insensitive")
		assert.Equal(t, []string{"f4"}, ids(store.EventFilter{Text: "198.51.100"}), "client address text")
		assert.Equal(t, []string{"f1"}, ids(store.EventFilter{Text: "942100"}), "rule id text")
		assert.Equal(t, []string{"f3"}, ids(store.EventFilter{Text: "100%_"}), "LIKE wildcards in the text are literal")
		assert.Equal(t, []string{"f3"}, ids(store.EventFilter{Text: "%"}), "a percent sign in the text matches only a literal percent sign")
		assert.Equal(t, []string{"f1"}, ids(store.EventFilter{Country: "NL", Text: "search"}), "filters combine")
		return nil
	})
}

func testTopEvents(t *testing.T, s store.Store) {
	tx(t, s, func(ctx context.Context, tx store.Tx) error {
		add := func(id string, off int, site, action, ip, path, cc string) {
			require.NoError(t, tx.InsertEvent(ctx, store.EventRow{
				ID: id, TS: base.Add(time.Duration(off) * time.Second), SiteID: site, Action: action, Mode: "block",
				ClientIP: ip, Method: "GET", Host: "h", Path: path, Status: 403, Body: []byte(`{}`), Country: cc,
			}))
		}
		add("t1", 1, "shop", "block", "192.0.2.1", "/a", "NL")
		add("t2", 2, "shop", "block", "192.0.2.1", "/a", "NL")
		add("t3", 3, "shop", "log", "192.0.2.2", "/b", "")
		add("t4", 4, "blog", "block", "192.0.2.1", "/a", "DE")
		add("t5", 100, "shop", "block", "192.0.2.9", "/late", "FR") // outside the range below

		f := store.EventFilter{From: base, To: base.Add(10 * time.Second)}
		top := func(dim string, f store.EventFilter, limit int) []store.ValueCount {
			got, err := tx.TopEventValues(ctx, dim, f, limit)
			require.NoError(t, err)
			return got
		}
		assert.Equal(t, []store.ValueCount{{Value: "192.0.2.1", Count: 3}, {Value: "192.0.2.2", Count: 1}}, top(store.DimIP, f, 10), "most frequent first, range respected")
		assert.Equal(t, []store.ValueCount{{Value: "/a", Count: 3}, {Value: "/b", Count: 1}}, top(store.DimPath, f, 10))
		assert.Equal(t, []store.ValueCount{{Value: "NL", Count: 2}, {Value: "DE", Count: 1}}, top(store.DimCountry, f, 10), "events with an unknown country are not counted")
		assert.Equal(t, []store.ValueCount{{Value: "shop", Count: 3}, {Value: "blog", Count: 1}}, top(store.DimSite, f, 10))
		assert.Equal(t, []store.ValueCount{{Value: "block", Count: 3}, {Value: "log", Count: 1}}, top(store.DimAction, f, 10))
		assert.Equal(t, []store.ValueCount{{Value: "192.0.2.1", Count: 2}, {Value: "192.0.2.2", Count: 1}}, top(store.DimIP, store.EventFilter{From: f.From, To: f.To, SiteID: "shop"}, 10), "site filter")
		assert.Equal(t, []store.ValueCount{{Value: "192.0.2.1", Count: 3}}, top(store.DimIP, store.EventFilter{From: f.From, To: f.To, Action: "block"}, 1), "action filter and limit")
		_, err := tx.TopEventValues(ctx, "weird", f, 5)
		assert.Error(t, err)
		_, err = tx.TopEventValues(ctx, store.DimIP, store.EventFilter{}, 5)
		assert.Error(t, err, "an unbounded scan is refused")
		return nil
	})
}
