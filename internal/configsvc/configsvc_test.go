package configsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/audit"
	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

var quiet = slog.New(slog.DiscardHandler)

// fakePlane records activations and can be told to fail or to run a hook.
type fakePlane struct {
	mu      sync.Mutex
	calls   []string // snapshot of every activated config, in order
	failOn  func(call int) error
	beforeF func() // runs inside Activate, after the call is recorded
}

func (f *fakePlane) Activate(_ context.Context, root *config.Root) error {
	snap, _ := config.Snapshot(root)
	f.mu.Lock()
	f.calls = append(f.calls, string(snap))
	n := len(f.calls)
	fail, hook := f.failOn, f.beforeF
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if fail != nil {
		return fail(n)
	}
	return nil
}

func (f *fakePlane) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakePlane) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return ""
	}
	return f.calls[len(f.calls)-1]
}

type env struct {
	st    store.Store
	plane *fakePlane
	svc   *Service
	audit *audit.Service
}

// engines yields a SQLite store and, when SHERLOCK_TEST_PG_DSN is set, a
// PostgreSQL one, so the ordering guarantees are exercised on both.
func forEachEngine(t *testing.T, fn func(t *testing.T, newStore func(t *testing.T) store.Store)) {
	t.Run("sqlite", func(t *testing.T) {
		fn(t, func(t *testing.T) store.Store {
			s, err := store.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "c.db"))
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })
			return s
		})
	})
	if dsn := os.Getenv("SHERLOCK_TEST_PG_DSN"); dsn != "" {
		t.Run("postgres", func(t *testing.T) {
			fn(t, func(t *testing.T) store.Store { return pgStore(t, dsn) })
		})
	}
}

func newEnv(t *testing.T, st store.Store) *env {
	t.Helper()
	plane := &fakePlane{}
	a := audit.New(quiet)
	return &env{st: st, plane: plane, audit: a, svc: New(st, a, plane, quiet)}
}

func cfg(t *testing.T, sites ...string) *config.Root {
	t.Helper()
	y := "schema_version: 1\nsites:\n"
	for _, id := range sites {
		y += fmt.Sprintf("  - id: %s\n    hosts: [%s.example.com]\n    tls: { mode: none }\n    upstreams: { targets: [\"10.0.0.1:80\"] }\n", id, id)
	}
	r, err := config.Parse([]byte(y))
	require.NoError(t, err)
	return r
}

func (e *env) apply(t *testing.T, root *config.Root, expected string) (store.ConfigVersion, error) {
	t.Helper()
	return e.svc.Apply(t.Context(), Request{Root: root, Expected: expected, Conditional: true, Actor: Actor{Type: audit.ActorUser, ID: "u1", IP: "192.0.2.1"}, Source: SourceAPI})
}

func (e *env) auditActions(t *testing.T) []string {
	t.Helper()
	var out []string
	require.NoError(t, e.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		all, err := tx.ListAuditAfter(ctx, 0, 1000)
		for _, a := range all {
			out = append(out, a.Action)
		}
		return err
	}))
	return out
}

func (e *env) head(t *testing.T) string {
	t.Helper()
	var h string
	require.NoError(t, e.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
		h, err = tx.ConfigHead(ctx)
		return err
	}))
	return h
}

func TestFirstApplyCreatesTheFirstVersion(t *testing.T) {
	forEachEngine(t, func(t *testing.T, ns func(*testing.T) store.Store) {
		e := newEnv(t, ns(t))
		_, _, err := e.svc.Current(t.Context())
		assert.ErrorIs(t, err, ErrNotFound, "no configuration before the first apply")

		v, err := e.apply(t, cfg(t, "shop"), "")
		require.NoError(t, err)
		assert.True(t, v.Applied)
		assert.Empty(t, v.ParentID)
		assert.Equal(t, SourceAPI, v.Source)
		assert.Equal(t, v.ID, e.head(t))
		assert.Equal(t, v.ID, e.svc.Head())
		assert.Equal(t, 1, e.plane.count())
		assert.Equal(t, []string{"config.apply"}, e.auditActions(t))

		cur, root, err := e.svc.Current(t.Context())
		require.NoError(t, err)
		assert.Equal(t, v.ID, cur.ID)
		assert.Equal(t, "shop", root.Sites[0].ID)

		var sites []store.Site
		require.NoError(t, e.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
			sites, err = tx.ListSites(ctx)
			return err
		}))
		require.Len(t, sites, 1)
		assert.Equal(t, "shop", sites[0].ID)
		assert.Equal(t, "detect", sites[0].Mode)

		rep, err := audit.Verify(t.Context(), e.st)
		require.NoError(t, err)
		assert.Nil(t, rep.Problem)
	})
}

func TestIfMatchIsEnforced(t *testing.T) {
	forEachEngine(t, func(t *testing.T, ns func(*testing.T) store.Store) {
		e := newEnv(t, ns(t))
		v1, err := e.apply(t, cfg(t, "shop"), "")
		require.NoError(t, err)

		_, err = e.svc.Apply(t.Context(), Request{Root: cfg(t, "shop", "blog"), Actor: System, Source: SourceAPI})
		assert.ErrorIs(t, err, ErrPreconditionRequired, "changing an existing config needs If-Match")

		_, err = e.apply(t, cfg(t, "shop", "blog"), "01WRONG")
		assert.ErrorIs(t, err, ErrPreconditionFailed)
		assert.Equal(t, 1, e.plane.count(), "a stale write never reaches the data plane")
		assert.Equal(t, v1.ID, e.head(t))

		v2, err := e.apply(t, cfg(t, "shop", "blog"), v1.ID)
		require.NoError(t, err)
		assert.Equal(t, v1.ID, v2.ParentID)
		assert.Equal(t, 2, e.plane.count())

		_, err = e.apply(t, cfg(t, "shop"), v1.ID)
		assert.ErrorIs(t, err, ErrPreconditionFailed, "v1 is no longer the head")
	})
}

// Acceptance criterion 3: two concurrent writes with the same ETag, one wins.
func TestConcurrentWritesWithTheSameETag(t *testing.T) {
	forEachEngine(t, func(t *testing.T, ns func(*testing.T) store.Store) {
		e := newEnv(t, ns(t))
		v1, err := e.apply(t, cfg(t, "shop"), "")
		require.NoError(t, err)

		const writers = 8
		var ok, stale atomic.Int32
		var wg sync.WaitGroup
		for i := range writers {
			wg.Go(func() {
				_, err := e.apply(t, cfg(t, "shop", fmt.Sprintf("site%d", i)), v1.ID)
				switch {
				case err == nil:
					ok.Add(1)
				case errors.Is(err, ErrPreconditionFailed):
					stale.Add(1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			})
		}
		wg.Wait()
		assert.EqualValues(t, 1, ok.Load(), "exactly one writer wins")
		assert.EqualValues(t, writers-1, stale.Load(), "the rest get 412")
		assert.Equal(t, 2, e.plane.count(), "losers are rejected before activation")
		rep, _ := audit.Verify(t.Context(), e.st)
		assert.Nil(t, rep.Problem)
	})
}

func TestInvalidConfigIsRejectedWithPathsAndNothingChanges(t *testing.T) {
	forEachEngine(t, func(t *testing.T, ns func(*testing.T) store.Store) {
		e := newEnv(t, ns(t))
		v1, err := e.apply(t, cfg(t, "shop"), "")
		require.NoError(t, err)

		bad := cfg(t, "shop")
		bad.Sites[0].Hosts = []string{"Not A Host"}
		_, err = e.apply(t, bad, v1.ID)
		var inv *InvalidError
		require.ErrorAs(t, err, &inv)
		assert.Equal(t, "/sites/0/hosts/0", inv.Errors[0].Path)
		assert.Equal(t, 1, e.plane.count())
		assert.Equal(t, v1.ID, e.head(t))
		assert.Equal(t, []string{"config.apply", "config.apply_failed"}, e.auditActions(t), "the rejected attempt is audited")
	})
}

func TestActivationFailureSavesNothing(t *testing.T) {
	forEachEngine(t, func(t *testing.T, ns func(*testing.T) store.Store) {
		e := newEnv(t, ns(t))
		v1, err := e.apply(t, cfg(t, "shop"), "")
		require.NoError(t, err)
		e.plane.failOn = func(int) error { return errors.New("caddy: no such certificate") }

		_, err = e.apply(t, cfg(t, "shop", "blog"), v1.ID)
		require.ErrorIs(t, err, ErrActivation)
		assert.Contains(t, err.Error(), "no such certificate")
		assert.Equal(t, v1.ID, e.head(t), "the head did not move")
		assert.Equal(t, v1.ID, e.svc.Head())
		assert.True(t, e.svc.Ready())
		vs, _ := e.svc.Versions(t.Context(), store.Cursor{}, 10)
		assert.Len(t, vs, 1, "no version row for a configuration that was never live")
		assert.Equal(t, []string{"config.apply", "config.apply_failed"}, e.auditActions(t))
	})
}

// The risky window: the data plane accepted the change but the commit failed
// (here because another process moved the head). The previous configuration
// must be restored and the head left untouched.
func TestCommitFailureRestoresThePreviousConfiguration(t *testing.T) {
	forEachEngine(t, func(t *testing.T, ns func(*testing.T) store.Store) {
		e := newEnv(t, ns(t))
		v1, err := e.apply(t, cfg(t, "shop"), "")
		require.NoError(t, err)
		before := e.plane.last()

		// Another process commits a different version while we are activating.
		e.plane.beforeF = func() {
			if e.plane.count() != 2 {
				return
			}
			require.NoError(t, e.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
				require.NoError(t, tx.InsertConfigVersion(ctx, store.ConfigVersion{
					ID: "intruder", ParentID: v1.ID, CreatedAt: v1.CreatedAt, AuthorType: "user",
					AuthorID: "x", Source: "api", SchemaVersion: 1, Snapshot: []byte(`{}`), Diff: []byte(`{}`), Applied: true,
				}))
				ok, err := tx.CompareAndSetConfigHead(ctx, v1.ID, "intruder")
				require.True(t, ok)
				return err
			}))
		}
		_, err = e.apply(t, cfg(t, "shop", "blog"), v1.ID)
		require.ErrorIs(t, err, ErrPreconditionFailed)

		assert.Equal(t, 3, e.plane.count(), "activated the change, then re-activated the previous configuration")
		assert.Equal(t, before, e.plane.last(), "the data plane is back on what it ran before")
		assert.True(t, e.svc.Ready())
		assert.Equal(t, "intruder", e.head(t), "we never moved the head")
		vs, _ := e.svc.Versions(t.Context(), store.Cursor{}, 10)
		assert.Len(t, vs, 2, "no row for the rolled-back attempt (v1 and the intruder)")
	})
}

func TestFailedRestoreMakesTheNodeNotReady(t *testing.T) {
	forEachEngine(t, func(t *testing.T, ns func(*testing.T) store.Store) {
		e := newEnv(t, ns(t))
		v1, err := e.apply(t, cfg(t, "shop"), "")
		require.NoError(t, err)
		e.plane.beforeF = func() {
			if e.plane.count() != 2 {
				return
			}
			require.NoError(t, e.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
				_ = tx.InsertConfigVersion(ctx, store.ConfigVersion{
					ID: "x", ParentID: v1.ID, CreatedAt: v1.CreatedAt, AuthorType: "user", AuthorID: "x",
					Source: "api", SchemaVersion: 1, Snapshot: []byte(`{}`), Diff: []byte(`{}`), Applied: true,
				})
				_, err := tx.CompareAndSetConfigHead(ctx, v1.ID, "x")
				return err
			}))
		}
		e.plane.failOn = func(n int) error {
			if n == 3 {
				return errors.New("cannot restore")
			}
			return nil
		}
		_, err = e.apply(t, cfg(t, "shop", "blog"), v1.ID)
		require.ErrorIs(t, err, ErrPreconditionFailed)
		assert.False(t, e.svc.Ready(), "running something that was not saved: readiness must say so")
	})
}

func TestNoOpApplyReturnsTheSameVersion(t *testing.T) {
	forEachEngine(t, func(t *testing.T, ns func(*testing.T) store.Store) {
		e := newEnv(t, ns(t))
		v1, err := e.apply(t, cfg(t, "shop"), "")
		require.NoError(t, err)
		again, err := e.apply(t, cfg(t, "shop"), v1.ID)
		require.NoError(t, err)
		assert.Equal(t, v1.ID, again.ID)
		assert.Equal(t, 1, e.plane.count(), "an identical configuration is not re-activated")
		assert.Equal(t, []string{"config.apply"}, e.auditActions(t), "and writes no new audit row")
	})
}

// Acceptance criterion 4.
func TestRollbackCreatesAnAuditedNewVersion(t *testing.T) {
	forEachEngine(t, func(t *testing.T, ns func(*testing.T) store.Store) {
		e := newEnv(t, ns(t))
		v1, _ := e.apply(t, cfg(t, "shop"), "")
		v2, err := e.apply(t, cfg(t, "shop", "blog"), v1.ID)
		require.NoError(t, err)
		v3, err := e.apply(t, cfg(t, "shop", "blog", "api"), v2.ID)
		require.NoError(t, err)

		_, err = e.svc.Rollback(t.Context(), v1.ID, Request{Actor: System})
		assert.ErrorIs(t, err, ErrPreconditionRequired)
		_, err = e.svc.Rollback(t.Context(), v1.ID, Request{Expected: v2.ID, Conditional: true, Actor: System})
		assert.ErrorIs(t, err, ErrPreconditionFailed, "rollback honours If-Match like any other change")

		rb, err := e.svc.Rollback(t.Context(), v1.ID, Request{Expected: v3.ID, Conditional: true, Actor: Actor{Type: audit.ActorUser, ID: "admin"}})
		require.NoError(t, err)
		assert.Equal(t, SourceRollback, rb.Source)
		assert.NotEqual(t, v1.ID, rb.ID, "history stays linear: a rollback is a new version")
		assert.Equal(t, v3.ID, rb.ParentID)
		assert.Equal(t, string(v1.Snapshot), string(rb.Snapshot), "with the old snapshot")
		assert.Equal(t, rb.ID, e.head(t))
		assert.Equal(t, v1.Snapshot, []byte(e.plane.last()))
		assert.Equal(t, "config.rollback", e.auditActions(t)[len(e.auditActions(t))-1])

		_, err = e.svc.Rollback(t.Context(), "nope", Request{Expected: rb.ID, Conditional: true, Actor: System})
		assert.ErrorIs(t, err, ErrNotFound)

		vs, err := e.svc.Versions(t.Context(), store.Cursor{}, 2)
		require.NoError(t, err)
		require.Len(t, vs, 2)
		assert.Equal(t, rb.ID, vs[0].ID, "newest first")
	})
}

func TestBootActivatesTheStoredHead(t *testing.T) {
	forEachEngine(t, func(t *testing.T, ns func(*testing.T) store.Store) {
		st := ns(t)
		first := newEnv(t, st)
		v1, err := first.apply(t, cfg(t, "shop", "blog"), "")
		require.NoError(t, err)

		// A fresh process on the same database.
		second := newEnv(t, st)
		require.NoError(t, second.svc.Boot(t.Context()))
		assert.Equal(t, 1, second.plane.count())
		assert.Equal(t, first.plane.last(), second.plane.last(), "boot restores exactly what was last saved")
		assert.Equal(t, v1.ID, second.svc.Head())
		assert.True(t, second.svc.Ready())

		empty := newEnv(t, ns(t))
		require.NoError(t, empty.svc.Boot(t.Context()))
		assert.Zero(t, empty.plane.count(), "an empty database activates nothing: no default config")
	})
}

func TestBootFailureIsReportedAndMarksTheNodeNotReady(t *testing.T) {
	forEachEngine(t, func(t *testing.T, ns func(*testing.T) store.Store) {
		st := ns(t)
		_, err := newEnv(t, st).apply(t, cfg(t, "shop"), "")
		require.NoError(t, err)

		e := newEnv(t, st)
		e.plane.failOn = func(int) error { return errors.New("port in use") }
		require.ErrorContains(t, e.svc.Boot(t.Context()), "port in use")
		assert.False(t, e.svc.Ready())

		// A snapshot that no longer parses is reported, not silently skipped.
		require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
			head, _ := tx.ConfigHead(ctx)
			return tx.InsertConfigVersion(ctx, store.ConfigVersion{
				ID: "z" + head, ParentID: head, CreatedAt: newEnvNow(), AuthorType: "user", AuthorID: "x",
				Source: "api", SchemaVersion: 9, Snapshot: []byte(`{"schema_version":9}`), Diff: []byte(`{}`), Applied: true,
			})
		}))
		require.NoError(t, st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
			head, _ := tx.ConfigHead(ctx)
			_, err := tx.CompareAndSetConfigHead(ctx, head, "z"+head)
			return err
		}))
		broken := newEnv(t, st)
		require.ErrorContains(t, broken.svc.Boot(t.Context()), "unusable")
		assert.False(t, broken.svc.Ready())
	})
}

func TestDiffNamesWhatChanged(t *testing.T) {
	old := cfg(t, "shop", "blog")
	next := cfg(t, "shop", "api")
	next.Sites[0].Policy.Mode = ptr(config.ModeBlock)
	d, err := Diff(old, next)
	require.NoError(t, err)
	assert.JSONEq(t, `{"global":false,"sites":{"added":["api"],"removed":["blog"],"changed":[{"site":"shop","fields":["policy"]}]}}`, string(d))

	first, err := Diff(nil, next)
	require.NoError(t, err)
	assert.JSONEq(t, `{"global":true,"sites":{"added":["api","shop"],"removed":[],"changed":[]}}`, string(first))

	next.Global.TrustedProxies = []string{"10.0.0.0/8"}
	d, _ = Diff(old, next)
	var parsed struct{ Global bool }
	require.NoError(t, json.Unmarshal(d, &parsed))
	assert.True(t, parsed.Global)
}

// A site called "token" or "key" must not trip the audit credential guard.
func TestUserChosenNamesNeverTripTheAuditGuard(t *testing.T) {
	forEachEngine(t, func(t *testing.T, ns func(*testing.T) store.Store) {
		e := newEnv(t, ns(t))
		v1, err := e.apply(t, cfg(t, "token"), "")
		require.NoError(t, err)
		_, err = e.apply(t, cfg(t, "token", "key", "password"), v1.ID)
		require.NoError(t, err)
	})
}

func TestETagHelpers(t *testing.T) {
	assert.Equal(t, `"01J"`, ETag("01J"))
	id, present, err := ParseIfMatch(`"01J"`)
	require.NoError(t, err)
	assert.True(t, present)
	assert.Equal(t, "01J", id)
	_, present, err = ParseIfMatch("")
	require.NoError(t, err)
	assert.False(t, present)
	for _, bad := range []string{`W/"01J"`, `"a", "b"`, `*`, `01J`, `"`} {
		_, present, err := ParseIfMatch(bad)
		require.Error(t, err, bad)
		assert.True(t, present, bad)
	}
}

// Acceptance criterion 9: an exported configuration imported elsewhere compiles to the same Caddy JSON.
func TestExportImportReproducesTheCompiledConfig(t *testing.T) {
	root := cfg(t, "shop", "blog")
	root.Global.TrustedProxies = []string{"10.0.0.0/8"}
	root.Sites[0].Policy.Mode = ptr(config.ModeBlock)
	root.Sites[0].Endpoints = []config.Endpoint{{ID: "login", Match: config.EndpointMatch{Path: "/login", Methods: []string{"POST"}}}}

	root.ApplyDefaults() // Apply does this before activating; compile what the node would actually run
	want, err := compiler.Compile(root, compiler.Options{DataDir: "/var/lib/sherlock"})
	require.NoError(t, err)
	snap, err := config.Snapshot(root)
	require.NoError(t, err)
	imported, err := config.FromSnapshot(snap)
	require.NoError(t, err)
	got, err := compiler.Compile(imported, compiler.Options{DataDir: "/var/lib/sherlock"})
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got))
}

func ptr[T any](v T) *T { return &v }
