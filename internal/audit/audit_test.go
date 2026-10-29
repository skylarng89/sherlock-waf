package audit

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

var quiet = slog.New(slog.DiscardHandler)

type fixture struct {
	st   store.Store
	path string
	svc  *Service
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	st, err := store.OpenSQLite(t.Context(), path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	svc := New(quiet)
	n := 0
	svc.now = func() time.Time { n++; return time.Date(2026, 10, 29, 9, 0, n, 111111000, time.UTC) }
	return fixture{st: st, path: path, svc: svc}
}

func (f fixture) record(t *testing.T, action string, details any) {
	t.Helper()
	require.NoError(t, f.svc.Record(t.Context(), f.st, Input{ActorType: ActorUser, ActorID: "u1", IP: "192.0.2.1", Action: action, ObjectType: "site", ObjectID: "shop", Details: details}))
}

func (f fixture) fill(t *testing.T, n int) {
	t.Helper()
	for i := range n {
		f.record(t, fmt.Sprintf("test.action_%d", i), map[string]any{"i": i, "note": "ok"})
	}
}

// raw runs SQL straight against the database file, the way an attacker (or a
// careless operator) with write access would.
func (f fixture) raw(t *testing.T, stmt string, args ...any) {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+f.path+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.ExecContext(t.Context(), stmt, args...)
	require.NoError(t, err)
}

func TestChainBuildsAndVerifies(t *testing.T) {
	f := newFixture(t)
	rep, err := Verify(t.Context(), f.st)
	require.NoError(t, err)
	assert.Nil(t, rep.Problem, "an empty log is valid")
	assert.Zero(t, rep.Entries)

	f.fill(t, 25)
	rep, err = Verify(t.Context(), f.st)
	require.NoError(t, err)
	assert.Nil(t, rep.Problem)
	assert.Equal(t, 25, rep.Entries)
	assert.EqualValues(t, 25, rep.Head.Seq)

	c, err := Head(t.Context(), f.st)
	require.NoError(t, err)
	assert.EqualValues(t, 25, c.Seq)
	assert.Equal(t, rep.Head.Hash, c.Hash)
}

// A pinned vector: changing the encoding silently would invalidate every
// existing log, so any change here must be deliberate (bump the domain string).
func TestHashGolden(t *testing.T) {
	e := store.AuditEntry{
		Seq: 7, ID: "01JB0000000000000000000000", At: time.Date(2026, 10, 29, 9, 0, 0, 123456000, time.UTC),
		ActorType: "user", ActorID: "u1", IP: "192.0.2.1", Action: "config.apply", ObjectType: "config", ObjectID: "v1",
		Details: []byte(`{"version":"v1"}`), PrevHash: "abc",
	}
	// Cross-checked against an independent implementation of the documented encoding.
	assert.Equal(t, "62704459338776960a39900906319073b0500891e437b419a8c27171ddd3249e", Hash(e))
}

func TestHashCoversEveryField(t *testing.T) {
	base := store.AuditEntry{
		Seq: 1, ID: "id", At: time.UnixMicro(1_000_000).UTC(), ActorType: "user", ActorID: "a", IP: "i", Action: "x",
		ObjectType: "o", ObjectID: "1", Details: []byte(`{}`), PrevHash: "p",
	}
	want := Hash(base)
	mut := map[string]func(*store.AuditEntry){
		"seq":         func(e *store.AuditEntry) { e.Seq++ },
		"id":          func(e *store.AuditEntry) { e.ID += "x" },
		"at":          func(e *store.AuditEntry) { e.At = e.At.Add(time.Microsecond) },
		"actor type":  func(e *store.AuditEntry) { e.ActorType = "token" },
		"actor id":    func(e *store.AuditEntry) { e.ActorID += "x" },
		"ip":          func(e *store.AuditEntry) { e.IP += "x" },
		"action":      func(e *store.AuditEntry) { e.Action += "x" },
		"object type": func(e *store.AuditEntry) { e.ObjectType += "x" },
		"object id":   func(e *store.AuditEntry) { e.ObjectID += "x" },
		"details":     func(e *store.AuditEntry) { e.Details = []byte(`{"a":1}`) },
		"prev hash":   func(e *store.AuditEntry) { e.PrevHash += "x" },
	}
	for name, fn := range mut {
		e := base
		fn(&e)
		assert.NotEqual(t, want, Hash(e), "changing %s must change the hash", name)
	}
	e := base
	e.Hash = "ignored"
	assert.Equal(t, want, Hash(e), "the stored hash is not part of its own input")
}

func TestFieldBoundariesAreUnambiguous(t *testing.T) {
	a := store.AuditEntry{Seq: 1, ID: "i", At: time.UnixMicro(1), ActorType: "user", ActorID: "ab", Action: "c", Details: []byte(`{}`)}
	b := a
	b.ActorID, b.Action = "a", "bc"
	assert.NotEqual(t, Hash(a), Hash(b), "length prefixes keep ('ab','c') apart from ('a','bc')")
}

func TestTamperingIsDetectedWhereItHappens(t *testing.T) {
	cases := []struct {
		name    string
		tamper  func(t *testing.T, f fixture)
		wantSeq int64
		wantMsg string
	}{
		{"edit details", func(t *testing.T, f fixture) {
			f.raw(t, `UPDATE audit_log SET details = '{"i":99}' WHERE seq = 6`)
		}, 6, "altered"},
		{"edit actor", func(t *testing.T, f fixture) {
			f.raw(t, `UPDATE audit_log SET actor_id = 'mallory' WHERE seq = 3`)
		}, 3, "altered"},
		{"edit timestamp", func(t *testing.T, f fixture) {
			f.raw(t, `UPDATE audit_log SET at = at + 1 WHERE seq = 9`)
		}, 9, "altered"},
		{"edit and recompute that one hash", func(t *testing.T, f fixture) {
			// Even a careful edit that fixes the entry's own hash breaks the next link.
			e := f.entry(t, 4)
			e.Action = "innocent.action"
			f.raw(t, `UPDATE audit_log SET action = ?, hash = ? WHERE seq = 4`, e.Action, Hash(e))
		}, 5, "previous entry"},
		{"delete a middle row", func(t *testing.T, f fixture) {
			f.raw(t, `DELETE FROM audit_log WHERE seq = 5`)
		}, 5, "removed"},
		{"delete the newest rows", func(t *testing.T, f fixture) {
			f.raw(t, `DELETE FROM audit_log WHERE seq > 8`)
		}, 9, "newest entries were removed"},
		{"point at another entry", func(t *testing.T, f fixture) {
			f.raw(t, `UPDATE audit_log SET prev_hash = (SELECT hash FROM audit_log WHERE seq = 1) WHERE seq = 7`)
		}, 7, "previous entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.fill(t, 10)
			tc.tamper(t, f)
			rep, err := Verify(t.Context(), f.st)
			require.NoError(t, err)
			require.NotNil(t, rep.Problem, "tampering must be detected")
			assert.Equal(t, tc.wantSeq, rep.Problem.Seq)
			assert.Contains(t, rep.Problem.Reason, tc.wantMsg)
			assert.Contains(t, rep.Problem.Error(), fmt.Sprint(tc.wantSeq))
		})
	}
}

// The limit stated in the package comment, as a test: someone who can write the
// database and recompute every hash from the edit onwards (and the head) is not detected.
func TestHonestLimitRewritingTheTailIsNotDetectable(t *testing.T) {
	f := newFixture(t)
	f.fill(t, 5)
	all := f.all(t)
	prev := all[2].Hash
	var newest store.AuditEntry
	for _, e := range all[3:] {
		e.PrevHash = prev
		e.Action = "forged." + e.Action
		e.Hash = Hash(e)
		f.raw(t, `UPDATE audit_log SET action = ?, prev_hash = ?, hash = ? WHERE seq = ?`, e.Action, e.PrevHash, e.Hash, e.Seq)
		prev, newest = e.Hash, e
	}
	f.raw(t, `UPDATE audit_head SET hash = ? WHERE id = 1`, newest.Hash)
	rep, err := Verify(t.Context(), f.st)
	require.NoError(t, err)
	assert.Nil(t, rep.Problem, "a full tail rewrite is only caught by a checkpoint kept elsewhere")
}

func (f fixture) all(t *testing.T) []store.AuditEntry {
	t.Helper()
	var out []store.AuditEntry
	require.NoError(t, f.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) (err error) {
		out, err = tx.ListAuditAfter(ctx, 0, 1000)
		return err
	}))
	return out
}

func (f fixture) entry(t *testing.T, seq int) store.AuditEntry { return f.all(t)[seq-1] }

func TestConcurrentWritersKeepOneValidChain(t *testing.T) {
	f := newFixture(t)
	f.svc.now = time.Now // real clock; ordering comes from seq, not time
	const writers, each = 8, 10
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			for i := range each {
				if err := f.svc.Record(t.Context(), f.st, Input{ActorType: ActorSystem, ActorID: "s", Action: fmt.Sprintf("w%d.%d", w, i)}); err != nil {
					t.Errorf("writer %d: %v", w, err)
					return
				}
			}
		})
	}
	wg.Wait()
	rep, err := Verify(t.Context(), f.st)
	require.NoError(t, err)
	assert.Nil(t, rep.Problem)
	assert.Equal(t, writers*each, rep.Entries)
}

func TestAppendRollsBackWithTheChange(t *testing.T) {
	f := newFixture(t)
	f.fill(t, 2)
	boom := errors.New("business change failed")
	err := f.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		if _, err := f.svc.Append(ctx, tx, Input{ActorType: ActorUser, ActorID: "u", Action: "config.apply"}); err != nil {
			return err
		}
		return boom
	})
	require.ErrorIs(t, err, boom)

	c, err := Head(t.Context(), f.st)
	require.NoError(t, err)
	assert.EqualValues(t, 2, c.Seq, "the audit row and the head move back with the failed transaction")
	rep, _ := Verify(t.Context(), f.st)
	assert.Nil(t, rep.Problem)
	f.fill(t, 1)
	rep, _ = Verify(t.Context(), f.st)
	assert.Nil(t, rep.Problem, "the sequence continues without a gap")
	assert.Equal(t, 3, rep.Entries)
}

func TestCredentialsAreRefusedInDetails(t *testing.T) {
	f := newFixture(t)
	bad := []any{
		map[string]any{"password": "x"},
		map[string]any{"user": map[string]any{"new_password": "x"}},
		map[string]any{"items": []any{map[string]any{"api_key": "x"}}},
		map[string]any{"token": "shk_abc"},
		map[string]any{"Authorization": "Bearer x"},
		struct {
			TOTPSecret string `json:"totp_secret"`
		}{"x"},
		map[string]any{"session_id": "x"},
	}
	for _, d := range bad {
		err := f.svc.Record(t.Context(), f.st, Input{ActorType: ActorUser, ActorID: "u", Action: "x", Details: d})
		assert.ErrorIs(t, err, ErrSecretInDetails, "%v", d)
	}
	ok := []any{nil, map[string]any{"token_id": "01J", "key_count": 3, "role": "admin", "site": "shop"}, "plain string", []int{1, 2}}
	for _, d := range ok {
		require.NoError(t, f.svc.Record(t.Context(), f.st, Input{ActorType: ActorUser, ActorID: "u", Action: "x", Details: d}), "%v", d)
	}
	c, _ := Head(t.Context(), f.st)
	assert.EqualValues(t, len(ok), c.Seq, "refused entries leave no trace in the log")
	assert.True(t, Redacted("API_KEY"))
	assert.False(t, Redacted("object_id"))

	stored := f.all(t)
	assert.JSONEq(t, `{}`, string(stored[0].Details), "nil details are stored as an empty object")
}

type recSink struct {
	mu   sync.Mutex
	got  []extension.AuditRecord
	fail error
	boom bool
}

func (r *recSink) Deliver(_ context.Context, rec extension.AuditRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.boom {
		panic("sink exploded")
	}
	r.got = append(r.got, rec)
	return r.fail
}

func TestSinksSeeCommittedRecordsAndCannotBreakTheChain(t *testing.T) {
	f := newFixture(t)
	good, failing, panicking := &recSink{}, &recSink{fail: errors.New("s3 down")}, &recSink{boom: true}
	f.svc.AddSink(failing)
	f.svc.AddSink(panicking)
	f.svc.AddSink(good)

	f.record(t, "first", map[string]any{"a": 1})
	f.record(t, "second", nil)

	require.Len(t, good.got, 2, "later sinks still run after an earlier one fails or panics")
	assert.EqualValues(t, 1, good.got[0].Seq)
	assert.Equal(t, "first", good.got[0].Action)
	assert.JSONEq(t, `{"a":1}`, string(good.got[0].Details))
	assert.Equal(t, good.got[0].Hash, f.entry(t, 1).Hash, "sinks receive the chained record")
	assert.Equal(t, good.got[0].Hash, good.got[1].PrevHash)

	rep, err := Verify(t.Context(), f.st)
	require.NoError(t, err)
	assert.Nil(t, rep.Problem, "a failing sink never fails or alters the audited operation")
}

func TestSinkNotCalledForAFailedTransaction(t *testing.T) {
	f := newFixture(t)
	sink := &recSink{}
	f.svc.AddSink(sink)
	_ = f.st.Tx(t.Context(), func(ctx context.Context, tx store.Tx) error {
		_, err := f.svc.Append(ctx, tx, Input{ActorType: ActorUser, ActorID: "u", Action: "x"})
		require.NoError(t, err)
		return errors.New("rolled back") // the caller never reaches Deliver
	})
	assert.Empty(t, sink.got)
}

// lockedBuffer is a bytes.Buffer safe to read while another goroutine logs into it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestCheckpointerLogsTheHead(t *testing.T) {
	f := newFixture(t)
	f.fill(t, 3)
	var buf lockedBuffer
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		RunCheckpointer(ctx, f.st, slog.New(slog.NewTextHandler(&buf, nil)), 10*time.Millisecond)
		close(done)
	}()
	require.Eventually(t, func() bool { return strings.Contains(buf.String(), "audit checkpoint") }, 2*time.Second, 5*time.Millisecond)
	cancel()
	<-done
	c, _ := Head(t.Context(), f.st)
	assert.Contains(t, buf.String(), c.Hash)
	assert.Contains(t, buf.String(), "seq=3")

	RunCheckpointer(t.Context(), f.st, quiet, 0) // a zero interval returns immediately
}
