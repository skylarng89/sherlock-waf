package events

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONLWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONLWriter(&buf)
	require.NoError(t, w.Write(&Event{ID: "a", Schema: SchemaV1, Request: Request{Query: "q=<b>&x=1"}}))
	require.NoError(t, w.Write(&Event{ID: "b"}))
	require.NoError(t, w.Flush())
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2)
	var e Event
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &e))
	assert.Equal(t, "q=<b>&x=1", e.Request.Query)
	assert.Contains(t, lines[0], "<b>", "HTML must not be escaped in log lines")
	require.NoError(t, w.Close())
}

func TestRotatingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "events.jsonl")
	r, err := NewRotatingFile(path, 100, 2)
	require.NoError(t, err)
	line := strings.Repeat("x", 59) + "\n" // 60 bytes: two never fit in 100
	for range 7 {
		_, err := r.Write([]byte(line))
		require.NoError(t, err)
	}
	require.NoError(t, r.Close())

	entries, err := os.ReadDir(filepath.Join(dir, "sub"))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		info, err := e.Info()
		require.NoError(t, err)
		assert.LessOrEqual(t, info.Size(), int64(100))
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	assert.ElementsMatch(t, []string{"events.jsonl", "events.jsonl.1", "events.jsonl.2"}, names, "only `keep` rotated files remain")
	st, err := os.Stat(filepath.Join(dir, "sub"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), st.Mode().Perm())
}

func TestRotatingFileResumesSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.jsonl")
	r, err := NewRotatingFile(path, 100, 1)
	require.NoError(t, err)
	_, _ = r.Write(bytes.Repeat([]byte("a"), 80))
	require.NoError(t, r.Close())
	r, err = NewRotatingFile(path, 100, 1)
	require.NoError(t, err)
	_, _ = r.Write(bytes.Repeat([]byte("b"), 40)) // 80 existing + 40 > 100 -> rotate
	require.NoError(t, r.Close())
	_, err = os.Stat(path + ".1")
	assert.NoError(t, err)
}

func TestRotatingFileErrors(t *testing.T) {
	_, err := NewRotatingFile(filepath.Join(t.TempDir(), "x"), 0, 1)
	require.Error(t, err)
	_, err = NewRotatingFile("/proc/definitely/not/writable/e.jsonl", 10, 1)
	require.Error(t, err)
}

func TestRotatingFileKeepZeroTruncates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.jsonl")
	r, err := NewRotatingFile(path, 50, 0)
	require.NoError(t, err)
	for range 5 {
		_, err = r.Write(bytes.Repeat([]byte("z"), 40))
		require.NoError(t, err)
	}
	require.NoError(t, r.Close())
	_, err = os.Stat(path + ".1")
	assert.True(t, os.IsNotExist(err))
}

type memSink struct {
	mu      sync.Mutex
	ids     []string
	flushes int
}

func (m *memSink) Write(ev *Event) error {
	m.mu.Lock()
	m.ids = append(m.ids, ev.ID)
	m.mu.Unlock()
	return nil
}
func (m *memSink) Flush() error { m.mu.Lock(); m.flushes++; m.mu.Unlock(); return nil }
func (m *memSink) Close() error { return nil }
func (m *memSink) count() int   { m.mu.Lock(); defer m.mu.Unlock(); return len(m.ids) }

func TestDrainDeliversAndFinalFlush(t *testing.T) {
	b := NewBus(1024)
	sub := b.Subscribe(false)
	sink := &memSink{}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { Drain(ctx, sub, 10*time.Millisecond, sink); close(done) }()

	for i := range 300 {
		b.Publish(ev(i))
	}
	require.Eventually(t, func() bool { return sink.count() == 300 }, 3*time.Second, 5*time.Millisecond)
	for i := range 5 {
		b.Publish(ev(1000 + i))
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Drain did not return")
	}
	assert.Equal(t, 305, sink.count(), "events published before cancel are drained")
	assert.Positive(t, sink.flushes)
}

func TestDrainWritesFileEndToEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	rf, err := NewRotatingFile(path, 1<<20, 1)
	require.NoError(t, err)
	sink := NewJSONLWriter(rf)
	b := NewBus(64)
	sub := b.Subscribe(false)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { Drain(ctx, sub, 5*time.Millisecond, sink); close(done) }()
	b.Publish(&Event{ID: "one", Schema: SchemaV1})
	b.Publish(&Event{ID: "two", Schema: SchemaV1})
	cancel()
	<-done
	require.NoError(t, sink.Close())

	f, err := os.Open(path) //nolint:gosec // test temp path
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	var got []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		require.NoError(t, json.Unmarshal(sc.Bytes(), &e))
		got = append(got, e.ID)
	}
	assert.Equal(t, []string{"one", "two"}, got)
}

// recordingWriter remembers each Write call separately.
type recordingWriter struct{ calls [][]byte }

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.calls = append(r.calls, append([]byte(nil), p...))
	return len(p), nil
}

// TestJSONLWriterNeverSplitsALine is the invariant tailers rely on: every
// write reaching the file is a whole number of complete JSON lines, however
// large the batch, because a reader can observe the file between any two writes.
func TestJSONLWriterNeverSplitsALine(t *testing.T) {
	rec := &recordingWriter{}
	w := NewJSONLWriter(rec)
	big := strings.Repeat("x", 9000) // events of varying size straddle batch boundaries
	for i := range 400 {
		ev := &Event{ID: strconv.Itoa(i), Schema: SchemaV1}
		if i%3 == 0 {
			ev.Request.Query = big
		}
		require.NoError(t, w.Write(ev))
	}
	require.NoError(t, w.Flush())

	require.Greater(t, len(rec.calls), 1, "the batch limit must have triggered intermediate writes")
	var total int
	for i, c := range rec.calls {
		assert.Equal(t, byte('\n'), c[len(c)-1], "write %d does not end on a line boundary", i)
		for _, line := range bytes.Split(bytes.TrimSuffix(c, []byte("\n")), []byte("\n")) {
			var e Event
			require.NoError(t, json.Unmarshal(line, &e), "write %d holds a partial line", i)
			total++
		}
	}
	assert.Equal(t, 400, total)
}

func TestJSONLWriterFlushWithNothingPending(t *testing.T) {
	rec := &recordingWriter{}
	w := NewJSONLWriter(rec)
	require.NoError(t, w.Flush())
	assert.Empty(t, rec.calls)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestJSONLWriterReportsWriteErrors(t *testing.T) {
	w := NewJSONLWriter(failingWriter{})
	require.NoError(t, w.Write(&Event{ID: "a"}))
	err := w.Flush()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")
	require.NoError(t, w.Flush(), "a failed batch is dropped, not retried forever")
}
