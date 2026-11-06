package exporters

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/events"
)

func TestSplitSettings(t *testing.T) {
	rest, n, err := splitSettings(json.RawMessage(`{"url":"https://x","spool_max_mb":64}`))
	require.NoError(t, err)
	assert.EqualValues(t, 64<<20, n)
	assert.JSONEq(t, `{"url":"https://x"}`, string(rest), "the key is stripped before the type sees the settings")

	for _, raw := range []string{``, `null`, `{}`, `{"url":"https://x"}`, `"not an object"`} {
		rest, n, err := splitSettings(json.RawMessage(raw))
		require.NoError(t, err, raw)
		assert.Zero(t, n, raw)
		assert.Equal(t, raw, string(rest), "settings without the key pass through untouched")
	}

	for _, bad := range []string{`1.5`, `"64"`, `15`, `0`, `-1`, `102401`, `null`, `1e2`, `true`} {
		_, _, err := splitSettings(json.RawMessage(`{"spool_max_mb":` + bad + `}`))
		assert.Error(t, err, "spool_max_mb=%s", bad)
	}
	for _, ok := range []string{`16`, `102400`} {
		_, n, err := splitSettings(json.RawMessage(`{"spool_max_mb":` + ok + `}`))
		require.NoError(t, err, ok)
		assert.NotZero(t, n)
	}
}

func TestManagerAppliesSpoolSetting(t *testing.T) {
	m := NewManager(t.Context(), events.NewBus(8), t.TempDir(), fastOpts, quiet)
	require.NoError(t, m.RegisterType(fakeType{exp: &fake{}}))
	defer m.Stop()

	c := Config{ID: "a", Type: "fake", Stream: StreamEvents, Enabled: true}
	require.NoError(t, m.Apply([]Config{c}))
	assert.EqualValues(t, DefaultSpoolBytes, m.Status()[0].SpoolMaxBytes, "default when the key is absent")

	c.Settings = json.RawMessage(`{"spool_max_mb":32}`)
	require.NoError(t, m.Validate(c))
	require.NoError(t, m.Apply([]Config{c}))
	assert.EqualValues(t, 32<<20, m.Status()[0].SpoolMaxBytes, "a changed cap restarts the runner with the new limit")

	c.Settings = json.RawMessage(`{"spool_max_mb":8}`)
	assert.ErrorIs(t, m.Validate(c), ErrInvalid)
	assert.ErrorIs(t, m.Test(t.Context(), c), ErrInvalid)
	assert.Error(t, m.Apply([]Config{c}))
}

func TestLoweredSpoolLimitDropsOldestOnNextAppend(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSpool(dir, SpoolOptions{MaxBytes: 64 << 10, SegmentBytes: 4 << 10})
	require.NoError(t, err)
	rec := make([]byte, 1000)
	for range 50 {
		_, err := s.Append(rec)
		require.NoError(t, err)
	}
	require.Greater(t, s.Stats().Bytes, int64(16<<10))
	require.NoError(t, s.Close())

	s, err = OpenSpool(dir, SpoolOptions{MaxBytes: 16 << 10, SegmentBytes: 4 << 10})
	require.NoError(t, err)
	defer s.Close()
	evicted, err := s.Append(rec)
	require.NoError(t, err)
	assert.Positive(t, evicted, "the existing backlog is trimmed to the lowered cap")
	assert.LessOrEqual(t, s.Stats().Bytes, int64(16<<10)+4<<10)
	assert.NotZero(t, s.Stats().Dropped, "trimmed records are counted, not silent")
}
