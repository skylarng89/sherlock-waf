package exporters

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func recs(from, to int) [][]byte {
	var out [][]byte
	for i := from; i < to; i++ {
		out = append(out, fmt.Appendf(nil, "record-%04d", i))
	}
	return out
}

func drain(t *testing.T, s *Spool, per int) []string {
	t.Helper()
	var got []string
	for {
		b, err := s.Next(per, 1<<20)
		require.NoError(t, err)
		if b.Len() == 0 {
			return got
		}
		for _, r := range b.Records {
			got = append(got, string(r))
		}
		require.NoError(t, s.Ack(b))
	}
}

func TestSpoolRoundTripAcrossSegments(t *testing.T) {
	s, err := OpenSpool(t.TempDir(), SpoolOptions{SegmentBytes: 100})
	require.NoError(t, err)
	defer s.Close()
	_, err = s.Append(recs(0, 50)...)
	require.NoError(t, err)
	assert.Equal(t, 50, s.Stats().Pending)

	got := drain(t, s, 7)
	require.Len(t, got, 50)
	assert.Equal(t, "record-0000", got[0])
	assert.Equal(t, "record-0049", got[49])
	assert.Zero(t, s.Stats().Pending)
}

func TestSpoolNextDoesNotConsumeUntilAck(t *testing.T) {
	s, err := OpenSpool(t.TempDir(), SpoolOptions{})
	require.NoError(t, err)
	defer s.Close()
	_, _ = s.Append(recs(0, 3)...)

	b1, _ := s.Next(2, 1<<20)
	b2, _ := s.Next(2, 1<<20)
	assert.Equal(t, b1.Records, b2.Records, "an unacknowledged batch is returned again")
	require.NoError(t, s.Ack(b1))
	b3, _ := s.Next(5, 1<<20)
	assert.Equal(t, [][]byte{[]byte("record-0002")}, b3.Records)
}

func TestSpoolSurvivesRestartWithCursor(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSpool(dir, SpoolOptions{SegmentBytes: 120})
	require.NoError(t, err)
	_, _ = s.Append(recs(0, 20)...)
	b, _ := s.Next(8, 1<<20)
	require.NoError(t, s.Ack(b))
	require.NoError(t, s.Close())

	s, err = OpenSpool(dir, SpoolOptions{SegmentBytes: 120})
	require.NoError(t, err)
	defer s.Close()
	assert.Equal(t, 12, s.Stats().Pending)
	got := drain(t, s, 100)
	assert.Equal(t, "record-0008", got[0], "delivery resumes after the acknowledged records")
	assert.Len(t, got, 12)
}

func TestSpoolTruncatesTornTail(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSpool(dir, SpoolOptions{})
	require.NoError(t, err)
	_, _ = s.Append(recs(0, 3)...)
	require.NoError(t, s.Close())

	segs, _ := filepath.Glob(filepath.Join(dir, "*"+segSuffix))
	require.Len(t, segs, 1)
	f, err := os.OpenFile(segs[0], os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)
	_, _ = f.Write([]byte{0, 0, 0, 40, 1, 2, 3, 4, 'x'}) // header promises 40 bytes, one arrives
	require.NoError(t, f.Close())

	s, err = OpenSpool(dir, SpoolOptions{})
	require.NoError(t, err)
	defer s.Close()
	assert.Len(t, drain(t, s, 10), 3, "the three whole records survive; the torn one is cut")
	_, err = s.Append([]byte("after"))
	require.NoError(t, err)
	assert.Equal(t, []string{"after"}, drain(t, s, 10), "appending after repair works")
}

func TestSpoolRejectsCorruptRecord(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenSpool(dir, SpoolOptions{})
	require.NoError(t, err)
	_, _ = s.Append(recs(0, 2)...)
	require.NoError(t, s.Close())

	segs, _ := filepath.Glob(filepath.Join(dir, "*"+segSuffix))
	b, _ := os.ReadFile(segs[0])
	b[len(b)-1] ^= 0xff                                 // flip a payload bit of the last record
	require.NoError(t, os.WriteFile(segs[0], b, 0o600)) //nolint:gosec // segment found by glob inside t.TempDir()

	s, err = OpenSpool(dir, SpoolOptions{})
	require.NoError(t, err)
	defer s.Close()
	assert.Equal(t, []string{"record-0000"}, drain(t, s, 10), "the checksum catches the damaged record")
}

func TestSpoolEvictsOldestWhenFullAndCounts(t *testing.T) {
	s, err := OpenSpool(t.TempDir(), SpoolOptions{MaxBytes: 600, SegmentBytes: 100})
	require.NoError(t, err)
	defer s.Close()
	evicted, err := s.Append(recs(0, 100)...)
	require.NoError(t, err)

	st := s.Stats()
	assert.LessOrEqual(t, st.Bytes, int64(600)+100, "bounded by the cap plus at most the active segment")
	assert.Positive(t, evicted)
	assert.EqualValues(t, evicted, st.Dropped)
	assert.Equal(t, 100-evicted, st.Pending)

	got := drain(t, s, 10)
	assert.Len(t, got, 100-evicted)
	assert.Equal(t, "record-0099", got[len(got)-1], "the newest records are kept")
}

func TestSpoolEvictionCountsOnlyUnsentRecords(t *testing.T) {
	s, err := OpenSpool(t.TempDir(), SpoolOptions{MaxBytes: 500, SegmentBytes: 100})
	require.NoError(t, err)
	defer s.Close()
	_, _ = s.Append(recs(0, 6)...)
	b, _ := s.Next(6, 1<<20)
	require.NoError(t, s.Ack(b))
	evicted, _ := s.Append(recs(6, 7)...)
	assert.Zero(t, evicted, "acknowledged records are not counted as lost")
	assert.Zero(t, s.Stats().Dropped)
}

func TestSpoolRefusesOversizedRecord(t *testing.T) {
	s, err := OpenSpool(t.TempDir(), SpoolOptions{})
	require.NoError(t, err)
	defer s.Close()
	_, err = s.Append(make([]byte, MaxRecordBytes+1))
	assert.ErrorIs(t, err, ErrRecordTooLarge)
}
