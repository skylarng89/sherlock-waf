package ids

import (
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	re := regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	earlier, err := New(time.UnixMilli(1_700_000_000_000))
	require.NoError(t, err)
	later, err := New(time.UnixMilli(1_700_000_001_000))
	require.NoError(t, err)
	assert.Regexp(t, re, earlier)
	assert.Regexp(t, re, later)
	assert.Less(t, earlier, later, "ULIDs sort by time")

	seen := map[string]bool{}
	for range 1000 {
		id, err := New(time.Now())
		require.NoError(t, err)
		assert.False(t, seen[id])
		seen[id] = true
	}
}

// A known vector: timestamp 0 with zero entropy would be all zeros; the
// timestamp part of a real ULID decodes back to the input.
func TestEventIDTimestampPrefix(t *testing.T) {
	id, err := New(time.UnixMilli(0))
	require.NoError(t, err)
	assert.Equal(t, "0000000000", id[:10])
	id, err = New(time.UnixMilli(1))
	require.NoError(t, err)
	assert.Equal(t, "0000000001", id[:10])
}
