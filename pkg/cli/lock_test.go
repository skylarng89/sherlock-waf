package cli_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/ops"
)

// holdLock stands in for a running server, which holds the data-dir lock.
func holdLock(t *testing.T, dir string) func() {
	t.Helper()
	release, err := ops.Lock(dir)
	require.NoError(t, err)
	return release
}
