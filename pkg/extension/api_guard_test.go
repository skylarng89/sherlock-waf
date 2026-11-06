package extension_test

import (
	"testing"

	"github.com/skylarng89/sherlock-waf/internal/apiguard"
)

// TestAPIGuard fails when the exported API of pkg/extension changes without a
// matching update of testdata/api.txt (go test ./pkg/extension -run APIGuard -update).
func TestAPIGuard(t *testing.T) { apiguard.Check(t, ".", "testdata/api.txt") }
