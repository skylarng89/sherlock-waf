package policy

import (
	"context"
	"net/netip"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecisionLifecycle(t *testing.T) {
	d := NewDecision("id", "shop", ModeBlock, netip.MustParseAddr("192.0.2.1"))
	assert.Equal(t, ActionAllow, d.Action())
	assert.Empty(t, d.Terminated())

	d.AddFinding(Finding{Module: "waf", RuleID: "942100", Severity: SeverityCritical, Score: 5})
	d.Terminate("waf", ActionBlock)

	assert.Equal(t, ActionBlock, d.Action())
	assert.Equal(t, "waf", d.Terminated())
	fs := d.Findings()
	require.Len(t, fs, 1)
	fs[0].RuleID = "mutated"
	assert.Equal(t, "942100", d.Findings()[0].RuleID, "Findings must return a copy")
}

func TestDecisionConcurrentFindings(t *testing.T) {
	d := NewDecision("id", "s", ModeDetect, netip.Addr{})
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() { d.AddFinding(Finding{Module: "x"}) })
	}
	wg.Wait()
	assert.Len(t, d.Findings(), 50)
}

func TestDecisionContext(t *testing.T) {
	assert.Nil(t, DecisionFrom(context.Background()))
	d := NewDecision("id", "s", ModeOff, netip.Addr{})
	assert.Same(t, d, DecisionFrom(WithDecision(context.Background(), d)))
}

func TestSeverityString(t *testing.T) {
	assert.Equal(t, "critical", SeverityCritical.String())
	assert.Equal(t, "unknown", Severity(99).String())
	b, err := SeverityWarning.MarshalText()
	require.NoError(t, err)
	assert.Equal(t, "warning", string(b))
}

func TestNewEventID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	earlier, err := NewEventID(time.UnixMilli(1_700_000_000_000))
	require.NoError(t, err)
	later, err := NewEventID(time.UnixMilli(1_700_000_001_000))
	require.NoError(t, err)
	assert.Regexp(t, re, earlier)
	assert.Regexp(t, re, later)
	assert.Less(t, earlier, later, "ULIDs sort by time")

	seen := map[string]bool{}
	for range 1000 {
		id, err := NewEventID(time.Now())
		require.NoError(t, err)
		assert.False(t, seen[id])
		seen[id] = true
	}
}

// A known vector: timestamp 0 with zero entropy would be all zeros; the
// timestamp part of a real ULID decodes back to the input.
func TestEventIDTimestampPrefix(t *testing.T) {
	id, err := NewEventID(time.UnixMilli(0))
	require.NoError(t, err)
	assert.Equal(t, "0000000000", id[:10])
	id, err = NewEventID(time.UnixMilli(1))
	require.NoError(t, err)
	assert.Equal(t, "0000000001", id[:10])
}
