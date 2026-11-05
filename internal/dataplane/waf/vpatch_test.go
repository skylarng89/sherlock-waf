package waf

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/policy"
	"github.com/skylarng89/sherlock-waf/internal/vpatch"
)

func withPatches(ids ...string) func(*Handler) {
	return func(h *Handler) { h.VirtualPatches = ids }
}

func allPatchIDs(t *testing.T) []string {
	t.Helper()
	all, err := vpatch.All()
	require.NoError(t, err)
	ids := make([]string, len(all))
	for i, p := range all {
		ids[i] = p.ID
	}
	return ids
}

func run(t *testing.T, h *Handler, tr vpatch.TestRequest) outcome {
	t.Helper()
	return serveWith(t, h, tr.Method, tr.Path, tr.ContentType, tr.Body, tr.Headers)
}

func vpatchFindings(d *policy.Decision) []string {
	var ids []string
	for _, f := range d.Findings() {
		if n, err := strconv.Atoi(f.RuleID); err == nil && vpatch.IsRuleID(n) {
			ids = append(ids, f.RuleID)
		}
	}
	return ids
}

// Acceptance criterion 4: every virtual patch blocks its exploit tests and
// does not fire on its benign requests. The positive test runs with only the
// patch under test enabled (and CRS at PL1), the negative one with the whole
// pack enabled so a rule cannot hide behind another.
func TestEveryVirtualPatchBlocksItsExploitAndSparesBenignRequests(t *testing.T) {
	all, err := vpatch.All()
	require.NoError(t, err)
	everything := newHandler(t, config.ModeBlock, config.FailClosed, withPatches(allPatchIDs(t)...))
	for _, p := range all {
		t.Run(p.ID, func(t *testing.T) {
			only := newHandler(t, config.ModeBlock, config.FailClosed, withPatches(p.ID))
			for _, tr := range p.Tests.Positive {
				out := run(t, only, tr)
				assert.False(t, out.upstream, "exploit %q reached the upstream", tr.Name)
				assert.Equal(t, http.StatusForbidden, out.rec.Code, "exploit %q", tr.Name)
				found := vpatchFindings(out.d)
				require.NotEmpty(t, found, "exploit %q must be stopped by the patch itself, rules=%v", tr.Name, ruleIDs(out.d))
				for _, f := range found {
					n, _ := strconv.Atoi(f)
					assert.Contains(t, p.RuleIDs, n, "exploit %q matched a rule of another patch", tr.Name)
				}
			}
			for _, tr := range p.Tests.Negative {
				out := run(t, everything, tr)
				assert.Empty(t, vpatchFindings(out.d), "benign request %q matched a virtual patch", tr.Name)
			}
		})
	}
}

// Acceptance criterion 4, second half: a product-specific rule does not
// activate on a site that has not declared the stack.
func TestProductRulesStayOffWithoutTheirStack(t *testing.T) {
	all, err := vpatch.All()
	require.NoError(t, err)
	for _, p := range all {
		active, err := vpatch.Select(true, nil, nil)
		require.NoError(t, err)
		assert.NotContains(t, active, p.ID, "%s must not be active on an undeclared site", p.ID)
	}
	// End to end: the WordPress rule is absent for a Drupal-only site.
	ids, err := vpatch.Select(true, nil, []string{"drupal"})
	require.NoError(t, err)
	h := newHandler(t, config.ModeBlock, config.FailClosed, withPatches(ids...))
	p, _ := vpatch.Get("SV-2020-0001")
	out := run(t, h, p.Tests.Positive[0])
	assert.Empty(t, vpatchFindings(out.d))
	assert.Equal(t, http.StatusOK, out.rec.Code)
}

func TestVirtualPatchInDetectModeLogsWithoutBlocking(t *testing.T) {
	p, ok := vpatch.Get("SV-2023-0003")
	require.True(t, ok)
	h := newHandler(t, config.ModeDetect, config.FailOpen, withPatches(p.ID))
	out := run(t, h, p.Tests.Positive[0])
	assert.True(t, out.upstream)
	assert.Equal(t, http.StatusOK, out.rec.Code)
	assert.NotEmpty(t, vpatchFindings(out.d))
	assert.Equal(t, policy.ActionLog, out.d.Action())
}

// The CVEs that CRS already blocks stay documented and true.
func TestCoveredByCRS(t *testing.T) {
	covered, err := vpatch.Covered()
	require.NoError(t, err)
	require.NotEmpty(t, covered)
	h := newHandler(t, config.ModeBlock, config.FailClosed) // CRS only, PL1, no patches
	for _, c := range covered {
		t.Run(c.CVE, func(t *testing.T) {
			out := run(t, h, c.Test)
			assert.Equal(t, http.StatusForbidden, out.rec.Code, "CRS no longer blocks %s: write a virtual patch", c.CVE)
			for _, id := range c.CRSRules {
				assert.Contains(t, ruleIDs(out.d), id)
			}
		})
	}
}

// The whole pack, on a site that declared every stack, still lets the benign
// corpus through (M8-T6c: zero blocks on the benign corpus).
func TestBenignCorpusHasNoBlocksWithEveryPatchEnabled(t *testing.T) {
	root, err := os.OpenRoot("../../../test/corpus/benign")
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	f, err := root.Open("requests.jsonl")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	h := newHandler(t, config.ModeBlock, config.FailClosed, withPatches(allPatchIDs(t)...))
	sc := bufio.NewScanner(f)
	var total int
	for sc.Scan() {
		var cr corpusRequest
		require.NoError(t, json.Unmarshal(sc.Bytes(), &cr))
		out := serveWith(t, h, cr.Method, cr.Path, cr.ContentType, cr.Body, cr.Headers)
		total++
		assert.Empty(t, vpatchFindings(out.d), "%s %s matched a virtual patch", cr.Method, cr.Path)
		assert.Equal(t, http.StatusOK, out.rec.Code, "%s %s", cr.Method, cr.Path)
	}
	require.NoError(t, sc.Err())
	assert.GreaterOrEqual(t, total, 1000)
}
