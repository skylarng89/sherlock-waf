package waf

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
)

type corpusRequest struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	ContentType string            `json:"content_type"`
	Body        string            `json:"body"`
	Headers     map[string]string `json:"headers"`
}

// TestBenignCorpusHasNoBlocksAtPL1 is acceptance criterion 2 of M1 and the
// benign-corpus gate of M2: no request in test/corpus/benign may be blocked at PL1.
func TestBenignCorpusHasNoBlocksAtPL1(t *testing.T) {
	root, err := os.OpenRoot("../../../test/corpus/benign")
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	f, err := root.Open("requests.jsonl")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	h := newHandler(t, config.ModeBlock, config.FailClosed)
	var total, blocked int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var cr corpusRequest
		require.NoError(t, json.Unmarshal(sc.Bytes(), &cr))
		out := serveWith(t, h, cr.Method, cr.Path, cr.ContentType, cr.Body, cr.Headers)
		total++
		if !out.upstream || out.rec.Code != http.StatusOK {
			blocked++
			assert.Fail(t, "benign request was blocked", "%s %s -> %d rules=%v", cr.Method, cr.Path, out.rec.Code, ruleIDs(out.d))
		}
	}
	require.NoError(t, sc.Err())
	assert.GreaterOrEqual(t, total, 1000, "the corpus must keep at least 1,000 requests")
	assert.Zero(t, blocked)
}

// TestKnownFalsePositivesStayDocumented replays test/corpus/benign/known-false-positives.jsonl.
// These benign requests are blocked by CRS at PL1 today. If one stops being
// blocked, move it into requests.jsonl; if a new one appears, add it here with
// a reason instead of weakening the corpus test.
func TestKnownFalsePositivesStayDocumented(t *testing.T) {
	root, err := os.OpenRoot("../../../test/corpus/benign")
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	f, err := root.Open("known-false-positives.jsonl")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	h := newHandler(t, config.ModeBlock, config.FailClosed)
	sc := bufio.NewScanner(f)
	var n int
	for sc.Scan() {
		var cr struct {
			corpusRequest
			Reason string `json:"reason"`
		}
		require.NoError(t, json.Unmarshal(sc.Bytes(), &cr))
		require.NotEmpty(t, cr.Reason, "every known false positive needs a reason")
		out := serveWith(t, h, cr.Method, cr.Path, cr.ContentType, cr.Body, cr.Headers)
		n++
		assert.False(t, out.upstream, "%s %s is no longer blocked: move it into requests.jsonl (%s)", cr.Method, cr.Path, cr.Reason)
	}
	require.NoError(t, sc.Err())
	assert.Positive(t, n)
}
