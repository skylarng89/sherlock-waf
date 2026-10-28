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
	Method      string `json:"method"`
	Path        string `json:"path"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

// TestBenignCorpusHasNoBlocksAtPL1 is acceptance criterion 2 of milestone M1.
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
		out := serve(t, h, cr.Method, cr.Path, cr.ContentType, cr.Body)
		total++
		if !out.upstream || out.rec.Code != http.StatusOK {
			blocked++
			assert.Fail(t, "benign request was blocked", "%s %s -> %d rules=%v", cr.Method, cr.Path, out.rec.Code, ruleIDs(out.d))
		}
	}
	require.NoError(t, sc.Err())
	assert.Equal(t, 200, total, "corpus must contain exactly 200 requests")
	assert.Zero(t, blocked)
}
