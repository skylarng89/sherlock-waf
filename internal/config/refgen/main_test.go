package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratesSchemaAndReferenceFromTheRealPackage(t *testing.T) {
	out := t.TempDir()
	require.NoError(t, run("..", out), "every configuration key must carry a doc comment")

	raw, err := os.ReadFile(filepath.Join(out, "config.schema.json")) //nolint:gosec // test output
	require.NoError(t, err)
	var schema struct {
		Ref  string `json:"$ref"`
		Defs map[string]struct {
			Properties           map[string]json.RawMessage `json:"properties"`
			AdditionalProperties bool                       `json:"additionalProperties"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(raw, &schema))
	assert.Equal(t, "#/$defs/Root", schema.Ref)
	policy := schema.Defs["Policy"]
	for _, key := range []string{"mode", "waf", "bot", "api", "login_protection", "dlp", "rate_limits"} {
		assert.Contains(t, policy.Properties, key)
	}
	assert.False(t, policy.AdditionalProperties, "unknown keys are rejected, as the loader does")

	md, err := os.ReadFile(filepath.Join(out, "config-reference.md")) //nolint:gosec // test output
	require.NoError(t, err)
	assert.Contains(t, string(md), "| `login_protection` |")
	assert.Contains(t, string(md), "one of `off`, `detect`, `block`")
}

func TestUndocumentedFieldsAreReported(t *testing.T) {
	p := &pkgInfo{structs: map[string][]field{"T": {{Key: "a", Doc: "x"}, {Key: "b"}}}}
	assert.Equal(t, []string{"T.b"}, p.undocumented([]string{"T"}))
}
