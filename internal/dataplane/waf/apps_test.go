package waf

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/skylarng89/sherlock-waf/internal/config"
)

type appSample struct {
	corpusRequest
	App                   string `json:"app"`
	Kind                  string `json:"kind"`
	BlockedWithoutPackage bool   `json:"blocked_without_package"`
	Note                  string `json:"note"`
}

func loadPackage(t *testing.T, root *os.Root, app string) []config.Exclusion {
	t.Helper()
	b, err := root.ReadFile("exclusion-packages/" + app + ".yaml")
	require.NoError(t, err)
	var pkg struct {
		Exclusions []config.Exclusion `yaml:"exclusions"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	require.NoError(t, dec.Decode(&pkg))
	require.NotEmpty(t, pkg.Exclusions)
	for _, x := range pkg.Exclusions {
		require.Empty(t, config.ValidateExclusion(x), "package %s exclusion %s", app, x.ID)
	}
	return pkg.Exclusions
}

// TestAppExclusionPackages is M8-T7: for WordPress, Django admin and JSON APIs
// the documented false positives are real (blocked without the package), the
// package fixes them, and the same package leaves attacks on the same
// endpoints blocked.
func TestAppExclusionPackages(t *testing.T) {
	root, err := os.OpenRoot("../../../test/corpus/benign")
	require.NoError(t, err)
	defer func() { _ = root.Close() }()
	f, err := root.Open("apps.jsonl")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	byApp := map[string][]appSample{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var s appSample
		require.NoError(t, json.Unmarshal(sc.Bytes(), &s))
		byApp[s.App] = append(byApp[s.App], s)
	}
	require.NoError(t, sc.Err())
	require.Len(t, byApp, 3)

	for app, samples := range byApp {
		t.Run(app, func(t *testing.T) {
			without := newHandler(t, config.ModeBlock, config.FailClosed)
			with := newHandler(t, config.ModeBlock, config.FailClosed, withExclusions(loadPackage(t, root, app)...))
			var fps, benign, attacks int
			for _, s := range samples {
				plain := serveWith(t, without, s.Method, s.Path, s.ContentType, s.Body, s.Headers)
				fixed := serveWith(t, with, s.Method, s.Path, s.ContentType, s.Body, s.Headers)
				switch s.Kind {
				case "benign":
					benign++
					if s.BlockedWithoutPackage {
						fps++
						assert.False(t, plain.upstream, "%s %s should be a CRS false positive without the package (%s)", s.Method, s.Path, s.Note)
					} else {
						assert.True(t, plain.upstream, "%s %s is benign and must pass without a package, rules=%v", s.Method, s.Path, ruleIDs(plain.d))
					}
					assert.True(t, fixed.upstream && fixed.rec.Code == http.StatusOK, "%s %s must pass with the package, rules=%v", s.Method, s.Path, ruleIDs(fixed.d))
				case "attack":
					attacks++
					assert.False(t, plain.upstream, "%s %s", s.Method, s.Path)
					assert.False(t, fixed.upstream, "the package must not hide the attack %s %s, rules=%v", s.Method, s.Path, ruleIDs(fixed.d))
				}
			}
			assert.Positive(t, fps, "the package exists to fix at least one real false positive")
			assert.Greater(t, benign, 10)
			assert.Greater(t, attacks, 2)
		})
	}
}
