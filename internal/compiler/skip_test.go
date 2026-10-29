package compiler

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/skylarng89/sherlock-waf/internal/config"
)

func TestSkipExtensionsDisabledWhenStackPatchesApply(t *testing.T) {
	eff := config.EffectivePolicy{WAF: config.EffectiveWAF{SkipInspectionExtensions: config.DefaultSkipInspectionExtensions()}}
	assert.NotEmpty(t, skipExtensions(eff, nil), "no declared stack: static assets still skip inspection")
	assert.NotEmpty(t, skipExtensions(eff, []string{"SV-1"}), "patches without a declared stack: generic only, skip stays")

	eff.Stacks = []string{"exchange"}
	assert.NotEmpty(t, skipExtensions(eff, nil), "declared stack but no active patch: skip stays")
	assert.Empty(t, skipExtensions(eff, []string{"SV-1"}), "declared stack with active patches: inspect everything")
}
