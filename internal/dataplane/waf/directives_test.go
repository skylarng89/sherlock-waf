package waf

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/config"
)

func valid(mode config.Mode) Settings {
	return Settings{Mode: mode, ParanoiaLevel: 2, BlockingParanoiaLevel: 1, InboundThreshold: 7, OutboundThreshold: 3, MaxBodyBytes: 2048}
}

func TestDirectives(t *testing.T) {
	block, err := valid(config.ModeBlock).Directives()
	require.NoError(t, err)
	assert.Contains(t, block, "SecRuleEngine On\n")
	assert.Contains(t, block, "SecRequestBodyLimitAction Reject\n")
	assert.Contains(t, block, "tx.blocking_paranoia_level=1")
	assert.Contains(t, block, "tx.detection_paranoia_level=2")
	assert.Contains(t, block, "tx.inbound_anomaly_score_threshold=7,setvar:tx.outbound_anomaly_score_threshold=3")
	assert.Contains(t, block, "SecRequestBodyLimit 2048\n")
	assert.Contains(t, block, "SecRequestBodyInMemoryLimit 2048\n", "in-memory limit never exceeds the body limit")
	assert.Contains(t, block, "tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE")
	assert.Contains(t, block, "Include @owasp_crs/REQUEST-*.conf")
	assert.NotContains(t, block, "RESPONSE-")

	detect, err := valid(config.ModeDetect).Directives()
	require.NoError(t, err)
	assert.Contains(t, detect, "SecRuleEngine DetectionOnly\n")
	assert.Contains(t, detect, "SecRequestBodyLimitAction ProcessPartial\n")

	again, _ := valid(config.ModeBlock).Directives()
	assert.Equal(t, block, again, "output must be deterministic")
}

func TestDirectivesRejectInvalid(t *testing.T) {
	for name, mutate := range map[string]func(*Settings){
		"off mode":          func(s *Settings) { s.Mode = config.ModeOff },
		"pl zero":           func(s *Settings) { s.ParanoiaLevel = 0 },
		"pl five":           func(s *Settings) { s.ParanoiaLevel = 5 },
		"blocking above pl": func(s *Settings) { s.BlockingParanoiaLevel = 3 },
		"threshold zero":    func(s *Settings) { s.InboundThreshold = 0 },
		"body zero":         func(s *Settings) { s.MaxBodyBytes = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			s := valid(config.ModeBlock)
			mutate(&s)
			_, err := s.Directives()
			require.Error(t, err)
		})
	}
}
