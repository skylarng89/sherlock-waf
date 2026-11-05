package ops

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
)

func TestLoginPolicyFromEnv(t *testing.T) {
	clear := func(t *testing.T) {
		for _, k := range []string{EnvLoginIPAttempts, EnvLoginUserAttempts, EnvLoginLockAfter, EnvLoginLockMaxMins} {
			t.Setenv(k, "")
		}
	}
	t.Run("unset is the default", func(t *testing.T) {
		clear(t)
		p, err := LoginPolicyFromEnv()
		require.NoError(t, err)
		assert.Equal(t, auth.DefaultLoginPolicy, p)
	})
	t.Run("overrides apply", func(t *testing.T) {
		clear(t)
		t.Setenv(EnvLoginIPAttempts, "10")
		t.Setenv(EnvLoginUserAttempts, "50")
		t.Setenv(EnvLoginLockAfter, "0")
		t.Setenv(EnvLoginLockMaxMins, "30")
		p, err := LoginPolicyFromEnv()
		require.NoError(t, err)
		assert.Equal(t, auth.LoginPolicy{IPAttempts: 10, UsernameAttempts: 50, LockAfter: 0, LockMax: 30 * time.Minute}, p)
	})
	for name, kv := range map[string][2]string{
		"zero attempts":      {EnvLoginIPAttempts, "0"},
		"negative lock":      {EnvLoginLockAfter, "-1"},
		"not a number":       {EnvLoginUserAttempts, "many"},
		"lock over a day":    {EnvLoginLockMaxMins, "1441"},
		"zero lock duration": {EnvLoginLockMaxMins, "0"},
	} {
		t.Run(name, func(t *testing.T) {
			clear(t)
			t.Setenv(kv[0], kv[1])
			_, err := LoginPolicyFromEnv()
			assert.ErrorContains(t, err, kv[0])
		})
	}
}
