package ops

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
)

func TestTokenMaxLifetimeFromEnv(t *testing.T) {
	for name, c := range map[string]struct {
		value string
		set   bool
		want  time.Duration
		err   bool
	}{
		"unset means the default": {want: auth.DefaultTokenMaxLifetime},
		"blank means the default": {set: true, value: "  ", want: auth.DefaultTokenMaxLifetime},
		"zero removes the cap":    {set: true, value: "0", want: 0},
		"days":                    {set: true, value: "30", want: 30 * 24 * time.Hour},
		"negative refuses":        {set: true, value: "-1", err: true},
		"fraction refuses":        {set: true, value: "1.5", err: true},
		"words refuse":            {set: true, value: "forever", err: true},
		"unit suffix refuses":     {set: true, value: "30d", err: true},
	} {
		t.Run(name, func(t *testing.T) {
			if c.set {
				t.Setenv(EnvAPITokenMaxDays, c.value)
			}
			got, err := TokenMaxLifetimeFromEnv()
			if c.err {
				require.Error(t, err, "a bad value must stop the node rather than fall back silently")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestCLITokenCreationObeysTheLifetimeCap(t *testing.T) {
	e := open(t)
	ctx := t.Context()
	_, err := e.CreateUser(ctx, "ada", pw, "admin")
	require.NoError(t, err)

	t.Setenv(EnvAPITokenMaxDays, "30")
	_, err = e.CreateToken(ctx, "ada", "ci", []string{"read"}, nil, time.Now().Add(90*24*time.Hour))
	require.ErrorIs(t, err, auth.ErrTokenLifetime, "the CLI path enforces the same maximum as the API")

	ct, err := e.CreateToken(ctx, "ada", "ci", []string{"read"}, nil, time.Time{})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(30*24*time.Hour), ct.Record.ExpiresAt, time.Minute)
}
