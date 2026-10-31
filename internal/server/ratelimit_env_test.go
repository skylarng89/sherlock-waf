package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIRateLimitFromEnv(t *testing.T) {
	tests := []struct {
		name, value string
		want        int
		wantErr     bool
	}{
		{"unset uses the default", "", 0, false},
		{"set", "1200", 1200, false},
		{"surrounding space", " 50 ", 50, false},
		{"zero", "0", 0, true},
		{"negative", "-5", 0, true},
		{"not a number", "lots", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvAPIRateLimit, tt.value)
			got, err := apiRateLimitFromEnv()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), EnvAPIRateLimit)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
