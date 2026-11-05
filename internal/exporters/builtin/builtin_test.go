package builtin

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypesAreNamedAndValidate(t *testing.T) {
	var names []string
	for _, ty := range Types("1.0") {
		names = append(names, ty.Name())
		assert.Error(t, ty.Validate(json.RawMessage(`{}`)), "%s rejects an empty configuration", ty.Name())
		_, err := ty.New(json.RawMessage(`{}`))
		assert.Error(t, err, ty.Name())
	}
	require.Equal(t, []string{"syslog", "webhook", "otlp"}, names)
}
