//go:build otelcol

package otlp

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// TestRealCollector sends to a running OpenTelemetry Collector (the CI job
// starts one and then checks that the records reached its file exporter).
// OTEL_COLLECTOR_ENDPOINT is the host:port of the OTLP/HTTP receiver (4318) and
// OTEL_COLLECTOR_GRPC_ENDPOINT, if set, that of the gRPC receiver (4317).
func TestRealCollector(t *testing.T) {
	httpEP := os.Getenv("OTEL_COLLECTOR_ENDPOINT")
	if httpEP == "" {
		t.Skip("OTEL_COLLECTOR_ENDPOINT is not set")
	}
	rec := eventRec("01OTELCOLLECTORHTTP")
	rec.At = time.Now()
	send := func(t *testing.T, m map[string]any, id string) {
		r := rec
		r.ID = id
		e := newExp(t, m)
		require.NoError(t, e.(extension.ExporterTester).Test(t.Context()))
		require.NoError(t, e.Send(t.Context(), []extension.ExportRecord{r}))
	}
	t.Run("http", func(t *testing.T) {
		send(t, map[string]any{"endpoint": "http://" + httpEP, "allow_http": true}, "01OTELCOLLECTORHTTP")
	})
	t.Run("http gzip", func(t *testing.T) {
		send(t, map[string]any{"endpoint": "http://" + httpEP, "allow_http": true, "compression": "gzip"}, "01OTELCOLLECTORGZIP")
	})
	if g := os.Getenv("OTEL_COLLECTOR_GRPC_ENDPOINT"); g != "" {
		t.Run("grpc", func(t *testing.T) {
			send(t, map[string]any{"endpoint": "http://" + g, "protocol": "grpc", "allow_http": true}, "01OTELCOLLECTORGRPC")
		})
	}
}
