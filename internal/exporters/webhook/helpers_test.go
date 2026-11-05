package webhook

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/exporters/exptest"
)

func tlsConfig(leaf exptest.Leaf) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{leaf.TLS}, MinVersion: tls.VersionTLS12}
}

func contextTimeout(t *testing.T, d time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(t.Context(), d)
}
