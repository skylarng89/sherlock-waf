// Package builtin lists the exporter types the open-source core ships.
package builtin

import (
	"github.com/skylarng89/sherlock-waf/internal/exporters/otlp"
	"github.com/skylarng89/sherlock-waf/internal/exporters/syslog"
	"github.com/skylarng89/sherlock-waf/internal/exporters/webhook"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// Types returns the built-in exporter types. version is the Sherlock version,
// reported in CEF headers, User-Agent and OTLP resource attributes.
func Types(version string) []extension.ExporterType {
	return []extension.ExporterType{
		syslog.Type{Version: version},
		webhook.Type{Version: version},
		otlp.Type{Version: version},
	}
}
