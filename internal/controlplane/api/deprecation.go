package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
)

// Deprecation of an operation (docs/release/versioning.md): the spec marks it
// `deprecated: true` and gives `x-sherlock-sunset` (RFC 3339, the earliest date
// it may be removed, at least one minor release after the announcement) and,
// optionally, `x-sherlock-deprecation-link` (an https page with the migration
// notes). Every response to it then carries Deprecation, Sunset and Link headers.
const (
	sunsetExt          = "x-sherlock-sunset"
	deprecationLinkExt = "x-sherlock-deprecation-link"
)

type deprecation struct {
	sunset time.Time
	link   string
}

func extString(ext map[string]any, key string) string {
	switch v := ext[key].(type) {
	case string:
		return v
	case json.RawMessage:
		var s string
		_ = json.Unmarshal(v, &s)
		return s
	}
	return ""
}

// deprecationTableFor maps each deprecated operation to its sunset date. A
// deprecated operation without a valid sunset, a sunset on an operation that is
// not deprecated, or a link that is not an https URL is a start-up error: the
// promise to clients must be machine-readable or it is not made.
func deprecationTableFor(spec *openapi3.T) (map[string]deprecation, error) {
	table := map[string]deprecation{}
	for p, item := range spec.Paths.Map() {
		for method, op := range item.Operations() {
			key := method + " " + BasePath + p
			raw := extString(op.Extensions, sunsetExt)
			if !op.Deprecated {
				if raw != "" {
					return nil, fmt.Errorf("operation %s %s has %s but is not marked deprecated", method, p, sunsetExt)
				}
				continue
			}
			if raw == "" {
				return nil, fmt.Errorf("deprecated operation %s %s has no %s", method, p, sunsetExt)
			}
			sunset, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return nil, fmt.Errorf("operation %s %s: %s %q is not an RFC 3339 date: %w", method, p, sunsetExt, raw, err)
			}
			d := deprecation{sunset: sunset.UTC()}
			if link := extString(op.Extensions, deprecationLinkExt); link != "" {
				u, err := url.Parse(link)
				if err != nil || u.Scheme != "https" || u.Host == "" {
					return nil, fmt.Errorf("operation %s %s: %s must be an https URL", method, p, deprecationLinkExt)
				}
				d.link = u.String()
			}
			table[key] = d
		}
	}
	return table, nil
}

// setDeprecationHeaders announces the deprecation on a response.
func setDeprecationHeaders(h http.Header, d deprecation) {
	h.Set("Deprecation", "true")
	h.Set("Sunset", d.sunset.Format(http.TimeFormat))
	if d.link != "" {
		h.Add("Link", "<"+d.link+`>; rel="deprecation"`)
	}
}
