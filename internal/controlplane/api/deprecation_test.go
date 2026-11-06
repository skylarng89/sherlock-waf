package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/controlplane/api/apigen"
)

func loadSpec(t *testing.T, doc string) *openapi3.T {
	t.Helper()
	spec, err := openapi3.NewLoader().LoadFromData([]byte(doc))
	require.NoError(t, err)
	return spec
}

const specHead = `
openapi: 3.0.3
info: { title: t, version: 1.0.0 }
paths:
  /old:
    get:
      operationId: old
      x-sherlock-permission: public
`

func TestDeprecationTable(t *testing.T) {
	good := loadSpec(t, specHead+`
      deprecated: true
      x-sherlock-sunset: "2027-06-01T00:00:00Z"
      x-sherlock-deprecation-link: "https://docs.example.com/migrate"
      responses: { "200": { description: ok } }
  /new:
    get:
      operationId: new
      x-sherlock-permission: public
      responses: { "200": { description: ok } }
`)
	table, err := deprecationTableFor(good)
	require.NoError(t, err)
	require.Len(t, table, 1, "only the deprecated operation is listed")
	d := table["GET "+BasePath+"/old"]
	assert.Equal(t, time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC), d.sunset)
	assert.Equal(t, "https://docs.example.com/migrate", d.link)

	h := http.Header{}
	setDeprecationHeaders(h, d)
	assert.Equal(t, "true", h.Get("Deprecation"))
	assert.Equal(t, "Tue, 01 Jun 2027 00:00:00 GMT", h.Get("Sunset"), "an HTTP-date, as RFC 8594 requires")
	assert.Equal(t, `<https://docs.example.com/migrate>; rel="deprecation"`, h.Get("Link"))

	h = http.Header{}
	setDeprecationHeaders(h, deprecation{sunset: d.sunset})
	assert.Empty(t, h.Get("Link"), "no link header without a link")
}

func TestDeprecationTableRefusesIncompleteDeclarations(t *testing.T) {
	for name, extra := range map[string]string{
		"deprecated without a sunset": "      deprecated: true\n",
		"sunset without deprecated":   "      x-sherlock-sunset: \"2027-06-01T00:00:00Z\"\n",
		"sunset not a date":           "      deprecated: true\n      x-sherlock-sunset: next spring\n",
		"link not https":              "      deprecated: true\n      x-sherlock-sunset: \"2027-06-01T00:00:00Z\"\n      x-sherlock-deprecation-link: \"http://docs.example.com\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			spec := loadSpec(t, specHead+extra+"      responses: { \"200\": { description: ok } }\n")
			_, err := deprecationTableFor(spec)
			require.Error(t, err)
		})
	}
}

// TestEmbeddedSpecDeprecationsAreComplete is the CI check: every operation the
// real spec marks deprecated names its sunset date (none is deprecated at 1.0).
func TestEmbeddedSpecDeprecationsAreComplete(t *testing.T) {
	spec, err := apigen.GetSpec()
	require.NoError(t, err)
	table, err := deprecationTableFor(spec)
	require.NoError(t, err)
	assert.Empty(t, table, "nothing is deprecated at 1.0; add the sunset and a changelog entry when that changes")
}

func TestDeprecatedOperationsAnnounceThemselvesOnEveryResponse(t *testing.T) {
	s, err := New(Deps{})
	require.NoError(t, err)
	s.deprecations = map[string]deprecation{
		"GET " + BasePath + "/auth/me": {sunset: time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC), link: "https://docs.example.com/migrate"},
	}
	srv := s.Handler()

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, BasePath+"/auth/me", nil))
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "refused responses carry the headers too")
	assert.Equal(t, "true", rec.Header().Get("Deprecation"))
	assert.Equal(t, "Tue, 01 Jun 2027 00:00:00 GMT", rec.Header().Get("Sunset"))
	assert.Contains(t, rec.Header().Get("Link"), `rel="deprecation"`)

	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, BasePath+"/auth/sessions", nil))
	assert.Empty(t, rec.Header().Get("Deprecation"), "other operations are untouched")
}
