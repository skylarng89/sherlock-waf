package blockpage

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const eventID = "01J9ZK4Y3V7Q8XM2N5R6T0WABC"

func do(t *testing.T, accept string, status int, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", "<script>alert(1)</script>")
	rec := httptest.NewRecorder()
	Write(rec, req, status, eventID)
	return rec
}

func TestWriteNegotiation(t *testing.T) {
	tests := []struct {
		accept   string
		wantHTML bool
	}{
		{"text/html", true},
		{"text/html,application/xhtml+xml;q=0.9,*/*;q=0.8", true},
		{"application/json, text/html;q=0.5", true},
		{"text/html;q=0", false},
		{"*/*", false},
		{"application/json", false},
		{"", false},
		{"garbage;;;", false},
	}
	for _, tc := range tests {
		t.Run(tc.accept, func(t *testing.T) {
			rec := do(t, tc.accept, http.StatusForbidden, "/get")
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Equal(t, eventID, rec.Header().Get(EventIDHeader))
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			if tc.wantHTML {
				assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
				assert.Contains(t, rec.Body.String(), eventID)
				assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "default-src 'none'")
			} else {
				assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
			}
		})
	}
}

func TestProblemJSON(t *testing.T) {
	rec := do(t, "application/json", http.StatusForbidden, "/get")
	var p problem
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))
	assert.Equal(t, problem{
		Type: "about:blank", Title: "Forbidden", Status: 403,
		Detail: "This request was blocked by the web application firewall.", EventID: eventID,
	}, p)
}

func TestNoRequestEcho(t *testing.T) {
	for _, accept := range []string{"text/html", "application/json"} {
		rec := do(t, accept, http.StatusForbidden, "/search?q=%3Cscript%3Eevil%3C/script%3E&id=1%27+OR+1=1")
		body := rec.Body.String()
		for _, leak := range []string{"evil", "script", "OR 1=1", "/search", "alert"} {
			if accept == "text/html" && leak == "script" {
				// the page has no <script>; only <style> exists
				assert.NotContains(t, body, "<script")
				continue
			}
			assert.NotContains(t, body, leak, accept)
		}
	}
}

func TestEventIDIsEscaped(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	Write(rec, req, http.StatusForbidden, `"><img src=x onerror=1>`)
	assert.NotContains(t, rec.Body.String(), "<img")
	assert.True(t, strings.Contains(rec.Body.String(), "&lt;img"))
}

func TestStatusDetails(t *testing.T) {
	for _, st := range []int{http.StatusRequestEntityTooLarge, http.StatusServiceUnavailable, http.StatusTeapot} {
		rec := do(t, "application/json", st, "/")
		assert.Equal(t, st, rec.Code)
		assert.NotEmpty(t, detail(st))
	}
}
