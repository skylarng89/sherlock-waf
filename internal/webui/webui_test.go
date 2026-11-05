package webui_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/webui"
)

func TestHandler(t *testing.T) {
	t.Parallel()

	built := fstest.MapFS{
		"index.html":    {Data: []byte("<html>app</html>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}

	tests := []struct {
		name       string
		fsys       fstest.MapFS
		method     string
		target     string
		wantStatus int
		wantBody   string
	}{
		{"root serves index", built, http.MethodGet, "/", http.StatusOK, "<html>app</html>"},
		{"asset is served", built, http.MethodGet, "/assets/app.js", http.StatusOK, "console.log(1)"},
		{"client route falls back to index", built, http.MethodGet, "/sites/shop", http.StatusOK, "<html>app</html>"},
		{"missing asset is 404", built, http.MethodGet, "/assets/missing.js", http.StatusNotFound, ""},
		{"traversal cannot escape", built, http.MethodGet, "/../../etc/passwd", http.StatusOK, "<html>app</html>"},
		{"POST is rejected", built, http.MethodPost, "/", http.StatusMethodNotAllowed, ""},
		{"unbuilt dashboard is 503", fstest.MapFS{}, http.MethodGet, "/", http.StatusServiceUnavailable, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			webui.NewHandler(tc.fsys).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), tc.method, tc.target, nil))

			require.Equal(t, tc.wantStatus, rec.Code)
			if tc.wantBody != "" {
				require.Contains(t, rec.Body.String(), tc.wantBody)
			}
			require.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
			require.Contains(t, rec.Header().Get("Content-Security-Policy"), "default-src 'self'")
		})
	}
}

func TestEmbeddedHandlerWithoutBuild(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	webui.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	// A clean clone only has the .gitkeep placeholder; a built tree serves the app.
	require.Contains(t, []int{http.StatusOK, http.StatusServiceUnavailable}, rec.Code)
}
