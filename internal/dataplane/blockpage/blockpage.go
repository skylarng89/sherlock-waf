// Package blockpage renders the response for requests Sherlock terminates:
// an HTML page or an RFC 9457 problem document chosen by the Accept header.
// Responses carry the event ID and nothing derived from the request.
package blockpage

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"maps"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
)

// MaxTemplateBytes bounds an uploaded template.
const MaxTemplateBytes = 64 << 10

// EventIDHeader is set on every terminated response.
const EventIDHeader = "X-Sherlock-Event-Id"

//go:embed block.html.tmpl
var htmlSource string

var htmlTemplate = template.Must(template.New("block").Parse(htmlSource))

// custom holds the uploaded templates by id. It is replaced as a whole so the
// request path reads it without locking.
var custom atomic.Pointer[map[string]*template.Template]

func parseTemplate(id, src string) (*template.Template, error) {
	if len(src) > MaxTemplateBytes {
		return nil, fmt.Errorf("template is larger than %d bytes", MaxTemplateBytes)
	}
	t, err := template.New(id).Option("missingkey=error").Parse(src)
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}
	// Render once with sample data so a template that fails at request time
	// (for example by referencing a field that does not exist) is refused now.
	if _, err := render(t, view{Status: 403, Title: "Forbidden", Detail: detail(403), EventID: "01SAMPLEEVENT0000000000000"}); err != nil {
		return nil, err
	}
	return t, nil
}

// ValidateTemplate reports whether src can be used as a block page. Available
// fields: .Status, .Title, .Detail, .EventID.
func ValidateTemplate(src string) error {
	_, err := parseTemplate("validate", src)
	return err
}

// SetTemplate installs (or replaces) the custom template id.
func SetTemplate(id, src string) error {
	t, err := parseTemplate(id, src)
	if err != nil {
		return err
	}
	for {
		old := custom.Load()
		next := map[string]*template.Template{}
		if old != nil {
			maps.Copy(next, *old)
		}
		next[id] = t
		if custom.CompareAndSwap(old, &next) {
			return nil
		}
	}
}

// DeleteTemplate removes the custom template id.
func DeleteTemplate(id string) {
	for {
		old := custom.Load()
		if old == nil {
			return
		}
		next := map[string]*template.Template{}
		maps.Copy(next, *old)
		delete(next, id)
		if custom.CompareAndSwap(old, &next) {
			return
		}
	}
}

func render(t *template.Template, v view) ([]byte, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, v); err != nil {
		return nil, fmt.Errorf("rendering template: %w", err)
	}
	return buf.Bytes(), nil
}

type view struct {
	Status  int
	Title   string
	Detail  string
	EventID string
}

type problem struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Status  int    `json:"status"`
	Detail  string `json:"detail"`
	EventID string `json:"event_id"`
}

// Write sends the terminated-request response for status. The request is only
// read for its Accept header.
func Write(w http.ResponseWriter, r *http.Request, status int, eventID string) {
	WriteTemplate(w, r, status, eventID, "")
}

// WriteTemplate is Write with a custom HTML template (by id). An unknown id, or
// a template that fails to render, falls back to the built-in page: a block
// must never turn into an empty or broken response.
func WriteTemplate(w http.ResponseWriter, r *http.Request, status int, eventID, templateID string) {
	v := view{Status: status, Title: http.StatusText(status), Detail: detail(status), EventID: eventID}
	h := w.Header()
	h.Set(EventIDHeader, eventID)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Add("Vary", "Accept")

	if wantsHTML(r.Header.Values("Accept")) {
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		body := renderPage(templateID, v)
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}
	h.Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{
		Type: "about:blank", Title: v.Title, Status: status, Detail: v.Detail, EventID: eventID,
	})
}

func renderPage(templateID string, v view) []byte {
	if templateID != "" && templateID != "default" {
		if m := custom.Load(); m != nil {
			if t, ok := (*m)[templateID]; ok {
				if b, err := render(t, v); err == nil {
					return b
				} else {
					slog.Warn("custom block page failed to render; using the default page", "template_id", templateID, "error", err)
				}
			} else {
				slog.Warn("block page template is not loaded; using the default page", "template_id", templateID)
			}
		}
	}
	b, err := render(htmlTemplate, v)
	if err != nil { // the built-in template is static; this cannot happen
		return []byte(http.StatusText(v.Status))
	}
	return b
}

func detail(status int) string {
	switch status {
	case http.StatusForbidden:
		return "This request was blocked by the web application firewall."
	case http.StatusRequestEntityTooLarge:
		return "The request body exceeds the size this site allows."
	case http.StatusServiceUnavailable:
		return "The firewall could not process this request safely."
	default:
		return "This request could not be completed."
	}
}

// wantsHTML reports whether text/html is acceptable with a non-zero weight.
// Wildcards do not count, so API clients sending */* get JSON.
func wantsHTML(values []string) bool {
	for _, v := range values {
		for part := range strings.SplitSeq(v, ",") {
			mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil || mt != "text/html" {
				continue
			}
			if q, ok := params["q"]; ok {
				if f, err := strconv.ParseFloat(q, 64); err != nil || f <= 0 {
					continue
				}
			}
			return true
		}
	}
	return false
}
