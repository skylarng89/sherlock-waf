// Package blockpage renders the response for requests Sherlock terminates:
// an HTML page or an RFC 9457 problem document chosen by the Accept header.
// Responses carry the event ID and nothing derived from the request.
package blockpage

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// EventIDHeader is set on every terminated response.
const EventIDHeader = "X-Sherlock-Event-Id"

//go:embed block.html.tmpl
var htmlSource string

var htmlTemplate = template.Must(template.New("block").Parse(htmlSource))

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
	v := view{Status: status, Title: http.StatusText(status), Detail: detail(status), EventID: eventID}
	h := w.Header()
	h.Set(EventIDHeader, eventID)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Add("Vary", "Accept")

	if wantsHTML(r.Header.Values("Accept")) {
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		w.WriteHeader(status)
		_ = htmlTemplate.Execute(w, v)
		return
	}
	h.Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{
		Type: "about:blank", Title: v.Title, Status: status, Detail: v.Detail, EventID: eventID,
	})
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
