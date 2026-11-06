package login

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	// maxBodyPeek bounds how much of a request body is read to find the
	// username. A login form is a few hundred bytes; anything bigger is not one.
	maxBodyPeek = 64 << 10
	// maxUsernameLen bounds the name that is hashed.
	maxUsernameLen = 256
)

type bodyKind int

const (
	kindNone bodyKind = iota
	kindJSON
	kindForm
)

// kindOf says which parser a Content-Type selects. Multipart and every other
// type are not parsed: the username is then unknown and only the address and
// device counters apply.
func kindOf(contentType string) bodyKind {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return kindNone
	}
	switch {
	case mt == "application/x-www-form-urlencoded":
		return kindForm
	case mt == "application/json", strings.HasSuffix(mt, "+json"):
		return kindJSON
	}
	return kindNone
}

// pointer splits a JSON pointer ("/user/email") into its reference tokens, or
// returns nil for a plain field name.
func pointer(field string) []string {
	rest, ok := strings.CutPrefix(field, "/")
	if !ok {
		return nil
	}
	tokens := strings.Split(rest, "/")
	for i, t := range tokens {
		t = strings.ReplaceAll(t, "~1", "/")
		tokens[i] = strings.ReplaceAll(t, "~0", "~")
	}
	return tokens
}

// extractUsername reads the username out of a bounded body. It never fails: a
// body that does not parse, a field that is missing and a value that is not a
// string or number all give "", and the request carries on without a username
// counter. The result is capped at maxUsernameLen bytes.
func extractUsername(kind bodyKind, body []byte, field string, tokens []string) string {
	var v string
	switch kind {
	case kindNone:
		return ""
	case kindForm:
		q, _ := url.ParseQuery(string(body)) // a partial parse is still useful
		v = q.Get(field)
	case kindJSON:
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var doc any
		if err := dec.Decode(&doc); err != nil {
			return ""
		}
		v = jsonField(doc, field, tokens)
	}
	if len(v) > maxUsernameLen {
		v = v[:maxUsernameLen]
	}
	return v
}

func jsonField(doc any, field string, tokens []string) string {
	cur := doc
	if tokens == nil {
		tokens = []string{field} // a plain name is a top-level key
	}
	for _, t := range tokens {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[t]
			if !ok {
				return ""
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(t)
			if err != nil || i < 0 || i >= len(node) || strconv.Itoa(i) != t {
				return ""
			}
			cur = node[i]
		default:
			return ""
		}
	}
	switch s := cur.(type) {
	case string:
		return s
	case json.Number:
		return s.String()
	}
	return ""
}

type restoredBody struct {
	io.Reader
	io.Closer
}

// peekBody reads up to maxBodyPeek bytes of r's body and puts them back, so the
// upstream still receives the complete body. ok is false when the body is
// larger than the cap (it is still restored whole) or could not be read.
func peekBody(r *http.Request) (body []byte, ok bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, false
	}
	orig := r.Body
	buf, err := io.ReadAll(io.LimitReader(orig, maxBodyPeek+1))
	r.Body = restoredBody{Reader: io.MultiReader(bytes.NewReader(buf), orig), Closer: orig}
	if err != nil || len(buf) > maxBodyPeek {
		return nil, false
	}
	return buf, true
}
