package events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

const redacted = "[REDACTED]"

// defaultNamePattern lists parameter names whose values are never recorded.
const defaultNamePattern = `(?i)pass|pwd|secret|token|otp|pin|cvv|cvc|card|pan|ssn|authorization`

const (
	minPANDigits = 13
	maxPANDigits = 19
	maxBodyScan  = 64 << 10
)

// Redactor applies docs/architecture/events.md redaction. It is immutable and
// safe for concurrent use.
type Redactor struct {
	names *regexp.Regexp
}

// NewRedactor adds operator patterns (matched against parameter names) to the
// defaults. Go's RE2 engine keeps user patterns linear-time.
func NewRedactor(extraNamePatterns []string) (*Redactor, error) {
	parts := []string{defaultNamePattern}
	for i, p := range extraNamePatterns {
		if len(p) > 256 {
			return nil, fmt.Errorf("redaction pattern %d: longer than 256 bytes", i)
		}
		if _, err := regexp.Compile(p); err != nil {
			return nil, fmt.Errorf("redaction pattern %d: %w", i, err)
		}
		parts = append(parts, "(?:"+p+")")
	}
	re, err := regexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		return nil, fmt.Errorf("compiling redaction patterns: %w", err)
	}
	return &Redactor{names: re}, nil
}

// SensitiveName reports whether values of the named parameter are redacted.
func (r *Redactor) SensitiveName(name string) bool { return r.names.MatchString(name) }

// Text masks Luhn-valid card numbers; it is the value-level rule.
func (r *Redactor) Text(s string) string { return maskPANs(s) }

// Value redacts by parameter name first, then by content.
func (r *Redactor) Value(name, v string) string {
	if r.SensitiveName(name) {
		return redacted
	}
	return maskPANs(v)
}

// Query redacts a raw query string, keeping parameter names and order.
func (r *Redactor) Query(raw string) string {
	if raw == "" {
		return ""
	}
	if len(raw) > maxQueryBytes {
		raw = truncateUTF8(raw, maxQueryBytes)
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		k, v, hasV := strings.Cut(p, "=")
		name := unescape(k)
		switch {
		case r.SensitiveName(name):
			if hasV {
				parts[i] = k + "=" + redacted
			}
		case hasV:
			parts[i] = k + "=" + maskPANs(unescape(v))
		default:
			parts[i] = maskPANs(unescape(k))
		}
	}
	return strings.Join(parts, "&")
}

// Header redacts and bounds an allow-listed header value.
func (r *Redactor) Header(name, v string) string {
	return truncateUTF8(r.Value(name, v), maxHeaderBytes)
}

// Finding converts and redacts a policy finding. The matched value is dropped
// when the target names a sensitive parameter (e.g. ARGS:password).
func (r *Redactor) Finding(f policy.Finding) Finding {
	matched := f.Matched
	if _, key, ok := strings.Cut(f.Target, ":"); ok && r.SensitiveName(key) {
		matched = redacted
	} else {
		matched = maskPANs(truncateUTF8(matched, MaxMatchedBytes))
	}
	return Finding{
		Module:   f.Module,
		RuleID:   f.RuleID,
		Tags:     f.Tags,
		Severity: f.Severity.String(),
		Target:   f.Target,
		Matched:  truncateUTF8(matched, MaxMatchedBytes),
		Message:  maskPANs(f.Message),
		Score:    f.Score,
	}
}

// Body returns a redacted excerpt of at most MaxBodyExcerptBytes. JSON bodies
// are redacted by key, form bodies like query strings; anything else only gets
// card masking. Only the first 64 KiB is inspected.
func (r *Redactor) Body(contentType string, body []byte) string {
	if len(body) > maxBodyScan {
		body = body[:maxBodyScan]
	}
	if len(body) == 0 {
		return ""
	}
	ct := strings.ToLower(contentType)
	var out string
	switch {
	case strings.Contains(ct, "json"):
		out = r.jsonBody(body)
	case strings.Contains(ct, "x-www-form-urlencoded"):
		out = r.Query(string(body))
	default:
		out = maskPANs(strings.ToValidUTF8(string(body), ""))
	}
	return truncateUTF8(out, MaxBodyExcerptBytes)
}

func (r *Redactor) jsonBody(body []byte) string {
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		// Truncated or malformed JSON: values cannot be attributed to keys, so
		// drop the content rather than risk leaking a secret.
		return "[unparseable json body omitted]"
	}
	out, err := json.Marshal(r.walk("", v))
	if err != nil {
		return "[unparseable json body omitted]"
	}
	return string(out)
}

func (r *Redactor) walk(key string, v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = r.walk(k, val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = r.walk(key, val)
		}
		return t
	case string:
		return r.Value(key, t)
	case json.Number:
		if r.SensitiveName(key) {
			return redacted
		}
		if m := maskPANs(t.String()); m != t.String() {
			return m
		}
		return t
	case nil:
		return nil
	default:
		if r.SensitiveName(key) {
			return redacted
		}
		return t
	}
}

// maskPANs replaces every Luhn-valid run of 13-19 digits (optionally grouped
// with single spaces or dashes) by [PAN:****1234]. Longer digit runs are
// searched for valid windows so a card number glued to other digits is still
// caught.
func maskPANs(s string) string {
	if len(s) < minPANDigits {
		return s
	}
	var b strings.Builder
	i, last := 0, 0
	for i < len(s) {
		if !isDigit(s[i]) {
			i++
			continue
		}
		// Collect a run: digits with single ' ' or '-' separators between digits.
		start, end := i, i
		digits := make([]int, 0, 24) // byte offsets of digits
		for j := i; j < len(s); {
			if isDigit(s[j]) {
				digits = append(digits, j)
				end = j + 1
				j++
				continue
			}
			if (s[j] == ' ' || s[j] == '-') && j+1 < len(s) && isDigit(s[j+1]) && len(digits) > 0 {
				j++
				continue
			}
			break
		}
		i = end
		if len(digits) < minPANDigits {
			continue
		}
		if m, from, to, ok := findPAN(s, digits); ok {
			b.WriteString(s[last:from])
			b.WriteString(m)
			last = to
			i = to
		}
		_ = start
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// cardLayouts are the digit-group sizes real cards are written in when split
// by spaces or dashes. Arbitrary groups (UUID fragments, phone numbers, ids)
// must not match, or ordinary identifiers get masked about one time in ten
// (a random digit string passes Luhn 10% of the time).
var cardLayouts = [][]int{
	{4, 4, 4, 4},    // Visa, Mastercard, Discover
	{4, 6, 5},       // American Express
	{4, 6, 4},       // Diners Club (14)
	{4, 4, 4, 1},    // 13-digit
	{4, 4, 4, 2},    // 14-digit
	{4, 4, 4, 3},    // 15-digit
	{4, 4, 4, 4, 1}, // 17-digit
	{4, 4, 4, 4, 2}, // 18-digit
	{4, 4, 4, 4, 3}, // 19-digit
}

func isCardLayout(sizes []int) bool {
	for _, l := range cardLayouts {
		if slices.Equal(l, sizes) {
			return true
		}
	}
	return false
}

// findPAN returns the mask and byte span of a Luhn-valid card number inside a
// run of digits (digits holds each digit's byte offset in s).
//
//   - A contiguous run of 13-19 digits is checked as a whole, so ordinary
//     non-card numbers are left alone.
//   - A longer contiguous run is searched window by window, longest first,
//     because a card may be glued to other digits.
//   - A run grouped by spaces or dashes is searched for spans of consecutive
//     groups that use one separator and a real card layout, so
//     "qty 2 4111 1111 1111 1111" still finds the card.
func findPAN(s string, digits []int) (mask string, from, to int, ok bool) {
	n := len(digits)
	// groups[k] = [first, last+1) indexes into digits.
	var groups [][2]int
	first := 0
	for k := 1; k <= n; k++ {
		if k == n || digits[k] != digits[k-1]+1 {
			groups = append(groups, [2]int{first, k})
			first = k
		}
	}

	try := func(a, b int) (string, int, int, bool) { // digits[a:b]
		if b-a < minPANDigits || b-a > maxPANDigits {
			return "", 0, 0, false
		}
		var d strings.Builder
		for _, off := range digits[a:b] {
			d.WriteByte(s[off])
		}
		ds := d.String()
		if !Luhn(ds) {
			return "", 0, 0, false
		}
		return "[PAN:****" + ds[len(ds)-4:] + "]", digits[a], digits[b-1] + 1, true
	}

	if len(groups) == 1 {
		if n <= maxPANDigits {
			return try(0, n)
		}
		for a := 0; a+minPANDigits <= n; a++ {
			for b := min(a+maxPANDigits, n); b >= a+minPANDigits; b-- {
				if m, f, t, ok := try(a, b); ok {
					return m, f, t, true
				}
			}
		}
		return "", 0, 0, false
	}

	// A group followed by one separator character; sep[k] sits between group k and k+1.
	sep := make([]byte, len(groups)-1)
	for k := range sep {
		sep[k] = s[digits[groups[k][1]-1]+1]
	}
	// Fewest groups first: a real card is one group or the usual four, and a
	// wider span could swallow unrelated neighbouring numbers.
	for span := 1; span <= len(groups); span++ {
		for gi := 0; gi+span <= len(groups); gi++ {
			if span > 1 && !uniformCardSpan(groups[gi:gi+span], sep[gi:gi+span-1]) {
				continue
			}
			if span > 1 && !standalone(s, digits[groups[gi][0]], digits[groups[gi+span-1][1]-1]+1) {
				continue
			}
			if m, f, t, ok := try(groups[gi][0], groups[gi+span-1][1]); ok {
				return m, f, t, true
			}
		}
	}
	return "", 0, 0, false
}

// standalone reports whether s[from:to] is not glued to letters or digits. A
// grouped digit span inside an identifier such as "…-2742-4580-8814-289c5adf…"
// is a fragment of that identifier, not a card number; a dash or space next to
// the span is fine ("card-4111-1111-1111-1111").
func standalone(s string, from, to int) bool {
	alnum := func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
	}
	return (from == 0 || !alnum(s[from-1])) && (to >= len(s) || !alnum(s[to]))
}

// uniformCardSpan reports whether the groups use a single separator and a
// known card layout.
func uniformCardSpan(groups [][2]int, seps []byte) bool {
	for _, c := range seps[1:] {
		if c != seps[0] {
			return false
		}
	}
	sizes := make([]int, len(groups))
	for i, g := range groups {
		sizes[i] = g[1] - g[0]
	}
	return isCardLayout(sizes)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func unescape(s string) string {
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return s
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
