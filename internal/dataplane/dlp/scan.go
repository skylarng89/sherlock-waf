package dlp

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/skylarng89/sherlock-waf/internal/events"
)

// Detector kinds. A custom detector's kind is customPrefix + its name.
const (
	kindPAN      = "pan"
	kindIBAN     = "iban"
	customPrefix = "custom:"

	maskByte = '*'
	// bareFill replaces the digits of an unquoted JSON number. It must be a digit,
	// and not '0', which would give a leading zero and an invalid document.
	bareFill = '9'
	// maxMatches bounds the work a single response can cause. Past it the rest of
	// the body is still masked by the matches found so far; the finding says so.
	maxMatches = 10_000
)

// Pattern is a named custom detector.
type Pattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

// Match is one sensitive value: the half-open byte span and the detector kind.
// The value itself is never copied out of the body.
type Match struct {
	Start, End int
	Kind       string
}

type customDetector struct {
	name string
	re   *regexp.Regexp
}

// Scanner finds sensitive values in a response body. It is immutable after
// NewScanner and safe for concurrent use. Custom patterns are RE2, so a hostile
// response cannot make a scan super-linear.
type Scanner struct {
	pan, iban bool
	custom    []customDetector
}

// ErrNoDetector means a configuration selects nothing to look for.
var ErrNoDetector = errors.New("dlp: detect lists no detector")

// NewScanner builds a Scanner for detect (pan, iban, custom:<name>) and the
// declared custom patterns. A pattern that matches the empty string is refused:
// it would match everywhere.
func NewScanner(detect []string, patterns []Pattern) (*Scanner, error) {
	if len(detect) == 0 {
		return nil, ErrNoDetector
	}
	compiled := make(map[string]*regexp.Regexp, len(patterns))
	for _, p := range patterns {
		if p.Name == "" {
			return nil, errors.New("dlp: a custom pattern has no name")
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("dlp: custom pattern %q: %w", p.Name, err)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("dlp: custom pattern %q matches the empty string", p.Name)
		}
		compiled[p.Name] = re
	}
	s := &Scanner{}
	for _, d := range detect {
		switch {
		case d == kindPAN:
			s.pan = true
		case d == kindIBAN:
			s.iban = true
		case strings.HasPrefix(d, customPrefix):
			name := strings.TrimPrefix(d, customPrefix)
			re, ok := compiled[name]
			if !ok {
				return nil, fmt.Errorf("dlp: detect %q has no matching custom pattern", d)
			}
			if !slices.ContainsFunc(s.custom, func(c customDetector) bool { return c.name == name }) {
				s.custom = append(s.custom, customDetector{name: name, re: re})
			}
		default:
			return nil, fmt.Errorf("dlp: unknown detector %q", d)
		}
	}
	return s, nil
}

// Scan returns the non-overlapping matches in b, in order. When detectors
// overlap, the one that starts first wins, then the longer one.
func (s *Scanner) Scan(b []byte) []Match {
	if len(b) == 0 {
		return nil
	}
	var all []Match
	if s.pan {
		for _, sp := range events.FindPANs(string(b)) {
			all = append(all, Match{Start: sp.From, End: sp.To, Kind: kindPAN})
		}
	}
	if s.iban {
		all = append(all, findIBANs(b)...)
	}
	for _, c := range s.custom {
		for _, loc := range c.re.FindAllIndex(b, maxMatches) {
			if loc[1] > loc[0] {
				all = append(all, Match{Start: loc[0], End: loc[1], Kind: customPrefix + c.name})
			}
		}
	}
	if len(all) < 2 {
		return all
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Start != all[j].Start {
			return all[i].Start < all[j].Start
		}
		return all[i].End > all[j].End
	})
	out := all[:0]
	end := 0
	for _, m := range all {
		if m.Start < end {
			continue
		}
		out = append(out, m)
		end = m.End
	}
	if len(out) > maxMatches {
		out = out[:maxMatches]
	}
	return out
}

// Mask overwrites the matches in b in place, so the length never changes and the
// layout around a value survives (a Content-Length stays correct).
//
//   - pan keeps the last four digits; every other digit becomes '*' (or '9' when
//     bareNumber says the value is an unquoted JSON number, which must stay a
//     number), and separators stay.
//   - iban keeps the two-letter country code and the last four characters;
//     everything else alphanumeric becomes '*', spaces stay.
//   - a custom match is masked entirely: every ASCII letter or digit and every
//     byte of a multi-byte character becomes '*', other ASCII stays.
func Mask(b []byte, matches []Match, bareNumber func(Match) bool) {
	for _, m := range matches {
		seg := b[m.Start:m.End]
		switch m.Kind {
		case kindPAN:
			fill := byte(maskByte)
			if bareNumber != nil && bareNumber(m) {
				fill = bareFill
			}
			keepLast(seg, 4, 0, isDigit, fill)
		case kindIBAN:
			keepLast(seg, 4, 2, isAlnum, maskByte)
		default:
			for i, c := range seg {
				if isAlnum(c) || c >= 0x80 {
					seg[i] = maskByte
				}
			}
		}
	}
}

// keepLast masks every byte of seg for which maskable is true, except the first
// head and the last tail such bytes.
func keepLast(seg []byte, tail, head int, maskable func(byte) bool, fill byte) {
	n := 0
	for _, c := range seg {
		if maskable(c) {
			n++
		}
	}
	seen := 0
	for i, c := range seg {
		if !maskable(c) {
			continue
		}
		if seen >= head && seen < n-tail {
			seg[i] = fill
		}
		seen++
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isAlnum(c byte) bool { return isDigit(c) || isUpper(c) || c >= 'a' && c <= 'z' }

// ibanLengths is the IBAN registry: total length by country code.
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29,
	"BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29,
	"ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
	"HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
	"LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22,
	"MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25,
	"QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25,
	"SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}

const maxIBANLen = 34

// findIBANs finds IBANs: an upper-case country code and two check digits, then
// the rest of the country's length, optionally written in groups of four
// separated by single spaces, passing ISO 13616 mod-97. A candidate glued to
// other letters or digits is not an IBAN.
func findIBANs(b []byte) []Match {
	var out []Match
	var compact [maxIBANLen]byte
	for i := 0; i+4 <= len(b); i++ {
		if !isUpper(b[i]) || !isUpper(b[i+1]) || !isDigit(b[i+2]) || !isDigit(b[i+3]) {
			continue
		}
		if i > 0 && isAlnum(b[i-1]) {
			continue
		}
		want, ok := ibanLengths[string(b[i:i+2])]
		if !ok {
			continue
		}
		n, j := 0, i
		for j < len(b) && n < want {
			c := b[j]
			switch {
			case isDigit(c) || isUpper(c):
				compact[n] = c
				n++
				j++
				continue
			case c == ' ' && n%4 == 0 && j+1 < len(b) && (isDigit(b[j+1]) || isUpper(b[j+1])):
				j++
				continue
			}
			break
		}
		if n != want || (j < len(b) && isAlnum(b[j])) || !ibanChecksum(compact[:n]) {
			continue
		}
		out = append(out, Match{Start: i, End: j, Kind: kindIBAN})
		i = j - 1
		if len(out) >= maxMatches {
			break
		}
	}
	return out
}

// ibanChecksum is the ISO 7064 mod-97-10 check: move the first four characters
// to the end, read letters as 10..35, and the number must be 1 modulo 97.
func ibanChecksum(c []byte) bool {
	rem := 0
	feed := func(ch byte) {
		if isDigit(ch) {
			rem = (rem*10 + int(ch-'0')) % 97
			return
		}
		rem = (rem*100 + int(ch-'A') + 10) % 97
	}
	for _, ch := range c[4:] {
		feed(ch)
	}
	for _, ch := range c[:4] {
		feed(ch)
	}
	return rem == 1
}
