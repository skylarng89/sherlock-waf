package dlp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test card numbers are the public test values of the card networks; none is a
// real account. Built by concatenation so a secret scanner does not flag the file.
const (
	visa      = "4111" + "1111" + "1111" + "1111"
	visaSp    = "4111 1111 1111 1111"
	visaDash  = "4111-1111-1111-1111"
	amex      = "3782 822463 10005"
	mc        = "5555" + "5555" + "5555" + "4444"
	notLuhn   = "4111" + "1111" + "1111" + "1112"
	ibanDE    = "DE89370400440532013000"
	ibanDEsp  = "DE89 3704 0044 0532 0130 00"
	ibanGB    = "GB82WEST12345698765432"
	ibanFR    = "FR1420041010050500013M02606"
	ibanBadCk = "DE88370400440532013000"
)

func newScanner(t *testing.T, detect []string, patterns ...Pattern) *Scanner {
	t.Helper()
	s, err := NewScanner(detect, patterns)
	require.NoError(t, err)
	return s
}

func spans(b string, ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Kind+"="+b[m.Start:m.End])
	}
	return out
}

func TestScanPAN(t *testing.T) {
	s := newScanner(t, []string{"pan"})
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"contiguous", `{"card":"` + visa + `"}`, []string{"pan=" + visa}},
		{"spaces", "pay with " + visaSp + " today", []string{"pan=" + visaSp}},
		{"dashes", "card " + visaDash + ".", []string{"pan=" + visaDash}},
		{"amex layout", "amex " + amex, []string{"pan=" + amex}},
		{"two cards", visa + " and " + mc, []string{"pan=" + visa, "pan=" + mc}},
		{"fails luhn", notLuhn, nil},
		{"too short", "4111 1111 1111", nil},
		{"identifier fragment", "id=7f3e4111-1111-1111-1111c9a0", nil},
		{"glued to letters", "ref" + visa + "x", nil},
		{"glued to more digits", "1" + visa + "22", nil},
		{"short digit run", "order 12345678901", nil},
		{"html", "<td>" + visa + "</td>", []string{"pan=" + visa}},
		{"bare json number", `{"n":` + visa + `}`, []string{"pan=" + visa}},
		{"empty", "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, spans(tc.in, s.Scan([]byte(tc.in))))
		})
	}
}

func TestScanIBAN(t *testing.T) {
	s := newScanner(t, []string{"iban"})
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"germany", "IBAN " + ibanDE + ".", []string{"iban=" + ibanDE}},
		{"germany grouped", "IBAN: " + ibanDEsp, []string{"iban=" + ibanDEsp}},
		{"britain", `"` + ibanGB + `"`, []string{"iban=" + ibanGB}},
		{"france with letters", ibanFR, []string{"iban=" + ibanFR}},
		{"wrong check digits", ibanBadCk, nil},
		{"wrong length", "DE8937040044053201300", nil},
		{"unknown country", "ZZ89370400440532013000", nil},
		{"lower case", strings.ToLower(ibanDE), nil},
		{"glued before", "X" + ibanDE, nil},
		{"glued after", ibanDE + "9", nil},
		{"two", ibanDE + "; " + ibanGB, []string{"iban=" + ibanDE, "iban=" + ibanGB}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, spans(tc.in, s.Scan([]byte(tc.in))))
		})
	}
}

func TestScanCustomAndOverlap(t *testing.T) {
	nin := Pattern{Name: "nin", Pattern: `\b[A-Z]{2}[0-9]{6}[A-D]\b`}
	s := newScanner(t, []string{"pan", "iban", "custom:nin"}, nin)
	in := "nino AB123456C card " + visa + " iban " + ibanGB
	assert.Equal(t, []string{"custom:nin=AB123456C", "pan=" + visa, "iban=" + ibanGB}, spans(in, s.Scan([]byte(in))))

	// A custom pattern that covers a card number does not report it twice.
	wide := Pattern{Name: "wide", Pattern: `card [0-9 ]+`}
	s = newScanner(t, []string{"pan", "custom:wide"}, wide)
	in = "see card " + visaSp + "!"
	got := s.Scan([]byte(in))
	require.Len(t, got, 1)
	assert.Equal(t, "custom:wide", got[0].Kind, "the match that starts first wins")
}

func TestNewScannerRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		detect   []string
		patterns []Pattern
	}{
		"no detector":       {nil, nil},
		"unknown detector":  {[]string{"ssn"}, nil},
		"undeclared custom": {[]string{"custom:x"}, nil},
		"unnamed pattern":   {[]string{"pan"}, []Pattern{{Pattern: "a"}}},
		"bad regexp":        {[]string{"custom:x"}, []Pattern{{Name: "x", Pattern: "("}}},
		"matches empty":     {[]string{"custom:x"}, []Pattern{{Name: "x", Pattern: "a*"}}},
		"not RE2":           {[]string{"custom:x"}, []Pattern{{Name: "x", Pattern: "a(?=b)"}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewScanner(tc.detect, tc.patterns)
			assert.Error(t, err)
		})
	}
}

func TestMask(t *testing.T) {
	s := newScanner(t, []string{"pan", "iban", "custom:nin"}, Pattern{Name: "nin", Pattern: `AB[0-9]{6}[A-D]|é+`})
	tests := []struct{ name, in, want string }{
		{"contiguous keeps the last four", "c=" + visa + ";", "c=************1111;"},
		{"separators stay", visaSp, "**** **** **** 1111"},
		{"dashes", visaDash, "****-****-****-1111"},
		{"amex", amex, "**** ****** *0005"},
		{"iban keeps country and last four", ibanDE, "DE****************3000"},
		{"grouped iban", ibanDEsp, "DE** **** **** **** **30 00"},
		{"custom is masked entirely", "id AB123456C ok", "id ********* ok"},
		{"multi-byte custom keeps UTF-8 valid and length", "x ééé y", "x ****** y"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := []byte(tc.in)
			Mask(b, s.Scan(b), nil)
			assert.Equal(t, len(tc.in), len(b), "length never changes")
			assert.Equal(t, tc.want, string(b))
		})
	}
}

func TestMaskBareJSONNumberStaysANumber(t *testing.T) {
	s := newScanner(t, []string{"pan"})
	b := []byte(`{"n":` + visa + `,"s":"` + visa + `"}`)
	ms := s.Scan(b)
	require.Len(t, ms, 2)
	Mask(b, ms, func(m Match) bool { return b[m.Start-1] == ':' })
	assert.Equal(t, `{"n":999999999999`+`1111,"s":"************1111"}`, string(b))
}

func TestMaskNeverTouchesBytesOutsideMatches(t *testing.T) {
	s := newScanner(t, []string{"pan", "iban"})
	in := []byte("before " + visa + " middle " + ibanGB + " after")
	out := bytes.Clone(in)
	ms := s.Scan(out)
	Mask(out, ms, nil)
	inside := make([]bool, len(in))
	for _, m := range ms {
		for i := m.Start; i < m.End; i++ {
			inside[i] = true
		}
	}
	for i := range in {
		if !inside[i] {
			assert.Equal(t, in[i], out[i], "byte %d is outside every match", i)
		}
	}
}

func TestScanFindsAMatchAnywhereInALargeBody(t *testing.T) {
	filler := strings.Repeat("lorem ipsum 12345 ", 5000)
	for _, at := range []int{0, 17, len(filler) / 2, len(filler)} {
		body := filler[:at] + " " + visa + " " + filler[at:]
		got := newScanner(t, []string{"pan"}).Scan([]byte(body))
		require.Len(t, got, 1, "at %d", at)
		assert.Equal(t, visa, body[got[0].Start:got[0].End])
	}
}

func BenchmarkScan(b *testing.B) {
	page := strings.Repeat(`<tr><td>order 8841</td><td>jane@example.com</td><td>2026-11-06</td><td>total 129.90</td></tr>`+"\n", 1000)
	page += "card " + visa + " iban " + ibanGB
	s, err := NewScanner([]string{"pan", "iban"}, nil)
	require.NoError(b, err)
	body := []byte(page)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if len(s.Scan(body)) != 2 {
			b.Fatal("expected two matches")
		}
	}
}

func BenchmarkScanClean(b *testing.B) {
	body := []byte(strings.Repeat(`{"id":8841,"name":"Jane","tags":["a","b"],"total":129.90}`, 2000))
	s, err := NewScanner([]string{"pan", "iban"}, nil)
	require.NoError(b, err)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		_ = s.Scan(body)
	}
}
