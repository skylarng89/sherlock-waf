package dlp

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func fuzzScanner(tb testing.TB) *Scanner {
	tb.Helper()
	s, err := NewScanner([]string{"pan", "iban", "custom:nin"}, []Pattern{{Name: "nin", Pattern: `[A-Z]{2}[0-9]{6}[A-D]|é+`}})
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

// FuzzScanAndMask checks the properties masking relies on, for any input: no
// panic, matches ordered and inside the body, the length unchanged, no byte
// outside a match modified, and valid UTF-8 stays valid UTF-8.
func FuzzScanAndMask(f *testing.F) {
	for _, s := range []string{
		visa, visaSp, visaDash, amex, ibanDE, ibanDEsp, ibanGB, "AB123456C", "ééé", "",
		`{"n":` + visa + `,"s":"` + ibanGB + `"}`, "x" + visa + "y", strings.Repeat("4", 40), "DE89 3704 0044 0532 0130 0",
	} {
		f.Add(s)
	}
	sc := fuzzScanner(f)
	f.Fuzz(func(t *testing.T, s string) {
		in := []byte(s)
		out := bytes.Clone(in)
		ms := sc.Scan(out)
		prev := 0
		inside := make([]bool, len(in))
		for _, m := range ms {
			if m.Start < prev || m.End <= m.Start || m.End > len(in) {
				t.Fatalf("bad match %+v in %q", m, s)
			}
			prev = m.End
			for i := m.Start; i < m.End; i++ {
				inside[i] = true
			}
		}
		Mask(out, ms, func(Match) bool { return len(s)%2 == 0 })
		if len(out) != len(in) {
			t.Fatalf("length changed: %d -> %d", len(in), len(out))
		}
		for i := range in {
			if !inside[i] && in[i] != out[i] {
				t.Fatalf("byte %d outside every match changed: %q -> %q", i, s, out)
			}
		}
		if utf8.Valid(in) && !utf8.Valid(out) {
			t.Fatalf("masking broke UTF-8: %q -> %q", s, out)
		}
	})
}

// FuzzPlantedCardIsAlwaysFound: a card number between NUL bytes (which isolate it
// from the fuzzed text) is found and, once masked, no longer present.
func FuzzPlantedCardIsAlwaysFound(f *testing.F) {
	for _, s := range []string{"", "id 12345", visa, "{\"a\":1}"} {
		f.Add(s)
	}
	sc, err := NewScanner([]string{"pan"}, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		body := []byte(s + "\x00" + visa + "\x00" + s)
		ms := sc.Scan(body)
		found := false
		for _, m := range ms {
			if string(body[m.Start:m.End]) == visa {
				found = true
			}
		}
		if !found {
			t.Fatalf("planted card not found next to %.60q", s)
		}
		Mask(body, ms, nil)
		if bytes.Contains(body, []byte("\x00"+visa+"\x00")) {
			t.Fatalf("planted card survived masking next to %.60q", s)
		}
	})
}
