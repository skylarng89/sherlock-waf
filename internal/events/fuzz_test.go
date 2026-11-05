package events

import (
	"strings"
	"testing"
)

// secretValue is planted into fuzzed inputs; no redaction path may let it through
// when it sits under a sensitive name or is a valid card number.
const (
	secretValue = "S3cr3tValue-ZZ9" //nolint:gosec // fuzz canary, not a credential
	panValue    = "4111111111111111"
)

func FuzzRedactQuery(f *testing.F) {
	for _, s := range []string{"a=b", "password=" + secretValue, "x=" + panValue, "%zz=%", "&&&=", "token=" + secretValue + "&n=" + panValue} {
		f.Add(s)
	}
	r, _ := NewRedactor(nil)
	f.Fuzz(func(t *testing.T, s string) {
		_ = r.Query(s)
		// A sensitive parameter's value must never survive, whatever precedes it.
		in := s + "&password=" + secretValue
		got := r.Query(in)
		// Oversized queries are truncated, which drops the planted parameter
		// together with its secret; otherwise it must be redacted in place.
		if len(in) <= maxQueryBytes && !strings.HasSuffix(got, "&password=[REDACTED]") {
			t.Fatalf("planted password not redacted: %.80q -> %.80q", s, got)
		}
		if !strings.Contains(s, secretValue) && strings.Contains(got, secretValue) {
			t.Fatalf("secret survived: %.80q", s)
		}
	})
}

func FuzzMaskPANs(f *testing.F) {
	for _, s := range []string{panValue, "x" + panValue + "y", "4111 1111 1111 1111", "99" + panValue, ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// NUL bytes isolate the planted card from digits in the fuzzed text.
		if got := maskPANs(s + "\x00" + panValue + "\x00" + s); strings.Contains(got, "\x00"+panValue+"\x00") {
			t.Fatalf("PAN survived: %q -> %q", s, got)
		}
	})
}

func FuzzRedactBody(f *testing.F) {
	for _, s := range []string{`{"password":"x"}`, `[`, `{"a":{"token":"y"}}`, "a=b&pin=1"} {
		f.Add(s, "application/json")
		f.Add(s, "application/x-www-form-urlencoded")
	}
	r, _ := NewRedactor(nil)
	f.Fuzz(func(t *testing.T, body, ct string) {
		got := r.Body(ct, []byte(body))
		if len(got) > MaxBodyExcerptBytes {
			t.Fatalf("excerpt too long: %d", len(got))
		}
		if strings.Contains(r.Body("application/json", []byte(`{"password":"`+secretValue+`"}`)), secretValue) {
			t.Fatal("secret leaked from json")
		}
	})
}

func FuzzLuhn(f *testing.F) {
	f.Add(panValue)
	f.Fuzz(func(_ *testing.T, s string) { _ = Luhn(s) })
}
