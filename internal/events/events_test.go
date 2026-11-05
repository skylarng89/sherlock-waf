package events

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

func TestLuhn(t *testing.T) {
	valid := []string{"4111111111111111", "5500005555555559", "378282246310005", "6011111111111117", "4012888888881881", "0000000000000"}
	for _, v := range valid {
		assert.True(t, Luhn(v), v)
	}
	for _, v := range []string{"4111111111111112", "", "41111111x1111111", "1234567890123"} {
		assert.False(t, Luhn(v), v)
	}
}

func mustRedactor(t *testing.T, extra ...string) *Redactor {
	t.Helper()
	r, err := NewRedactor(extra)
	require.NoError(t, err)
	return r
}

func TestRedactQuery(t *testing.T) {
	r := mustRedactor(t)
	tests := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"plain", "a=1&b=two", "a=1&b=two"},
		{"password", "user=bob&password=hunter2", "user=bob&password=[REDACTED]"},
		{"case-insensitive name", "PassWord=x&API_TOKEN=y", "PassWord=[REDACTED]&API_TOKEN=[REDACTED]"},
		{"encoded name", "pass%77ord=x", "pass%77ord=[REDACTED]"},
		{"card name", "card_number=4111111111111111", "card_number=[REDACTED]"},
		{"authorization", "authorization=Bearer+abc", "authorization=[REDACTED]"},
		{"pan in innocuous param", "note=4111111111111111", "note=[PAN:****1111]"},
		{"pan with dashes", "note=4111-1111-1111-1111", "note=[PAN:****1111]"},
		{"pan url-encoded spaces", "note=4111+1111+1111+1111", "note=[PAN:****1111]"},
		{"not luhn", "n=4111111111111112", "n=4111111111111112"},
		{"12 digits", "n=123456789012", "n=123456789012"},
		{"valueless sensitive", "token", "token"},
		{"duplicate keys", "p=1&password=a&password=b", "p=1&password=[REDACTED]&password=[REDACTED]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.want, r.Query(tc.in)) })
	}
}

func TestMaskPANsEdgeCases(t *testing.T) {
	tests := []struct{ in, want string }{
		{"card 4111111111111111 end", "card [PAN:****1111] end"},
		{"two 4111111111111111 and 5500005555555559", "two [PAN:****1111] and [PAN:****5559]"},
		{"glued 9999994111111111111111 digits", "glued 9999994111111111111111 digits"},
		{"order id 1234567890", "order id 1234567890"},
		{"4111 1111 1111 1111", "[PAN:****1111]"},
		{"4111  1111 1111 1111", "4111  1111 1111 1111"}, // double space breaks the group
		{"qty 2 4111111111111111 3", "qty 2 [PAN:****1111] 3"},
		{"qty 2 4111 1111 1111 1111", "qty 2 [PAN:****1111]"},
	}
	for _, tc := range tests {
		got := maskPANs(tc.in)
		if tc.in == "glued 9999994111111111111111 digits" {
			assert.NotContains(t, got, "4111111111111111", "a PAN glued to other digits must still be masked")
			continue
		}
		assert.Equal(t, tc.want, got, tc.in)
	}
}

// Identifiers that are not cards must survive: a random digit string passes
// Luhn one time in ten, so unrestricted grouping would corrupt ordinary
// evidence (UUIDs, phone numbers, order references).
func TestMaskPANsLeavesNonCardIdentifiers(t *testing.T) {
	keep := []string{
		"920470-6-08e17576-9227-4693-a35f-e992df686796-s",
		"550e8400-e29b-41d4-a716-446655440000",
		"+49 170 1234567 89",
		"order 12345-67890-12345",
		"1793220045915", // epoch milliseconds
		"2026-10-28 12:30:45.123456",
		"192.168.100.200",
		"4111 1111-1111 1111", // mixed separators are not a card layout
		"4111-1111 1111-1111",
		// Digit-only fragments inside identifiers that happen to be Luhn-valid
		// (this exact marker was corrupted about one test in a thousand).
		"944130-129-b051ca84-2742-4580-8814-289c5adf2677-s",
		"tok-4111-1111-1111-1111x",
		"x4111 1111 1111 1111",
	}
	for _, in := range keep {
		assert.Equal(t, in, maskPANs(in), in)
	}
	// Real layouts, all Luhn-valid test numbers.
	for in, want := range map[string]string{
		"4111 1111 1111 1111":       "[PAN:****1111]",
		"4111-1111-1111-1111":       "[PAN:****1111]",
		"3782 822463 10005":         "[PAN:****0005]",
		"3782-822463-10005":         "[PAN:****0005]",
		"3056 930902 5904":          "[PAN:****5904]",
		"6011 1111 1111 1117":       "[PAN:****1117]",
		"a 5500005555555559 b":      "a [PAN:****5559] b",
		"card-4111-1111-1111-1111":  "card-[PAN:****1111]",
		"pay: 4111 1111 1111 1111.": "pay: [PAN:****1111].",
		"(4111-1111-1111-1111)":     "([PAN:****1111])",
	} {
		assert.Equal(t, want, maskPANs(in), in)
	}
}

func TestCustomPatterns(t *testing.T) {
	r := mustRedactor(t, `(?i)^iban$`, `internal_ref`)
	assert.Equal(t, "iban=[REDACTED]&x=1", r.Query("iban=DE89370400440532013000&x=1"))
	assert.Equal(t, "my_internal_ref_2=[REDACTED]", r.Query("my_internal_ref_2=abc"))

	_, err := NewRedactor([]string{"("})
	require.Error(t, err)
	_, err = NewRedactor([]string{strings.Repeat("a", 300)})
	require.Error(t, err)
}

func TestRedactBody(t *testing.T) {
	r := mustRedactor(t)
	t.Run("json nested", func(t *testing.T) {
		got := r.Body("application/json", []byte(`{"user":"bob","auth":{"password":"hunter2","otp":123456},"cards":[{"number":"4111111111111111"}],"n":4111111111111111}`))
		assert.NotContains(t, got, "hunter2")
		assert.NotContains(t, got, "123456")
		assert.NotContains(t, got, "4111111111111111")
		assert.Contains(t, got, "bob")
		assert.Contains(t, got, "[PAN:****1111]")
	})
	t.Run("json invalid is dropped", func(t *testing.T) {
		got := r.Body("application/json", []byte(`{"password":"hunter2`))
		assert.NotContains(t, got, "hunter2")
	})
	t.Run("form", func(t *testing.T) {
		got := r.Body("application/x-www-form-urlencoded", []byte("u=bob&password=hunter2"))
		assert.Equal(t, "u=bob&password=[REDACTED]", got)
	})
	t.Run("other type gets card masking only", func(t *testing.T) {
		assert.Equal(t, "pay [PAN:****1111]", r.Body("text/plain", []byte("pay 4111111111111111")))
	})
	t.Run("bounded to 2KB", func(t *testing.T) {
		got := r.Body("text/plain", []byte(strings.Repeat("é", 5000)))
		assert.LessOrEqual(t, len(got), MaxBodyExcerptBytes)
		assert.True(t, json.Valid([]byte(`"`+got+`"`)), "must not split a rune")
	})
	assert.Empty(t, r.Body("text/plain", nil))
}

func TestRedactFinding(t *testing.T) {
	r := mustRedactor(t)
	f := r.Finding(policy.Finding{Module: "waf", RuleID: "942100", Severity: policy.SeverityCritical, Target: "ARGS:password", Matched: "hunter2", Message: "x"})
	assert.Equal(t, "[REDACTED]", f.Matched)
	assert.Equal(t, "critical", f.Severity)

	f = r.Finding(policy.Finding{Target: "ARGS:id", Matched: "1' OR 4111111111111111"})
	assert.Equal(t, "1' OR [PAN:****1111]", f.Matched)

	f = r.Finding(policy.Finding{Target: "ARGS:id", Matched: strings.Repeat("a", 1000)})
	assert.Len(t, f.Matched, MaxMatchedBytes)
}

func TestHeaderBoundedAndMasked(t *testing.T) {
	r := mustRedactor(t)
	assert.Len(t, r.Header("User-Agent", strings.Repeat("x", 2000)), 512)
	assert.Equal(t, "ref [PAN:****1111]", r.Header("Referer", "ref 4111111111111111"))
}

func TestSchemaIsCurrent(t *testing.T) {
	want, err := Schema()
	require.NoError(t, err)
	got, err := os.ReadFile("../../docs/reference/event.schema.json")
	require.NoError(t, err, "run make gen")
	assert.Equal(t, string(want), string(got), "docs/reference/event.schema.json is stale; run make gen")
}

func TestSchemaStructure(t *testing.T) {
	b, err := Schema()
	require.NoError(t, err)
	var s map[string]any
	require.NoError(t, json.Unmarshal(b, &s))
	assert.Equal(t, false, s["additionalProperties"])
	assert.ElementsMatch(t, []any{"id", "schema", "ts", "node", "site_id", "action", "mode", "client", "request", "response", "timing", "findings", "anomaly_score"}, s["required"])
	props := s["properties"].(map[string]any) //nolint:errcheck,forcetypeassert // test shape
	assert.Equal(t, map[string]any{"type": "string", "format": "date-time", "description": "Request start"}, props["ts"])
}

func TestEventJSONRoundTrip(t *testing.T) {
	rep := 80
	ev := Event{
		ID: "01TEST", Schema: SchemaV1, TS: time.Date(2026, 10, 28, 12, 0, 0, 5, time.UTC), Node: "n1", SiteID: "shop",
		Action: "block", Mode: "block", TerminatedBy: "waf",
		Client:   Client{IP: "192.0.2.1", Reputation: &rep},
		Request:  Request{Method: "GET", Host: "h", Path: "/", Headers: map[string]string{"User-Agent": "x"}},
		Response: Response{Status: 403, Bytes: 10}, Findings: []Finding{{Module: "waf", Severity: "critical"}},
	}
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	var back Event
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, ev, back)
	assert.NotContains(t, string(b), "config_version", "optional fields are omitted when empty")
}

// TestMaskPANsNeverTouchesIdentifiers generates test-marker-style identifiers
// (rule-test number + UUID) and requires them to come through untouched. With
// naive grouping about one in a thousand was masked, which silently corrupted
// evidence and broke the go-ftw harness that keys on these strings.
func TestMaskPANsNeverTouchesIdentifiers(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // fixed seed: deterministic, not security-sensitive
	const hexDigits = "0123456789abcdef"
	hex := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = hexDigits[rng.IntN(16)]
		}
		return string(b)
	}
	for range 50_000 {
		id := fmt.Sprintf("%d-%d-%s-%s-%s-%s-%s-%s", 900000+rng.IntN(100000), 1+rng.IntN(200),
			hex(8), hex(4), hex(4), hex(4), hex(12), []string{"s", "e"}[rng.IntN(2)])
		if got := maskPANs(id); got != id {
			t.Fatalf("identifier was modified:\n in:  %s\n out: %s", id, got)
		}
	}
}
