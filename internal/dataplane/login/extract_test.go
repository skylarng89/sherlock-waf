package login

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		name, ct, body, field, want string
	}{
		{"form field", "application/x-www-form-urlencoded", "email=ada%40bank.test&password=x", "email", "ada@bank.test"},
		{"form plus is a space", "application/x-www-form-urlencoded", "email=ada+lovelace", "email", "ada lovelace"},
		{"form missing", "application/x-www-form-urlencoded", "password=x", "email", ""},
		{"form first value wins", "application/x-www-form-urlencoded", "email=a&email=b", "email", "a"},
		{"form malformed escape still readable", "application/x-www-form-urlencoded", "email=ada&bad=%zz", "email", "ada"},
		{"json plain key", "application/json", `{"email":"ada","password":"x"}`, "email", "ada"},
		{"json charset", "application/json; charset=utf-8", `{"email":"ada"}`, "email", "ada"},
		{"json api type", "application/vnd.bank+json", `{"email":"ada"}`, "email", "ada"},
		{"json pointer", "application/json", `{"user":{"email":"ada"}}`, "/user/email", "ada"},
		{"json pointer array", "application/json", `{"creds":[{"u":"x"},{"u":"ada"}]}`, "/creds/1/u", "ada"},
		{"json pointer escapes", "application/json", `{"a/b":{"c~d":"ada"}}`, "/a~1b/c~0d", "ada"},
		{"json number", "application/json", `{"id":12345}`, "id", "12345"},
		{"json bool is not a name", "application/json", `{"email":true}`, "email", ""},
		{"json object is not a name", "application/json", `{"email":{"x":1}}`, "email", ""},
		{"json missing", "application/json", `{"other":"x"}`, "email", ""},
		{"json pointer through a scalar", "application/json", `{"user":"x"}`, "/user/email", ""},
		{"json array index out of range", "application/json", `[1]`, "/5", ""},
		{"json array index with sign", "application/json", `["a","b"]`, "/+1", ""},
		{"json array index with leading zero", "application/json", `["a","b"]`, "/01", ""},
		{"json malformed", "application/json", `{"email":`, "email", ""},
		{"json empty", "application/json", ``, "email", ""},
		{"json trailing garbage is ignored", "application/json", `{"email":"ada"} garbage`, "email", "ada"},
		{"multipart is not parsed", "multipart/form-data; boundary=x", "email=ada", "email", ""},
		{"text is not parsed", "text/plain", "email=ada", "email", ""},
		{"no content type", "", "email=ada", "email", ""},
		{"garbage content type", ";;;", "email=ada", "email", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind := kindOf(tc.ct)
			assert.Equal(t, tc.want, extractUsername(kind, []byte(tc.body), tc.field, pointer(tc.field)))
		})
	}
}

func TestUsernameIsCapped(t *testing.T) {
	long := strings.Repeat("a", 10_000)
	got := extractUsername(kindForm, []byte("email="+long), "email", nil)
	assert.Len(t, got, maxUsernameLen)
}

func TestPeekBodyRestoresEverything(t *testing.T) {
	read := func(r *http.Request) string {
		b := make([]byte, 0, 16)
		buf := make([]byte, 1<<16)
		for {
			n, err := r.Body.Read(buf)
			b = append(b, buf[:n]...)
			if err != nil {
				return string(b)
			}
		}
	}
	small := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader("email=ada"))
	body, ok := peekBody(small)
	assert.True(t, ok)
	assert.Equal(t, "email=ada", string(body))
	assert.Equal(t, "email=ada", read(small), "the upstream still gets the body")

	big := strings.Repeat("x", maxBodyPeek+5000)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(big))
	_, ok = peekBody(r)
	assert.False(t, ok, "an oversized body is not parsed")
	assert.Equal(t, big, read(r), "but it is passed on whole")

	exact := strings.Repeat("y", maxBodyPeek)
	r = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(exact))
	_, ok = peekBody(r)
	assert.True(t, ok, "a body of exactly the cap is read")

	empty := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", http.NoBody)
	_, ok = peekBody(empty)
	assert.False(t, ok)

	broken := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", iotest.ErrReader(assert.AnError))
	_, ok = peekBody(broken)
	assert.False(t, ok, "a body that fails to read yields no username and no panic")
	_, err := broken.Body.Read(make([]byte, 1))
	require.Error(t, err, "and the failure is still visible to the upstream")
}

func FuzzUsernameExtract(f *testing.F) {
	seeds := []struct{ ct, body, field string }{
		{"application/x-www-form-urlencoded", "email=ada&password=x", "email"},
		{"application/json", `{"user":{"email":"ada"}}`, "/user/email"},
		{"application/json", `[{"a":1}]`, "/0/a"},
		{"application/json", `{"a/b":"x"}`, "/a~1b"},
		{"multipart/form-data; boundary=x", "x", "email"},
	}
	for _, s := range seeds {
		f.Add(s.ct, []byte(s.body), s.field)
	}
	f.Fuzz(func(t *testing.T, ct string, body []byte, field string) {
		got := extractUsername(kindOf(ct), body, field, pointer(field))
		if len(got) > maxUsernameLen {
			t.Fatalf("username of %d bytes escaped the cap", len(got))
		}
		if kindOf(ct) == kindNone && got != "" {
			t.Fatalf("a body that is not parsed produced %q", got)
		}
		// The hash step must cope with whatever came out, valid UTF-8 or not.
		if h := hashUsername(got); h != "" && len(h) != 24 {
			t.Fatalf("hash of %q has length %d", got, len(h))
		}
		_ = utf8.ValidString(got)
	})
}
