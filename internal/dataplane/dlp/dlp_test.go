package dlp

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/policy"
)

type upstream func(w http.ResponseWriter, r *http.Request)

func provisioned(t *testing.T, h Handler) *Handler {
	t.Helper()
	if h.SiteID == "" {
		h.SiteID = "bank"
	}
	if h.Mode == "" {
		h.Mode = "block"
	}
	if len(h.Detect) == 0 {
		h.Detect = []string{"pan", "iban"}
	}
	require.NoError(t, h.Provision(caddy.Context{}))
	require.NoError(t, h.Validate())
	return &h
}

type outcome struct {
	rec      *httptest.ResponseRecorder
	decision *policy.Decision
	seenAE   string // Accept-Encoding the origin received
}

func (o outcome) body() string { return o.rec.Body.String() }

func serve(t *testing.T, h *Handler, req *http.Request, up upstream) outcome {
	t.Helper()
	d := policy.NewDecision("EV1", h.SiteID, policy.Mode(h.Mode), netip.MustParseAddr("192.0.2.1"))
	req = req.WithContext(policy.WithDecision(req.Context(), d))
	rec := httptest.NewRecorder()
	var seen string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		seen = r.Header.Get("Accept-Encoding")
		up(w, r)
		return nil
	})
	require.NoError(t, h.ServeHTTP(rec, req, next))
	return outcome{rec: rec, decision: d, seenAE: seen}
}

func get(t *testing.T, hdr ...string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/account", nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	return r
}

func respond(ct, body string) upstream {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ct)
		_, _ = io.WriteString(w, body)
	}
}

func findingText(d *policy.Decision) string {
	var b strings.Builder
	for _, f := range d.Findings() {
		b.WriteString(f.Module + "|" + f.RuleID + "|" + f.Target + "|" + f.Message + "|" + f.Matched + "\n")
	}
	return b.String()
}

const page = "<p>Card " + visa + " and " + visaSp + "</p><p>IBAN " + ibanGB + "</p>"

func TestMaskReplacesValuesKeepsLengthAndRecordsCountsOnly(t *testing.T) {
	h := provisioned(t, Handler{Action: "mask"})
	o := serve(t, h, get(t), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", itoa(len(page)))
		_, _ = io.WriteString(w, page)
	})
	assert.Equal(t, http.StatusOK, o.rec.Code)
	assert.Equal(t, "<p>Card ************1111 and **** **** **** 1111</p><p>IBAN GB****************5432</p>", o.body())
	assert.Equal(t, itoa(len(page)), o.rec.Header().Get("Content-Length"), "masking keeps the length, so the header stays right")
	assert.Len(t, o.body(), len(page))

	fs := o.decision.Findings()
	require.Len(t, fs, 2)
	assert.Equal(t, "dlp", fs[0].Module)
	assert.Equal(t, "pan", fs[0].RuleID)
	assert.Contains(t, fs[0].Message, "2 card numbers")
	assert.Contains(t, fs[1].Message, "1 IBANs")
	text := findingText(o.decision)
	for _, v := range []string{visa, "4111", ibanGB, "WEST"} {
		assert.NotContains(t, text, v, "findings carry counts, never values")
	}
	assert.Empty(t, fs[0].Matched)
	assert.Equal(t, policy.ActionLog, o.decision.Action(), "a masked response is recorded, not blocked")
}

func TestCardsSplitAcrossWritesAreFound(t *testing.T) {
	h := provisioned(t, Handler{Action: "mask"})
	for cut := 1; cut < len(visa); cut++ {
		o := serve(t, h, get(t), func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"card":"`+visa[:cut])
			_, _ = io.WriteString(w, visa[cut:]+`"}`)
		})
		assert.Equal(t, `{"card":"************1111"}`, o.body(), "cut at %d", cut)
	}
}

func TestBareJSONNumberStaysValidJSON(t *testing.T) {
	h := provisioned(t, Handler{Action: "mask"})
	o := serve(t, h, get(t), respond("application/json", `{"n":`+visa+`,"s":"`+visa+`","l":[`+visa+`]}`))
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(o.body()), &doc), o.body())
	assert.Equal(t, "************1111", doc["s"])
	assert.NotContains(t, o.body(), "4111")
}

func TestStructuredSuffixTypesAreScanned(t *testing.T) {
	h := provisioned(t, Handler{Action: "mask"})
	o := serve(t, h, get(t), respond("application/problem+json", `{"detail":"`+visa+`"}`))
	assert.NotContains(t, o.body(), visa)
}

func TestBlockReplacesTheResponseBeforeAnyByteIsSent(t *testing.T) {
	h := provisioned(t, Handler{Action: "block"})
	o := serve(t, h, get(t, "Accept", "text/html"), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Origin-Secret", "leak-me")
		w.Header().Set("Set-Cookie", "session=origin")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "<p>"+visa+"</p>")
	})
	assert.Equal(t, http.StatusBadGateway, o.rec.Code)
	assert.NotContains(t, o.body(), visa)
	assert.NotContains(t, o.body(), "4111")
	assert.Empty(t, o.rec.Header().Get("X-Origin-Secret"), "nothing from the origin leaks into the replacement")
	assert.Empty(t, o.rec.Header().Get("Set-Cookie"))
	assert.Equal(t, policy.ActionBlock, o.decision.Action())
	assert.Equal(t, moduleName, o.decision.Terminated())
	assert.Contains(t, findingText(o.decision), "response blocked")
}

func TestLogLeavesTheBodyAndDetectModeNeverChangesAnything(t *testing.T) {
	for name, h := range map[string]*Handler{
		"log action":  provisioned(t, Handler{Action: "log"}),
		"detect mode": provisioned(t, Handler{Action: "block", Mode: "detect"}),
		"detect mask": provisioned(t, Handler{Action: "mask", Mode: "detect"}),
	} {
		t.Run(name, func(t *testing.T) {
			o := serve(t, h, get(t), respond("text/html", page))
			assert.Equal(t, page, o.body(), "the response is untouched")
			assert.Equal(t, http.StatusOK, o.rec.Code)
			assert.NotEqual(t, policy.ActionBlock, o.decision.Action())
			require.NotEmpty(t, o.decision.Findings(), "but the finding is recorded")
			assert.Empty(t, o.decision.Terminated())
		})
	}
	o := serve(t, provisioned(t, Handler{Action: "block", Mode: "detect"}), get(t), respond("text/html", page))
	assert.Contains(t, findingText(o.decision), "detect mode")
}

func TestCleanResponsesPassUnchanged(t *testing.T) {
	h := provisioned(t, Handler{Action: "block"})
	body := `{"id":8841,"order":"2026-11-06","total":129.90}`
	o := serve(t, h, get(t), respond("application/json", body))
	assert.Equal(t, body, o.body())
	assert.Empty(t, o.decision.Findings())
}

func TestContentTypeAllowList(t *testing.T) {
	h := provisioned(t, Handler{Action: "mask", ContentTypes: []string{"application/json"}})
	assert.Equal(t, "<p>"+visa+"</p>", serve(t, h, get(t), respond("text/html", "<p>"+visa+"</p>")).body(), "HTML is not on this list")
	assert.NotContains(t, serve(t, h, get(t), respond("application/json; charset=utf-8", visa)).body(), "4111")

	prefix := provisioned(t, Handler{Action: "mask", ContentTypes: []string{"text/"}})
	assert.NotContains(t, serve(t, prefix, get(t), respond("text/csv", visa)).body(), "4111", "a prefix entry covers the family")
}

func TestUnscannableResponsesPassAndAreNotHeld(t *testing.T) {
	h := provisioned(t, Handler{Action: "block"})
	t.Run("no content type", func(t *testing.T) {
		o := serve(t, h, get(t), func(w http.ResponseWriter, _ *http.Request) {
			w.Header()["Content-Type"] = nil
			_, _ = io.WriteString(w, visa)
		})
		assert.Equal(t, visa, o.body())
	})
	t.Run("event stream", func(t *testing.T) {
		hs := provisioned(t, Handler{Action: "block", ContentTypes: []string{"text/"}})
		o := serve(t, hs, get(t), respond("text/event-stream", "data: "+visa+"\n\n"))
		assert.Contains(t, o.body(), visa, "a stream never ends, so it is never held")
	})
	t.Run("unsupported encoding", func(t *testing.T) {
		o := serve(t, h, get(t), func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Encoding", "br")
			_, _ = io.WriteString(w, visa)
		})
		assert.Equal(t, visa, o.body(), "passed through, and counted as skipped")
	})
	t.Run("HEAD and 304", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodHead, "/", nil)
		o := serve(t, h, req, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotModified)
		})
		assert.Equal(t, http.StatusNotModified, o.rec.Code)
	})
	t.Run("error statuses are scanned too", func(t *testing.T) {
		hm := provisioned(t, Handler{Action: "mask"})
		o := serve(t, hm, get(t), func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "failed for card "+visa)
		})
		assert.Equal(t, http.StatusInternalServerError, o.rec.Code)
		assert.NotContains(t, o.body(), "4111")
	})
}

func TestUpgradeRequestsBypass(t *testing.T) {
	h := provisioned(t, Handler{Action: "block"})
	req := get(t, "Upgrade", "websocket", "Connection", "Upgrade", "Accept-Encoding", "br")
	o := serve(t, h, req, respond("text/html", visa))
	assert.Equal(t, visa, o.body())
	assert.Equal(t, "br", o.seenAE, "the request is not rewritten")
}

func TestAcceptEncodingIsReducedToWhatCanBeScanned(t *testing.T) {
	h := provisioned(t, Handler{Action: "mask"})
	for in, want := range map[string]string{
		"":                       "",
		"br":                     "",
		"zstd, br":               "",
		"gzip, br":               "gzip",
		"br;q=1.0, GZIP;q=0.5":   "gzip",
		"gzip;q=0, br":           "",
		"identity":               "",
		"deflate, gzip;q=0.8, *": "gzip",
	} {
		req := get(t)
		if in != "" {
			req.Header.Set("Accept-Encoding", in)
		}
		assert.Equal(t, want, serve(t, h, req, respond("text/html", "ok")).seenAE, "client sent %q", in)
	}
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err := w.Write([]byte(s))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return b.Bytes()
}

func gunz(t *testing.T, b []byte) string {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(b))
	require.NoError(t, err)
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func gzUpstream(t *testing.T, body string) upstream {
	enc := gz(t, body)
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", itoa(len(enc)))
		w.Header().Set("Digest", "sha-256=stale")
		_, _ = w.Write(enc)
	}
}

func TestGzipIsDecodedMaskedAndReEncodedWithACorrectLength(t *testing.T) {
	h := provisioned(t, Handler{Action: "mask"})
	o := serve(t, h, get(t, "Accept-Encoding", "gzip"), gzUpstream(t, page))
	raw := o.rec.Body.Bytes()
	assert.Equal(t, "gzip", o.rec.Header().Get("Content-Encoding"))
	assert.Equal(t, itoa(len(raw)), o.rec.Header().Get("Content-Length"), "the length follows the re-encoded body")
	assert.Empty(t, o.rec.Header().Get("Digest"), "digests of the original no longer apply")
	plain := gunz(t, raw)
	assert.NotContains(t, plain, "4111 1111")
	assert.Contains(t, plain, "************1111")
	assert.Contains(t, plain, "GB****************5432")
}

func TestGzipWithoutMatchesIsSentByteForByte(t *testing.T) {
	h := provisioned(t, Handler{Action: "mask"})
	body := "nothing sensitive here"
	o := serve(t, h, get(t, "Accept-Encoding", "gzip"), gzUpstream(t, body))
	assert.Equal(t, gz(t, body), o.rec.Body.Bytes())
}

func TestGzipBlockAndOversizedAndCorrupt(t *testing.T) {
	blocked := serve(t, provisioned(t, Handler{Action: "block"}), get(t, "Accept-Encoding", "gzip"), gzUpstream(t, page))
	assert.Equal(t, http.StatusBadGateway, blocked.rec.Code)
	assert.Empty(t, blocked.rec.Header().Get("Content-Encoding"))

	// A bomb: tiny on the wire, larger than the limit once decoded. It is passed on
	// untouched (and counted), never expanded beyond the limit.
	small := provisioned(t, Handler{Action: "mask", MaxBodyBytes: 2048})
	bomb := gz(t, strings.Repeat("a", 1<<20)+visa)
	o := serve(t, small, get(t, "Accept-Encoding", "gzip"), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(bomb)
	})
	assert.Equal(t, bomb, o.rec.Body.Bytes())

	corrupt := serve(t, provisioned(t, Handler{Action: "mask"}), get(t), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "not gzip")
	})
	assert.Equal(t, "not gzip", corrupt.body(), "a body that is not valid gzip is passed on as received")
}

func TestOversizedIdentityBodyMasksThePrefixAndStreamsTheRest(t *testing.T) {
	h := provisioned(t, Handler{Action: "mask", MaxBodyBytes: 1024})
	head := strings.Repeat("x", 100) + " " + visa + " "
	rest := strings.Repeat("y", 4000) + " " + visa
	o := serve(t, h, get(t), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, head+strings.Repeat("z", 900))
		_, _ = io.WriteString(w, rest)
	})
	out := o.body()
	assert.Len(t, out, len(head)+900+len(rest), "nothing is lost or added")
	assert.Contains(t, out, "************1111", "the held part is masked")
	assert.Contains(t, out, "yyy "+visa, "past the limit the body is not scanned (documented gap, counted as skipped)")
}

func TestOversizedBodyIsStillBlockedWhenTheHeldPartMatches(t *testing.T) {
	h := provisioned(t, Handler{Action: "block", MaxBodyBytes: 256})
	o := serve(t, h, get(t), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, visa+" "+strings.Repeat("a", 4000))
	})
	assert.Equal(t, http.StatusBadGateway, o.rec.Code)
	assert.NotContains(t, o.body(), "4111")
}

func TestCustomPatterns(t *testing.T) {
	h := provisioned(t, Handler{
		Action: "mask", Detect: []string{"custom:nin"},
		CustomPatterns: []Pattern{{Name: "nin", Pattern: `[A-Z]{2}[0-9]{6}[A-D]`}},
	})
	o := serve(t, h, get(t), respond("text/html", "nino AB123456C and card "+visa))
	assert.Equal(t, "nino ********* and card "+visa, o.body(), "only the declared detector applies")
	assert.Equal(t, "custom:nin", o.decision.Findings()[0].RuleID)
	assert.NotContains(t, findingText(o.decision), "AB123456C")
}

func TestHandlerValidation(t *testing.T) {
	assert.Error(t, (&Handler{}).Validate())
	assert.Error(t, (&Handler{SiteID: "s", Action: "nuke", Detect: []string{"pan"}}).Validate())
	assert.Error(t, (&Handler{SiteID: "s", Action: "mask"}).Validate())
	bad := &Handler{SiteID: "s", Detect: []string{"custom:x"}, CustomPatterns: []Pattern{{Name: "x", Pattern: "a*"}}}
	assert.Error(t, bad.Provision(caddy.Context{}), "a pattern that matches the empty string is refused")
	assert.NoError(t, (&Handler{SiteID: "s", Action: "block", Detect: []string{"pan"}}).Validate())
}

func TestNoDecisionMeansNoScanning(t *testing.T) {
	h := provisioned(t, Handler{Action: "block"})
	rec := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(rec, get(t), caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, visa)
		return nil
	})))
	assert.Equal(t, visa, rec.Body.String(), "core did not run, so there is nothing to attribute a block to")
}

func itoa(n int) string { return strconv.Itoa(n) }

func BenchmarkHandlerMask(b *testing.B) {
	h := &Handler{SiteID: "bank", Mode: "block", Action: "mask", Detect: []string{"pan", "iban"}}
	if err := h.Provision(caddy.Context{}); err != nil {
		b.Fatal(err)
	}
	body := strings.Repeat("<tr><td>order 8841</td><td>jane@example.com</td></tr>\n", 2000) + "card " + visa
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, body)
		return nil
	})
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		d := policy.NewDecision("EV", "bank", policy.ModeBlock, netip.MustParseAddr("192.0.2.1"))
		req := httptest.NewRequestWithContext(policy.WithDecision(b.Context(), d), http.MethodGet, "/", nil)
		if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
			b.Fatal(err)
		}
	}
}
