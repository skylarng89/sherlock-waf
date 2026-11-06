package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func raw(s string) json.RawMessage { return json.RawMessage(s) }

func TestValidate(t *testing.T) {
	tests := []struct {
		name, kind, settings string
		ok                   bool
	}{
		{"unknown kind", "pager", `{}`, false},
		{"slack https", "slack", `{"url":"https://hooks.example.com/T/B/x"}`, true},
		{"slack http refused", "slack", `{"url":"http://hooks.example.com/x"}`, false},
		{"slack http allowed explicitly", "slack", `{"url":"http://hooks.internal/x","allow_http":true}`, true},
		{"missing url", "webhook", `{}`, false},
		{"userinfo in url", "teams", `{"url":"https://u:p@example.com/x"}`, false},
		{"unknown field", "slack", `{"url":"https://a.example/x","chanel":"x"}`, false},
		{"url with newline", "webhook", "{\"url\":\"https://a.example/x\\nHost: evil\"}", false},
		{"file scheme", "webhook", `{"url":"file:///etc/passwd"}`, false},
		{"bearer on slack", "slack", `{"url":"https://a.example/x","bearer_token":"t"}`, false},
		{"bearer with newline", "webhook", `{"url":"https://a.example/x","bearer_token":"a\nb"}`, false},
		{"bearer on webhook", "webhook", `{"url":"https://a.example/x","bearer_token":"tok"}`, true},
		{"smtp ok", "smtp", `{"host":"mail.example.com","from":"sherlock@example.com","to":["a@example.com"]}`, true},
		{"smtp no recipients", "smtp", `{"host":"mail.example.com","from":"s@example.com","to":[]}`, false},
		{"smtp too many recipients", "smtp", `{"host":"m.example","from":"s@example.com","to":[` + strings.TrimSuffix(strings.Repeat(`"a@example.com",`, 21), ",") + `]}`, false},
		{"smtp clear text needs opt in", "smtp", `{"host":"m.example","security":"none","from":"s@example.com","to":["a@example.com"]}`, false},
		{"smtp clear text opted in", "smtp", `{"host":"m.example","security":"none","allow_insecure":true,"from":"s@example.com","to":["a@example.com"]}`, true},
		{"smtp auth over clear text", "smtp", `{"host":"m.example","security":"none","allow_insecure":true,"username":"u","password":"p","from":"s@example.com","to":["a@example.com"]}`, false},
		{"smtp bad security", "smtp", `{"host":"m.example","security":"ssl3","from":"s@example.com","to":["a@example.com"]}`, false},
		{"smtp header injection in from", "smtp", "{\"host\":\"m.example\",\"from\":\"s@example.com\\r\\nBcc: x@evil.test\",\"to\":[\"a@example.com\"]}", false},
		{"smtp header injection in to", "smtp", "{\"host\":\"m.example\",\"from\":\"s@example.com\",\"to\":[\"a@example.com\\nBcc: x@evil.test\"]}", false},
		{"smtp host with path", "smtp", `{"host":"m.example/x","from":"s@example.com","to":["a@example.com"]}`, false},
		{"smtp bad port", "smtp", `{"host":"m.example","port":70000,"from":"s@example.com","to":["a@example.com"]}`, false},
		{"smtp bad timeout", "smtp", `{"host":"m.example","timeout_seconds":600,"from":"s@example.com","to":["a@example.com"]}`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.kind, raw(tc.settings))
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}

func TestKinds(t *testing.T) {
	assert.ElementsMatch(t, []string{"smtp", "webhook", "slack", "teams"}, Kinds())
}

type capture struct {
	mu     sync.Mutex
	body   []byte
	header http.Header
}

func (c *capture) handler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.body, c.header = b, r.Header.Clone()
		c.mu.Unlock()
		w.WriteHeader(status)
	}
}

func httpChannel(t *testing.T, kind string, h http.Handler, extra string) Sender {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	s, err := New(kind, raw(fmt.Sprintf(`{"url":%q,"allow_http":true%s}`, srv.URL+"/secret-token-path", extra)))
	require.NoError(t, err)
	return s
}

var hostile = Message{
	Title:    "Blocks on <!channel> shop",
	Body:     "Attacker [click](https://evil.test) *bold*\nsecond line",
	Severity: SeverityCritical,
	RuleID:   "r1", RuleName: "Block spike", At: time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC),
	Fields: map[string]string{"site": "shop", "country": "<@U123>\x00`x`", "bad\nkey": "v"},
}

func TestWebhookPayload(t *testing.T) {
	var c capture
	s := httpChannel(t, KindWebhook, c.handler(200), `,"bearer_token":"tok"`)
	require.NoError(t, s.Send(t.Context(), hostile))

	var got map[string]any
	require.NoError(t, json.Unmarshal(c.body, &got))
	assert.Equal(t, "sherlock.alert.v1", got["schema"])
	assert.Equal(t, "critical", got["severity"])
	assert.Equal(t, "Bearer tok", c.header.Get("Authorization"))
	assert.Equal(t, "application/json", c.header.Get("Content-Type"))
	f := got["fields"].(map[string]any)
	assert.Equal(t, "shop", f["site"])
	assert.NotContains(t, string(c.body), `\u0000`, "control characters are stripped")
	assert.Contains(t, f, "bad key", "newlines in keys are flattened")
}

func TestSlackEscapesMentionsAndLinks(t *testing.T) {
	var c capture
	s := httpChannel(t, KindSlack, c.handler(200), "")
	require.NoError(t, s.Send(t.Context(), hostile))
	var p struct {
		Text   string           `json:"text"`
		Blocks []map[string]any `json:"blocks"`
	}
	require.NoError(t, json.Unmarshal(c.body, &p))
	body, err := json.Marshal(p.Blocks)
	require.NoError(t, err)
	decoded := strings.NewReplacer(`\u0026`, "&", `\u003c`, "<", `\u003e`, ">").Replace(string(body))
	assert.NotContains(t, decoded, "<!channel>")
	assert.NotContains(t, decoded, "<@U123>")
	assert.Contains(t, decoded, "&lt;!channel&gt;")
	assert.NotEmpty(t, p.Text)
	assert.Len(t, p.Blocks, 2)
}

func TestTeamsUsesAdaptiveCardEnvelopeAndEscapesMarkdown(t *testing.T) {
	var c capture
	s := httpChannel(t, KindTeams, c.handler(202), "")
	require.NoError(t, s.Send(t.Context(), hostile))
	var p struct {
		Type        string `json:"type"`
		Attachments []struct {
			ContentType string `json:"contentType"`
			Content     struct {
				Type string `json:"type"`
				Body []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"body"`
			} `json:"content"`
		} `json:"attachments"`
	}
	require.NoError(t, json.Unmarshal(c.body, &p))
	assert.Equal(t, "message", p.Type)
	require.Len(t, p.Attachments, 1)
	assert.Equal(t, "application/vnd.microsoft.card.adaptive", p.Attachments[0].ContentType)
	assert.Equal(t, "AdaptiveCard", p.Attachments[0].Content.Type)
	var text string
	for _, b := range p.Attachments[0].Content.Body {
		text += b.Text
	}
	assert.NotContains(t, text, "[click](https", "markdown links are neutralised")
	assert.Contains(t, text, `\[click\]\(https`)
}

func TestHTTPFailuresNeverLeakTheURL(t *testing.T) {
	t.Run("connection refused", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL + "/secret-token-path"
		srv.Close()
		s, err := New(KindSlack, raw(fmt.Sprintf(`{"url":%q,"allow_http":true}`, url)))
		require.NoError(t, err)
		err = s.Send(t.Context(), hostile)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "secret-token-path")
		assert.Contains(t, err.Error(), "127.0.0.1")
	})
	t.Run("bad status", func(t *testing.T) {
		var c capture
		err := httpChannel(t, KindWebhook, c.handler(500), "").Send(t.Context(), hostile)
		require.ErrorContains(t, err, "status 500")
		assert.NotContains(t, err.Error(), "secret-token-path")
	})
	t.Run("redirects are not followed", func(t *testing.T) {
		hit := false
		target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
		defer target.Close()
		err := httpChannel(t, KindWebhook, http.RedirectHandler(target.URL, http.StatusFound), "").Send(t.Context(), hostile)
		require.ErrorContains(t, err, "status 302")
		assert.False(t, hit)
	})
}

func TestMetadataAddressIsRefusedAtDialTime(t *testing.T) {
	s, err := New(KindWebhook, raw(`{"url":"http://169.254.169.254/latest/meta-data/","allow_http":true}`))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	err = s.Send(ctx, hostile)
	require.Error(t, err)
	assert.ErrorContains(t, err, "not allowed")
}

func TestSendHonoursContext(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)
	s, err := New(KindWebhook, raw(fmt.Sprintf(`{"url":%q,"allow_http":true}`, srv.URL)))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	require.Error(t, s.Send(ctx, hostile))
	assert.Less(t, time.Since(start), 3*time.Second)
}

func TestNormaliseBoundsInput(t *testing.T) {
	long := strings.Repeat("a", 5000)
	fields := map[string]string{}
	for i := range 40 {
		fields[fmt.Sprintf("k%02d", i)] = long
	}
	n := normalise(Message{Title: long, Body: long, Severity: "bogus", Fields: fields})
	assert.LessOrEqual(t, len([]rune(n.Title)), maxTitle+1)
	assert.LessOrEqual(t, len([]rune(n.Body)), maxBody+1)
	assert.Len(t, n.Fields, maxFields)
	assert.LessOrEqual(t, len([]rune(n.Fields[0].Value)), maxFieldValue+1)
	assert.Equal(t, SeverityWarning, n.Severity, "an unknown severity falls back")
	assert.Equal(t, "k00", n.Fields[0].Key, "fields are ordered")
}

// fakeSMTP is a minimal plain-text SMTP server that records one transaction.
type fakeSMTP struct {
	ln   net.Listener
	mu   sync.Mutex
	from string
	rcpt []string
	data string
}

func startSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakeSMTP{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	say := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 fake")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			f.mu.Lock()
			f.from = strings.TrimSpace(line[len("MAIL FROM:"):])
			f.mu.Unlock()
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			f.mu.Lock()
			f.rcpt = append(f.rcpt, strings.TrimSpace(line[len("RCPT TO:"):]))
			f.mu.Unlock()
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func TestSMTPDeliveryAndHeaderInjection(t *testing.T) {
	srv := startSMTP(t)
	port := srv.ln.Addr().(*net.TCPAddr).Port
	s, err := New(KindSMTP, raw(fmt.Sprintf(
		`{"host":"127.0.0.1","port":%d,"security":"none","allow_insecure":true,"from":"Sherlock <sherlock@example.com>","to":["a@example.com","b@example.com"]}`, port)))
	require.NoError(t, err)

	m := hostile
	m.Title = "Spike\r\nBcc: attacker@evil.test"
	require.NoError(t, s.Send(t.Context(), m))

	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.Equal(t, "<sherlock@example.com>", srv.from)
	assert.Equal(t, []string{"<a@example.com>", "<b@example.com>"}, srv.rcpt)
	head, body, ok := strings.Cut(srv.data, "\r\n\r\n")
	require.True(t, ok)
	assert.NotContains(t, strings.ToLower(head), "\r\nbcc:", "event data cannot add a header")
	assert.Contains(t, head, "Subject: ")
	assert.Contains(t, head, "Content-Transfer-Encoding: base64")
	dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\r\n", ""))
	require.NoError(t, err)
	assert.Contains(t, string(dec), "Block spike")
	assert.Contains(t, string(dec), "site: shop")
}

func TestSMTPRefusesStartTLSDowngrade(t *testing.T) {
	srv := startSMTP(t) // does not advertise STARTTLS
	port := srv.ln.Addr().(*net.TCPAddr).Port
	s, err := New(KindSMTP, raw(fmt.Sprintf(`{"host":"127.0.0.1","port":%d,"from":"s@example.com","to":["a@example.com"],"username":"u","password":"p"}`, port)))
	require.NoError(t, err)
	err = s.Send(t.Context(), hostile)
	require.ErrorContains(t, err, "STARTTLS")
	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.Empty(t, srv.data, "nothing is sent, and no credentials, without TLS")
}

func TestSMTPMetadataAddressRefused(t *testing.T) {
	s, err := New(KindSMTP, raw(`{"host":"169.254.169.254","port":25,"security":"none","allow_insecure":true,"from":"s@example.com","to":["a@example.com"],"timeout_seconds":3}`))
	require.NoError(t, err)
	require.ErrorContains(t, s.Send(t.Context(), hostile), "not allowed")
}

func TestTestSendsALabelledMessage(t *testing.T) {
	var c capture
	srv := httptest.NewServer(c.handler(200))
	defer srv.Close()
	require.NoError(t, Test(t.Context(), KindWebhook, raw(fmt.Sprintf(`{"url":%q,"allow_http":true}`, srv.URL))))
	assert.Contains(t, string(c.body), "test notification")
	require.ErrorIs(t, Test(t.Context(), KindWebhook, raw(`{}`)), ErrInvalid)
}

// teamsCardProblems checks a Teams Workflows payload against the parts of the
// Adaptive Card 1.4 schema this code relies on, offline. It returns every
// violation found.
func teamsCardProblems(p map[string]any) []string {
	var out []string
	bad := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }

	if p["type"] != "message" {
		bad("envelope type = %v, want message", p["type"])
	}
	atts, _ := p["attachments"].([]map[string]any)
	if len(atts) != 1 {
		bad("want exactly one attachment, got %d", len(atts))
		return out
	}
	if atts[0]["contentType"] != "application/vnd.microsoft.card.adaptive" {
		bad("contentType = %v", atts[0]["contentType"])
	}
	card, _ := atts[0]["content"].(map[string]any)
	if card["type"] != "AdaptiveCard" {
		bad("card type = %v", card["type"])
	}
	if s, _ := card["$schema"].(string); !strings.HasSuffix(s, "/schemas/adaptive-card.json") {
		bad("$schema = %v", card["$schema"])
	}
	v, _ := card["version"].(string)
	var major, minor int
	if _, err := fmt.Sscanf(v, "%d.%d", &major, &minor); err != nil || major != 1 || minor > 4 {
		bad("version = %q, want 1.x with x <= 4", v)
	}
	tones := []string{"Default", "Dark", "Light", "Accent", "Good", "Warning", "Attention"}
	body, _ := card["body"].([]map[string]any)
	if len(body) == 0 {
		bad("card has an empty body")
	}
	for i, el := range body {
		switch el["type"] {
		case "TextBlock":
			if txt, ok := el["text"].(string); !ok || txt == "" {
				bad("body[%d]: TextBlock needs non-empty text", i)
			}
			if c, ok := el["color"]; ok && !slices.Contains(tones, fmt.Sprint(c)) { //nolint:misspell // "color" is the Adaptive Card property name
				bad("body[%d]: tone %v is not in the Adaptive Card enum", i, c)
			}
		case "FactSet":
			facts, _ := el["facts"].([]map[string]string)
			if len(facts) == 0 {
				bad("body[%d]: FactSet needs facts", i)
			}
			for j, f := range facts {
				if f["title"] == "" || f["value"] == "" {
					bad("body[%d].facts[%d]: title and value are required", i, j)
				}
			}
		default:
			bad("body[%d]: unexpected element type %v", i, el["type"])
		}
	}
	return out
}

func TestTeamsCardMatchesAdaptiveCard14(t *testing.T) {
	for _, sev := range []string{SeverityInfo, SeverityWarning, SeverityCritical, "nonsense"} {
		n := normalise(Message{
			Title: "Blocks spiking", Body: "120 blocks in 5 minutes", Severity: sev, At: time.Unix(1700000000, 0),
			Fields: map[string]string{"site": "shop", "country": "NG"},
		})
		assert.Empty(t, teamsCardProblems(teamsPayload(n)), "severity %q", sev)
	}
	// The checker itself must notice a broken card.
	broken := teamsPayload(normalise(Message{Title: "x", Severity: SeverityInfo}))
	broken["type"] = "MessageCard"
	assert.NotEmpty(t, teamsCardProblems(broken))
}

func TestTeamsPayloadStaysUnderTheWorkflowsLimit(t *testing.T) {
	// Every character is one the Markdown escaper doubles and JSON then escapes
	// again (< is \< in the card and \\< on the wire), the worst case.
	hostile := strings.Repeat("<", 4000)
	fields := map[string]string{}
	for i := range 40 {
		fields[fmt.Sprintf("<%02d%s", i, strings.Repeat("<", 60))] = hostile
	}
	n := normalise(Message{Title: hostile, Body: hostile, Severity: SeverityCritical, Fields: fields})
	require.Greater(t, teamsSize(teamsCard(n)), teamsMaxBytes, "the input must exceed the limit, or this test proves nothing")
	p := teamsPayload(n)

	wire, err := json.Marshal(p)
	require.NoError(t, err)
	assert.Less(t, len(wire), 28*1000, "the Workflows trigger rejects payloads of about 28 KB")
	assert.Empty(t, teamsCardProblems(p), "a shortened card is still a valid card")
	assert.True(t, utf8.Valid(wire), "truncation never cuts a rune in half")
}

func TestTeamsPayloadKeepsSmallMessagesWhole(t *testing.T) {
	n := normalise(Message{Title: "t", Body: "b", Severity: SeverityInfo, Fields: map[string]string{"a": "1", "b": "2"}})
	body := teamsPayload(n)["attachments"].([]map[string]any)[0]["content"].(map[string]any)["body"].([]map[string]any)
	facts := body[len(body)-1]["facts"].([]map[string]string)
	assert.Len(t, facts, 2, "nothing is shed when the card fits")
}

func TestTruncateRunes(t *testing.T) {
	assert.Equal(t, "abc", truncateRunes("abc", 10))
	got := truncateRunes("aé€x", 2) // 2 falls inside the two-byte é
	assert.True(t, utf8.ValidString(got), got)
	assert.Equal(t, "a…", got)
}
