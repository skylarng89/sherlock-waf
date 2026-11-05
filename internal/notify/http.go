package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/netx"
)

const (
	httpTimeout   = 10 * time.Second
	maxURLLen     = 2048
	maxBearerLen  = 512
	maxReplyBytes = 4096
)

type httpSettings struct {
	URL         string `json:"url"`
	AllowHTTP   bool   `json:"allow_http"`
	BearerToken string `json:"bearer_token"` // webhook only
}

type httpSender struct {
	kind   string
	target *url.URL
	host   string // safe to put in errors; the full URL is a secret
	bearer string
	client *http.Client
}

func newHTTP(kind string, raw json.RawMessage) (Sender, error) {
	var s httpSettings
	if err := decodeStrict(raw, &s); err != nil {
		return nil, err
	}
	if s.BearerToken != "" && kind != KindWebhook {
		return nil, fmt.Errorf("%w: bearer_token is only supported by webhook channels", ErrInvalid)
	}
	if len(s.BearerToken) > maxBearerLen || strings.ContainsAny(s.BearerToken, "\r\n\x00") {
		return nil, fmt.Errorf("%w: bearer_token is not valid", ErrInvalid)
	}
	u, err := parseTarget(s.URL, s.AllowHTTP)
	if err != nil {
		return nil, err
	}
	// Private destinations are allowed (an on-premises chat or relay is a normal
	// target); link-local, including cloud metadata, stays blocked by netx.
	c := netx.NewClient(netx.Options{AllowPrivate: true, Timeout: httpTimeout})
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &httpSender{kind: kind, target: u, host: u.Hostname(), bearer: s.BearerToken, client: c}, nil
}

func parseTarget(raw string, allowHTTP bool) (*url.URL, error) {
	if raw == "" || len(raw) > maxURLLen || strings.ContainsAny(raw, "\r\n\x00 ") {
		return nil, fmt.Errorf("%w: url is required and must be a valid URL", ErrInvalid)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("%w: url is required and must be a valid URL", ErrInvalid)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowHTTP:
	default:
		return nil, fmt.Errorf("%w: url must use https (set allow_http only for a trusted internal endpoint)", ErrInvalid)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: credentials in the url are not allowed", ErrInvalid)
	}
	return u, nil
}

func (h *httpSender) Send(ctx context.Context, m Message) error {
	n := normalise(m)
	var payload any
	switch h.kind {
	case KindSlack:
		payload = slackPayload(n)
	case KindTeams:
		payload = teamsPayload(n)
	default:
		payload = webhookPayload(n)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%s channel: encoding message: %w", h.kind, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.target.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s channel: building request: %s", h.kind, h.host)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Sherlock-WAF")
	if h.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+h.bearer)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		// *url.Error embeds the URL; report only the cause and the host.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return fmt.Errorf("%s channel %s: %w", h.kind, h.host, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxReplyBytes))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s channel %s: unexpected status %d", h.kind, h.host, resp.StatusCode)
	}
	return nil
}

func webhookPayload(n normalised) map[string]any {
	fields := make(map[string]string, len(n.Fields))
	for _, f := range n.Fields {
		fields[f.Key] = f.Value
	}
	return map[string]any{
		"schema":    "sherlock.alert.v1",
		"title":     n.Title,
		"body":      n.Body,
		"severity":  n.Severity,
		"rule_id":   n.RuleID,
		"rule_name": n.RuleName,
		"at":        n.At.Format(time.RFC3339),
		"fields":    fields,
	}
}

// slackEscape applies Slack's own escaping: & < > are the only characters that
// start links, mentions (<!channel>) or entities in a message.
var slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func slackPayload(n normalised) map[string]any {
	var text strings.Builder
	fmt.Fprintf(&text, "*%s* (%s)", slackEscape.Replace(n.Title), n.Severity)
	if n.Body != "" {
		text.WriteString("\n" + slackEscape.Replace(n.Body))
	}
	blocks := []map[string]any{{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": text.String()}}}
	if len(n.Fields) > 0 {
		var fs strings.Builder
		for _, f := range n.Fields {
			fmt.Fprintf(&fs, "%s: `%s`\n", slackEscape.Replace(f.Key), strings.ReplaceAll(slackEscape.Replace(f.Value), "`", "'"))
		}
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": strings.TrimSpace(fs.String())}})
	}
	// "text" is the notification fallback and what plain Slack-compatible
	// receivers (Mattermost, Rocket.Chat) render.
	return map[string]any{"text": slackEscape.Replace(n.Title) + " (" + n.Severity + ")", "blocks": blocks}
}

// teamsMarkdown backslash-escapes characters that Adaptive Card TextBlocks
// interpret as Markdown, so event data cannot inject links or formatting.
var teamsMarkdown = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "{", `\{`, "}", `\}`, "[", `\[`, "]", `\]`,
	"(", `\(`, ")", `\)`, "#", `\#`, "+", `\+`, "-", `\-`, ".", `\.`, "!", `\!`, "|", `\|`,
	"<", `\<`, ">", `\>`, "~", `\~`, "&", `\&`,
)

// teamsPayload targets the Teams "Workflows" webhook trigger ("When a Teams
// webhook request is received"), which replaced the retired Office 365
// connectors (MessageCard). It expects a message envelope carrying an Adaptive
// Card attachment; a bare {"text": ...} body is not accepted there.
func teamsPayload(n normalised) map[string]any {
	tone := map[string]string{SeverityCritical: "Attention", SeverityWarning: "Warning", SeverityInfo: "Default"}[n.Severity]
	body := []map[string]any{
		{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": true, "color": tone, "text": teamsMarkdown.Replace(n.Title)}, //nolint:misspell // "color" is the Adaptive Card property name
	}
	if n.Body != "" {
		body = append(body, map[string]any{"type": "TextBlock", "wrap": true, "text": teamsMarkdown.Replace(n.Body)})
	}
	if len(n.Fields) > 0 {
		facts := make([]map[string]string, 0, len(n.Fields))
		for _, f := range n.Fields {
			facts = append(facts, map[string]string{"title": teamsMarkdown.Replace(f.Key), "value": teamsMarkdown.Replace(f.Value)})
		}
		body = append(body, map[string]any{"type": "FactSet", "facts": facts})
	}
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body":    body,
			},
		}},
	}
}
