package format

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// parseCEF is a small reference parser written from the CEF specification:
// header fields split on unescaped '|', extension keys found by scanning for
// unescaped " key=" boundaries so values may contain spaces.
func parseCEF(t *testing.T, line string) (hdr []string, ext map[string]string) {
	t.Helper()
	require.True(t, strings.HasPrefix(line, "CEF:0|"), line)
	rest := line
	for len(hdr) < 7 {
		var field strings.Builder
		i := 0
		for ; i < len(rest); i++ {
			c := rest[i]
			if c == '\\' && i+1 < len(rest) {
				i++
				field.WriteByte(rest[i])
				continue
			}
			if c == '|' {
				break
			}
			field.WriteByte(c)
		}
		require.Less(t, i, len(rest), "header ends early: %q", line)
		hdr = append(hdr, field.String())
		rest = rest[i+1:]
	}
	ext = map[string]string{}
	type kv struct {
		key        string
		start, end int
	}
	var keys []kv
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\\' {
			i++
			continue
		}
		if rest[i] == '=' {
			j := i
			for j > 0 && rest[j-1] != ' ' {
				j--
			}
			keys = append(keys, kv{key: rest[j:i], start: i + 1, end: len(rest)})
			if n := len(keys); n > 1 {
				keys[n-2].end = j - 1
			}
		}
	}
	for _, k := range keys {
		var v strings.Builder
		raw := rest[k.start:k.end]
		for i := 0; i < len(raw); i++ {
			if raw[i] == '\\' && i+1 < len(raw) {
				i++
				switch raw[i] {
				case 'n':
					v.WriteByte('\n')
				case 'r':
					v.WriteByte('\r')
				default:
					v.WriteByte(raw[i])
				}
				continue
			}
			v.WriteByte(raw[i])
		}
		ext[k.key] = v.String()
	}
	return hdr, ext
}

func eventRecord(t *testing.T, ev events.Event) extension.ExportRecord {
	t.Helper()
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	return extension.ExportRecord{ID: ev.ID, Stream: extension.StreamEvents, At: ev.TS, Body: b}
}

func TestCEFEventRoundTripsTrickyValues(t *testing.T) {
	ev := events.Event{
		ID: "01JBX", Schema: events.SchemaV1, TS: time.UnixMilli(1_700_000_000_123), Node: "waf=01",
		SiteID: `shop\eu`, Action: "block",
		Client:       events.Client{IP: "198.51.100.7"},
		Request:      events.Request{Method: "GET", Host: "例え.example", Path: "/a=b c|d\nline2"},
		AnomalyScore: events.AnomalyScore{Inbound: 13},
		Findings: []events.Finding{
			{Module: "waf", RuleID: "942100", Severity: "notice", Message: "low"},
			{Module: "waf", RuleID: "949110", Severity: "critical", Message: `Inbound | score \ exceeded`},
		},
	}
	line, err := CEF(eventRecord(t, ev), "1.2.3|x")
	require.NoError(t, err)
	assert.NotContains(t, line, "\n", "one record is one line")

	hdr, ext := parseCEF(t, line)
	assert.Equal(t, []string{"CEF:0", "Sherlock", "Sherlock WAF", "1.2.3|x", "949110", `Inbound | score \ exceeded`, "10"}, hdr, "primary finding is the most severe")
	assert.Equal(t, "198.51.100.7", ext["src"])
	assert.Equal(t, "waf=01", ext["dvchost"])
	assert.Equal(t, "1700000000123", ext["rt"])
	assert.Equal(t, "GET", ext["requestMethod"])
	assert.Equal(t, "例え.example/a=b c|d\nline2", ext["request"])
	assert.Equal(t, "block", ext["act"])
	assert.Equal(t, "site", ext["cs1Label"])
	assert.Equal(t, `shop\eu`, ext["cs1"])
	assert.Equal(t, "event_id", ext["cs2Label"])
	assert.Equal(t, "01JBX", ext["cs2"])
	assert.Equal(t, "anomaly_score", ext["cn1Label"])
	assert.Equal(t, "13", ext["cn1"])
}

func TestCEFEventWithoutFindings(t *testing.T) {
	line, err := CEF(eventRecord(t, events.Event{ID: "e", Action: "allow", TS: time.UnixMilli(5)}), "dev")
	require.NoError(t, err)
	hdr, _ := parseCEF(t, line)
	assert.Equal(t, []string{"CEF:0", "Sherlock", "Sherlock WAF", "dev", "0", "request allow", "1"}, hdr)
}

func TestCEFSeverityMapping(t *testing.T) {
	for sev, want := range map[string]string{"info": "1", "notice": "3", "warning": "5", "error": "7", "critical": "10", "": "1"} {
		line, err := CEF(eventRecord(t, events.Event{Findings: []events.Finding{{Module: "m", Severity: sev}}}), "v")
		require.NoError(t, err)
		hdr, _ := parseCEF(t, line)
		assert.Equal(t, want, hdr[6], sev)
	}
}

func TestCEFAudit(t *testing.T) {
	doc := AuditDoc{
		Schema: AuditSchemaV1, ID: "a1", Seq: 4, At: time.UnixMilli(42), ActorType: "user", ActorID: "u=1", IP: "10.0.0.1",
		Action: "config.apply", ObjectType: "config", ObjectID: "v|2",
	}
	b, _ := json.Marshal(doc)
	line, err := CEF(extension.ExportRecord{ID: "a1", Stream: extension.StreamAudit, Body: b}, "1.0")
	require.NoError(t, err)
	hdr, ext := parseCEF(t, line)
	assert.Equal(t, []string{"CEF:0", "Sherlock", "Sherlock WAF", "1.0", "audit.config.apply", "config.apply config", "3"}, hdr)
	assert.Equal(t, "u=1", ext["suser"])
	assert.Equal(t, "10.0.0.1", ext["src"])
	assert.Equal(t, "object", ext["cs1Label"])
	assert.Equal(t, "config/v|2", ext["cs1"])
	assert.Equal(t, "audit_id", ext["cs2Label"])
	assert.Equal(t, "a1", ext["cs2"])
	assert.Equal(t, "42", ext["rt"])
}

func TestCEFErrors(t *testing.T) {
	_, err := CEF(extension.ExportRecord{Stream: "nope"}, "v")
	assert.Error(t, err)
	_, err = CEF(extension.ExportRecord{Stream: extension.StreamEvents, Body: json.RawMessage(`{`)}, "v")
	assert.Error(t, err)
	_, err = CEF(extension.ExportRecord{Stream: extension.StreamAudit, Body: json.RawMessage(`[]`)}, "v")
	assert.Error(t, err)
}

func TestSyslogSeverity(t *testing.T) {
	for sev, want := range map[string]int{"critical": 2, "error": 3, "warning": 4, "notice": 5, "info": 6, "": 6} {
		rec := eventRecord(t, events.Event{Findings: []events.Finding{{Module: "m", Severity: sev}}})
		assert.Equal(t, want, SyslogSeverity(rec), sev)
	}
	assert.Equal(t, 6, SyslogSeverity(eventRecord(t, events.Event{})))
	audit := func(action string) extension.ExportRecord {
		b, _ := json.Marshal(AuditDoc{Action: action})
		return extension.ExportRecord{Stream: extension.StreamAudit, Body: b}
	}
	assert.Equal(t, 6, SyslogSeverity(audit("config.apply")))
	assert.Equal(t, 4, SyslogSeverity(audit("auth.login_failed")))
	assert.Equal(t, 4, SyslogSeverity(audit("access.denied")))
	assert.Equal(t, 6, SyslogSeverity(extension.ExportRecord{Stream: extension.StreamEvents, Body: json.RawMessage(`garbage`)}))
}
