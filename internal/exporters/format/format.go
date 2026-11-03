// Package format turns export records into the wire formats exporters speak:
// CEF for SIEMs that parse it, and the severity mappings shared by syslog and
// OTLP. It is separate from the exporters so every destination describes an
// event the same way.
package format

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// AuditSchemaV1 is the Schema value of an AuditDoc.
const AuditSchemaV1 = "sherlock.audit.v1"

// AuditDoc is the JSON body of an audit export record.
type AuditDoc struct {
	Schema     string          `json:"schema"`
	ID         string          `json:"id"`
	Seq        int64           `json:"seq"`
	At         time.Time       `json:"at"`
	ActorType  string          `json:"actor_type"`
	ActorID    string          `json:"actor_id"`
	IP         string          `json:"ip,omitempty"`
	Action     string          `json:"action"`
	ObjectType string          `json:"object_type,omitempty"`
	ObjectID   string          `json:"object_id,omitempty"`
	Details    json.RawMessage `json:"details,omitempty"`
	PrevHash   string          `json:"prev_hash"`
	Hash       string          `json:"hash"`
}

// CEF severities (0-10) by finding severity.
var cefSeverity = map[string]int{"info": 1, "notice": 3, "warning": 5, "error": 7, "critical": 10}

// Syslog severities (RFC 5424 table 2) by finding severity.
var syslogSeverity = map[string]int{"critical": 2, "error": 3, "warning": 4, "notice": 5, "info": 6}

const (
	cefAuditSeverity = 3
	sysInformational = 6
	sysWarning       = 4
)

// primary returns the most severe finding, the first one on a tie.
func primary(fs []events.Finding) (events.Finding, bool) {
	best, ok := events.Finding{}, false
	for _, f := range fs {
		if !ok || cefSeverity[f.Severity] > cefSeverity[best.Severity] {
			best, ok = f, true
		}
	}
	return best, ok
}

// Severity is the finding-severity name ("info" ... "critical") of rec, used by
// the OTLP mapping. Records without findings, and audit records, are "info".
func Severity(rec extension.ExportRecord) string {
	if rec.Stream != extension.StreamEvents {
		return "info"
	}
	var ev events.Event
	if json.Unmarshal(rec.Body, &ev) != nil {
		return "info"
	}
	if f, ok := primary(ev.Findings); ok && cefSeverity[f.Severity] > 0 {
		return f.Severity
	}
	return "info"
}

// SyslogSeverity maps rec to an RFC 5424 severity (0-7). Audit records are
// informational, except failures and denials, which are warnings.
func SyslogSeverity(rec extension.ExportRecord) int {
	if rec.Stream == extension.StreamAudit {
		var a AuditDoc
		if json.Unmarshal(rec.Body, &a) == nil && (strings.Contains(a.Action, "failed") || strings.Contains(a.Action, "denied")) {
			return sysWarning
		}
		return sysInformational
	}
	return syslogSeverity[Severity(rec)]
}

// CEF renders rec as one CEF:0 line (no trailing newline).
func CEF(rec extension.ExportRecord, version string) (string, error) {
	switch rec.Stream {
	case extension.StreamEvents:
		var ev events.Event
		if err := json.Unmarshal(rec.Body, &ev); err != nil {
			return "", fmt.Errorf("decoding event %s: %w", rec.ID, err)
		}
		return eventCEF(&ev, version), nil
	case extension.StreamAudit:
		var a AuditDoc
		if err := json.Unmarshal(rec.Body, &a); err != nil {
			return "", fmt.Errorf("decoding audit record %s: %w", rec.ID, err)
		}
		return auditCEF(&a, version), nil
	}
	return "", fmt.Errorf("unknown stream %q", rec.Stream)
}

func eventCEF(ev *events.Event, version string) string {
	sigID, name, sev := "0", "request "+ev.Action, 1
	if f, ok := primary(ev.Findings); ok {
		sigID = firstNonEmpty(f.RuleID, f.Module)
		name = firstNonEmpty(f.Message, f.Module+" finding")
		sev = max(cefSeverity[f.Severity], 1)
	}
	var b ext
	b.add("rt", strconv.FormatInt(ev.TS.UnixMilli(), 10))
	b.add("dvchost", ev.Node)
	b.add("src", ev.Client.IP)
	b.add("requestMethod", ev.Request.Method)
	b.add("request", ev.Request.Host+ev.Request.Path)
	b.add("act", ev.Action)
	b.label("cs1", "site", ev.SiteID)
	b.label("cs2", "event_id", ev.ID)
	b.label("cn1", "anomaly_score", strconv.Itoa(ev.AnomalyScore.Inbound))
	return header(version, sigID, name, sev) + b.String()
}

func auditCEF(a *AuditDoc, version string) string {
	var b ext
	b.add("rt", strconv.FormatInt(a.At.UnixMilli(), 10))
	b.add("suser", a.ActorID)
	b.add("src", a.IP)
	b.label("cs1", "object", strings.Trim(a.ObjectType+"/"+a.ObjectID, "/"))
	b.label("cs2", "audit_id", a.ID)
	return header(version, "audit."+a.Action, strings.TrimSpace(a.Action+" "+a.ObjectType), cefAuditSeverity) + b.String()
}

func header(version, sigID, name string, severity int) string {
	return "CEF:0|Sherlock|Sherlock WAF|" + headerEscape(version) + "|" + headerEscape(sigID) + "|" + headerEscape(name) + "|" + strconv.Itoa(severity) + "|"
}

var headerReplacer = strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\r\n", " ", "\n", " ", "\r", " ")

// headerEscape escapes a header field. CEF has no newline escape in headers, so
// line breaks become spaces rather than splitting the record in two.
func headerEscape(s string) string { return headerReplacer.Replace(s) }

var extReplacer = strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\r\n", `\n`, "\n", `\n`, "\r", `\r`)

// ext accumulates the space-separated key=value extension.
type ext struct{ sb strings.Builder }

func (e *ext) add(key, val string) {
	if val == "" {
		return
	}
	if e.sb.Len() > 0 {
		e.sb.WriteByte(' ')
	}
	e.sb.WriteString(key + "=" + extReplacer.Replace(val))
}

func (e *ext) label(key, label, val string) {
	if val == "" {
		return
	}
	e.add(key+"Label", label)
	e.add(key, val)
}

func (e *ext) String() string { return e.sb.String() }

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
