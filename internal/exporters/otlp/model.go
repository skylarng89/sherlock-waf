package otlp

import (
	"encoding/binary"
	"encoding/json"
	"strconv"
	"time"

	"github.com/skylarng89/sherlock-waf/internal/events"
	"github.com/skylarng89/sherlock-waf/internal/exporters/format"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// OTLP severity numbers (logs data model) for Sherlock severities.
var severities = map[string]struct {
	num  int
	text string
}{
	"info":     {9, "INFO"},
	"notice":   {10, "NOTICE"},
	"warning":  {13, "WARN"},
	"error":    {17, "ERROR"},
	"critical": {21, "CRITICAL"},
}

// value is the subset of AnyValue Sherlock emits.
type value struct {
	s     string
	i     int64
	arr   []string
	isInt bool
	isArr bool
}

type attr struct {
	key string
	val value
}

func strAttr(k, v string) attr       { return attr{k, value{s: v}} }
func intAttr(k string, v int64) attr { return attr{k, value{i: v, isInt: true}} }

type logRecord struct {
	timeNano, observedNano int64
	sevNum                 int
	sevText                string
	body                   string
	attrs                  []attr
}

// toLogRecord maps an export record. The whole document travels as the body so
// nothing is lost; the attributes are the fields a collector pipeline filters on.
func toLogRecord(rec extension.ExportRecord, observed time.Time) logRecord {
	sev := severities[format.Severity(rec)]
	at := rec.At
	if at.IsZero() {
		at = observed
	}
	lr := logRecord{
		timeNano: at.UnixNano(), observedNano: observed.UnixNano(),
		sevNum: sev.num, sevText: sev.text, body: string(rec.Body),
		attrs: []attr{strAttr("sherlock.stream", rec.Stream)},
	}
	switch rec.Stream {
	case extension.StreamEvents:
		var ev events.Event
		if json.Unmarshal(rec.Body, &ev) != nil {
			return lr
		}
		lr.attrs = append(lr.attrs, strAttr("sherlock.event.id", ev.ID), strAttr("sherlock.site_id", ev.SiteID),
			strAttr("sherlock.action", ev.Action), strAttr("client.address", ev.Client.IP),
			strAttr("http.request.method", ev.Request.Method), strAttr("server.address", ev.Request.Host),
			strAttr("url.path", ev.Request.Path), intAttr("http.response.status_code", int64(ev.Response.Status)))
		if ev.Client.Country != "" {
			lr.attrs = append(lr.attrs, strAttr("sherlock.client.country", ev.Client.Country))
		}
		var rules []string
		for _, f := range ev.Findings {
			if f.RuleID != "" {
				rules = append(rules, f.RuleID)
			}
		}
		if len(rules) > 0 {
			lr.attrs = append(lr.attrs, attr{"sherlock.rule_ids", value{arr: rules, isArr: true}})
		}
	case extension.StreamAudit:
		var a format.AuditDoc
		if json.Unmarshal(rec.Body, &a) != nil {
			return lr
		}
		lr.attrs = append(lr.attrs, strAttr("sherlock.audit.id", a.ID), strAttr("sherlock.audit.action", a.Action),
			strAttr("sherlock.audit.actor_id", a.ActorID), strAttr("sherlock.audit.object_type", a.ObjectType),
			strAttr("sherlock.audit.object_id", a.ObjectID), strAttr("client.address", a.IP))
	}
	// Empty values add nothing a pipeline can filter on.
	kept := lr.attrs[:0]
	for _, a := range lr.attrs {
		if a.val.isInt || a.val.isArr || a.val.s != "" {
			kept = append(kept, a)
		}
	}
	lr.attrs = kept
	return lr
}

// --- OTLP/JSON (protobuf JSON mapping: camelCase names, 64-bit ints as strings) ---

type jsonAny struct {
	StringValue *string    `json:"stringValue,omitempty"`
	IntValue    *string    `json:"intValue,omitempty"`
	ArrayValue  *jsonArray `json:"arrayValue,omitempty"`
}

type jsonArray struct {
	Values []jsonAny `json:"values"`
}

type jsonKV struct {
	Key   string  `json:"key"`
	Value jsonAny `json:"value"`
}

type jsonLog struct {
	TimeUnixNano         string   `json:"timeUnixNano"`
	ObservedTimeUnixNano string   `json:"observedTimeUnixNano"`
	SeverityNumber       int      `json:"severityNumber"`
	SeverityText         string   `json:"severityText"`
	Body                 jsonAny  `json:"body"`
	Attributes           []jsonKV `json:"attributes"`
}

type jsonScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type jsonScopeLogs struct {
	Scope      jsonScope `json:"scope"`
	LogRecords []jsonLog `json:"logRecords"`
}

type jsonResource struct {
	Attributes []jsonKV `json:"attributes"`
}

type jsonResourceLogs struct {
	Resource  jsonResource    `json:"resource"`
	ScopeLogs []jsonScopeLogs `json:"scopeLogs"`
}

type jsonRequest struct {
	ResourceLogs []jsonResourceLogs `json:"resourceLogs"`
}

func toJSONValue(v value) jsonAny {
	switch {
	case v.isInt:
		s := strconv.FormatInt(v.i, 10)
		return jsonAny{IntValue: &s}
	case v.isArr:
		arr := &jsonArray{Values: make([]jsonAny, len(v.arr))}
		for i := range v.arr {
			arr.Values[i] = jsonAny{StringValue: &v.arr[i]}
		}
		return jsonAny{ArrayValue: arr}
	}
	return jsonAny{StringValue: &v.s}
}

func toJSONAttrs(as []attr) []jsonKV {
	out := make([]jsonKV, len(as))
	for i, a := range as {
		out[i] = jsonKV{Key: a.key, Value: toJSONValue(a.val)}
	}
	return out
}

func marshalJSON(res []attr, version string, lrs []logRecord) ([]byte, error) {
	logs := make([]jsonLog, len(lrs))
	for i, l := range lrs {
		body := l.body
		logs[i] = jsonLog{
			TimeUnixNano: strconv.FormatInt(l.timeNano, 10), ObservedTimeUnixNano: strconv.FormatInt(l.observedNano, 10),
			SeverityNumber: l.sevNum, SeverityText: l.sevText, Body: jsonAny{StringValue: &body}, Attributes: toJSONAttrs(l.attrs),
		}
	}
	return json.Marshal(jsonRequest{ResourceLogs: []jsonResourceLogs{{
		Resource:  jsonResource{Attributes: toJSONAttrs(res)},
		ScopeLogs: []jsonScopeLogs{{Scope: jsonScope{Name: scopeName, Version: version}, LogRecords: logs}},
	}}})
}

// --- OTLP/protobuf, hand-encoded: the messages are small and stable, and this
// avoids a gRPC or protobuf dependency in the core module. Field numbers are
// from opentelemetry/proto/{logs,common,resource}/v1. ---

func appendVarint(b []byte, v uint64) []byte { return binary.AppendUvarint(b, v) }

func appendTag(b []byte, field, wire int) []byte {
	return appendVarint(b, uint64(field)<<3|uint64(wire)) //nolint:gosec // small non-negative constants
}

func appendBytes(b []byte, field int, p []byte) []byte {
	b = appendTag(b, field, 2)
	b = appendVarint(b, uint64(len(p)))
	return append(b, p...)
}

func appendString(b []byte, field int, s string) []byte {
	if s == "" {
		return b
	}
	return appendBytes(b, field, []byte(s))
}

func appendFixed64(b []byte, field int, v int64) []byte {
	b = appendTag(b, field, 1)
	return binary.LittleEndian.AppendUint64(b, uint64(v)) //nolint:gosec // bit pattern of a timestamp
}

func pbValue(v value) []byte {
	switch {
	case v.isInt:
		b := appendTag(nil, 3, 0)
		return appendVarint(b, uint64(v.i)) //nolint:gosec // int64 is encoded as its two's complement varint
	case v.isArr:
		var arr []byte
		for _, s := range v.arr {
			arr = appendBytes(arr, 1, appendBytes(nil, 1, []byte(s)))
		}
		return appendBytes(nil, 5, arr)
	}
	return appendBytes(nil, 1, []byte(v.s)) // empty strings must still be present
}

func pbKV(a attr) []byte {
	b := appendString(nil, 1, a.key)
	return appendBytes(b, 2, pbValue(a.val))
}

func marshalProto(res []attr, version string, lrs []logRecord) []byte {
	var resource []byte
	for _, a := range res {
		resource = appendBytes(resource, 1, pbKV(a))
	}
	scope := appendString(appendString(nil, 1, scopeName), 2, version)
	var scopeLogs []byte
	scopeLogs = appendBytes(scopeLogs, 1, scope)
	for _, l := range lrs {
		var r []byte
		r = appendFixed64(r, 1, l.timeNano)
		r = appendTag(r, 2, 0)
		r = appendVarint(r, uint64(l.sevNum)) //nolint:gosec // 1-24
		r = appendString(r, 3, l.sevText)
		r = appendBytes(r, 5, appendBytes(nil, 1, []byte(l.body)))
		for _, a := range l.attrs {
			r = appendBytes(r, 6, pbKV(a))
		}
		r = appendFixed64(r, 11, l.observedNano)
		scopeLogs = appendBytes(scopeLogs, 2, r)
	}
	var resourceLogs []byte
	resourceLogs = appendBytes(resourceLogs, 1, resource)
	resourceLogs = appendBytes(resourceLogs, 2, scopeLogs)
	return appendBytes(nil, 1, resourceLogs)
}
