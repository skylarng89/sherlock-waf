// Package events defines the v1 security event, its JSON Schema, the
// redaction rules applied before an event leaves the request path, and the
// non-blocking bus and sinks that carry events (ADR-0007).
package events

import "time"

// SchemaV1 is the value of Event.Schema.
const SchemaV1 = "sherlock.event.v1"

// Event is one request that had findings or was terminated. Changing it needs
// sherlock.event.v2 and a dual-write period (docs/architecture/events.md).
type Event struct {
	ID            string       `json:"id" desc:"ULID; also returned to the client in X-Sherlock-Event-Id"`
	Schema        string       `json:"schema" enum:"sherlock.event.v1"`
	TS            time.Time    `json:"ts" desc:"Request start"`
	Node          string       `json:"node" desc:"Node name"`
	SiteID        string       `json:"site_id"`
	Action        string       `json:"action" enum:"allow,log,challenge,block,ratelimit,ban"`
	Mode          string       `json:"mode" enum:"off,detect,block" desc:"Site mode at that time"`
	TerminatedBy  string       `json:"terminated_by,omitempty" desc:"Module that ended the request; empty if proxied"`
	Client        Client       `json:"client"`
	Request       Request      `json:"request"`
	Response      Response     `json:"response"`
	Timing        Timing       `json:"timing"`
	AnomalyScore  AnomalyScore `json:"anomaly_score"`
	ConfigVersion string       `json:"config_version,omitempty" desc:"Which config produced the decision"`
	// Findings is deliberately the last field: JSON key order carries no
	// meaning, and putting the largest, most variable part at the end means a
	// reader that catches a line mid-write sees a prefix that is cut inside
	// the findings rather than somewhere ambiguous.
	Findings []Finding `json:"findings"`
}

// Client identifies the requester as resolved by sherlock_core.
type Client struct {
	IP         string `json:"ip"`
	Country    string `json:"country,omitempty" desc:"ISO 3166-1 alpha-2"`
	ASN        int    `json:"asn,omitempty"`
	Reputation *int   `json:"reputation,omitempty" desc:"0-100"`
}

// Request is the redacted request summary.
type Request struct {
	Method      string            `json:"method"`
	Host        string            `json:"host"`
	Path        string            `json:"path"`
	Query       string            `json:"query,omitempty" desc:"Redacted"`
	Headers     map[string]string `json:"headers,omitempty" desc:"Allow-list only: User-Agent, Referer, Content-Type, Content-Length, Accept, X-Forwarded-For"`
	BodyExcerpt string            `json:"body_excerpt,omitempty" desc:"Off by default; first 2 KB, redacted"`
}

// Response is what the client received.
type Response struct {
	Status int   `json:"status"`
	Bytes  int64 `json:"bytes"`
}

// Timing is in milliseconds.
type Timing struct {
	TotalMS float64 `json:"total_ms"`
	WAFMS   float64 `json:"waf_ms"`
}

// Finding is a redacted policy.Finding.
type Finding struct {
	Module   string   `json:"module"`
	RuleID   string   `json:"rule_id,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Severity string   `json:"severity" enum:"info,notice,warning,error,critical"`
	Target   string   `json:"target,omitempty"`
	Matched  string   `json:"matched,omitempty" desc:"At most 256 bytes, redacted"`
	Score    int      `json:"score,omitempty" desc:"Anomaly score contribution, CRS only"`
	Message  string   `json:"message,omitempty"`
}

// AnomalyScore holds the CRS totals.
type AnomalyScore struct {
	Inbound  int `json:"inbound"`
	Outbound int `json:"outbound"`
}

// AllowedHeaders is the only set of request headers an event may carry.
// Authorization and Cookie are deliberately absent.
var AllowedHeaders = []string{"User-Agent", "Referer", "Content-Type", "Content-Length", "Accept", "X-Forwarded-For"}

const (
	// MaxMatchedBytes bounds Finding.Matched.
	MaxMatchedBytes = 256
	// MaxBodyExcerptBytes bounds Request.BodyExcerpt.
	MaxBodyExcerptBytes = 2048
	maxHeaderBytes      = 512
	maxQueryBytes       = 4096
)
