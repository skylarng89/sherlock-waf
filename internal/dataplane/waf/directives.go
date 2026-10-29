package waf

import (
	"fmt"
	"strings"

	"github.com/skylarng89/sherlock-waf/internal/config"
)

// inMemoryBodyLimit is how much of a request body Coraza keeps in memory
// before spilling to the temp dir.
const inMemoryBodyLimit = 131072

// extraDirectives is appended before the CRS include. It is empty in every
// build except sherlock_testhooks, where it adds the go-ftw log marker rule.
var extraDirectives string

// Settings is the per-endpoint WAF configuration produced by the compiler
// from an effective policy.
type Settings struct {
	Mode                  config.Mode `json:"mode"`
	ParanoiaLevel         int         `json:"paranoia_level"`
	BlockingParanoiaLevel int         `json:"blocking_paranoia_level"`
	InboundThreshold      int         `json:"inbound_threshold"`
	OutboundThreshold     int         `json:"outbound_threshold"`
	MaxBodyBytes          int64       `json:"max_body_bytes"`
}

// Directives renders the SecLang configuration for one WAF instance. The
// output is deterministic so identical settings share one compiled instance.
//
// detect mode runs the engine in DetectionOnly: every rule evaluates and is
// recorded, but nothing interrupts, so the anomaly-evaluation rule (949110)
// firing means "would have blocked". Oversized bodies are inspected up to the
// limit in detect mode and rejected with 413 in block mode.
func (s Settings) Directives() (string, error) {
	var engine, limitAction string
	switch s.Mode {
	case config.ModeBlock:
		engine, limitAction = "On", "Reject"
	case config.ModeDetect:
		engine, limitAction = "DetectionOnly", "ProcessPartial"
	case config.ModeOff:
		return "", fmt.Errorf("waf is not compiled for mode %q", s.Mode)
	default:
		return "", fmt.Errorf("waf mode must be detect or block, got %q", s.Mode)
	}
	if s.ParanoiaLevel < 1 || s.ParanoiaLevel > 4 || s.BlockingParanoiaLevel < 1 || s.BlockingParanoiaLevel > s.ParanoiaLevel {
		return "", fmt.Errorf("invalid paranoia levels %d/%d", s.ParanoiaLevel, s.BlockingParanoiaLevel)
	}
	if s.InboundThreshold < 1 || s.OutboundThreshold < 1 || s.MaxBodyBytes < 1 {
		return "", fmt.Errorf("thresholds and body limit must be positive")
	}

	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	line("SecRuleEngine %s", engine)
	line("SecRequestBodyAccess On")
	line("SecResponseBodyAccess Off")
	line("SecAuditEngine Off")
	line("SecRequestBodyLimit %d", s.MaxBodyBytes)
	line("SecRequestBodyInMemoryLimit %d", min(s.MaxBodyBytes, inMemoryBodyLimit))
	line("SecRequestBodyLimitAction %s", limitAction)
	line("SecRequestBodyJsonDepthLimit 1024")
	line(`SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"`)
	line(`SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"`)
	line(`SecRule REQUEST_HEADERS:Content-Type "^application/[a-z0-9.-]+[+]json" "id:200006,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"`)
	line(`SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%%{reqbody_error_msg}',severity:2"`)
	line(`SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:200003,phase:2,t:none,log,deny,status:400,msg:'Multipart request body failed strict validation.',severity:2"`)
	line(`SecDefaultAction "phase:1,log,auditlog,pass"`)
	line(`SecDefaultAction "phase:2,log,auditlog,pass"`)
	line(`SecAction "id:900990,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=4250"`)
	line(`SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`, s.BlockingParanoiaLevel)
	line(`SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=%d"`, s.ParanoiaLevel)
	line(`SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"`, s.InboundThreshold, s.OutboundThreshold)
	// CRS allows only GET HEAD POST OPTIONS by default, which would block
	// ordinary REST traffic. TRACE and CONNECT stay disallowed.
	line(`SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"`)
	if extraDirectives != "" {
		line("%s", extraDirectives)
	}
	// Only request rules: response inspection is out of scope for M1.
	line("Include @owasp_crs/REQUEST-*.conf")
	return b.String(), nil
}
