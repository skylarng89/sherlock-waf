package waf

import (
	"fmt"
	"slices"
	"strings"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/vpatch"
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

	// Exclusions are the effective, site-scoped rule removals (M8-T1). They
	// compile to runtime exclusion rules placed before the CRS includes.
	Exclusions []config.Exclusion `json:"exclusions,omitempty"`
	// CustomRules is validated operator SecLang (ids 10000-99999).
	CustomRules string `json:"custom_rules,omitempty"`
	// VirtualPatches are the ids of the patches active for this endpoint,
	// resolved by the compiler from stacks and policy (M8-T6b).
	VirtualPatches []string `json:"virtual_patches,omitempty"`

	// OutboundInspection adds the CRS response rules (RESPONSE-*.conf) and
	// response body access, limited to OutboundContentTypes and
	// OutboundMaxBodyBytes (M8-T4).
	OutboundInspection   bool     `json:"outbound_inspection,omitempty"`
	OutboundMaxBodyBytes int64    `json:"outbound_max_body_bytes,omitempty"`
	OutboundContentTypes []string `json:"outbound_content_types,omitempty"`
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

	if s.OutboundInspection && (s.OutboundMaxBodyBytes < 1 || len(s.OutboundContentTypes) == 0) {
		return "", fmt.Errorf("outbound inspection needs a body limit and at least one content type")
	}

	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	line("SecRuleEngine %s", engine)
	line("SecRequestBodyAccess On")
	if s.OutboundInspection {
		line("SecResponseBodyAccess On")
		line("SecResponseBodyLimit %d", s.OutboundMaxBodyBytes)
		line("SecResponseBodyLimitAction ProcessPartial")
		// The handler filters by content type itself (prefix match); this
		// makes the engine accept whatever the handler hands over.
		line(`SecAction "id:200010,phase:3,pass,nolog,t:none,ctl:forceResponseBodyVariable=On"`)
	} else {
		line("SecResponseBodyAccess Off")
	}
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
	// Virtual patches, then operator rules, then exclusions: all before CRS so
	// that ctl:ruleRemove* takes effect and patches run even if CRS interrupts.
	vp, err := vpatch.Directives(s.VirtualPatches)
	if err != nil {
		return "", fmt.Errorf("loading virtual patches: %w", err)
	}
	if vp != "" {
		line("%s", strings.TrimRight(vp, "\n"))
	}
	if cr := strings.TrimSpace(strings.ReplaceAll(s.CustomRules, "\r\n", "\n")); cr != "" {
		line("%s", cr)
	}
	ex, err := exclusionDirectives(s.Exclusions)
	if err != nil {
		return "", err
	}
	if ex != "" {
		line("%s", ex)
	}
	line("Include @owasp_crs/REQUEST-*.conf")
	if s.OutboundInspection {
		line("Include @owasp_crs/RESPONSE-*.conf")
	}
	return b.String(), nil
}

// firstExclusionRuleID is the id of the first generated exclusion rule. CRS
// reserves 9,000,000-9,999,999 for third parties; Sherlock uses 9,100,000+ for
// exclusions, 9,500,000+ for virtual patches.
const firstExclusionRuleID = 9_100_000

// exclusionDirectives renders the exclusions in id order as CRS-style runtime
// exclusion rules. Every value that reaches the output has passed
// config validation; the escaping here is defence in depth.
func exclusionDirectives(exclusions []config.Exclusion) (string, error) {
	sorted := slices.Clone(exclusions)
	slices.SortFunc(sorted, func(a, b config.Exclusion) int { return strings.Compare(a.ID, b.ID) })
	var b strings.Builder
	for i, x := range sorted {
		ctls, err := exclusionActions(x)
		if err != nil {
			return "", fmt.Errorf("exclusion %q: %w", x.ID, err)
		}
		id := firstExclusionRuleID + i
		pathRE, err := config.PathsRegexp(x.Match.Paths)
		if err != nil {
			return "", fmt.Errorf("exclusion %q: %w", x.ID, err)
		}
		methodRE := ""
		if len(x.Match.Methods) > 0 {
			methodRE = "^(?:" + strings.Join(x.Match.Methods, "|") + ")$"
		}
		head := fmt.Sprintf("id:%d,phase:1,pass,nolog,t:none", id)
		switch {
		case pathRE == "" && methodRE == "":
			fmt.Fprintf(&b, "SecAction \"%s,%s\"\n", head, ctls)
		case pathRE != "" && methodRE != "":
			fmt.Fprintf(&b, "SecRule REQUEST_FILENAME \"@rx %s\" \"%s,chain\"\n", pathRE, head)
			fmt.Fprintf(&b, "  SecRule REQUEST_METHOD \"@rx %s\" \"t:none,%s\"\n", methodRE, ctls)
		case pathRE != "":
			fmt.Fprintf(&b, "SecRule REQUEST_FILENAME \"@rx %s\" \"%s,%s\"\n", pathRE, head, ctls)
		default:
			fmt.Fprintf(&b, "SecRule REQUEST_METHOD \"@rx %s\" \"%s,%s\"\n", methodRE, head, ctls)
		}
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func exclusionActions(x config.Exclusion) (string, error) {
	var ctls []string
	for _, id := range x.RemoveRuleIDs {
		if _, _, ok := config.ParseRuleIDRange(id); !ok {
			return "", fmt.Errorf("invalid rule id %q", id)
		}
		ctls = append(ctls, "ctl:ruleRemoveById="+id)
	}
	for _, t := range x.RemoveTags {
		if strings.ContainsAny(t, `,;'"\ `) {
			return "", fmt.Errorf("invalid tag %q", t)
		}
		ctls = append(ctls, "ctl:ruleRemoveByTag="+t)
	}
	for _, t := range x.RemoveTargets {
		if strings.ContainsAny(t.Target, `;'"\ `) {
			return "", fmt.Errorf("invalid target %q", t.Target)
		}
		for _, id := range t.RuleIDs {
			if _, _, ok := config.ParseRuleIDRange(id); !ok {
				return "", fmt.Errorf("invalid rule id %q", id)
			}
			ctls = append(ctls, "ctl:ruleRemoveTargetById="+id+";"+t.Target)
		}
		for _, tag := range t.Tags {
			if strings.ContainsAny(tag, `,;'"\ `) {
				return "", fmt.Errorf("invalid tag %q", tag)
			}
			ctls = append(ctls, "ctl:ruleRemoveTargetByTag="+tag+";"+t.Target)
		}
	}
	if len(ctls) == 0 {
		return "", fmt.Errorf("removes nothing")
	}
	return strings.Join(ctls, ","), nil
}
