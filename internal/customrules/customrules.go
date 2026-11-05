// Package customrules validates operator-written SecLang before it reaches a
// production Coraza instance (threat T9). A rule set is accepted only if it
// passes a static allow-list of directives, actions, operators and variables,
// keeps to the reserved ID range, and compiles in a throwaway Coraza instance.
//
// The allow-list is deliberately narrow: user rules may detect and deny, but
// they cannot execute programs, read files, reach the network, change the
// engine configuration, or switch off other protections.
package customrules

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

// ID range reserved for user rules (M8-T3).
const (
	MinID = 10000
	MaxID = 99999
	// MaxBytes bounds the stored rule text.
	MaxBytes = 64 << 10
	// MaxRules bounds the number of rule groups.
	MaxRules = 500
)

// Ranges that user rules may never remove with ctl: the Sherlock body
// processors and CRS initialisation (200000-200099, 900000-900999) and the
// virtual-patch pack (9500000-9599999).
var protectedRanges = [][2]int{{200000, 200099}, {900000, 900999}, {9500000, 9599999}}

// Issue codes.
const (
	CodeSyntax             = "syntax"
	CodeTooLarge           = "too_large"
	CodeForbiddenDirective = "forbidden_directive"
	CodeForbiddenAction    = "forbidden_action"
	CodeForbiddenOperator  = "forbidden_operator"
	CodeForbiddenVariable  = "forbidden_variable"
	CodeForbiddenCtl       = "forbidden_ctl"
	CodeIDRange            = "id_range"
	CodeIDMissing          = "id_missing"
	CodeIDDuplicate        = "id_duplicate"
	CodePhase              = "phase"
	CodeCompile            = "compile"
)

// Issue is one problem found in a rule set. Line is 1-based (0: whole input).
type Issue struct {
	Line    int    `json:"line"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Result is the outcome of Check.
type Result struct {
	Issues  []Issue `json:"issues"`
	RuleIDs []int   `json:"rule_ids"`
}

// Valid reports whether the rule set may be saved.
func (r Result) Valid() bool { return len(r.Issues) == 0 }

// Err returns the issues as an error, or nil.
func (r Result) Err() error {
	if r.Valid() {
		return nil
	}
	parts := make([]string, len(r.Issues))
	for i, is := range r.Issues {
		parts[i] = is.String()
	}
	return fmt.Errorf("%s", strings.Join(parts, "; "))
}

func (i Issue) String() string {
	if i.Line == 0 {
		return i.Message
	}
	return fmt.Sprintf("line %d: %s", i.Line, i.Message)
}

var (
	allowedActions = map[string]bool{
		"id": true, "phase": true, "msg": true, "logdata": true, "severity": true, "tag": true, "rev": true, "ver": true,
		"maturity": true, "accuracy": true, "status": true, "t": true, "log": true, "nolog": true, "auditlog": true,
		"noauditlog": true, "pass": true, "deny": true, "block": true, "capture": true, "chain": true, "skip": true,
		"skipafter": true, "setvar": true, "multimatch": true, "ctl": true,
	}
	// actionHints explain the most likely reasons an action is refused.
	actionHints = map[string]string{
		"exec":        "running programs is never allowed in custom rules",
		"allow":       "a rule that allows a request bypasses every later protection; use an exclusion or an ACL allow list instead",
		"drop":        "use deny with a status instead",
		"redirect":    "redirects can be abused to send visitors elsewhere; use deny instead",
		"proxy":       "forwarding requests is not supported",
		"setenv":      "environment variables are not accessible",
		"initcol":     "persistent collections are not supported",
		"expirevar":   "persistent collections are not supported",
		"setsid":      "sessions are not supported",
		"setuid":      "sessions are not supported",
		"setrsc":      "persistent collections are not supported",
		"sanitisearg": "use the event redaction settings instead",
	}
	forbiddenOperators = map[string]string{
		"inspectfile":     "it executes an external program",
		"rbl":             "it performs DNS lookups, and the request path makes no network calls",
		"pmfromfile":      "it reads a file from disk; inline the phrases with @pm",
		"pmf":             "it reads a file from disk; inline the phrases with @pm",
		"ipmatchfromfile": "it reads a file from disk; inline the addresses with @ipMatch",
		"ipmatchf":        "it reads a file from disk; inline the addresses with @ipMatch",
		"validatedtd":     "it reads a file from disk",
		"validateschema":  "it reads a file from disk",
		"fuzzyhash":       "it reads a file from disk",
		"gsblookup":       "it performs network lookups",
		"geolookup":       "country matching belongs in the ACL settings",
	}
	safeCtl = map[string]bool{
		"ruleremovebyid": true, "ruleremovebytag": true, "ruleremovetargetbyid": true, "ruleremovetargetbytag": true,
	}
	// protectedTX are CRS variables whose change would weaken blocking.
	protectedTX = regexp.MustCompile(`(?i)^(blocking_paranoia_level|detection_paranoia_level|inbound_anomaly_score_threshold|outbound_anomaly_score_threshold|crs_setup_version|allowed_|restricted_|max_num_args|arg_|total_arg_length|combined_file_sizes|enforce_bodyproc|sampling_percentage|reporting_level|early_blocking|critical_anomaly_score|error_anomaly_score|warning_anomaly_score|notice_anomaly_score)`)
	envVar      = regexp.MustCompile(`(?i)(^|[|&!])ENV(:|$|\|)`)
	envMacro    = regexp.MustCompile(`(?i)%\{\s*env[.}]`)
)

// directive is one logical SecLang statement after continuation joining.
type directive struct {
	line int
	text string
}

func logicalLines(src string) []directive {
	var out []directive
	var cur strings.Builder
	start := 0
	for i, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(raw)
		if cur.Len() == 0 {
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			start = i + 1
		}
		if strings.HasSuffix(t, `\`) {
			cur.WriteString(strings.TrimSuffix(t, `\`))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(t)
		out = append(out, directive{line: start, text: cur.String()})
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, directive{line: start, text: cur.String()})
	}
	return out
}

// fields splits on whitespace, keeping double-quoted tokens whole and
// unescaping \" inside them.
func fields(s string) ([]string, error) {
	var out []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		var b strings.Builder
		if s[i] == '"' {
			i++
			closed := false
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) && s[i+1] == '"' {
					b.WriteByte('"')
					i += 2
					continue
				}
				if s[i] == '"' {
					closed = true
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated double quote")
			}
		} else {
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				b.WriteByte(s[i])
				i++
			}
		}
		out = append(out, b.String())
	}
	return out, nil
}

type action struct{ name, arg string }

// parseActions splits an action list on commas outside single quotes.
func parseActions(s string) []action {
	var out []action
	var cur strings.Builder
	inQuote := false
	flush := func() {
		part := strings.TrimSpace(cur.String())
		cur.Reset()
		if part == "" {
			return
		}
		name, arg, _ := strings.Cut(part, ":")
		out = append(out, action{strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(arg)})
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(c)
			i++
			cur.WriteByte(s[i])
		case c == '\'':
			inQuote = !inQuote
			cur.WriteByte(c)
		case c == ',' && !inQuote:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}

// group is a rule plus the rules chained to it.
type group struct {
	line int
	text []string
}

// Check validates src and returns every issue found.
func Check(src string) Result {
	res := Result{Issues: []Issue{}, RuleIDs: []int{}}
	add := func(line int, code, format string, args ...any) {
		res.Issues = append(res.Issues, Issue{Line: line, Code: code, Message: fmt.Sprintf(format, args...)})
	}
	if len(src) > MaxBytes {
		add(0, CodeTooLarge, "custom rules may be at most %d bytes", MaxBytes)
		return res
	}
	if strings.ContainsRune(src, 0) {
		add(0, CodeSyntax, "rules must not contain NUL bytes")
		return res
	}
	// These would let the validator and Coraza disagree about where a
	// directive ends, so they are refused rather than interpreted.
	if strings.Contains(strings.ReplaceAll(src, "\r\n", ""), "\r") {
		add(0, CodeSyntax, "use Unix or Windows line endings; a lone carriage return is not allowed")
		return res
	}
	if strings.Contains(src, "`") {
		add(0, CodeSyntax, "backticks start multi-line blocks and are not supported; write the character as \\x60 in a regular expression")
		return res
	}
	if strings.HasSuffix(strings.TrimRight(src, " \t\r\n"), `\`) {
		add(0, CodeSyntax, "the rules must not end with a line continuation (a trailing backslash)")
		return res
	}

	var groups []group
	seen := map[int]int{}
	chaining := false
	for _, d := range logicalLines(src) {
		toks, err := fields(d.text)
		if err != nil || len(toks) == 0 {
			add(d.line, CodeSyntax, "cannot parse directive: %v", err)
			continue
		}
		name := strings.ToLower(toks[0])
		switch name {
		case "secrule", "secaction":
		case "secmarker":
			if len(toks) != 2 || !regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`).MatchString(toks[1]) {
				add(d.line, CodeSyntax, "SecMarker takes one name made of letters, digits, '_', '.' or '-'")
				continue
			}
			groups = append(groups, group{d.line, []string{d.text}})
			continue
		default:
			add(d.line, CodeForbiddenDirective, "%s is not allowed in custom rules; only SecRule, SecAction and SecMarker are (engine settings, includes, scripts and audit logging are managed by Sherlock)", toks[0])
			continue
		}

		var actions []action
		var rest []string
		if name == "secrule" {
			if len(toks) < 3 || len(toks) > 4 {
				add(d.line, CodeSyntax, "SecRule needs VARIABLES, OPERATOR and optionally ACTIONS")
				continue
			}
			vars, op := toks[1], toks[2]
			if envVar.MatchString(vars) {
				add(d.line, CodeForbiddenVariable, "the ENV variable is not accessible in custom rules")
			}
			if o := operatorName(op); o != "" {
				if why, bad := forbiddenOperators[o]; bad {
					add(d.line, CodeForbiddenOperator, "operator @%s is not allowed: %s", o, why)
				}
			}
			if len(toks) == 4 {
				rest = toks[3:]
			}
		} else {
			if len(toks) != 2 {
				add(d.line, CodeSyntax, "SecAction needs one quoted action list")
				continue
			}
			rest = toks[1:]
		}
		if len(rest) == 1 {
			actions = parseActions(rest[0])
		}
		if envMacro.MatchString(d.text) {
			add(d.line, CodeForbiddenVariable, "ENV macros are not accessible in custom rules")
		}

		var id, phase int
		hasChain := false
		for _, a := range actions {
			if !allowedActions[a.name] {
				hint := actionHints[a.name]
				if hint != "" {
					add(d.line, CodeForbiddenAction, "action %q is not allowed: %s", a.name, hint)
				} else {
					add(d.line, CodeForbiddenAction, "action %q is not allowed in custom rules", a.name)
				}
				continue
			}
			switch a.name {
			case "id":
				n, err := strconv.Atoi(a.arg)
				if err != nil {
					add(d.line, CodeSyntax, "id must be a number")
				} else {
					id = n
				}
			case "phase":
				p := strings.ToLower(a.arg)
				switch p {
				case "request":
					phase = 2
				case "response":
					phase = 4
				default:
					n, err := strconv.Atoi(p)
					if err != nil || n < 1 || n > 4 {
						add(d.line, CodePhase, "phase must be 1 to 4 (phase 5, logging, is not available)")
					}
					phase = n
				}
			case "chain":
				hasChain = true
			case "ctl":
				checkCtl(d.line, a.arg, add)
			case "setvar":
				checkSetvar(d.line, a.arg, add)
			}
		}
		_ = phase

		switch {
		case chaining:
			if id != 0 {
				add(d.line, CodeSyntax, "a chained rule must not have its own id")
			}
			groups[len(groups)-1].text = append(groups[len(groups)-1].text, d.text)
		default:
			switch {
			case id == 0:
				add(d.line, CodeIDMissing, "every rule needs an id between %d and %d", MinID, MaxID)
			case id < MinID || id > MaxID:
				add(d.line, CodeIDRange, "id %d is outside the range reserved for custom rules (%d-%d)", id, MinID, MaxID)
			case seen[id] != 0:
				add(d.line, CodeIDDuplicate, "id %d is already used on line %d", id, seen[id])
			default:
				seen[id] = d.line
				res.RuleIDs = append(res.RuleIDs, id)
			}
			groups = append(groups, group{d.line, []string{d.text}})
		}
		chaining = hasChain
	}
	if chaining {
		add(0, CodeSyntax, "the last rule ends with chain but no chained rule follows")
	}
	if len(groups) > MaxRules {
		add(0, CodeTooLarge, "at most %d rules are allowed", MaxRules)
	}
	slices.Sort(res.RuleIDs)
	if len(res.Issues) > 0 {
		return res
	}

	if err := compile(groups); err != nil {
		add(err.line, CodeCompile, "%s", err.msg)
	}
	return res
}

func operatorName(op string) string {
	op = strings.TrimPrefix(strings.TrimSpace(op), "!")
	if !strings.HasPrefix(op, "@") {
		return ""
	}
	name, _, _ := strings.Cut(op[1:], " ")
	return strings.ToLower(name)
}

func checkCtl(line int, arg string, add func(int, string, string, ...any)) {
	name, val, _ := strings.Cut(arg, "=")
	lname := strings.ToLower(strings.TrimSpace(name))
	if !safeCtl[lname] {
		add(line, CodeForbiddenCtl, "ctl:%s is not allowed; only ruleRemoveById, ruleRemoveByTag, ruleRemoveTargetById and ruleRemoveTargetByTag are", name)
		return
	}
	if lname == "ruleremovebyid" || lname == "ruleremovetargetbyid" {
		idpart, _, _ := strings.Cut(val, ";")
		lo, hi, ok := parseIDRange(idpart)
		if !ok {
			add(line, CodeForbiddenCtl, "ctl:%s needs a rule id or range such as 942100 or 942100-942199", name)
			return
		}
		for _, r := range protectedRanges {
			if lo <= r[1] && hi >= r[0] {
				add(line, CodeForbiddenCtl, "ctl:%s may not touch rules %d-%d: they belong to Sherlock (virtual patches and engine setup)", name, r[0], r[1])
			}
		}
	}
}

func parseIDRange(s string) (lo, hi int, ok bool) {
	a, b, isRange := strings.Cut(strings.TrimSpace(s), "-")
	lo, err := strconv.Atoi(a)
	if err != nil {
		return 0, 0, false
	}
	hi = lo
	if isRange {
		if hi, err = strconv.Atoi(b); err != nil || hi < lo {
			return 0, 0, false
		}
	}
	return lo, hi, true
}

func checkSetvar(line int, arg string, add func(int, string, string, ...any)) {
	arg = strings.TrimPrefix(unquote(arg), "!")
	coll, rest, ok := strings.Cut(arg, ".")
	if !ok || !strings.EqualFold(coll, "tx") {
		add(line, CodeForbiddenAction, "setvar may only change TX variables (setvar:tx.name=value)")
		return
	}
	name, _, _ := strings.Cut(rest, "=")
	if protectedTX.MatchString(strings.TrimSpace(name)) {
		add(line, CodeForbiddenAction, "setvar may not change tx.%s: it controls CRS blocking behaviour that Sherlock manages through the policy", strings.TrimSpace(name))
	}
}

type compileError struct {
	line int
	msg  string
}

func compile(groups []group) *compileError {
	try := func(gs []group) error {
		var b strings.Builder
		b.WriteString("SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\n")
		for _, g := range gs {
			for _, t := range g.text {
				b.WriteString(t)
				b.WriteByte('\n')
			}
		}
		_, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(b.String()))
		return err
	}
	if err := try(groups); err == nil {
		return nil
	} else if len(groups) == 0 {
		return &compileError{0, err.Error()}
	}
	// Find the first group that breaks the build so the editor can point at it.
	for i := range groups {
		if err := try(groups[:i+1]); err != nil {
			return &compileError{groups[i].line, "Coraza cannot compile this rule: " + cleanErr(err)}
		}
	}
	return &compileError{0, "Coraza cannot compile the rule set"}
}

func cleanErr(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
