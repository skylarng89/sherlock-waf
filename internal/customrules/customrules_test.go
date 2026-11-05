package customrules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheck(t *testing.T) {
	tests := []struct {
		name string
		src  string
		code string // "" means valid
	}{
		{"valid deny", `SecRule REQUEST_URI "@beginsWith /admin" "id:10001,phase:1,deny,status:403,msg:'Admin path blocked'"`, ""},
		{"valid chain", "SecRule REQUEST_URI \"@streq /a\" \"id:10002,phase:1,pass,nolog,chain\"\nSecRule REQUEST_METHOD \"@streq POST\" \"ctl:ruleRemoveById=942100\"", ""},
		{"valid continuation and comment", "# note\nSecRule ARGS:q \"@rx foo\" \\\n \"id:10003,phase:2,deny,t:lowercase,setvar:tx.my_hits=+1\"", ""},
		{"valid setvar score", `SecRule ARGS "@rx x" "id:10004,phase:2,pass,setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"`, ""},
		{"exec", `SecRule ARGS "@rx x" "id:10010,phase:2,pass,exec:/bin/sh"`, CodeForbiddenAction},
		{"lua script", `SecRuleScript /tmp/x.lua "id:10011,phase:2"`, CodeForbiddenDirective},
		{"include", `Include /etc/passwd`, CodeForbiddenDirective},
		{"audit log", `SecAuditLog /tmp/x`, CodeForbiddenDirective},
		{"engine off", `SecRuleEngine Off`, CodeForbiddenDirective},
		{"allow", `SecRule ARGS "@rx x" "id:10012,phase:2,allow"`, CodeForbiddenAction},
		{"ctl engine", `SecRule ARGS "@rx x" "id:10013,phase:2,pass,ctl:ruleEngine=Off"`, CodeForbiddenCtl},
		{"ctl remove vpatch", `SecRule ARGS "@rx x" "id:10014,phase:2,pass,ctl:ruleRemoveById=9500000-9599999"`, CodeForbiddenCtl},
		{"inspectFile", `SecRule FILES_TMPNAMES "@inspectFile /bin/av" "id:10015,phase:2,deny"`, CodeForbiddenOperator},
		{"rbl", `SecRule REMOTE_ADDR "@rbl dnsbl.example" "id:10016,phase:1,deny"`, CodeForbiddenOperator},
		{"pmFromFile", `SecRule ARGS "@pmFromFile /etc/passwd" "id:10017,phase:2,deny"`, CodeForbiddenOperator},
		{"env var", `SecRule ENV:HOME "@rx x" "id:10018,phase:1,deny"`, CodeForbiddenVariable},
		{"env macro", `SecRule ARGS "@rx x" "id:10019,phase:2,deny,logdata:'%{ENV.SECRET}'"`, CodeForbiddenVariable},
		{"id too low", `SecRule ARGS "@rx x" "id:900,phase:2,deny"`, CodeIDRange},
		{"id too high", `SecRule ARGS "@rx x" "id:100000,phase:2,deny"`, CodeIDRange},
		{"id missing", `SecRule ARGS "@rx x" "phase:2,deny"`, CodeIDMissing},
		{"duplicate", "SecRule ARGS \"@rx x\" \"id:10020,phase:2,deny\"\nSecRule ARGS \"@rx y\" \"id:10020,phase:2,deny\"", CodeIDDuplicate},
		{"setvar other collection", `SecRule ARGS "@rx x" "id:10021,phase:2,pass,setvar:ip.bad=1"`, CodeForbiddenAction},
		{"setvar threshold", `SecRule ARGS "@rx x" "id:10022,phase:2,pass,setvar:tx.inbound_anomaly_score_threshold=100000"`, CodeForbiddenAction},
		{"phase 5", `SecRule ARGS "@rx x" "id:10023,phase:5,pass"`, CodePhase},
		{"bad regex", `SecRule ARGS "@rx (" "id:10024,phase:2,deny"`, CodeCompile},
		{"dangling chain", `SecRule ARGS "@rx x" "id:10025,phase:2,deny,chain"`, CodeSyntax},
		{"unterminated quote", `SecRule ARGS "@rx x "id:10026"`, CodeSyntax},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := Check(tc.src)
			if tc.code == "" {
				require.True(t, res.Valid(), "%v", res.Issues)
				return
			}
			require.NotEmpty(t, res.Issues)
			codes := []string{}
			for _, i := range res.Issues {
				codes = append(codes, i.Code)
			}
			assert.Contains(t, codes, tc.code, "%v", res.Issues)
		})
	}
}

func TestCompileErrorPointsAtTheLine(t *testing.T) {
	res := Check("SecRule ARGS \"@rx x\" \"id:10030,phase:2,deny\"\n\nSecRule ARGS \"@rx (\" \"id:10031,phase:2,deny\"")
	require.Len(t, res.Issues, 1)
	assert.Equal(t, 3, res.Issues[0].Line)
}

func TestRuleIDsAreReturnedSorted(t *testing.T) {
	res := Check("SecAction \"id:10050,phase:1,pass,nolog\"\nSecAction \"id:10040,phase:1,pass,nolog\"")
	require.True(t, res.Valid(), "%v", res.Issues)
	assert.Equal(t, []int{10040, 10050}, res.RuleIDs)
}

func TestTooLarge(t *testing.T) {
	res := Check("#" + string(make([]byte, MaxBytes)))
	assert.False(t, res.Valid())
}

func TestParserDisagreementsAreRefused(t *testing.T) {
	for name, src := range map[string]string{
		"backtick":       "SecRule ARGS \"@rx x\" `\nid:10001,phase:2,deny\n`",
		"lone CR":        "SecAction \"id:10002,phase:1,pass\"\rSecRuleEngine Off",
		"trailing slash": "SecAction \"id:10003,phase:1,pass\" \\",
	} {
		t.Run(name, func(t *testing.T) { assert.False(t, Check(src).Valid()) })
	}
}
