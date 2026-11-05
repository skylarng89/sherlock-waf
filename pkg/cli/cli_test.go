package cli_test

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/skylarng89/sherlock-waf/pkg/cli"
)

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	info := cli.BuildInfo{Version: "1.2.3", Commit: "abc1234", Date: "2026-10-28T00:00:00Z"}

	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{
			name: "prints build info",
			args: []string{"version"},
			want: "sherlock 1.2.3 (commit abc1234, built 2026-10-28T00:00:00Z, " +
				runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + ")\n",
		},
		{name: "rejects extra arguments", args: []string{"version", "extra"}, wantErr: true},
		{name: "rejects unknown command", args: []string{"nope"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out, errOut bytes.Buffer
			cmd := cli.NewRootCommand(info)
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, out.String())
		})
	}
}
