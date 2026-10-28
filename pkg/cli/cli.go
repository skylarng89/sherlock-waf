// Package cli provides the sherlock command tree. It is shared by the open-source
// binary and any binary built on top of it, each passing its own BuildInfo.
package cli

import (
	"context"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// BuildInfo identifies a build. The values are injected with -ldflags at link time.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// Execute builds the command tree for info and runs it with ctx.
func Execute(ctx context.Context, info BuildInfo) error {
	return NewRootCommand(info).ExecuteContext(ctx)
}

// NewRootCommand returns the root `sherlock` command with all subcommands attached.
func NewRootCommand(info BuildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:           "sherlock",
		Short:         "Sherlock WAF: a self-hosted web application and API firewall",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(newVersionCommand(info))
	return root
}

func newVersionCommand(info BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "sherlock %s (commit %s, built %s, %s %s/%s)\n",
				info.Version, info.Commit, info.Date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}
}
