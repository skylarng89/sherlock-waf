// Package cli provides the sherlock command tree. It is shared by the open-source
// binary and any binary built on top of it, each passing its own BuildInfo.
package cli

import (
	"context"
	"fmt"
	"net/http"
	"runtime"

	"github.com/spf13/cobra"
)

// BuildInfo identifies a build. The values are injected with -ldflags at link time.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type options struct {
	ui http.Handler
}

// Option customises the command tree.
type Option func(*options)

// WithUI sets the handler that `run` serves the dashboard with. Each binary
// supplies its own, so an edition can embed a different dashboard build.
func WithUI(h http.Handler) Option {
	return func(o *options) { o.ui = h }
}

// Execute builds the command tree for info and runs it with ctx.
func Execute(ctx context.Context, info BuildInfo, opts ...Option) error {
	return NewRootCommand(info, opts...).ExecuteContext(ctx)
}

// NewRootCommand returns the root `sherlock` command with all subcommands attached.
func NewRootCommand(info BuildInfo, opts ...Option) *cobra.Command {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	root := &cobra.Command{
		Use:           "sherlock",
		Short:         "Sherlock WAF: a self-hosted web application and API firewall",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(newVersionCommand(info), newRunCommand(o))
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
