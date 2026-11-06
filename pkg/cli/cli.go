// Package cli provides the sherlock command tree. It is shared by the open-source
// binary and any binary built on top of it, each passing its own BuildInfo.
//
// Embedders such as the Enterprise build use it as a library: they call Execute
// (or NewRootCommand) with their own BuildInfo and Options. From v1.0 the
// supported surface is exactly the exported identifiers of this package; the
// commands and flags themselves are documented in docs/user and follow the same
// SemVer rules (see docs/release/versioning.md).
package cli

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// APIVersion is the control-plane API version this build serves, as in the
// /api/v1 path prefix. It changes only with a new major API.
const APIVersion = "v1"

// moduleVersion reports the version of a dependency compiled into the binary,
// or "unknown" when the build carries no module information.
func moduleVersion(path string) string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == path {
				return d.Version
			}
		}
	}
	return "unknown"
}

// BuildInfo identifies a build. The values are injected with -ldflags at link time.
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type options struct {
	ui         http.Handler
	extensions []extension.Extension
	releaseKey ed25519.PublicKey
}

// Option customises the command tree.
type Option func(*options)

// WithUI sets the handler that `run` serves the dashboard with. Each binary
// supplies its own, so an edition can embed a different dashboard build.
func WithUI(h http.Handler) Option {
	return func(o *options) { o.ui = h }
}

// WithExtensions registers extensions with the server. The open-source binary
// registers none (extension.None()); another edition passes its own.
func WithExtensions(exts ...extension.Extension) Option {
	return func(o *options) { o.extensions = append(o.extensions, exts...) }
}

// WithReleaseKey sets the Ed25519 public key `sherlock update` verifies release
// manifests with, instead of the key embedded in the open-source build. An
// edition that signs its own releases passes its key; tests pass a throw-away one.
// The override is part of the supported surface: an embedder may rely on it.
func WithReleaseKey(key ed25519.PublicKey) Option {
	return func(o *options) { o.releaseKey = key }
}

// Execute builds the command tree for info and runs it with ctx.
func Execute(ctx context.Context, info BuildInfo, opts ...Option) error {
	//nolint:contextcheck // false positive: cobra hands ctx to RunE via cmd.Context()
	return NewRootCommand(info, opts...).ExecuteContext(ctx)
}

// NewRootCommand returns the root `sherlock` command with all subcommands attached.
// The returned *cobra.Command is part of the supported surface: embedders may
// add their own subcommands or flags to it before executing it, so the cobra
// major version is a compatibility commitment of this module.
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
	var sf stateFlags
	sf.bind(root)
	root.AddCommand(
		newVersionCommand(info), newRunCommand(o, &sf, info),
		newUserCommand(&sf), newHashPasswordCommand(), newTokenCommand(&sf), newConfigCommand(&sf), newAuditCommand(&sf), newSecretsCommand(&sf),
		newUpdateCommand(o, &sf, info), newBackupCommand(&sf, info), newRestoreCommand(&sf), newHealthcheckCommand(),
	)
	return root
}

func newVersionCommand(info BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "sherlock %s (commit %s, built %s, %s %s/%s)\n",
				info.Version, info.Commit, info.Date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			fmt.Fprintf(out, "caddy %s · coraza %s · crs %s · config schema %d · api %s\n",
				moduleVersion("github.com/caddyserver/caddy/v2"), moduleVersion("github.com/corazawaf/coraza/v3"),
				crsVersion(), config.SchemaVersion, APIVersion)
		},
	}
}
