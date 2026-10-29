package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/skylarng89/sherlock-waf/internal/app"
	"github.com/skylarng89/sherlock-waf/internal/compiler"
	"github.com/skylarng89/sherlock-waf/internal/controlplane/api"
	"github.com/skylarng89/sherlock-waf/internal/server"
)

func newRunCommand(o options, sf *stateFlags, info BuildInfo) *cobra.Command {
	var (
		listen, configPath  string
		httpPort, httpsPort int
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the server",
		Long: "Start the server.\n\n" +
			"Without --config this is the full node: the control plane (API and dashboard over TLS) backed by the\n" +
			"database, which drives the data plane. A fresh node has no users and no configuration; create the first\n" +
			"admin with `sherlock user create --admin`, then sign in and add sites.\n\n" +
			"With --config it runs the data plane alone from a YAML file (SIGHUP reloads it), with no control plane.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			copts := compiler.Options{HTTPPort: httpPort, HTTPSPort: httpsPort, DataDir: sf.dataDir}
			if configPath != "" {
				return runDataPlane(cmd.Context(), configPath, copts)
			}
			logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
			slog.SetDefault(logger)
			return server.Run(cmd.Context(), server.Options{
				DataDir: sf.dataDir, DatabaseURL: sf.databaseURL, Listen: listen, Compiler: copts, UI: o.ui, Extensions: o.extensions, Logger: logger,
				Info: api.Info{Version: info.Version, Commit: info.Commit, CRSVersion: crsVersion()}, ReleaseKey: o.releaseKey,
			})
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "address for the API and dashboard, served over TLS (default: $"+server.EnvListen+" or "+server.DefaultListen+")")
	cmd.Flags().StringVar(&configPath, "config", "", "path to a YAML config; runs the data plane alone, without the control plane")
	cmd.Flags().IntVar(&httpPort, "http-port", 80, "data plane HTTP listen port")
	cmd.Flags().IntVar(&httpsPort, "https-port", 443, "data plane HTTPS listen port")
	return cmd
}

// runDataPlane serves the config file until ctx is cancelled, reloading it on SIGHUP.
// Decisions and lifecycle events are logged as JSON lines on stdout.
func runDataPlane(ctx context.Context, configPath string, opts compiler.Options) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	if err := app.New(configPath, opts, logger).Run(ctx, hup); err != nil {
		return fmt.Errorf("running data plane: %w", err)
	}
	return nil
}
