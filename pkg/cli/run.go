package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/skylarng89/sherlock-waf/internal/app"
	"github.com/skylarng89/sherlock-waf/internal/compiler"
)

const defaultListen = "127.0.0.1:9443"

func newRunCommand(o options) *cobra.Command {
	var (
		listen, configPath, dataDir string
		httpPort, httpsPort         int
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the server",
		Long: "Start the server. With --config, run the data plane: proxy the sites in the YAML file " +
			"through the WAF (SIGHUP reloads the file). Without it, serve the dashboard placeholder.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if configPath != "" {
				return runDataPlane(cmd.Context(), configPath, compiler.Options{HTTPPort: httpPort, HTTPSPort: httpsPort, DataDir: dataDir})
			}
			ln, err := (&net.ListenConfig{}).Listen(cmd.Context(), "tcp", listen)
			if err != nil {
				return fmt.Errorf("listening on %s: %w", listen, err)
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			return serve(cmd.Context(), logger, ln, o.ui)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", defaultListen, "address for the dashboard (plain HTTP until TLS lands in a later milestone)")
	cmd.Flags().StringVar(&configPath, "config", "", "path to the YAML config; starts the data plane")
	cmd.Flags().IntVar(&httpPort, "http-port", 80, "data plane HTTP listen port")
	cmd.Flags().IntVar(&httpsPort, "https-port", 443, "data plane HTTPS listen port")
	cmd.Flags().StringVar(&dataDir, "data-dir", "", "directory for certificates and state (default: the OS user data dir)")
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

// serve runs handler on ln until ctx is cancelled, then shuts down gracefully.
func serve(ctx context.Context, logger *slog.Logger, ln net.Listener, handler http.Handler) error {
	if handler == nil {
		handler = http.NotFoundHandler()
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	logger.Info("dashboard listening", "addr", ln.Addr().String())

	select {
	case err := <-errc:
		return fmt.Errorf("serving: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutting down: %w", err)
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serving: %w", err)
	}
	return nil
}
