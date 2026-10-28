package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

const defaultListen = "127.0.0.1:9443"

func newRunCommand(o options) *cobra.Command {
	var listen string

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ln, err := (&net.ListenConfig{}).Listen(cmd.Context(), "tcp", listen)
			if err != nil {
				return fmt.Errorf("listening on %s: %w", listen, err)
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			return serve(cmd.Context(), logger, ln, o.ui)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", defaultListen, "address for the dashboard (plain HTTP until TLS lands in a later milestone)")
	return cmd
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
