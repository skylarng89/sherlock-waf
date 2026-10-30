package cli

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/skylarng89/sherlock-waf/internal/server"
)

// newHealthcheckCommand probes the local node's /readyz so container runtimes
// can health-check a distroless image that has no shell or curl.
func newHealthcheckCommand() *cobra.Command {
	var listen string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Exit 0 if the local node reports ready (for container health checks)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if listen == "" {
				listen = os.Getenv(server.EnvListen)
			}
			if listen == "" {
				listen = server.DefaultListen
			}
			host, port, err := net.SplitHostPort(listen)
			if err != nil {
				return fmt.Errorf("invalid listen address %q: %w", listen, err)
			}
			// A wildcard bind is reachable through loopback; never probe a remote host.
			if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
				host = "127.0.0.1"
			}
			if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
				return fmt.Errorf("healthcheck only probes the local node, not %q", host)
			}
			// The node serves TLS on loopback; keep certificate verification enabled.
			client := &http.Client{Timeout: timeout, Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			}}
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, "https://"+net.JoinHostPort(host, port)+"/readyz", http.NoBody)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("node not reachable: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("node not ready: %s", resp.Status)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ready")
			return nil
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "address of the control plane (default: $"+server.EnvListen+" or "+server.DefaultListen+")")
	cmd.Flags().DurationVar(&timeout, "timeout", 3*time.Second, "probe timeout")
	return cmd
}
