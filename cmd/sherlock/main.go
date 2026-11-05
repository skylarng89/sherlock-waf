// Command sherlock is the Sherlock WAF server and CLI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/skylarng89/sherlock-waf/internal/webui"
	"github.com/skylarng89/sherlock-waf/pkg/cli"
	"github.com/skylarng89/sherlock-waf/pkg/extension"
)

// Set at link time: -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := cli.Execute(ctx, cli.BuildInfo{Version: version, Commit: commit, Date: date},
		cli.WithUI(webui.Handler()), cli.WithExtensions(extension.None()))
	stop()
	if err != nil {
		os.Exit(1)
	}
}
