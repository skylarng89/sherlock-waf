package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/skylarng89/sherlock-waf/internal/app"
	"github.com/skylarng89/sherlock-waf/internal/dataplane/waf"
	"github.com/skylarng89/sherlock-waf/internal/ops"
)

// stateFlags are the persistent flags every command that touches node state shares.
type stateFlags struct {
	dataDir, databaseURL string
}

func (f *stateFlags) bind(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&f.dataDir, "data-dir", "", "directory for node state (default: the OS user data dir)")
	cmd.PersistentFlags().StringVar(&f.databaseURL, "database-url", "", "database DSN: postgres://… or a SQLite path (default: $"+ops.EnvDatabaseURL+" or <data-dir>/sherlock.db)")
}

// open opens the node state. The returned func closes it.
func (f *stateFlags) open(ctx context.Context) (*ops.Env, func(), error) {
	env, err := ops.Open(ctx, ops.OpenOptions{
		DataDir: app.ResolveDataDir(f.dataDir), DatabaseURL: f.databaseURL,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		return nil, nil, err
	}
	return env, func() { _ = env.Close() }, nil
}

// lockOffline takes the data-dir lock for commands that must not run beside a live server.
func (f *stateFlags) lockOffline() (func(), error) {
	release, err := ops.Lock(app.ResolveDataDir(f.dataDir))
	if errors.Is(err, ops.ErrLocked) {
		return nil, fmt.Errorf("%w: use --server and --token to change a running node through its API, or stop it first", err)
	}
	return release, err
}

// readPassword takes a password from stdin (--password-stdin, for scripts and
// secret managers) or prompts twice without echo. It is never read from a flag
// value or the environment, which other local users can see.
func readPassword(cmd *cobra.Command, fromStdin bool) (string, error) {
	if fromStdin {
		line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("reading password from stdin: %w", err)
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			return "", errors.New("no password on stdin")
		}
		return pw, nil
	}
	fd := int(os.Stdin.Fd()) //nolint:gosec // fd fits int
	if !term.IsTerminal(fd) {
		return "", errors.New("stdin is not a terminal; pass --password-stdin to read the password from it")
	}
	prompt := func(label string) (string, error) {
		fmt.Fprint(cmd.ErrOrStderr(), label)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(cmd.ErrOrStderr())
		return string(b), err
	}
	first, err := prompt("Password: ")
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	second, err := prompt("Repeat password: ")
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	if first != second {
		return "", errors.New("passwords do not match")
	}
	return first, nil
}

func opsApply(source string, requireEmpty bool, expect string) ops.ApplyOptions {
	return ops.ApplyOptions{Source: source, RequireEmpty: requireEmpty, Expect: expect}
}

func crsVersion() string { return waf.CRSVersion }
