package cli

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/skylarng89/sherlock-waf/internal/app"
	"github.com/skylarng89/sherlock-waf/internal/ops"
	"github.com/skylarng89/sherlock-waf/internal/store"
)

func newBackupCommand(sf *stateFlags, info BuildInfo) *cobra.Command {
	var (
		output                string
		includeKey, filesOnly bool
		passphraseStdin       bool
	)
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Write a backup of the node (database snapshot and data files); safe while the server runs",
		Long: "Write a backup archive (gzip tar) holding a consistent SQLite snapshot, the data directory's files and a\n" +
			"manifest with SHA-256 checksums. The default location is <data-dir>/backups. The node key is left out\n" +
			"unless --include-key is given, which encrypts the whole archive with a passphrase.\n\n" +
			"PostgreSQL nodes: dump the database with pg_dump and use --files-only for the rest.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var pass string
			if includeKey || passphraseStdin {
				var err error
				if pass, err = readSecret(cmd, passphraseStdin, "Passphrase", true); err != nil {
					return err
				}
			}
			env, closeEnv, err := sf.open(cmd.Context())
			if err != nil {
				return err
			}
			defer closeEnv()
			bi, err := env.Backup(cmd.Context(), ops.BackupOptions{Output: output, IncludeKey: includeKey, Passphrase: pass, FilesOnly: filesOnly, Version: info.Version})
			if err != nil {
				return err
			}
			matchOwner(env.DataDir, filepath.Dir(bi.Path), bi.Path, filepath.Join(env.DataDir, "sherlock.db"), filepath.Join(env.DataDir, "sherlock.db-wal"), filepath.Join(env.DataDir, "sherlock.db-shm"))
			fmt.Fprintf(cmd.OutOrStdout(), "backup written: %s (%d bytes, %d files%s)\n", bi.Path, bi.Bytes, bi.Files, map[bool]string{true: ", encrypted", false: ""}[bi.Encrypted])
			if !includeKey {
				fmt.Fprintln(cmd.ErrOrStderr(), "the node key is not in this backup: keep a separate copy of "+filepath.Join(env.DataDir, "node.key")+" (or use --include-key)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "archive path (default: <data-dir>/backups/sherlock-backup-<time>.tar.gz)")
	cmd.Flags().BoolVar(&includeKey, "include-key", false, "include the node key; requires a passphrase and encrypts the archive")
	cmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "read the archive passphrase from stdin (encrypts the archive)")
	cmd.Flags().BoolVar(&filesOnly, "files-only", false, "skip the database (PostgreSQL nodes: use pg_dump for it)")

	var verifyStdin bool
	verify := &cobra.Command{
		Use:   "verify FILE",
		Short: "Check a backup end to end without changing anything",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pass, err := optionalPassphrase(cmd, verifyStdin)
			if err != nil {
				return err
			}
			ri, err := ops.VerifyBackup(cmd.Context(), ops.RestoreOptions{Archive: args[0], Passphrase: pass})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "backup OK: version %s, created %s, database %s, %d files, %d audit entries intact\n",
				ri.Manifest.Version, ri.Manifest.CreatedAt.Format("2006-01-02 15:04:05Z"), ri.Manifest.Database, len(ri.Manifest.Files), ri.AuditEntries)
			return nil
		},
	}
	verify.Flags().BoolVar(&verifyStdin, "passphrase-stdin", false, "read the archive passphrase from stdin")

	list := &cobra.Command{
		Use:   "list",
		Short: "List the node's own backups in <data-dir>/backups",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			files, err := ops.ListBackups(app.ResolveDataDir(sf.dataDir))
			if err != nil {
				return err
			}
			for _, f := range files {
				fmt.Fprintf(cmd.OutOrStdout(), "%s\t%d\t%s\n", f.Name, f.Bytes, f.CreatedAt.Format("2006-01-02T15:04:05Z"))
			}
			return nil
		},
	}
	cmd.AddCommand(verify, list)
	return cmd
}

func optionalPassphrase(cmd *cobra.Command, fromStdin bool) (string, error) {
	if !fromStdin {
		return "", nil
	}
	return readSecret(cmd, true, "Passphrase", false)
}

func newRestoreCommand(sf *stateFlags) *cobra.Command {
	var force, passphraseStdin bool
	cmd := &cobra.Command{
		Use:   "restore FILE",
		Short: "Restore a backup into the data directory (server must be stopped)",
		Long: "Verify FILE completely (checksums, database integrity, audit chain) in a staging area, then install it.\n" +
			"An existing database is never overwritten unless --force is given, and then it is moved to\n" +
			"<data-dir>/pre-restore-<time>/. Run it as the service user so restored files keep the right owner.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pass, err := optionalPassphrase(cmd, passphraseStdin)
			if err != nil {
				return err
			}
			dataDir := app.ResolveDataDir(sf.dataDir)
			release, err := sf.lockOffline()
			if err != nil {
				return err
			}
			defer release()
			dsn := ops.DatabaseURL(dataDir, sf.databaseURL)
			ri, err := ops.Restore(cmd.Context(), ops.RestoreOptions{
				DataDir: dataDir, Archive: args[0], Passphrase: pass, Force: force,
				Postgres: store.IsPostgresDSN(dsn),
			})
			if err != nil {
				if errors.Is(err, ops.ErrWrongPassphrase) {
					return fmt.Errorf("%w (nothing was changed)", err)
				}
				return err
			}
			if ri.MovedAside != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "previous state moved to %s\n", ri.MovedAside)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "restored backup from %s (version %s): %d files, %d audit entries verified\n",
				ri.Manifest.CreatedAt.Format("2006-01-02 15:04:05Z"), ri.Manifest.Version, len(ri.Manifest.Files), ri.AuditEntries)
			if !ri.Manifest.IncludeKey {
				fmt.Fprintln(cmd.ErrOrStderr(), "this backup has no node key: place the node key file at "+filepath.Join(dataDir, "node.key")+" before starting the server, or sealed secrets (certificate keys, TOTP) cannot be read")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing database (it is moved aside, not deleted)")
	cmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "read the archive passphrase from stdin")
	return cmd
}
