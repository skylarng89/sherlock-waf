package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/skylarng89/sherlock-waf/internal/app"
	"github.com/skylarng89/sherlock-waf/internal/ops"
	"github.com/skylarng89/sherlock-waf/internal/store"
	"github.com/skylarng89/sherlock-waf/internal/updater"
)

type updateFlags struct {
	check, noRestart, noBackup, rollback, applyStaged bool
	bundle, manifest, signature, source, binary       string
}

func newUpdateCommand(o options, sf *stateFlags, info BuildInfo) *cobra.Command {
	var f updateFlags
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check for, verify and install a signed release",
		Long: "Update the sherlock binary from a signed release.\n\n" +
			"Every release carries a manifest signed with the release key built into this binary; the archive is\n" +
			"installed only if the signature and the SHA-256 checksum verify and the release is newer than the\n" +
			"running version. Downgrades are refused. The data is backed up first, the binary is swapped atomically\n" +
			"(the old one is kept as <binary>.bak), and the systemd unit is restarted; --rollback undoes the swap.\n\n" +
			"  sherlock update --check\n" +
			"  sudo sherlock update\n" +
			"  sudo sherlock update --bundle sherlock_X.Y.Z_linux_amd64.tar.gz   (release-manifest.json and .sig beside it)\n\n" +
			"In a container, update by pulling the new image instead; this command only checks.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUpdate(cmd, o, sf, info, f)
		},
	}
	fl := cmd.Flags()
	fl.BoolVar(&f.check, "check", false, "only report whether a newer release is available")
	fl.StringVar(&f.bundle, "bundle", "", "install from a downloaded release archive instead of the network (offline)")
	fl.StringVar(&f.manifest, "manifest", "", "signed manifest for --bundle (default: release-manifest.json beside the archive)")
	fl.StringVar(&f.signature, "signature", "", "manifest signature for --bundle (default: release-manifest.json.sig beside the archive)")
	fl.StringVar(&f.source, "source", "", "https base URL serving the release assets (default: the project's GitHub release)")
	fl.BoolVar(&f.noRestart, "no-restart", false, "swap the binary but leave the restart to you")
	fl.BoolVar(&f.noBackup, "skip-backup", false, "do not back the data up first (not recommended)")
	fl.BoolVar(&f.rollback, "rollback", false, "put the previous binary back and restart")
	fl.BoolVar(&f.applyStaged, "apply-staged", false, "install an update staged through the API (used by the systemd unit before start)")
	fl.StringVar(&f.binary, "binary", "", "path of the binary to replace (default: the running executable)")
	_ = fl.MarkHidden("apply-staged")
	_ = fl.MarkHidden("binary")
	return cmd
}

func runUpdate(cmd *cobra.Command, o options, sf *stateFlags, info BuildInfo, f updateFlags) error {
	ctx, out := cmd.Context(), cmd.OutOrStdout()
	dataDir := app.ResolveDataDir(sf.dataDir)
	u, err := updater.New(updater.Options{Key: o.releaseKey, CurrentVersion: info.Version, DataDir: dataDir, BaseURL: f.source, ExePath: f.binary})
	if err != nil {
		return err
	}

	switch {
	case f.rollback:
		if err := u.Rollback(); err != nil {
			return err
		}
		fmt.Fprintln(out, "previous binary restored")
		return restartAfter(ctx, cmd, f.noRestart, nil)

	case f.applyStaged:
		res, had, err := u.ApplyStaged(ctx)
		switch {
		case err != nil:
			return err
		case had:
			fmt.Fprintf(out, "installed staged update %s -> %s\n", res.From, res.To)
		}
		return nil

	case f.check:
		st, err := u.Check(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "running %s, latest release %s (CRS %s)\n", st.Current, st.Latest, st.CRS)
		switch {
		case st.Reason != "":
			fmt.Fprintln(out, "a newer release exists but cannot be installed directly:", st.Reason)
		case st.Available:
			fmt.Fprintln(out, "update available: run `sudo sherlock update`")
		default:
			fmt.Fprintln(out, "up to date")
		}
		return nil
	}

	if updater.InContainer() {
		return fmt.Errorf("running in a container: the binary inside an image is not replaced. Pull the new image (ghcr.io/skylarng89/sherlock-waf) and recreate the container; use `sherlock update --check` to see what is available")
	}

	var v *updater.Verified
	if f.bundle != "" {
		b, err := updater.LoadBundle(f.bundle, f.manifest, f.signature)
		if err != nil {
			return err
		}
		v, err = u.VerifyBundle(b)
		if err != nil {
			return refuse(err)
		}
	} else {
		fmt.Fprintln(out, "downloading and verifying the latest release...")
		if v, err = u.Download(ctx); err != nil {
			return refuse(err)
		}
	}
	fmt.Fprintf(out, "verified release %s (signature and checksum OK)\n", v.Manifest.Version)

	if !f.noBackup {
		if err := preUpdateBackup(cmd, sf, info); err != nil {
			return fmt.Errorf("backup before update failed, nothing was changed (use --skip-backup to override): %w", err)
		}
	}
	res, staged, err := u.InstallOrStage(ctx, v)
	if err != nil {
		return err
	}
	if staged {
		fmt.Fprintf(out, "this user cannot write the installed binary, so %s is staged in %s.\n"+
			"It is installed (after a fresh verification) when the service next starts, or run `sudo sherlock update --apply-staged`.\n",
			v.Manifest.Version, filepath.Join(dataDir, "updates", "staged"))
		return nil
	}
	fmt.Fprintf(out, "installed %s -> %s (previous binary kept as %s)\n", res.From, res.To, res.Backup)
	return restartAfter(ctx, cmd, f.noRestart, u)
}

func refuse(err error) error {
	return fmt.Errorf("refusing to install: %w", err)
}

// preUpdateBackup saves the data before a new binary can migrate the database.
func preUpdateBackup(cmd *cobra.Command, sf *stateFlags, info BuildInfo) error {
	env, closeEnv, err := sf.open(cmd.Context())
	if err != nil {
		return err
	}
	defer closeEnv()
	filesOnly := false
	if env.Store.Dialect() != store.SQLite {
		fmt.Fprintln(cmd.ErrOrStderr(), "PostgreSQL: dump the database with pg_dump before updating; backing up data files only")
		filesOnly = true
	}
	bi, err := env.Backup(cmd.Context(), ops.BackupOptions{Version: info.Version, FilesOnly: filesOnly})
	if err != nil {
		return err
	}
	matchOwner(env.DataDir, filepath.Dir(bi.Path), bi.Path, filepath.Join(env.DataDir, "sherlock.db"), filepath.Join(env.DataDir, "sherlock.db-wal"), filepath.Join(env.DataDir, "sherlock.db-shm"))
	fmt.Fprintf(cmd.OutOrStdout(), "backup written: %s\n", bi.Path)
	return nil
}

// restartAfter restarts the systemd unit and, when a freshly installed binary
// does not stay up, restores the previous one. u is nil for an explicit rollback.
func restartAfter(ctx context.Context, cmd *cobra.Command, noRestart bool, u *updater.Updater) error {
	out := cmd.OutOrStdout()
	if noRestart || !updater.UnderSystemd(ctx) {
		printRestartHelp(out, noRestart)
		return nil
	}
	fmt.Fprintln(out, "restarting sherlock.service...")
	if err := updater.RestartSystemd(ctx, 60*time.Second); err != nil {
		if u == nil {
			return fmt.Errorf("the service did not come back after restart: %w", err)
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "the service did not stay up with the new binary; rolling back")
		if rerr := u.Rollback(); rerr != nil {
			return fmt.Errorf("restart failed (%w) and rollback failed: %w", err, rerr)
		}
		if rerr := updater.RestartSystemd(ctx, 60*time.Second); rerr != nil {
			return fmt.Errorf("restart failed (%w); rolled back the binary but the service is still not up: %w", err, rerr)
		}
		return fmt.Errorf("the new version did not start and was rolled back: %w. The data backup from before the update is in the data directory's backups folder", err)
	}
	fmt.Fprintln(out, "sherlock.service is running the new version")
	return nil
}

func printRestartHelp(w io.Writer, requested bool) {
	switch {
	case requested:
		fmt.Fprintln(w, "restart skipped: restart sherlock to run the new version (systemd: `sudo systemctl restart sherlock`)")
	default:
		fmt.Fprintln(w, "the sherlock systemd unit is not active here: restart the process yourself to run the new version")
	}
}
