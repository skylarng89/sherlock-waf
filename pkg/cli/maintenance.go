package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newAuditCommand(sf *stateFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Inspect the audit log"}
	cmd.AddCommand(&cobra.Command{
		Use:   "verify",
		Short: "Verify the audit log's hash chain; exits non-zero if it was altered",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			env, closeEnv, err := sf.open(cmd.Context())
			if err != nil {
				return err
			}
			defer closeEnv()
			rep, err := env.VerifyAudit(cmd.Context())
			if err != nil {
				return err
			}
			if rep.Problem != nil {
				return fmt.Errorf("%w (checked %d entries)", *rep.Problem, rep.Entries)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "audit chain intact: %d entries, head seq %d hash %s\n", rep.Entries, rep.Head.Seq, rep.Head.Hash)
			return nil
		},
	})
	return cmd
}

func newSecretsCommand(sf *stateFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "secrets", Short: "Manage the node's secret store"}
	cmd.AddCommand(&cobra.Command{
		Use:   "rotate-key",
		Short: "Re-encrypt every stored secret under a new node key (server must be stopped)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			release, err := sf.lockOffline()
			if err != nil {
				return err
			}
			defer release()
			env, closeEnv, err := sf.open(cmd.Context())
			if err != nil {
				return err
			}
			defer closeEnv()
			if err := env.RotateKey(cmd.Context()); err != nil {
				return fmt.Errorf("rotating node key: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "node key rotated; back up the new key file")
			return nil
		},
	})
	return cmd
}
