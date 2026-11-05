package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/skylarng89/sherlock-waf/internal/controlplane/auth"
)

func newHashPasswordCommand() *cobra.Command {
	var fromStdin bool
	cmd := &cobra.Command{
		Use:   "hash-password",
		Short: "Print an argon2id hash for a site password gate (acl.password_gate.password_hash)",
		Long: "Hash a password for the site password gate. The clear password is never stored in the\n" +
			"configuration: paste the printed hash into `acl.password_gate.password_hash`. The password is read from\n" +
			"a prompt, or from stdin with --password-stdin.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pw, err := readPassword(cmd, fromStdin)
			if err != nil {
				return err
			}
			if err := auth.ValidatePassword(pw); err != nil {
				return err
			}
			hash, err := auth.NewHasher(1).Hash(cmd.Context(), pw)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), hash)
			return nil
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "password-stdin", false, "read the password from stdin")
	return cmd
}
