package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newUserCommand(sf *stateFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "user", Short: "Manage local accounts"}

	var (
		role        string
		admin       bool
		pwFromStdin bool
	)
	create := &cobra.Command{
		Use:   "create <username>",
		Short: "Create an account (there is no default one)",
		Long: "Create a local account. The user enrols an authenticator app at first sign-in.\n" +
			"The password is read from a prompt, or from stdin with --password-stdin.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if admin {
				role = "admin"
			}
			pw, err := readPassword(cmd, pwFromStdin)
			if err != nil {
				return err
			}
			env, closeEnv, err := sf.open(cmd.Context())
			if err != nil {
				return err
			}
			defer closeEnv()
			u, err := env.CreateUser(cmd.Context(), args[0], pw, role)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "created %s %q (id %s)\n", u.Role, u.Username, u.ID)
			return nil
		},
	}
	create.Flags().StringVar(&role, "role", "viewer", "role: admin or viewer")
	create.Flags().BoolVar(&admin, "admin", false, "shorthand for --role admin")
	create.Flags().BoolVar(&pwFromStdin, "password-stdin", false, "read the password from stdin")

	var resetStdin bool
	resetPW := &cobra.Command{
		Use:   "reset-password <username>",
		Short: "Set a new password, clear any lock and end the user's sessions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pw, err := readPassword(cmd, resetStdin)
			if err != nil {
				return err
			}
			env, closeEnv, err := sf.open(cmd.Context())
			if err != nil {
				return err
			}
			defer closeEnv()
			if err := env.ResetPassword(cmd.Context(), args[0], pw); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "password reset for %q; their sessions were ended\n", args[0])
			return nil
		},
	}
	resetPW.Flags().BoolVar(&resetStdin, "password-stdin", false, "read the password from stdin")

	resetMFA := &cobra.Command{
		Use:   "reset-mfa <username>",
		Short: "Clear the user's authenticator enrolment (they re-enrol at next sign-in)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, closeEnv, err := sf.open(cmd.Context())
			if err != nil {
				return err
			}
			defer closeEnv()
			if err := env.ResetMFA(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "MFA reset for %q; their sessions were ended\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(create, resetPW, resetMFA)
	return cmd
}
