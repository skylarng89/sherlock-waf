package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func newTokenCommand(sf *stateFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage API tokens"}

	var (
		user, name string
		scopes     []string
		cidrs      []string
		expiresIn  time.Duration
	)
	create := &cobra.Command{
		Use:   "create",
		Short: "Create an API token for a user (the secret is printed once)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var exp time.Time
			if expiresIn > 0 {
				exp = time.Now().Add(expiresIn)
			}
			env, closeEnv, err := sf.open(cmd.Context())
			if err != nil {
				return err
			}
			defer closeEnv()
			ct, err := env.CreateToken(cmd.Context(), user, name, scopes, cidrs, exp)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "token %s created for %q; it is shown once, store it now\n", ct.Record.ID, user)
			fmt.Fprintln(cmd.OutOrStdout(), ct.Secret)
			return nil
		},
	}
	create.Flags().StringVar(&user, "user", "", "owner username (required)")
	create.Flags().StringVar(&name, "name", "", "token name (required)")
	create.Flags().StringSliceVar(&scopes, "scope", nil, "scope: read, write, events:read or admin (repeatable)")
	create.Flags().StringSliceVar(&cidrs, "cidr", nil, "only accept the token from these CIDRs (repeatable)")
	create.Flags().DurationVar(&expiresIn, "expires-in", 0, "token lifetime, for example 720h (default: no expiry)")
	_ = create.MarkFlagRequired("user")
	_ = create.MarkFlagRequired("name")
	_ = create.MarkFlagRequired("scope")

	cmd.AddCommand(create)
	return cmd
}
