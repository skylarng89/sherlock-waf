package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/skylarng89/sherlock-waf/internal/config"
	"github.com/skylarng89/sherlock-waf/internal/configsvc"
)

type remoteFlags struct {
	server, token, pin string
}

func (f *remoteFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.server, "server", os.Getenv("SHERLOCK_API_URL"), "change a running node through its API, e.g. https://127.0.0.1:9443 (env SHERLOCK_API_URL)")
	cmd.Flags().StringVar(&f.token, "token", os.Getenv("SHERLOCK_TOKEN"), "API token (env SHERLOCK_TOKEN)")
	cmd.Flags().StringVar(&f.pin, "tls-pin", os.Getenv("SHERLOCK_TLS_PIN"), "SHA-256 of the server's public key (from its start-up log) to trust a self-signed certificate")
}

func (f *remoteFlags) enabled() bool { return f.server != "" }

func newConfigCommand(sf *stateFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Validate, export, import and apply configuration"}

	cmd.AddCommand(&cobra.Command{
		Use:   "validate <file>",
		Short: "Check a YAML configuration file without touching any node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := config.Load(args[0])
			if err != nil {
				return err
			}
			if errs := configsvc.Validate(root); len(errs) > 0 {
				return errs
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is valid: %d site(s)\n", args[0], len(root.Sites))
			return nil
		},
	})

	var (
		out, format string
		exportRem   remoteFlags
	)
	export := &cobra.Command{
		Use:   "export",
		Short: "Print the node's live configuration as YAML (or JSON)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var root *config.Root
			if exportRem.enabled() {
				r, err := newRemote(exportRem.server, exportRem.token, exportRem.pin)
				if err != nil {
					return err
				}
				root, _, err = r.exportConfig(cmd.Context())
				if err != nil {
					return err
				}
				if root == nil {
					return errors.New("the node has no configuration yet")
				}
			} else {
				env, closeEnv, err := sf.open(cmd.Context())
				if err != nil {
					return err
				}
				defer closeEnv()
				if root, _, err = env.ExportConfig(cmd.Context()); err != nil {
					return err
				}
			}
			var b []byte
			var err error
			switch format {
			case "yaml":
				b, err = config.MarshalYAML(root)
			case "json":
				b, err = json.MarshalIndent(root, "", "  ")
				b = append(b, '\n')
			default:
				return fmt.Errorf("--format must be yaml or json, got %q", format)
			}
			if err != nil {
				return err
			}
			if out == "" || out == "-" {
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			return os.WriteFile(out, b, 0o600)
		},
	}
	export.Flags().StringVarP(&out, "output", "o", "", "write to a file instead of stdout")
	export.Flags().StringVar(&format, "format", "yaml", "yaml or json")
	exportRem.bind(export)

	var impRem remoteFlags
	importCmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Load a YAML configuration into a node that has none",
		Long: "Load a YAML configuration into a fresh node. It refuses to replace an existing configuration;\n" +
			"use `config apply` for that. Without --server it writes the database directly and needs the server stopped.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return applyFile(cmd, sf, &impRem, args[0], true, "")
		},
	}
	impRem.bind(importCmd)

	var (
		applyRem remoteFlags
		expect   string
	)
	apply := &cobra.Command{
		Use:   "apply <file>",
		Short: "Make a YAML file the node's configuration (no-op when identical)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return applyFile(cmd, sf, &applyRem, args[0], false, expect)
		},
	}
	apply.Flags().StringVar(&expect, "expect-version", "", "fail unless the node is still at this version id (optimistic concurrency)")
	applyRem.bind(apply)

	cmd.AddCommand(export, importCmd, apply)
	return cmd
}

func applyFile(cmd *cobra.Command, sf *stateFlags, rf *remoteFlags, path string, requireEmpty bool, expect string) error {
	root, err := config.Load(path)
	if err != nil {
		return err
	}
	if errs := configsvc.Validate(root); len(errs) > 0 {
		return errs
	}
	out := cmd.OutOrStdout()

	if rf.enabled() {
		r, err := newRemote(rf.server, rf.token, rf.pin)
		if err != nil {
			return err
		}
		live, etag, err := r.exportConfig(cmd.Context())
		if err != nil {
			return err
		}
		if live != nil && requireEmpty {
			return errors.New("this node already has a configuration; use `sherlock config apply` to replace it")
		}
		if expect != "" {
			etag = `"` + strings.Trim(expect, `"`) + `"`
		}
		newTag, err := r.putConfig(cmd.Context(), root, etag)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "applied; live version %s\n", strings.Trim(newTag, `"`))
		return nil
	}

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
	src := configsvc.SourceCLI
	if requireEmpty {
		src = configsvc.SourceImport
	}
	v, changed, err := env.ApplyConfig(cmd.Context(), root, opsApply(src, requireEmpty, expect))
	if err != nil {
		return err
	}
	if !changed {
		fmt.Fprintf(out, "no change; live version %s\n", v.ID)
		return nil
	}
	fmt.Fprintf(out, "stored version %s; it goes live when the server starts\n", v.ID)
	return nil
}
