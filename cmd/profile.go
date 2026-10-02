package cmd

import (
	"github.com/spf13/cobra"

	"github.com/KomoriNoKage/cli-odoo/internal/config"
	"github.com/KomoriNoKage/cli-odoo/internal/odoo"
	"github.com/KomoriNoKage/cli-odoo/internal/output"
)

func newProfileCmd() *cobra.Command {
	var noModules bool
	var moduleLimit int
	cmd := &cobra.Command{
		Use:   "profile [--no-modules] [--module-limit N]",
		Short: "Show installed models and modules (Odoo 17 compatible)",
		Run: func(cmd *cobra.Command, args []string) {
			inst, err := config.Resolve(InstanceName())
			if err != nil {
				output.Fail("profile", err)
				return
			}
			cl, err := odoo.New(inst)
			if err != nil {
				output.Fail("profile", err)
				return
			}
			modelRes, err := cl.Execute("ir.model", "search_read",
				[]any{[]any{}, []any{"model", "name"}},
				map[string]any{"limit": 100000, "order": "model asc"})
			if err != nil {
				output.Fail("profile", err)
				return
			}
			result := map[string]any{"models": modelRes}
			if !noModules {
				limit := moduleLimit
				if limit <= 0 {
					limit = 1000
				}
				modRes, err := cl.Execute("ir.module.module", "search_read",
					[]any{[]any{[]any{"state", "=", "installed"}}, []any{"name", "shortdesc", "installed_version"}},
					map[string]any{"limit": limit, "order": "name asc"})
				if err != nil {
					output.Fail("profile", err)
					return
				}
				result["modules"] = modRes
				result["module_limit"] = limit
			}
			output.Ok("profile", result, 0)
		},
	}
	cmd.Flags().BoolVar(&noModules, "no-modules", false, "skip the installed-modules listing")
	cmd.Flags().IntVar(&moduleLimit, "module-limit", 1000, "cap on installed modules returned")
	return cmd
}

func newHealthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Check server version, transport, and user (no secrets)",
		Run: func(cmd *cobra.Command, args []string) {
			inst, err := config.Resolve(InstanceName())
			if err != nil {
				output.Fail("health", err)
				return
			}
			cl, err := odoo.New(inst)
			if err != nil {
				output.Fail("health", err)
				return
			}
			ver, err := cl.ServerVersion()
			if err != nil {
				output.Fail("health", err)
				return
			}
			ctx, err := cl.UserContext()
			if err != nil {
				output.Fail("health", err)
				return
			}
			// Redacted by construction: URL (no credentials), DB, transport, uid.
			output.Ok("health", map[string]any{
				"url":       inst.URL,
				"db":        inst.DB,
				"transport": cl.Transport,
				"uid":       cl.UID(),
				"username":  inst.Username,
				"version":   ver,
				"context":   ctx,
			}, 0)
		},
	}
}

func init() {
	RootCmd.AddCommand(newProfileCmd())
	RootCmd.AddCommand(newHealthCmd())
}
