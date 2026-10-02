package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/KomoriNoKage/cli-odoo/internal/config"
	"github.com/KomoriNoKage/cli-odoo/internal/output"
)

var (
	cfgFile   string
	outFormat string
	instance  string
)

// RootCmd is the base command for odoo CLI.
var RootCmd = &cobra.Command{
	Use:   "odoo",
	Short: "Self-contained CLI for Odoo ERP, designed for AI agents",
	Long: `odoo talks to any Odoo 16+ instance over XML-RPC (default) or JSON-2 (Odoo 19+).

Every command emits stable JSON with --format json (default), or human tables
with --format table. Writes are gated: preview first, then confirm explicitly.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := config.Load(cfgFile); err != nil {
			return err
		}
		f, err := output.ParseFormat(outFormat)
		if err != nil {
			return err
		}
		output.SetDefault(f)
		return nil
	},
}

func init() {
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default ~/.config/odoo-cli/config.yaml)")
	RootCmd.PersistentFlags().StringVarP(&outFormat, "format", "f", "json", "output format: json|table|yaml")
	RootCmd.PersistentFlags().StringVar(&instance, "instance", "", "named instance from config file (default instance if empty)")
	RootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose stderr diagnostics")
	_ = viper.BindPFlag("verbose", RootCmd.PersistentFlags().Lookup("verbose"))

	RootCmd.AddCommand(newVersionCmd())
}

// InstanceName resolves the effective instance: flag > env > default.
func InstanceName() string {
	if instance != "" {
		return instance
	}
	if v := os.Getenv("ODOO_INSTANCE"); v != "" {
		return v
	}
	return ""
}
