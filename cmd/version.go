package cmd

import (
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/KomoriNoKage/cli-odoo/internal/output"
)

// Version is set at build time via -ldflags "-X main.version=...".
var Version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			v := Version
			if v == "dev" {
				if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
					v = info.Main.Version
				}
			}
			output.Print(map[string]string{"version": v})
		},
	}
}
