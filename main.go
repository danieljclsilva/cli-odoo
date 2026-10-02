// Command odoo is a self-contained CLI for Odoo ERP, designed for AI agents.
package main

import (
	"os"

	"github.com/KomoriNoKage/cli-odoo/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
