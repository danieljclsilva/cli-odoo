package cmd

import (
	"encoding/json"
	"strings"

	"github.com/spf13/cobra"

	"github.com/KomoriNoKage/cli-odoo/internal/config"
	"github.com/KomoriNoKage/cli-odoo/internal/odoo"
	"github.com/KomoriNoKage/cli-odoo/internal/output"
	"github.com/KomoriNoKage/cli-odoo/internal/safety"
)

func newCallCmd() *cobra.Command {
	var argsJSON, kwargsJSON string
	var dryRun, yes bool
	cmd := &cobra.Command{
		Use:   "call <model> <method> --args-json '[...]' --kwargs-json '{...}' [--dry-run] [--yes]",
		Short: "Call any Odoo model method (Odoo 17-safe ORM methods)",
		Long: `Call an arbitrary Odoo model method via execute_kw.

Destructive methods (create, write, unlink, *destructive*) require --yes
plus ODOO_WRITES_ENABLED=1; preview the payload first with --dry-run.`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			model, method := args[0], args[1]
			var posArgs []any
			if strings.TrimSpace(argsJSON) == "" {
				posArgs = []any{}
			} else if err := json.Unmarshal([]byte(argsJSON), &posArgs); err != nil {
				output.Fail("call", err)
				return
			}
			kwargs, err := odoo.ParseJSONObj(kwargsJSON)
			if err != nil {
				output.Fail("call", err)
				return
			}
			if dryRun {
				output.Ok("call", map[string]any{
					"model":   model,
					"method":  method,
					"args":    posArgs,
					"kwargs":  kwargs,
					"dry_run": true,
				}, 0)
				return
			}
			if callIsDestructive(method) {
				if err := safety.RequireConfirm(yes, dryRun); err != nil {
					output.Fail("call", err)
					return
				}
			}
			inst, err := config.Resolve(InstanceName())
			if err != nil {
				output.Fail("call", err)
				return
			}
			cl, err := odoo.New(inst)
			if err != nil {
				output.Fail("call", err)
				return
			}
			result, err := cl.Execute(model, method, posArgs, kwargs)
			if err != nil {
				output.Fail("call", err)
				return
			}
			output.Ok("call", result, 0)
		},
	}
	cmd.Flags().StringVar(&argsJSON, "args-json", "", "positional args as JSON array (default [])")
	cmd.Flags().StringVar(&kwargsJSON, "kwargs-json", "", "keyword args as JSON object (default {})")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the payload without calling Odoo")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm a destructive call (also needs ODOO_WRITES_ENABLED=1)")
	return cmd
}

// callIsDestructive reports whether method mutates data and therefore
// needs explicit confirmation.
func callIsDestructive(method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "create", "write", "unlink":
		return true
	}
	return strings.Contains(strings.ToLower(method), "destruct")
}

func init() {
	RootCmd.AddCommand(newCallCmd())
}
