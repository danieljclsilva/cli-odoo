package cmd

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/KomoriNoKage/cli-odoo/internal/config"
	"github.com/KomoriNoKage/cli-odoo/internal/odoo"
	"github.com/KomoriNoKage/cli-odoo/internal/output"
	"github.com/KomoriNoKage/cli-odoo/internal/safety"
)

// callMethodRe validates Odoo method names: non-empty [A-Za-z0-9_]+.
var callMethodRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func newCallCmd() *cobra.Command {
	var argsJSON, kwargsJSON string
	var dryRun, yes bool
	cmd := &cobra.Command{
		Use:   "call <model> <method> --args-json '[...]' --kwargs-json '{...}' [--dry-run] [--yes]",
		Short: "Call any Odoo model method (Odoo 17-safe ORM methods)",
		Long: `Call an arbitrary Odoo model method via execute_kw.

Default-deny: every method requires --yes plus ODOO_WRITES_ENABLED=1,
except the read-only allowlist (search_read, read, search_count,
read_group, fields_get, name_search, check_access_rights, version,
context_get). Preview the payload first with --dry-run.`,
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
			if err := rpCheckModel(model); err != nil {
				output.Fail("call", err)
				return
			}
			if !callMethodRe.MatchString(strings.TrimSpace(method)) {
				output.Fail("call", fmt.Errorf("invalid method name %q: must match [A-Za-z0-9_]+", method))
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
			if !callIsReadOnly(method) {
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
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm a gated (non-read-only) call (also needs ODOO_WRITES_ENABLED=1)")
	return cmd
}

// callIsReadOnly reports whether method is on the read-only allowlist and
// therefore exempt from the confirmation gate. Comparison is
// case-insensitive on the trimmed method name; everything else is gated.
func callIsReadOnly(method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "search_read", "read", "search_count", "read_group", "fields_get",
		"name_search", "check_access_rights", "version", "context_get":
		return true
	}
	return false
}

func init() {
	RootCmd.AddCommand(newCallCmd())
}
