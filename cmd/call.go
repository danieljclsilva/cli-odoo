package cmd

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljclsilva/cli-odoo/internal/config"
	"github.com/danieljclsilva/cli-odoo/internal/odoo"
	"github.com/danieljclsilva/cli-odoo/internal/output"
	"github.com/danieljclsilva/cli-odoo/internal/safety"
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
	
	Default-deny: instances are read-only unless readonly:false is set in the
	config file, and every non-read-only method additionally requires --yes
	plus ODOO_WRITES_ENABLED=1 plus a human-at-TTY confirmation (type YES at
	/dev/tty; ODOO_ALLOW_NON_TTY=1 skips it for human-owned CI only).
	Read-only methods (search_read, read, search_count, read_group,
	fields_get, name_search, check_access_rights, version, context_get)
	run without confirmation. Preview the payload first with --dry-run.`,
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
			inst, err := config.Resolve(InstanceName())
			if err != nil {
				output.Fail("call", err)
				return
			}
			if !odoo.IsReadOnlyMethod(method) {
				if err := safety.RequireWrite(inst, yes, false, "call:"+model+"."+method); err != nil {
					output.Fail("call", err)
					return
				}
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
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview payload without calling the server (never mutates, bypasses all gates)")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm a gated write (also needs ODOO_WRITES_ENABLED=1, a writable instance, and human-at-TTY confirmation)")
	return cmd
}

func init() {
	RootCmd.AddCommand(newCallCmd())
}
