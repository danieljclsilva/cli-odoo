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
)

// callMethodRe validates Odoo method names: non-empty [A-Za-z0-9_]+.
var callMethodRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func newCallCmd() *cobra.Command {
	var argsJSON, kwargsJSON string
	cmd := &cobra.Command{
		Use:   "call <model> <method> --args-json '[...]' --kwargs-json '{...}'",
		Short: "Call a read-only Odoo model method (escape hatch for allowlisted reads)",
		Long: `Call an arbitrary read-only Odoo model method via execute_kw.

The CLI is read-only: only search_read, read, search_count, read_group,
fields_get, name_search, check_access_rights, version, and context_get run.
Any other method is refused before any RPC is sent; there is no write path.`,
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
			if !odoo.IsReadOnlyMethod(method) {
				output.Fail("call", fmt.Errorf("refusing %s.%s: CLI is read-only (no write request is ever sent)", model, method))
				return
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
	return cmd
}

func init() {
	RootCmd.AddCommand(newCallCmd())
}
