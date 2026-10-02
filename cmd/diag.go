package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljclsilva/cli-odoo/internal/odoo"
	"github.com/danieljclsilva/cli-odoo/internal/output"
)

func init() {
	RootCmd.AddCommand(newDiagnoseAccessCmd())
	RootCmd.AddCommand(newRelationsCmd())
}

// opsPackCheckAccess calls check_access_rights (Odoo 17 safe) for one operation.
func opsPackCheckAccess(client *odoo.Client, model, operation string) (bool, error) {
	res, err := client.Execute(model, "check_access_rights", []any{operation}, map[string]any{"raise_exception": false})
	if err != nil {
		return false, err
	}
	b, ok := res.(bool)
	if !ok {
		return false, fmt.Errorf("unexpected check_access_rights response: %v", res)
	}
	return b, nil
}

func newDiagnoseAccessCmd() *cobra.Command {
	var operation string
	c := &cobra.Command{
		Use:   "diagnose-access <model>",
		Short: "Probe access rights for a model (check_access_rights + read probe)",
		Long: `Probe access rights for a model using only Odoo 17-safe methods.

Runs check_access_rights for read/write/create/unlink, then probes actual
read access via fields_get and search_count.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "diagnose_access"
			model := args[0]
			op := strings.ToLower(strings.TrimSpace(operation))
			switch op {
			case "read", "write", "create", "unlink":
			default:
				output.Fail(tool, fmt.Errorf("invalid --operation %q (want read|write|create|unlink)", operation))
				return
			}
			client, _, err := opsPackClient()
			if err != nil {
				output.Fail(tool, err)
				return
			}
			rights := map[string]any{}
			for _, o := range []string{"read", "write", "create", "unlink"} {
				allowed, err := opsPackCheckAccess(client, model, o)
				if err != nil {
					rights[o] = map[string]any{"allowed": false, "error": err.Error()}
					continue
				}
				rights[o] = map[string]any{"allowed": allowed}
			}
			probe := map[string]any{}
			if fg, err := client.Execute(model, "fields_get", []any{[]any{}}, map[string]any{"attributes": []any{"string", "type"}}); err != nil {
				probe["fields_get"] = map[string]any{"ok": false, "error": err.Error()}
			} else if m, ok := fg.(map[string]any); ok {
				probe["fields_get"] = map[string]any{"ok": true, "field_count": len(m)}
			} else {
				probe["fields_get"] = map[string]any{"ok": false, "error": "unexpected fields_get response"}
			}
			if sc, err := client.Execute(model, "search_count", []any{[]any{}}, nil); err != nil {
				probe["search_count"] = map[string]any{"ok": false, "error": err.Error()}
			} else if n, ok := opsPackInt(sc); ok {
				probe["search_count"] = map[string]any{"ok": true, "count": n}
			} else {
				probe["search_count"] = map[string]any{"ok": false, "error": fmt.Sprintf("unexpected search_count response: %v", sc)}
			}
			allowed := false
			if r, ok := rights[op].(map[string]any); ok {
				allowed, _ = r["allowed"].(bool)
			}
			output.Ok(tool, map[string]any{
				"model":     model,
				"operation": op,
				"allowed":   allowed,
				"rights":    rights,
				"probe":     probe,
			}, 1)
		},
	}
	c.Flags().StringVar(&operation, "operation", "read", "operation to check: read|write|create|unlink")
	return c
}

func newRelationsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "relations <model>",
		Short: "Show many2one/one2many/many2many fields of a model",
		Long: `Inspect relational fields of a model via fields_get (Odoo 17 safe).

Returns a map of field name to type, target model, label, and flags.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "inspect_model_relationships"
			model := args[0]
			client, _, err := opsPackClient()
			if err != nil {
				output.Fail(tool, err)
				return
			}
			fg, err := client.Execute(model, "fields_get", []any{[]any{}}, map[string]any{
				"attributes": []any{"string", "type", "relation", "required", "readonly"},
			})
			if err != nil {
				output.Fail(tool, err)
				return
			}
			fields, ok := fg.(map[string]any)
			if !ok {
				output.Fail(tool, fmt.Errorf("unexpected fields_get response"))
				return
			}
			names := make([]string, 0, len(fields))
			for name := range fields {
				names = append(names, name)
			}
			sort.Strings(names)
			rels := map[string]any{}
			for _, fname := range names {
				meta, _ := fields[fname].(map[string]any)
				if meta == nil {
					continue
				}
				t := opsPackStr(meta["type"])
				switch t {
				case "many2one", "one2many", "many2many":
				default:
					continue
				}
				rels[fname] = map[string]any{
					"type":     t,
					"relation": opsPackStr(meta["relation"]),
					"label":    opsPackStr(meta["string"]),
					"required": opsPackBool(meta["required"]),
					"readonly": opsPackBool(meta["readonly"]),
				}
			}
			counts := map[string]int{"many2one": 0, "one2many": 0, "many2many": 0}
			for _, v := range rels {
				if m, ok := v.(map[string]any); ok {
					counts[opsPackStr(m["type"])]++
				}
			}
			output.Ok(tool, map[string]any{"model": model, "relations": rels, "counts": counts}, len(rels))
		},
	}
}
