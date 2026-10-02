package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljclsilva/cli-odoo/internal/odoo"
	"github.com/danieljclsilva/cli-odoo/internal/output"
)

func newRpModelsCmd() *cobra.Command {
	var query string
	var limit int
	c := &cobra.Command{
		Use:   "models",
		Short: "List registered Odoo models (ir.model)",
		Long: `List registered Odoo models via ir.model (Odoo 17-safe).

Example:
  odoo models --query sale --limit 20`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "list_models"
			domain := []any{}
			if query != "" {
				domain = []any{
					[]any{"model", "ilike", query},
				}
			}
			cli := rpClientFor(tool)
			res, err := cli.Execute("ir.model", "search_read", nil, map[string]any{
				"domain": domain,
				"fields": []any{"model", "name"},
				"limit":  limit,
				"order":  "model asc",
			})
			if err != nil {
				output.Fail(tool, err)
			}
			output.Ok(tool, res, rpCount(res))
		},
	}
	c.Flags().StringVar(&query, "query", "", "case-insensitive substring filter on the model technical name")
	c.Flags().IntVar(&limit, "limit", 100, "maximum models to return")
	return c
}

func newRpFieldsCmd() *cobra.Command {
	var fieldsStr string
	c := &cobra.Command{
		Use:   "fields <model>",
		Short: "Describe a model's fields (fields_get)",
		Long: `Describe the fields of a model via fields_get (Odoo 17-safe).

Example:
  odoo fields sale.order`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "get_model_fields"
			model := args[0]
			if err := rpCheckModel(model); err != nil {
				output.Fail(tool, err)
			}
			var rpcArgs []any
			if names := odoo.ParseCSV(fieldsStr); len(names) > 0 {
				rpcArgs = []any{rpCSVToAny(names)}
			}
			cli := rpClientFor(tool)
			res, err := cli.Execute(model, "fields_get", rpcArgs, map[string]any{})
			if err != nil {
				output.Fail(tool, err)
			}
			output.Ok(tool, res, rpCount(res))
		},
	}
	c.Flags().StringVar(&fieldsStr, "fields", "", "comma-separated field names to describe (default: all)")
	return c
}

func newRpSchemaCmd() *cobra.Command {
	var query, modelsStr string
	var includeFields bool
	var limit int
	c := &cobra.Command{
		Use:   "schema",
		Short: "Catalog models and optionally their fields",
		Long: `Catalog registered models (ir.model + fields_get per model, capped) (Odoo 17-safe).

Example:
  odoo schema --query sale --include-fields --limit 10
  odoo schema --models sale.order,res.partner`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "schema_catalog"
			var targets []string
			if modelsStr != "" {
				for _, m := range odoo.ParseCSV(modelsStr) {
					if err := rpCheckModel(m); err != nil {
						output.Fail(tool, err)
					}
					targets = append(targets, m)
				}
			} else {
				domain := []any{}
				if query != "" {
					domain = []any{[]any{"model", "ilike", query}}
				}
				cli := rpClientFor(tool)
				res, err := cli.Execute("ir.model", "search_read", nil, map[string]any{
					"domain": domain,
					"fields": []any{"model", "name"},
					"limit":  limit,
					"order":  "model asc",
				})
				if err != nil {
					output.Fail(tool, err)
				}
				rows, ok := rpToSlice(res)
				if !ok {
					output.Fail(tool, fmt.Errorf("unexpected ir.model result shape"))
				}
				for _, r := range rows {
					m, ok := r.(map[string]any)
					if !ok {
						continue
					}
					name, _ := m["model"].(string)
					if name == "" {
						continue
					}
					targets = append(targets, name)
				}
			}
			if limit > 0 && len(targets) > limit {
				targets = targets[:limit]
			}
			cli := rpClientFor(tool)
			var entries []any
			for _, model := range targets {
				res, err := cli.Execute(model, "fields_get", nil, map[string]any{})
				if err != nil {
					output.Fail(tool, err)
				}
				entry := map[string]any{"model": model}
				if includeFields {
					entry["fields"] = res
					if m, ok := res.(map[string]any); ok {
						entry["field_count"] = len(m)
					}
				} else {
					if m, ok := res.(map[string]any); ok {
						names := make([]any, 0, len(m))
						for k := range m {
							names = append(names, k)
						}
						entry["fields"] = names
						entry["field_count"] = len(m)
					} else {
						entry["fields"] = res
					}
				}
				entries = append(entries, entry)
			}
			if entries == nil {
				entries = []any{}
			}
			output.Ok(tool, entries, len(entries))
		},
	}
	c.Flags().StringVar(&query, "query", "", "case-insensitive substring filter on the model technical name")
	c.Flags().StringVar(&modelsStr, "models", "", "comma-separated explicit models to catalog (skips ir.model lookup)")
	c.Flags().BoolVar(&includeFields, "include-fields", false, "include full fields_get descriptors instead of field-name lists")
	c.Flags().IntVar(&limit, "limit", 50, "maximum models to catalog")
	return c
}

func init() {
	RootCmd.AddCommand(newRpModelsCmd())
	RootCmd.AddCommand(newRpFieldsCmd())
	RootCmd.AddCommand(newRpSchemaCmd())
}
