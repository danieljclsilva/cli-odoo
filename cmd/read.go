package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljclsilva/cli-odoo/internal/odoo"
	"github.com/danieljclsilva/cli-odoo/internal/output"
)

func newRpAggregateCmd() *cobra.Command {
	var domainStr, groupbyStr, sumStr, avgStr string
	var wantCount bool
	c := &cobra.Command{
		Use:   "aggregate <model>",
		Short: "Aggregate records with read_group (group, sum, avg, count)",
		Long: `Aggregate records of a model using Odoo read_group (Odoo 17-safe).

Examples:
  odoo aggregate sale.order --domain '[["state","=","sale"]]' --groupby partner_id --sum amount_total --count
  odoo aggregate sale.order --groupby date_order:month --avg amount_total`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "aggregate_records"
			model := args[0]
			if err := rpCheckModel(model); err != nil {
				output.Fail(tool, err)
			}
			domain, err := odoo.ParseDomain(domainStr)
			if err != nil {
				output.Fail(tool, err)
			}
			groupby := odoo.ParseCSV(groupbyStr)
			if len(groupby) == 0 {
				output.Fail(tool, fmt.Errorf("--groupby is required (comma-separated, e.g. 'partner_id' or 'date_order:month')"))
			}
			sums := odoo.ParseCSV(sumStr)
			avgs := odoo.ParseCSV(avgStr)
			if len(sums) == 0 && len(avgs) == 0 && !wantCount {
				output.Fail(tool, fmt.Errorf("at least one of --sum, --avg, --count is required"))
			}
			// Classic read_group field spec: plain fields plus "field:sum"/"field:avg".
			var fields []any
			for _, g := range groupby {
				fields = append(fields, g)
			}
			for _, s := range sums {
				fields = append(fields, s+":sum")
			}
			for _, a := range avgs {
				fields = append(fields, a+":avg")
			}
			gb := make([]any, len(groupby))
			for i, g := range groupby {
				gb[i] = g
			}
			kwargs := map[string]any{"lazy": false}
			cli := rpClientFor(tool)
			res, err := cli.Execute(model, "read_group", []any{domain, fields, gb}, kwargs)
			if err != nil {
				output.Fail(tool, err)
			}
			rows, ok := rpToSlice(res)
			if !ok {
				output.Fail(tool, fmt.Errorf("unexpected read_group result shape"))
			}
			if wantCount {
				for _, r := range rows {
					if m, ok := r.(map[string]any); ok {
						if _, has := m["__count"]; !has {
							m["__count"] = m[groupby[0]+"_count"]
						}
					}
				}
			}
			output.Ok(tool, rows, len(rows))
		},
	}
	c.Flags().StringVar(&domainStr, "domain", "", "search domain as JSON array string, e.g. '[[\"state\",\"=\",\"sale\"]]'")
	c.Flags().StringVar(&groupbyStr, "groupby", "", "comma-separated group-by fields (supports interval suffixes, e.g. 'date_order:month')")
	c.Flags().StringVar(&sumStr, "sum", "", "comma-separated numeric fields to sum")
	c.Flags().StringVar(&avgStr, "avg", "", "comma-separated numeric fields to average")
	c.Flags().BoolVar(&wantCount, "count", false, "include per-group record counts (__count)")
	return c
}

func init() {
	RootCmd.AddCommand(newRpAggregateCmd())
}
