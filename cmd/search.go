package cmd

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljclsilva/cli-odoo/internal/config"
	"github.com/danieljclsilva/cli-odoo/internal/odoo"
	"github.com/danieljclsilva/cli-odoo/internal/output"
)

// rpModelRe validates Odoo model technical names.
var rpModelRe = regexp.MustCompile(`^[A-Za-z0-9._]+$`)

// rpCheckModel rejects empty or malformed model names.
func rpCheckModel(model string) error {
	if !rpModelRe.MatchString(model) {
		return fmt.Errorf("invalid model name %q: must match [A-Za-z0-9._]+", model)
	}
	return nil
}

// rpClientFor resolves the active instance and connects. Failures emit the
// stable error envelope and exit non-zero.
func rpClientFor(tool string) *odoo.Client {
	inst, err := config.Resolve(InstanceName())
	if err != nil {
		output.Fail(tool, err)
		return nil
	}
	cli, err := odoo.New(inst)
	if err != nil {
		output.Fail(tool, err)
		return nil
	}
	return cli
}

// rpCount returns a display count for an Execute result.
func rpCount(v any) int {
	if v == nil {
		return 0
	}
	if s, ok := v.([]any); ok {
		return len(s)
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map:
		return rv.Len()
	default:
		return 1
	}
}

// rpToSlice coerces an Execute list result to []any.
func rpToSlice(v any) ([]any, bool) {
	if v == nil {
		return nil, true
	}
	if s, ok := v.([]any); ok {
		return s, true
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = rv.Index(i).Interface()
		}
		return out, true
	}
	return nil, false
}

// rpCSVToAny converts parsed CSV fields to []any for RPC kwargs.
func rpCSVToAny(fields []string) []any {
	out := make([]any, len(fields))
	for i, f := range fields {
		out[i] = f
	}
	return out
}

func newRpSearchCmd() *cobra.Command {
	var domainStr, fieldsStr, order string
	var limit, offset int
	c := &cobra.Command{
		Use:   "search <model>",
		Short: "Search records with a domain (search_read)",
		Long: `Search records of a model using Odoo search_read (Odoo 17-safe).

Example:
  odoo search res.partner --domain '[["customer_rank",">",0]]' --fields name,email --limit 10`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "search_records"
			model := args[0]
			if err := rpCheckModel(model); err != nil {
				output.Fail(tool, err)
			}
			domain, err := odoo.ParseDomain(domainStr)
			if err != nil {
				output.Fail(tool, err)
			}
			kwargs := map[string]any{
				"domain": domain,
				"limit":  limit,
				"offset": offset,
			}
			if fs := odoo.ParseCSV(fieldsStr); len(fs) > 0 {
				kwargs["fields"] = rpCSVToAny(fs)
			}
			if order != "" {
				kwargs["order"] = order
			}
			cli := rpClientFor(tool)
			res, err := cli.Execute(model, "search_read", nil, kwargs)
			if err != nil {
				output.Fail(tool, err)
			}
			output.Ok(tool, res, rpCount(res))
		},
	}
	c.Flags().StringVar(&domainStr, "domain", "", "search domain as JSON array string, e.g. '[[\"name\",\"ilike\",\"acme\"]]'")
	c.Flags().StringVar(&fieldsStr, "fields", "", "comma-separated fields to return (default: all)")
	c.Flags().IntVar(&limit, "limit", 50, "maximum records to return")
	c.Flags().IntVar(&offset, "offset", 0, "records to skip")
	c.Flags().StringVar(&order, "order", "", "sort order, e.g. 'name asc'")
	return c
}

func newRpReadRecordCmd() *cobra.Command {
	var fieldsStr string
	c := &cobra.Command{
		Use:   "read <model> <id...>",
		Short: "Read records by ID",
		Long: `Read one or more records of a model by database ID (Odoo 17-safe).

Example:
  odoo read res.partner 7 8 --fields name,email`,
		Args: cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "read_record"
			model := args[0]
			if err := rpCheckModel(model); err != nil {
				output.Fail(tool, err)
			}
			var ids []any
			for _, a := range args[1:] {
				for _, part := range strings.Split(a, ",") {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					n, err := strconv.Atoi(part)
					if err != nil {
						output.Fail(tool, fmt.Errorf("invalid id %q: must be an integer", part))
					}
					ids = append(ids, n)
				}
			}
			if len(ids) == 0 {
				output.Fail(tool, fmt.Errorf("at least one record id is required"))
			}
			kwargs := map[string]any{}
			if fs := odoo.ParseCSV(fieldsStr); len(fs) > 0 {
				kwargs["fields"] = rpCSVToAny(fs)
			}
			cli := rpClientFor(tool)
			res, err := cli.Execute(model, "read", []any{ids}, kwargs)
			if err != nil {
				output.Fail(tool, err)
			}
			output.Ok(tool, res, rpCount(res))
		},
	}
	c.Flags().StringVar(&fieldsStr, "fields", "", "comma-separated fields to return (default: all)")
	return c
}

func init() {
	RootCmd.AddCommand(newRpSearchCmd())
	RootCmd.AddCommand(newRpReadRecordCmd())
}
