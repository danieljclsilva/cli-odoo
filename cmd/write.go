package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/KomoriNoKage/cli-odoo/internal/config"
	"github.com/KomoriNoKage/cli-odoo/internal/odoo"
	"github.com/KomoriNoKage/cli-odoo/internal/output"
	"github.com/KomoriNoKage/cli-odoo/internal/safety"
)

func init() {
	RootCmd.AddCommand(newCreateCmd(), newWriteCmd(), newUnlinkCmd())
}

// parseRecordIDs converts trailing <ids...> args to Odoo record IDs.
func parseRecordIDs(args []string) ([]any, error) {
	ids := make([]any, 0, len(args))
	for _, a := range args {
		n, err := strconv.Atoi(a)
		if err != nil {
			return nil, fmt.Errorf("invalid record id %q: must be an integer", a)
		}
		ids = append(ids, n)
	}
	return ids, nil
}

func newCreateCmd() *cobra.Command {
	var valuesJSON string
	var dryRun, confirmed bool
	c := &cobra.Command{
		Use:   "create <model>",
		Short: "Create a record (gated write)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			model := args[0]
			if err := rpCheckModel(model); err != nil {
				output.Fail("create", err)
				return
			}
			values, err := odoo.ParseJSONObj(valuesJSON)
			if err != nil {
				output.Fail("create", err)
				return
			}
			if dryRun {
				output.Ok("create_preview", map[string]any{"model": model, "values": values}, 0)
				return
			}
			if err := safety.RequireConfirm(confirmed, false); err != nil {
				output.Fail("create", err)
				return
			}
			inst, err := config.Resolve(InstanceName())
			if err != nil {
				output.Fail("create", err)
				return
			}
			cl, err := odoo.New(inst)
			if err != nil {
				output.Fail("create", err)
				return
			}
			res, err := cl.Execute(model, "create", []any{values}, nil)
			if err != nil {
				output.Fail("create", err)
				return
			}
			output.Ok("create", res, 0)
		},
	}
	c.Flags().StringVar(&valuesJSON, "values-json", "", "JSON object of field values (required)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "preview canonical payload without calling the server")
	c.Flags().BoolVar(&confirmed, "yes", false, "confirm mutation (also requires ODOO_WRITES_ENABLED=1)")
	_ = c.MarkFlagRequired("values-json")
	return c
}

func newWriteCmd() *cobra.Command {
	var valuesJSON string
	var dryRun, confirmed bool
	c := &cobra.Command{
		Use:   "write <model> <ids...>",
		Short: "Update records (gated write)",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			model := args[0]
			if err := rpCheckModel(model); err != nil {
				output.Fail("write", err)
				return
			}
			ids, err := parseRecordIDs(args[1:])
			if err != nil {
				output.Fail("write", err)
				return
			}
			values, err := odoo.ParseJSONObj(valuesJSON)
			if err != nil {
				output.Fail("write", err)
				return
			}
			if dryRun {
				output.Ok("write_preview", map[string]any{"model": model, "ids": ids, "values": values}, 0)
				return
			}
			if err := safety.RequireConfirm(confirmed, false); err != nil {
				output.Fail("write", err)
				return
			}
			inst, err := config.Resolve(InstanceName())
			if err != nil {
				output.Fail("write", err)
				return
			}
			cl, err := odoo.New(inst)
			if err != nil {
				output.Fail("write", err)
				return
			}
			res, err := cl.Execute(model, "write", []any{ids, values}, nil)
			if err != nil {
				output.Fail("write", err)
				return
			}
			output.Ok("write", res, 0)
		},
	}
	c.Flags().StringVar(&valuesJSON, "values-json", "", "JSON object of field values (required)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "preview canonical payload without calling the server")
	c.Flags().BoolVar(&confirmed, "yes", false, "confirm mutation (also requires ODOO_WRITES_ENABLED=1)")
	_ = c.MarkFlagRequired("values-json")
	return c
}

func newUnlinkCmd() *cobra.Command {
	var dryRun, confirmed bool
	c := &cobra.Command{
		Use:   "unlink <model> <ids...>",
		Short: "Delete records (gated write)",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			model := args[0]
			if err := rpCheckModel(model); err != nil {
				output.Fail("unlink", err)
				return
			}
			ids, err := parseRecordIDs(args[1:])
			if err != nil {
				output.Fail("unlink", err)
				return
			}
			if dryRun {
				output.Ok("unlink_preview", map[string]any{"model": model, "ids": ids}, 0)
				return
			}
			if err := safety.RequireConfirm(confirmed, false); err != nil {
				output.Fail("unlink", err)
				return
			}
			inst, err := config.Resolve(InstanceName())
			if err != nil {
				output.Fail("unlink", err)
				return
			}
			cl, err := odoo.New(inst)
			if err != nil {
				output.Fail("unlink", err)
				return
			}
			res, err := cl.Execute(model, "unlink", []any{ids}, nil)
			if err != nil {
				output.Fail("unlink", err)
				return
			}
			output.Ok("unlink", res, 0)
		},
	}
	c.Flags().BoolVar(&dryRun, "dry-run", false, "preview canonical payload without calling the server")
	c.Flags().BoolVar(&confirmed, "yes", false, "confirm mutation (also requires ODOO_WRITES_ENABLED=1)")
	return c
}
