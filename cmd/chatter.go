package cmd

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/KomoriNoKage/cli-odoo/internal/config"
	"github.com/KomoriNoKage/cli-odoo/internal/odoo"
	"github.com/KomoriNoKage/cli-odoo/internal/output"
	"github.com/KomoriNoKage/cli-odoo/internal/safety"
)

func init() {
	RootCmd.AddCommand(newChatterPostCmd())
}

func newChatterPostCmd() *cobra.Command {
	var body, subtype string
	var dryRun, confirmed bool
	c := &cobra.Command{
		Use:   "chatter-post <model> <id>",
		Short: "Post a chatter message via message_post (gated write, Odoo 17 safe)",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			model := args[0]
			if err := rpCheckModel(model); err != nil {
				output.Fail("chatter_post", err)
				return
			}
			id, err := strconv.Atoi(args[1])
			if err != nil {
				output.Fail("chatter_post", err)
				return
			}
			kwargs := map[string]any{"body": body}
			if subtype != "" {
				kwargs["subtype_xmlid"] = subtype
			}
			if dryRun {
				output.Ok("chatter_post_preview", map[string]any{"model": model, "id": id, "kwargs": kwargs}, 0)
				return
			}
			inst, err := config.Resolve(InstanceName())
			if err != nil {
				output.Fail("chatter_post", err)
				return
			}
			if err := safety.RequireWrite(inst, confirmed, false, "chatter_post:"+model+".message_post"); err != nil {
				output.Fail("chatter_post", err)
				return
			}
			cl, err := odoo.New(inst)
			if err != nil {
				output.Fail("chatter_post", err)
				return
			}
			res, err := cl.Execute(model, "message_post", []any{id}, kwargs)
			if err != nil {
				output.Fail("chatter_post", err)
				return
			}
			output.Ok("chatter_post", res, 0)
		},
	}
	c.Flags().StringVar(&body, "body", "", "message body HTML/text (required)")
	c.Flags().StringVar(&subtype, "subtype", "", "subtype XML ID (e.g. mail.mt_comment)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "preview canonical payload without calling the server")
	c.Flags().BoolVar(&confirmed, "yes", false, "confirm mutation (also requires ODOO_WRITES_ENABLED=1)")
	_ = c.MarkFlagRequired("body")
	return c
}
