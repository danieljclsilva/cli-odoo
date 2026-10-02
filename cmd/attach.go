package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/danieljclsilva/cli-odoo/internal/config"
	"github.com/danieljclsilva/cli-odoo/internal/odoo"
	"github.com/danieljclsilva/cli-odoo/internal/output"
)

func init() {
	RootCmd.AddCommand(newAttachmentGetCmd())
}

func newAttachmentGetCmd() *cobra.Command {
	var out string
	var force bool
	c := &cobra.Command{
		Use:   "attachment-get <id>",
		Short: "Download an ir.attachment (base64 datas decoded to file)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			id, err := strconv.Atoi(args[0])
			if err != nil {
				output.Fail("read_attachment", err)
				return
			}
			inst, err := config.Resolve(InstanceName())
			if err != nil {
				output.Fail("read_attachment", err)
				return
			}
			cl, err := odoo.New(inst)
			if err != nil {
				output.Fail("read_attachment", err)
				return
			}
			res, err := cl.Execute("ir.attachment", "read",
				[]any{[]any{id}, []any{"id", "name", "datas", "mimetype", "res_model", "res_id", "file_size"}}, nil)
			if err != nil {
				output.Fail("read_attachment", err)
				return
			}
			rows, ok := res.([]any)
			if !ok || len(rows) == 0 {
				output.Fail("read_attachment", fmt.Errorf("attachment %d not found", id))
				return
			}
			rec, ok := rows[0].(map[string]any)
			if !ok {
				output.Fail("read_attachment", fmt.Errorf("unexpected read result for attachment %d", id))
				return
			}
			datas, _ := rec["datas"].(string)
			if datas == "" || datas == "false" {
				output.Fail("read_attachment", fmt.Errorf("attachment %d has no stored datas", id))
				return
			}
			raw, err := base64.StdEncoding.DecodeString(datas)
			if err != nil {
				output.Fail("read_attachment", fmt.Errorf("decoding attachment %d datas: %w", id, err))
				return
			}
			if _, err := os.Stat(out); err == nil {
				if !force {
					output.Fail("read_attachment", fmt.Errorf("destination file %q already exists (use --force to overwrite)", out))
					return
				}
			}
			if err := os.WriteFile(out, raw, 0o600); err != nil {
				output.Fail("read_attachment", err)
				return
			}
			name, _ := rec["name"].(string)
			output.Ok("read_attachment", map[string]any{
				"id": id, "name": name, "out": out, "bytes": len(raw),
			}, 1)
		},
	}
	c.Flags().StringVar(&out, "out", "", "destination file path (required)")
	c.Flags().BoolVar(&force, "force", false, "overwrite destination file if it exists")
	_ = c.MarkFlagRequired("out")
	return c
}
