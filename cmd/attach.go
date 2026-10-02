package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/KomoriNoKage/cli-odoo/internal/config"
	"github.com/KomoriNoKage/cli-odoo/internal/odoo"
	"github.com/KomoriNoKage/cli-odoo/internal/output"
	"github.com/KomoriNoKage/cli-odoo/internal/safety"
)

const defaultMaxAttachmentBytes = 10 * 1024 * 1024

func init() {
	RootCmd.AddCommand(newAttachmentGetCmd(), newAttachmentAddCmd())
}

// maxAttachmentBytes reads the upload cap, defaulting to 10MB.
func maxAttachmentBytes() int {
	v := os.Getenv("ODOO_MCP_MAX_ATTACHMENT_UPLOAD_BYTES")
	if v == "" {
		return defaultMaxAttachmentBytes
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return defaultMaxAttachmentBytes
	}
	return n
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

func newAttachmentAddCmd() *cobra.Command {
	var file, name string
	var dryRun, confirmed bool
	c := &cobra.Command{
		Use:   "attachment-add <model> <res-id>",
		Short: "Upload a file as ir.attachment (gated write, 10MB default cap)",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			model := args[0]
			if err := rpCheckModel(model); err != nil {
				output.Fail("attachment_add", err)
				return
			}
			resID, err := strconv.Atoi(args[1])
			if err != nil {
				output.Fail("attachment_add", err)
				return
			}
			raw, err := os.ReadFile(file)
			if err != nil {
				output.Fail("attachment_add", err)
				return
			}
			if cap := maxAttachmentBytes(); len(raw) > cap {
				output.Fail("attachment_add", fmt.Errorf("file %d bytes exceeds cap %d bytes (ODOO_MCP_MAX_ATTACHMENT_UPLOAD_BYTES)", len(raw), cap))
				return
			}
			if name == "" {
				name = filepath.Base(file)
			}
			if dryRun {
				output.Ok("attachment_add_preview", map[string]any{
					"model": model, "res_id": resID, "name": name,
					"file": file, "bytes": len(raw),
				}, 0)
				return
			}
			inst, err := config.Resolve(InstanceName())
			if err != nil {
				output.Fail("attachment_add", err)
				return
			}
			if err := safety.RequireWrite(inst, confirmed, false, "attachment_add:ir.attachment.create"); err != nil {
				output.Fail("attachment_add", err)
				return
			}
			cl, err := odoo.New(inst)
			if err != nil {
				output.Fail("attachment_add", err)
				return
			}
			vals := map[string]any{
				"name":      name,
				"datas":     base64.StdEncoding.EncodeToString(raw),
				"res_model": model,
				"res_id":    resID,
			}
			res, err := cl.Execute("ir.attachment", "create", []any{vals}, nil)
			if err != nil {
				output.Fail("attachment_add", err)
				return
			}
			output.Ok("attachment_add", res, 0)
		},
	}
	c.Flags().StringVar(&file, "file", "", "local file to upload (required)")
	c.Flags().StringVar(&name, "name", "", "attachment name (default: file basename)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "preview canonical payload without calling the server")
	c.Flags().BoolVar(&confirmed, "yes", false, "confirm mutation (also requires ODOO_WRITES_ENABLED=1)")
	_ = c.MarkFlagRequired("file")
	return c
}
