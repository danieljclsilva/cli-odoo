package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
			if strings.TrimSpace(out) == "" {
				output.Fail("read_attachment", fmt.Errorf("missing --out destination file path"))
				return
			}
			if err := writeAttachmentFile(out, raw, force); err != nil {
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

// writeAttachmentFile stores decoded attachment bytes at out.
//
// Default (force=false) creates the file with O_EXCL, so the
// create-or-fail is atomic: a symlink swapped in at --out between the
// Lstat check and the write fails with EEXIST instead of redirecting
// server-controlled bytes through the link.
//
// With force=true the bytes go to a temp file (os.CreateTemp opens it
// 0600, O_EXCL) in the same parent directory, which commitAttachmentTemp
// then renames over the destination. Rename replaces a final-component
// symlink itself rather than following it, so a link swapped in at --out
// between check and write is replaced (never written through) and the
// link target stays untouched. A pre-existing symlink at --out is still
// refused outright (rename path included): with --force a raced-in link
// ends up replaced, never followed; either way the target is never
// written. Rename-overwrite also breaks (rather than follows) any
// pre-existing hardlink to the destination: linked copies keep the old
// content, which is the safe direction.
//
// The guarantee is destination-entry safety only, not that --out always
// ends up holding the downloaded bytes. The parent directory itself
// remains trusted: it must already exist and must not itself be a
// symlink (refused), but an attacker able to swap entries in the parent
// could substitute the temp source file between its creation and the
// rename, so --out could receive bytes other than the downloaded
// attachment. There is no fully portable (macOS/Linux/Windows) way to
// pin the parent without openat-style APIs, so callers must treat the
// --out parent directory as trusted. The attachment metadata "name"
// never influences the path.
func writeAttachmentFile(out string, data []byte, force bool) error {
	if strings.TrimSpace(out) == "" {
		return fmt.Errorf("missing --out destination file path")
	}
	dir := filepath.Dir(out)
	if di, err := os.Lstat(dir); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("destination directory %q does not exist: %w", dir, err)
		}
		return err
	} else if di.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("destination directory %q is a symlink (refusing to write through it)", dir)
	} else if !di.IsDir() {
		return fmt.Errorf("destination parent %q is not a directory", dir)
	}
	if fi, err := os.Lstat(out); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("destination file %q is a symlink (refusing to follow)", out)
		}
		if fi.IsDir() {
			return fmt.Errorf("destination file %q is a directory (refusing to overwrite)", out)
		}
		if !force {
			return fmt.Errorf("destination file %q already exists (use --force to overwrite)", out)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if !force {
		// O_EXCL makes the create-or-fail atomic: no TOCTOU
		// between the Lstat above and the write.
		// (A pre-existing symlink fails here with EEXIST: O_EXCL
		// treats the link itself as "exists", so it is not followed.)
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, werr := f.Write(data)
		cerr := f.Close()
		if werr == nil {
			werr = cerr
		}
		return werr
	}
	tmp, err := os.CreateTemp(dir, ".attachment-get-*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	return commitAttachmentTemp(tmp, out)
}

// commitAttachmentTemp closes the held temp file (already 0600 from
// os.CreateTemp) and renames it over out, removing the temp entry if
// the close or the rename fails. The caller passes the still-open file
// so no pathname-based lookup (and no chmod/stat gap) sits between the
// write and the rename.
func commitAttachmentTemp(tmp *os.File, out string) error {
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	// Atomic replacement: on POSIX rename swaps the destination link
	// itself (never follows a final-component symlink); on Windows
	// os.Rename replaces the existing destination the same way.
	if err := os.Rename(tmpName, out); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
