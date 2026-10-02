// Package safety gates mutating operations. Writes never run silently:
// they require an explicit confirmation flag plus an env gate, mirroring
// the preview/validate/execute approval flow of the reference MCP server.
package safety

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KomoriNoKage/cli-odoo/internal/config"
)

// WritesEnabled reports whether the env gate permits mutations.
func WritesEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("ODOO_WRITES_ENABLED")))
	return v == "1" || v == "true" || v == "yes"
}

// RequireConfirm errors unless confirmed==true AND the env gate is open.
// dryRun bypasses: preview path never mutates.
func RequireConfirm(confirmed, dryRun bool) error {
	if dryRun {
		return nil
	}
	if !confirmed {
		return fmt.Errorf("refusing to write: pass --yes to confirm (preview with --dry-run first)")
	}
	if !WritesEnabled() {
		return fmt.Errorf("refusing to write: set ODOO_WRITES_ENABLED=1 to enable mutations")
	}
	return nil
}

// RequireWrite gates a mutating operation op ("<tool>:<model>.<method>").
// Order: dry-run previews never mutate; read-only instances refuse; then
// the --yes flag and ODOO_WRITES_ENABLED gates; finally a human at a
// controlling terminal must type YES. The confirmation is read from /dev/tty
// (never stdin) so piped stdin cannot feed it, and a headless sandbox without
// a controlling terminal is refused. ODOO_ALLOW_NON_TTY=1 skips only the TTY
// step (human-owned CI only; agent-abusable, never a default).
func RequireWrite(inst *config.Instance, confirmed, dryRun bool, op string) error {
	if dryRun {
		return nil
	}
	name := ""
	if inst != nil {
		name = inst.Name
	}
	deny := func(reason string) error {
		if aerr := logAttempt(inst, op, reason); aerr != nil {
			return fmt.Errorf("refusing %s: %s (audit log failed: %v)", op, reason, aerr)
		}
		return fmt.Errorf("refusing %s: %s", op, reason)
	}
	if inst != nil && inst.ReadOnly {
		return deny(fmt.Sprintf("instance %q is read-only (set readonly:false in the config file; server ACLs still apply)", name))
	}
	if !confirmed {
		return deny("pass --yes to confirm (preview with --dry-run first)")
	}
	if !WritesEnabled() {
		return deny("set ODOO_WRITES_ENABLED=1 to enable mutations")
	}
	if os.Getenv("ODOO_ALLOW_NON_TTY") == "1" {
		_ = logAttempt(inst, op, "allowed without TTY (ODOO_ALLOW_NON_TTY=1)")
		return nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	if err != nil {
		return deny("no controlling terminal: writes need a human at a TTY (type YES at /dev/tty)")
	}
	defer tty.Close()
	fmt.Fprintf(os.Stderr, "Type YES to confirm %s: ", op)
	line, _ := bufio.NewReader(tty).ReadString('\n')
	if strings.TrimSpace(line) != "YES" {
		return deny("confirmation not given (type YES at /dev/tty to confirm)")
	}
	_ = logAttempt(inst, op, "confirmed at TTY")
	return nil
}

// logAttempt appends one JSON line for a mutation gate decision to the
// instance audit log (dir 0700, file 0600). Secrets are never recorded.
func logAttempt(inst *config.Instance, op, decision string) error {
	entry := map[string]any{
		"ts":       time.Now().UTC().Format(time.RFC3339),
		"op":       op,
		"decision": decision,
	}
	if inst != nil {
		entry["instance"] = inst.Name
		entry["url"] = inst.URL
		entry["db"] = inst.DB
		entry["username"] = inst.Username
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	path := ""
	if inst != nil {
		path = strings.TrimSpace(inst.AuditLog)
	}
	if path == "" {
		if v := strings.TrimSpace(os.Getenv("ODOO_AUDIT_LOG")); v != "" {
			path = v
		} else if home, herr := os.UserHomeDir(); herr == nil && home != "" {
			path = filepath.Join(home, ".config", "odoo-cli", "audit.log")
		} else {
			path = filepath.Join(".", "odoo-audit.log")
		}
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
