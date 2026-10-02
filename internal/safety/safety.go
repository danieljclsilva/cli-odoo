// Package safety gates mutating operations. Writes never run silently:
// they require an explicit confirmation flag plus an env gate, mirroring
// the preview/validate/execute approval flow of the reference MCP server.
package safety

import (
	"fmt"
	"os"
	"strings"
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
