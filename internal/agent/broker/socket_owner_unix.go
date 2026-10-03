//go:build !windows

package broker

import (
	"fmt"
	"os"
	"syscall"
)

// adminDirSuffix keys the private admin dir per user so two OS users never
// share it.
func adminDirSuffix() string {
	return fmt.Sprintf("%d", os.Geteuid())
}

// checkSocketOwner verifies path info names a file owned by this uid.
// Serve calls it for the admin dir and before removing any stale socket so
// an attacker-planted path owned by someone else denies instead of unlinking.
func checkSocketOwner(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return fmt.Errorf("cannot verify ownership")
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("owned by uid %d, want uid %d", st.Uid, os.Geteuid())
	}
	return nil
}
