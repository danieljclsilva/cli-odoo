//go:build unix || aix || android || darwin || dragonfly || freebsd || hurd || illumos || ios || linux || netbsd || openbsd || solaris

package snapshot

import (
	"os"
	"syscall"
)

// mkfifo creates a FIFO at path. Unix-only file, called from the portable
// evidence test with a skip fallback.
func mkfifo(path string) error {
	if err := syscall.Mkfifo(path, 0600); err != nil {
		return err
	}
	// Mkfifo honors umask; keep test ownership semantics simple.
	return os.Chmod(path, 0600)
}
