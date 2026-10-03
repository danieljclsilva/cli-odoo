//go:build unix || aix || android || darwin || dragonfly || freebsd || hurd || illumos || ios || linux || netbsd || openbsd || solaris

package workspace

import (
	"os"
	"syscall"
)

// makeFifo creates a FIFO at path. Unix-only file, called from the portable
// test with a skip fallback.
func makeFifo(path string) error {
	if err := syscall.Mkfifo(path, 0600); err != nil {
		return err
	}
	// Mkfifo honors umask; keep test ownership semantics simple.
	return os.Chmod(path, 0600)
}
