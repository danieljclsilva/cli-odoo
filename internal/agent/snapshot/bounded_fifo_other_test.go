//go:build !unix && !aix && !android && !darwin && !dragonfly && !freebsd && !hurd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris

package snapshot

import "errors"

// mkfifo reports unavailable where FIFOs cannot be planted as filesystem
// entries; the portable evidence test skips.
func mkfifo(path string) error {
	return errors.New("FIFO fixture unavailable on this platform")
}
