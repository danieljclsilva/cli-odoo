//go:build aix || android || darwin || dragonfly || freebsd || hurd || illumos || ios || linux || netbsd || openbsd || solaris

package snapshot

import (
	"os"
	"syscall"
)

// boundedOpenFlag opens human-handled reads without ever blocking on a
// FIFO: O_NONBLOCK makes the open itself return immediately, and the
// held-handle fstat in ReadBoundedFile then refuses the FIFO (and any
// other non-regular file) before any Read can block or observe EAGAIN.
const boundedOpenFlag = os.O_RDONLY | syscall.O_NONBLOCK
