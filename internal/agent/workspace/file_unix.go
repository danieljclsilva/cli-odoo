//go:build aix || android || darwin || dragonfly || freebsd || hurd || illumos || ios || linux || netbsd || openbsd || solaris

package workspace

import (
	"os"
	"syscall"
)

// openReadNoBlock opens reads without ever blocking on a FIFO: O_NONBLOCK
// makes the open itself return immediately; the held-handle f.Stat in Read
// then refuses the FIFO before any Read can block or observe EAGAIN.
const openReadNoBlock = os.O_RDONLY | syscall.O_NONBLOCK

// fileLinkCount reports the hardlink count of a held handle's stat result.
// ok=false only when the stat value carries no usable link count.
func fileLinkCount(fi os.FileInfo) (n uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	// Nlink widens differently per platform (16/32/64-bit): uint64
	// normalizes every width without truncation.
	return uint64(st.Nlink), true
}

// fileOwnerMatchesCurrent reports whether fi is owned by the calling euid.
// known=false only when ownership is unattestable from the stat value.
func fileOwnerMatchesCurrent(fi os.FileInfo) (match, known bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return false, false
	}
	// Uid widens differently per platform: compare in uint64 so no
	// width truncates on either side.
	return uint64(st.Uid) == uint64(os.Geteuid()), true
}
