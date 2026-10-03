//go:build windows

package workspace

import "os"

// openReadNoBlock: Windows exposes no O_NONBLOCK and Go's os.Root has no
// nonblocking open there, so Read opens with a plain blocking flag. This
// is not a FIFO hazard on Windows: FIFO nodes do not exist as filesystem
// entries (named pipes live outside the filesystem namespace and cannot
// be planted inside a workspace directory), and the held-handle f.Stat in
// Read still refuses every non-regular file before reading.
const openReadNoBlock = os.O_RDONLY

// fileLinkCount is unattestable on Windows through FileInfo.Sys in any
// form this package can rely on portably: it reports unknown so Read
// falls back to the trusted-private-contents posture (documented in
// workspace.go): the 0700-equivalent user-owned directory keeps link
// planting to the same user. Never claimed as confinement.
func fileLinkCount(os.FileInfo) (uint64, bool) { return 0, false }

// fileOwnerMatchesCurrent is skipped on Windows: ValidateDedicatedDir
// gates the owner check to non-Windows (documented limitation — Windows
// ACL ownership is not attested here).
func fileOwnerMatchesCurrent(os.FileInfo) (bool, bool) { return false, false }
