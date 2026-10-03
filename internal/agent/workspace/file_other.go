//go:build js || plan9 || wasip1 || zos

package workspace

import (
	"errors"
	"os"
)

var errNoFifoOther = errors.New("fifos unsupported on this platform")

// makeFifo is unavailable here: the FIFO test skips gracefully.
func makeFifo(string) error {
	return errNoFifoOther
}

// openReadNoBlock: no nonblocking-open primitive is relied on here (and on
// GOOS=js os.Root confinement itself has TOCTOU races, documented in
// workspace.go). Read opens plainly and still refuses every non-regular
// file via the held-handle f.Stat before reading.
const openReadNoBlock = os.O_RDONLY

// fileLinkCount is unattestable on these platforms: Read documents the
// trusted-private-contents fallback instead of claiming confinement.
func fileLinkCount(os.FileInfo) (uint64, bool) { return 0, false }

// fileOwnerMatchesCurrent is unattestable on these platforms:
// ValidateDedicatedDir fails closed (refuses) when ownership is unknown.
func fileOwnerMatchesCurrent(os.FileInfo) (bool, bool) { return false, false }
