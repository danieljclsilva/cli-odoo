//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !hurd && !illumos && !ios && !linux && !netbsd && !openbsd && !solaris

package snapshot

import "os"

// boundedOpenFlag: no nonblocking-open primitive is relied on here. FIFOs
// cannot be planted as filesystem entries on these platforms (Windows
// named pipes live outside the filesystem namespace), and ReadBoundedFile
// still refuses every non-regular file via the Lstat pre-check and the
// held-handle fstat before reading.
const boundedOpenFlag = os.O_RDONLY
