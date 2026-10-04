package snapshot

import (
	"fmt"
	"io"
	"os"
)

// ReadBoundedFile reads the human-handled file at path through its held
// open descriptor, capped at maxBytes. The sequence is:
//
//  1. Lstat (never follows a symlink, never blocks on a FIFO): a symlink
//     or non-regular file is refused before any open can block or follow.
//  2. Open with O_NONBLOCK where the platform offers it (unix:
//     bounded_unix.go) so a FIFO swapped in after Lstat still cannot
//     block the open.
//  3. fstat on the HELD handle: only the opened descriptor is judged
//     (never the name). Symlink, FIFO, socket, device, or any other
//     non-regular mode is refused before any Read runs.
//  4. os.SameFile(Lstat, fstat): a swap between Lstat and Open (symlink
//     plant, rename) fails closed instead of reading the wrong file.
//  5. Read through a cap+1 limiter: a file that grows past maxBytes
//     between open and read denies over-cap instead of allocating
//     unboundedly.
//
// There is deliberately no Stat-then-ReadFile: only cap+1 bytes are ever
// read, and only the held descriptor is judged.
//
// Errors wrap the underlying os error (%w), so a missing file still
// reports os.IsNotExist true and first-setup callers can treat it as
// absent. Every other refusal (symlink, non-regular, swapped, over-cap,
// permission) fails closed. Errors name the kind but not the path; the
// caller wraps with the path it opened.
func ReadBoundedFile(path string, maxBytes int64, kind string) ([]byte, error) {
	if kind == "" {
		kind = "file"
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("snapshot: %s: non-positive cap %d", kind, maxBytes)
	}
	if path == "" {
		return nil, fmt.Errorf("snapshot: %s: empty path", kind)
	}
	// Pre-open refusal via Lstat only: never follows, never blocks.
	// The held-handle fstat + SameFile check below is authoritative
	// against swaps between Lstat and Open.
	lst, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("snapshot: reading %s: %w", kind, err)
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("snapshot: %s is a symlink: refusing", kind)
	}
	if !lst.Mode().IsRegular() {
		return nil, fmt.Errorf("snapshot: %s is not a regular file", kind)
	}
	f, err := os.OpenFile(path, boundedOpenFlag, 0)
	if err != nil {
		return nil, fmt.Errorf("snapshot: reading %s: %w", kind, err)
	}
	defer f.Close()
	fst, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("snapshot: stat %s: %w", kind, err)
	}
	if mode := fst.Mode(); mode&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("snapshot: %s is a symlink: refusing", kind)
	} else if !mode.IsRegular() || mode&os.ModeNamedPipe != 0 ||
		mode&os.ModeSocket != 0 || mode&os.ModeDevice != 0 || mode&os.ModeCharDevice != 0 {
		return nil, fmt.Errorf("snapshot: %s is not a regular file", kind)
	}
	if !os.SameFile(lst, fst) {
		return nil, fmt.Errorf("snapshot: %s changed between check and open: refusing", kind)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("snapshot: reading %s: %w", kind, err)
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("snapshot: %s exceeds cap %d bytes", kind, maxBytes)
	}
	return b, nil
}
