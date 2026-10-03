// Package workspace confines model file access to one human-chosen
// directory using os.Root.
//
// The human picks the directory at setup time; Open refuses to create it
// (no MkdirAll surprises) and every access resolves inside it. Relative
// paths are cleaned and rejected when absolute or escaping (".." past the
// root); os.Root then confines even symlink traversals to the root.
// ValidateDedicatedDir (used by OpenValidated, setup, and the broker's
// serve-time check) additionally requires a dedicated, canonical,
// non-group/world-writable directory that overlaps no protected path.
//
// Trust and platform limits, stated honestly rather than hand-waved:
//
//   - Parent-root trust: OpenRoot follows symlinks in the dir path itself,
//     so the caller must trust every parent component of dir. Setup creates
//     the directory with mode 0700 under a user-owned path; Open verifies
//     dir exists and is a directory but cannot attest its parents.
//   - Symlinks: methods follow symlinks but confine them to the root;
//     absolute symlink targets and links escaping the root are rejected.
//     A symlink inside the root pointing at another inside-root path is
//     allowed and stays confined.
//   - Atomic writes: Write stages a 0600 temp file in the target's own
//     directory and renames it over the target. Rename replaces without
//     following the target, and it breaks hardlinks: a preexisting hardlink
//     keeps the old content (the safe direction — the link never observes
//     a half-written file). There is no in-place mutation.
//   - Hardlinks: reads through a hardlink planted inside the root to an
//     outside file are inherent (the link shares the inode; no path
//     check can see through it). Posture is trusted-private-contents:
//     the workspace dir is 0700 user-owned, so only the same user can
//     plant such a link. Rejecting hardlinked WRITES is unnecessary:
//     rename-write already breaks links instead of following them.
//   - No mount/device/proxy confinement: os.Root does not prohibit
//     filesystem-boundary traversal, bind mounts, /proc-style special
//     files, or Unix device nodes. Workspace content is human-placed;
//     Read and Write additionally refuse non-regular files (directories,
//     devices, sockets, pipes) so a planted device node cannot be read
//     through or written through.
//   - Chmod races: on Unix, Root.Chmod/Chown/Chtimes can be redirected by
//     swapping the target for a symlink mid-call. Write avoids this by
//     chmoding the still-open file handle (f.Chmod), not the path.
//   - Platform caveats (from os.Root): on GOOS=js, symlink validation has
//     TOCTOU races and confinement cannot be ensured; on GOOS=plan9 and
//     GOOS=js a Root tracks a directory name, not a handle, so renames of
//     the root itself are not tracked; WASI preview 1 lacks Chmod.
//
// Caps (maxEntries, maxBytes) are enforced by denial: over-cap reads fail
// instead of truncating, so a caller can never mistake a partial listing
// for a complete one. Listings are additionally capped by the fixed
// policy-side MaxListEntries: a caller max_entries only narrows, never
// widens it.
package workspace

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// MaxListEntries is the fixed policy-side listing cap. A caller max_entries
// may only narrow (never widen) this cap: List denies when either the
// caller's cap or MaxListEntries is exceeded, so the readdir
// materialization is bounded by policy-cap denial plus OS memory.
const MaxListEntries = 1000

// Entry is one directory listing row: name only, never content.
type Entry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
}

// CanonicalEqual reports whether two paths resolve (EvalSymlinks) to the
// same canonical absolute location. Unresolvable paths compare false.
func CanonicalEqual(a, b string) bool {
	ca, err := canonicalPath(a)
	if err != nil {
		return false
	}
	cb, err := canonicalPath(b)
	if err != nil {
		return false
	}
	return ca == cb
}

// Overlaps reports whether a and b name the same location, or one contains
// the other: equal, parent-of, child-of, or symlink-alias-equal (compared
// via EvalSymlinks on both sides so an aliasing symlink counts as overlap).
// Either path unresolvable reports overlap=true (fail closed): the caller
// cannot prove separation.
func Overlaps(a, b string) bool {
	ca, err := canonicalPath(a)
	if err != nil {
		return true
	}
	cb, err := canonicalPath(b)
	if err != nil {
		return true
	}
	if ca == cb {
		return true
	}
	if isWithin(ca, cb) || isWithin(cb, ca) {
		return true
	}
	return false
}

// canonicalPath resolves path to an absolute, symlink-resolved, cleaned
// location for overlap comparison.
func canonicalPath(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("workspace: empty path")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// The leaf may not exist yet (setup creates it): resolve the
		// deepest existing ancestor and reattach the remainder.
		cur := abs
		var tail []string
		for {
			parent := filepath.Dir(cur)
			if parent == cur {
				return "", err
			}
			tail = append([]string{filepath.Base(cur)}, tail...)
			if rp, rerr := filepath.EvalSymlinks(parent); rerr == nil {
				return filepath.Clean(filepath.Join(append([]string{rp}, tail...)...)), nil
			}
			cur = parent
		}
	}
	return filepath.Clean(resolved), nil
}

// isWithin reports whether child sits strictly under parent.
func isWithin(child, parent string) bool {
	if child == parent {
		return false
	}
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ValidateDedicatedDir checks that dir is a safe dedicated workspace:
// canonicalized (EvalSymlinks) and rejected when empty, a broad/system
// root, the home directory itself, missing, not a directory, group/other
// writable (Unix only; Windows skips the mode check), or overlapping any
// protected path (equal, parent-of, child-of, or symlink-alias-equal).
// Protected paths are the resolved profile path, snapshot path, config
// dir, and admin socket dir (plus the socket path itself).
func ValidateDedicatedDir(dir string, protected []string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("workspace: empty directory")
	}
	canon, err := canonicalPath(dir)
	if err != nil {
		return "", fmt.Errorf("workspace: resolving %q: %w", dir, err)
	}
	tmpRoot, _ := canonicalPath(strings.TrimSpace(os.TempDir()))
	// Per-tool subdirectories under the shared TMPDIR root are legitimate
	// workspaces even when TMPDIR itself sits under a system root
	// (e.g. /private/var on macOS): only the shared root itself rejects.
	if underTmp := tmpRoot != "" && canon != tmpRoot && isWithin(canon, tmpRoot); underTmp {
		// Per-tool temp subdir: skip the system-root scan (TMPDIR may
		// itself sit under a system root).
	} else {
		if canon == tmpRoot && tmpRoot != "" {
			return "", fmt.Errorf("workspace: %q is the shared temp root itself (use a dedicated subdirectory)", dir)
		}
		for _, root := range broadRoots() {
			cr, err := canonicalPath(root)
			if err != nil {
				cr = filepath.Clean(root)
			}
			// "/" rejects equality only: every absolute path sits under
			// it, so within-"/" alone must not deny.
			if cr == "/" {
				if canon == cr {
					return "", fmt.Errorf("workspace: %q is broad root %q", dir, root)
				}
				continue
			}
			if canon == cr || isWithin(canon, cr) {
				return "", fmt.Errorf("workspace: %q is at or inside broad root %q", dir, root)
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		if hc, herr := canonicalPath(home); herr == nil && canon == hc {
			return "", fmt.Errorf("workspace: %q is the home directory itself", dir)
		}
	}
	st, err := os.Stat(canon)
	if err != nil {
		return "", fmt.Errorf("workspace: %q: %w (create it first)", dir, err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("workspace: %q is not a directory", dir)
	}
	if runtime.GOOS != "windows" {
		if st.Mode().Perm()&0022 != 0 {
			return "", fmt.Errorf("workspace: %q has mode %04o: group/other write refused", dir, st.Mode().Perm())
		}
	}
	for _, p := range protected {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if Overlaps(canon, p) {
			return "", fmt.Errorf("workspace: %q overlaps protected path %q", dir, p)
		}
	}
	return canon, nil
}

// broadRoots lists locations a workspace must never sit at or under: the
// filesystem root, OS system roots, the drive root on Windows, and TMPDIR
// itself (a per-tool subdirectory is fine; the shared temp root is not).
func broadRoots() []string {
	roots := []string{"/", "/etc", "/bin", "/sbin", "/usr", "/var", "/System", "/Library"}
	if runtime.GOOS == "windows" {
		for _, d := range []string{"C:\\", "C:/"} {
			roots = append(roots, d)
		}
	}
	if tmp := strings.TrimSpace(os.TempDir()); tmp != "" {
		if abs, err := filepath.Abs(tmp); err == nil {
			roots = append(roots, filepath.Clean(abs))
		}
	}
	return roots
}

// OpenValidated validates dir against protected paths and then Opens it.
// The serve-time check lives in the broker; this helper is the shared
// validator both setup and the broker use.
func OpenValidated(dir string, protected []string) (*Workspace, error) {
	canon, err := ValidateDedicatedDir(dir, protected)
	if err != nil {
		return nil, err
	}
	return Open(canon)
}

// Workspace is an os.Root-confined handle on a human-chosen directory.
type Workspace struct {
	root *os.Root
	dir  string
}

// Dir returns the host path passed to Open.
func (w *Workspace) Dir() string { return w.dir }

// Close releases the root handle.
func (w *Workspace) Close() error {
	if w == nil || w.root == nil {
		return nil
	}
	return w.root.Close()
}

// Open confines dir: it must already exist and be a directory, otherwise
// Open errors and creates nothing. The caller must trust dir's parent
// components (see package comment).
func Open(dir string) (*Workspace, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("workspace: empty directory")
	}
	st, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("workspace: %q: %w (create it first; Open creates nothing)", dir, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("workspace: %q is not a directory", dir)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("workspace: opening %q: %w", dir, err)
	}
	return &Workspace{root: r, dir: dir}, nil
}

// cleanRel rejects absolute paths, NUL bytes, backslashes, and any ".."
// that escapes the root. Backslashes are rejected outright: on Windows
// they are path separators (so `..\x` escapes), and on Unix a backslash
// name is never legitimate workspace input. "" addresses the root itself.
// The result uses OS separators and is safe to hand to os.Root, which
// confines it a second time.
func cleanRel(rel string) (string, error) {
	if strings.ContainsRune(rel, 0) {
		return "", fmt.Errorf("workspace: path contains NUL")
	}
	if strings.Contains(rel, "\\") {
		return "", fmt.Errorf("workspace: backslash in path %q rejected", rel)
	}
	if rel == "" {
		return ".", nil
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("workspace: absolute path %q rejected", rel)
	}
	clean := filepath.Clean(rel)
	if clean == "." {
		return ".", nil
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("workspace: path %q escapes the workspace", rel)
	}
	for _, seg := range strings.Split(clean, string(filepath.Separator)) {
		if seg == ".." {
			return "", fmt.Errorf("workspace: path %q escapes the workspace", rel)
		}
	}
	return clean, nil
}

func (w *Workspace) List(rel string, maxEntries int) ([]Entry, error) {
	if w == nil || w.root == nil {
		return nil, fmt.Errorf("workspace: closed")
	}
	if maxEntries <= 0 {
		return nil, fmt.Errorf("workspace: maxEntries must be positive, got %d", maxEntries)
	}
	// The caller cap only narrows: it can never widen the fixed
	// policy-side MaxListEntries. ReadDir(-1) materializes the whole
	// directory, so the readdir cost is bounded by policy-cap denial
	// plus OS memory (documented, not streamed: os.Root has no ReadDirN
	// streaming form).
	effectiveMax := maxEntries
	if effectiveMax > MaxListEntries {
		effectiveMax = MaxListEntries
	}
	clean, err := cleanRel(rel)
	if err != nil {
		return nil, err
	}
	st, err := w.root.Stat(clean)
	if err != nil {
		return nil, fmt.Errorf("workspace: stat %q: %w", rel, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("workspace: %q is not a directory", rel)
	}
	f, err := w.root.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("workspace: opening %q: %w", rel, err)
	}
	defer f.Close()
	infos, err := f.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("workspace: listing %q: %w", rel, err)
	}
	if len(infos) > effectiveMax {
		return nil, fmt.Errorf("workspace: %q holds %d entries, over cap %d", rel, len(infos), effectiveMax)
	}
	out := make([]Entry, 0, len(infos))
	for _, info := range infos {
		fi, err := info.Info()
		if err != nil {
			return nil, fmt.Errorf("workspace: stat entry %q: %w", info.Name(), err)
		}
		out = append(out, Entry{
			Name:  info.Name(),
			IsDir: info.IsDir(),
			Size:  fi.Size(),
			Mode:  info.Type().String(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Read returns the full content of the regular file at rel. maxBytes must
// be positive; a file larger than maxBytes denies instead of truncating.
// After Open, the held handle is f.Stat'ed before reading and any
// non-regular mode (directories, devices, sockets, pipes incl. FIFOs)
// refuses, so Root.Open on a FIFO (which succeeds) never blocks in Read.
// Residual risk (documented): the path entry can be swapped between the
// pre-open Stat and Open; the post-open f.Stat closes the FIFO-block hole
// but a swapped regular file still reads the replacement.
func (w *Workspace) Read(rel string, maxBytes int) ([]byte, error) {
	if w == nil || w.root == nil {
		return nil, fmt.Errorf("workspace: closed")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("workspace: maxBytes must be positive, got %d", maxBytes)
	}
	clean, err := cleanRel(rel)
	if err != nil {
		return nil, err
	}
	if clean == "." {
		return nil, fmt.Errorf("workspace: refusing to read the workspace root")
	}
	if st, err := w.root.Stat(clean); err != nil {
		return nil, fmt.Errorf("workspace: stat %q: %w", rel, err)
	} else if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("workspace: %q is not a regular file", rel)
	}
	f, err := w.root.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("workspace: opening %q: %w", rel, err)
	}
	defer f.Close()
	// Held-handle check: refuse FIFOs/sockets/devices that Open let
	// through, before any blocking Read.
	if fst, err := f.Stat(); err != nil {
		return nil, fmt.Errorf("workspace: stat %q: %w", rel, err)
	} else if mode := fst.Mode(); !mode.IsRegular() || mode&fs.ModeNamedPipe != 0 ||
		mode&fs.ModeSocket != 0 || mode&fs.ModeDevice != 0 || mode&fs.ModeCharDevice != 0 {
		return nil, fmt.Errorf("workspace: %q is not a regular file", rel)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("workspace: reading %q: %w", rel, err)
	}
	if len(b) > maxBytes {
		return nil, fmt.Errorf("workspace: %q exceeds cap %d bytes", rel, maxBytes)
	}
	return b, nil
}

// Write stores data at rel atomically with mode 0600: a temp file is
// staged in the target's own directory and renamed over the target, so
// readers never observe a half-written file and preexisting hardlinks keep
// the old content (the safe direction). The temp name is random and
// created O_EXCL, so it never follows a planted symlink; rename replaces
// the target itself without following it. The parent directory must already
// exist. Writing the workspace root or a path with a trailing separator
// denies, as do non-regular existing targets.
func (w *Workspace) Write(rel string, data []byte) error {
	if w == nil || w.root == nil {
		return fmt.Errorf("workspace: closed")
	}
	clean, err := cleanRel(rel)
	if err != nil {
		return err
	}
	if clean == "." {
		return fmt.Errorf("workspace: refusing to write the workspace root")
	}
	if strings.HasSuffix(rel, "/") || strings.HasSuffix(rel, string(filepath.Separator)) {
		return fmt.Errorf("workspace: refusing to write directory path %q", rel)
	}
	// An existing symlink is fine: rename below replaces the link
	// itself, never following it. Non-regular, non-symlink targets deny.
	if st, err := w.root.Lstat(clean); err == nil {
		if !st.Mode().IsRegular() && st.Mode()&fs.ModeSymlink == 0 {
			return fmt.Errorf("workspace: %q exists and is not a regular file", rel)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("workspace: stat %q: %w", rel, err)
	}
	parent := filepath.Dir(clean)
	if parent != "." {
		pst, err := w.root.Stat(parent)
		if err != nil {
			return fmt.Errorf("workspace: parent of %q: %w (parents are never created)", rel, err)
		}
		if !pst.IsDir() {
			return fmt.Errorf("workspace: parent of %q is not a directory", rel)
		}
	}
	var tmpBase string
	for tries := 0; tries < 5; tries++ {
		var nonce [8]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return fmt.Errorf("workspace: random temp name: %w", err)
		}
		name := ".tmp-" + hex.EncodeToString(nonce[:])
		if parent == "." {
			tmpBase = name
		} else {
			tmpBase = parent + string(filepath.Separator) + name
		}
		f, err := w.root.OpenFile(tmpBase, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return fmt.Errorf("workspace: staging %q: %w", rel, err)
		}
		writeErr := func() error {
			defer f.Close()
			if _, err := f.Write(data); err != nil {
				return err
			}
			// Chmod the open handle, not the path: no symlink-swap
			// race between staging and rename.
			if err := f.Chmod(0600); err != nil {
				return err
			}
			if err := f.Sync(); err != nil {
				return err
			}
			return nil
		}()
		if writeErr != nil {
			_ = w.root.Remove(tmpBase)
			return fmt.Errorf("workspace: staging %q: %w", rel, writeErr)
		}
		if err := w.root.Rename(tmpBase, clean); err != nil {
			_ = w.root.Remove(tmpBase)
			return fmt.Errorf("workspace: committing %q: %w", rel, err)
		}
		return nil
	}
	return fmt.Errorf("workspace: staging %q: temp name collision", rel)
}

// MkdirAll creates rel and any missing parents inside the workspace,
// confined through the root (0700, no symlink following outside the root),
// so tool flows can create nested report directories without shell access.
// "" or "." is a no-op (the root already exists); an existing non-directory
// denies.
func (w *Workspace) MkdirAll(rel string) error {
	if w == nil || w.root == nil {
		return fmt.Errorf("workspace: closed")
	}
	clean, err := cleanRel(rel)
	if err != nil {
		return err
	}
	if clean == "." {
		return nil
	}
	if st, err := w.root.Stat(clean); err == nil {
		if !st.IsDir() {
			return fmt.Errorf("workspace: %q exists and is not a directory", rel)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("workspace: stat %q: %w", rel, err)
	}
	if err := w.root.MkdirAll(clean, 0700); err != nil {
		return fmt.Errorf("workspace: mkdir %q: %w", rel, err)
	}
	return nil
}
