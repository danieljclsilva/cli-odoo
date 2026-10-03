// Package workspace confines model file access to one human-chosen
// directory using os.Root.
//
// The human picks the directory at setup time; Open refuses to create it
// (no MkdirAll surprises) and every access resolves inside it. Relative
// paths are cleaned and rejected when absolute or escaping (".." past the
// root); os.Root then confines even symlink traversals to the root.
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
// for a complete one.
package workspace

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Entry is one directory listing row: name only, never content.
type Entry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
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
	if len(infos) > maxEntries {
		return nil, fmt.Errorf("workspace: %q holds %d entries, over cap %d", rel, len(infos), maxEntries)
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
// Non-regular files (directories, devices, sockets, pipes) deny.
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
	st, err := w.root.Stat(clean)
	if err != nil {
		return nil, fmt.Errorf("workspace: stat %q: %w", rel, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("workspace: %q is not a regular file", rel)
	}
	f, err := w.root.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("workspace: opening %q: %w", rel, err)
	}
	defer f.Close()
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
