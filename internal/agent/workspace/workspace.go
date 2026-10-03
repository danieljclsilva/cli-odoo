// Package workspace confines model file access to one human-chosen
// directory using os.Root.
//
// The human picks the directory at setup time; Open refuses to create it
// (no MkdirAll surprises) and every access resolves inside it. Relative
// paths are cleaned and rejected when absolute or escaping (".." past the
// root); os.Root then confines even symlink traversals to the root.
// ValidateDedicatedDir (used by OpenValidated, setup, and the broker's
// serve-time check) additionally requires a dedicated, canonical, 0700
// user-owned directory that overlaps no protected path.
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
//     outside file share the target's inode, so no path check can see
//     through the link. Where the platform reports link counts (unix),
//     Read refuses any held handle with more than one link, so a planted
//     hardlink denies instead of leaking. Where the count is unattestable
//     (Windows and other ports), posture is trusted-private-contents: the
//     workspace dir is 0700 user-owned, so only the same user could plant
//     such a link — never claimed as confinement. Writes are safe
//     everywhere regardless: rename-write breaks (not follows) links.
//   - FIFO blocking: opening a FIFO for reading blocks until a writer
//     arrives, so a planted FIFO is a hang, not just a read. Read and
//     List never let that happen: both open with O_NONBLOCK where the
//     platform offers it (unix), so the open returns immediately, and the
//     held-handle f.Stat then refuses the FIFO (Read: non-regular file;
//     List: not a directory) before any Read or readdir runs. There is no
//     pre-open Stat: the name can be swapped between Stat and Open, so
//     only the HELD handle is judged. On Windows O_NONBLOCK does not exist
//     and a plain open is used; FIFO nodes cannot be planted in a Windows
//     directory (named pipes live outside the filesystem namespace), so the
//     raced-FIFO block class does not apply there, and the held-handle
//     refusal still runs. (On GOOS=js os.Root confinement itself has TOCTOU
//     races — see below.)
//   - No mount/device/proxy confinement: os.Root does not prohibit
//     filesystem-boundary traversal, bind mounts, /proc-style special
//     files, or Unix device nodes. Workspace content is human-placed;
//     Read and Write additionally refuse non-regular files (directories,
//     devices, sockets, pipes) so a planted device node cannot be read
//     through or written through.
//   - Chmod races: on Unix, Root.Chmod/Chown/Chtimes can be redirected by
//     swapping the target for a symlink mid-call. Write avoids this by
//     chmoding the still-open file handle (f.Chmod), not the path.
//   - Ownership: ValidateDedicatedDir requires mode 0700 (any group/other
//     permission bit refuses) and, on unix, that the directory is owned by
//     the calling euid. On Windows neither check is attestable through
//     os.Stat, so both are skipped there (documented limitation, not a
//     silent approve); on js/plan9-class ports unattestable ownership
//     fails closed.
//   - Platform caveats (from os.Root): on GOOS=js, symlink validation has
//     TOCTOU races and confinement cannot be ensured; on GOOS=plan9 and
//     GOOS=js a Root tracks a directory name, not a handle, so renames of
//     the root itself are not tracked; WASI preview 1 lacks Chmod.
//
// Concurrency: a Workspace is safe for concurrent use. Mutating operations
// (Write, MkdirAll) serialize on an internal mutex so concurrent model
// dispatches cannot interleave renames/staging; List and Read take no
// exclusive lock because os.Root methods are documented safe for concurrent
// use and neither mutates workspace state. Callers needing a multi-step
// read-modify-write sequence must serialize it themselves: List+Read+Write
// are individually atomic, not jointly.
//
// Caps (maxEntries, maxBytes) are enforced by denial: over-cap reads fail
// instead of truncating, so a caller can never mistake a partial listing
// for a complete one. List reads at most cap+1 entries through the held
// directory handle and denies when the cap is exceeded, so enumeration cost
// is bounded by the policy cap (MaxListEntries, which a caller cap only
// narrows), never by directory size.
package workspace

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
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
// root, the home directory itself, missing, not a directory, carrying any
// group/other permission bit (0700-equivalent, non-Windows), not owned by
// the calling euid (unix only; see ownership note below), overlapping the
// legacy config-nested default (with a migration note), or overlapping any
// protected path (equal, parent-of, child-of, or symlink-alias-equal).
// Protected paths are the resolved profile path, snapshot path, config
// dir, and admin socket dir (plus the socket path itself).
//
// Ownership note: on unix the directory must be owned by the calling euid
// (verified from the stat owner). On Windows neither mode bits nor
// ownership are attestable through os.Stat, so both checks are skipped
// there — a documented platform limitation, not a silent approve. On
// js/plan9-class ports ownership is unattestable and fails closed.
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
	// 0700-equivalent: any group/other permission bit refuses. Skipped on
	// Windows, where os.Stat cannot attest mode bits (documented
	// limitation); enforced everywhere else (unix ownership check below
	// pins the same-user requirement on top).
	if runtime.GOOS != "windows" {
		if perm := st.Mode().Perm(); perm&0077 != 0 {
			return "", fmt.Errorf("workspace: %q has mode %04o: want 0700 (no group/other bits)", dir, perm)
		}
	}
	// Owner check: the directory must belong to the calling user, or a
	// foreign-owned 0700-by-someone-else dir could gatekeep reads while
	// passing the mode check.
	if match, known := fileOwnerMatchesCurrent(st); !known {
		if runtime.GOOS == "windows" {
			// Documented skip: Windows ACL ownership is not attested
			// here. Same-user posture only.
		} else {
			return "", fmt.Errorf("workspace: %q ownership unattestable on this platform", dir)
		}
	} else if !match {
		return "", fmt.Errorf("workspace: %q is not owned by the current user", dir)
	}
	// Legacy overlapping default: the setup default used to suggest a
	// workspace nested under ~/.config/odoo-cli (the config dir holding
	// the profile and snapshot). Any workspace at or under that config
	// dir rejects with a migration note — protected-overlap below would
	// also deny it, but the note tells the human where to move instead
	// of leaving them to guess.
	if home, herr := os.UserHomeDir(); herr == nil && strings.TrimSpace(home) != "" {
		legacyCfg := filepath.Join(home, ".config", "odoo-cli")
		if lc, lerr := canonicalPath(legacyCfg); lerr == nil && (canon == lc || isWithin(canon, lc)) {
			return "", fmt.Errorf("workspace: %q sits under the config dir %q (move it to ~/odoo-agent-workspace or another non-config directory)", dir, legacyCfg)
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
//
// Rename/symlink-substitution window: validation attests the name, but Open
// must serve the directory the name resolves to at open time. OpenValidated
// therefore compares the held root handle ("." through os.Root.Stat) with
// the validated path via os.SameFile and denies on mismatch: a root swapped
// between ValidateDedicatedDir and os.OpenRoot (rename, symlink
// substitution, mount swap) fails closed. The protected-set separation check
// is exact at validation time; callers that hold protected state across a
// longer session must revalidate before credential use (the broker performs
// its workspace validation inside Serve, immediately before credentials
// resolve — see RevalidateProtectedSeparation).
//
// Platform posture (honest, not proof): where os.SameFile, link counts, or
// ownership are unattestable, OpenValidated degrades rather than claims
// confinement. On Windows, mode/ownership checks are skipped (ACLs are not
// attested through os.Stat) and link counts are unknown, so posture is
// trusted-private-contents for the same user only — never claimed as
// confinement against a hostile same-user planter. On js/plan9-class ports
// ownership is unattestable and validation fails closed (denies).
func OpenValidated(dir string, protected []string) (*Workspace, error) {
	canon, err := ValidateDedicatedDir(dir, protected)
	if err != nil {
		return nil, err
	}
	ws, err := Open(canon)
	if err != nil {
		return nil, err
	}
	same, serr := ws.heldSameDir(canon)
	if serr != nil {
		_ = ws.Close()
		return nil, fmt.Errorf("workspace: identity of opened root %q: %w", canon, serr)
	}
	if !same {
		_ = ws.Close()
		return nil, fmt.Errorf("workspace: %q changed between validation and open (rename/symlink substitution): refusing", dir)
	}
	if err := ws.RevalidateProtectedSeparation(protected); err != nil {
		_ = ws.Close()
		return nil, err
	}
	return ws, nil
}

// heldSameDir reports whether the held root handle confines the same
// directory the validated host path names now: it stats the live path and
// "." through the held handle and compares with os.SameFile. A rename or
// symlink substitution between validation and open (or since open) fails
// closed. Where the platform cannot attest sameness (SameFile false on
// distinct-but-equal paths, or unattestable file identity), the caller gets
// (false, nil) on Windows — a documented degrade to trusted-private
// posture, never claimed as confinement — and OpenValidated still requires
// the dedicated-dir shape (ValidateDedicatedDir) to pass; other unattestable
// ports fail closed via ValidateDedicatedDir's ownership denial.
func (w *Workspace) heldSameDir(livePath string) (bool, error) {
	want, err := os.Stat(livePath)
	if err != nil {
		return false, err
	}
	got, err := w.root.Stat(".")
	if err != nil {
		return false, err
	}
	if os.SameFile(want, got) {
		return true, nil
	}
	// SameFile is unattestable-or-different here. On Windows the identity
	// comparison is not reliable through os.Stat, so degrade honestly:
	// fall back to comparing the canonicalized live path against the
	// open-time dir (EvalSymlinks-resolved on both sides). Equal canonical
	// paths are accepted under the documented trusted-private posture;
	// genuinely different locations still deny.
	if runtime.GOOS == "windows" {
		canonLive, lerr := canonicalPath(livePath)
		if lerr != nil {
			return false, lerr
		}
		canonHeld, herr := canonicalPath(strings.TrimSpace(w.dir))
		if herr != nil {
			return false, herr
		}
		return canonLive == canonHeld, nil
	}
	return false, nil
}

// RevalidateProtectedSeparation re-checks the already-open workspace's held
// root against a protected set: it denies when the held root no longer
// names the same directory as the open-time path (rename/substitution
// since open) or when the live path fails the dedicated-dir shape
// (mode/ownership/broad-root/protected-overlap). Serve calls OpenValidated
// (which performs this check before returning) and must call this again
// immediately before credential use when protected state may have moved
// since open; until this returns nil the caller must not use credentials
// against this workspace.
func (w *Workspace) RevalidateProtectedSeparation(protected []string) error {
	if w == nil || w.root == nil {
		return fmt.Errorf("workspace: closed")
	}
	canon := strings.TrimSpace(w.dir)
	if canon == "" {
		return fmt.Errorf("workspace: empty directory")
	}
	same, err := w.heldSameDir(canon)
	if err != nil {
		return fmt.Errorf("workspace: live root %q: %w", canon, err)
	}
	if !same {
		return fmt.Errorf("workspace: %q moved since open: refusing", canon)
	}
	if _, err := ValidateDedicatedDir(canon, protected); err != nil {
		return err
	}
	return nil
}

// Workspace is an os.Root-confined handle on a human-chosen directory.
// Mutating operations (Write, MkdirAll) serialize on mu; concurrent reads
// need no exclusive lock (os.Root is safe for concurrent use).
type Workspace struct {
	mu   sync.Mutex
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
	// policy-side MaxListEntries. Enumeration is a single bounded
	// ReadDir(cap+1) through the held handle: one extra entry proves
	// over-cap, and cost is bounded by the policy cap, never by
	// directory size.
	effectiveMax := maxEntries
	if effectiveMax > MaxListEntries {
		effectiveMax = MaxListEntries
	}
	clean, err := cleanRel(rel)
	if err != nil {
		return nil, err
	}
	// Open the held handle first, then judge the handle: no pre-open
	// Stat, so a swap between check and use cannot attest a name Open
	// no longer resolves to. A dir/file swap still resolves to the
	// replacement through the same held handle and denies below. The open
	// uses O_NONBLOCK where the platform offers it (unix), exactly like
	// Read: opening a planted FIFO returns immediately instead of hanging
	// for a writer, and the held-handle Stat below refuses the FIFO before
	// any readdir runs. On Windows O_NONBLOCK does not exist and a plain
	// open is used — FIFO nodes cannot be planted in a Windows directory
	// (named pipes live outside the filesystem namespace), so that block
	// class does not apply there, and the held-handle refusal still runs.
	f, err := w.root.OpenFile(clean, openReadNoBlock, 0)
	if err != nil {
		return nil, fmt.Errorf("workspace: opening %q: %w", rel, err)
	}
	defer f.Close()
	if fst, err := f.Stat(); err != nil {
		return nil, fmt.Errorf("workspace: stat %q: %w", rel, err)
	} else if !fst.IsDir() {
		return nil, fmt.Errorf("workspace: %q is not a directory", rel)
	}
	// Bounded enumeration: read at most cap+1 names through the held
	// handle. effectiveMax+1 always fits an int on every platform Go
	// supports (effectiveMax <= MaxListEntries = 1000). An empty or
	// short directory reports io.EOF alongside its (possibly zero)
	// entries: EOF is the end-of-directory signal, not a failure, so it
	// is accepted as a valid short/empty listing.
	want := effectiveMax + 1
	infos, err := f.ReadDir(want)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("workspace: listing %q: %w", rel, err)
	}
	if len(infos) > effectiveMax {
		return nil, fmt.Errorf("workspace: %q holds more than %d entries (over cap)", rel, effectiveMax)
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
// There is deliberately NO pre-open Stat: the name can be swapped between
// Stat and Open, so only the HELD handle is judged. The open itself uses
// O_NONBLOCK where the platform offers it (unix), so opening a planted
// FIFO returns immediately instead of blocking for a writer; the
// held-handle f.Stat then refuses the FIFO (and any other non-regular
// file: directories, devices, sockets, pipes) before any Read runs. On
// Windows O_NONBLOCK does not exist and a plain open is used — FIFO nodes
// cannot be planted in a Windows directory, so that block class does not
// apply there, and the held-handle refusal still runs. Where the platform
// reports link counts (unix), a handle with more than one link (a hardlink
// planted inside the root to an outside file shares the inode) refuses;
// where unattestable the posture is trusted-private-contents (0700
// user-owned dir), documented above, never claimed as confinement.
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
	// Single raced-open path: judge only what Open returned. (A pre-open
	// Stat would attest a name that Open may no longer resolve to.)
	f, err := w.root.OpenFile(clean, openReadNoBlock, 0)
	if err != nil {
		return nil, fmt.Errorf("workspace: opening %q: %w", rel, err)
	}
	defer f.Close()
	// Held-handle check: refuse every non-regular file BEFORE any Read.
	// Root.Open (and OpenFile) succeed on FIFOs, so judging the name
	// first would still block; judging the handle cannot.
	if fst, err := f.Stat(); err != nil {
		return nil, fmt.Errorf("workspace: stat %q: %w", rel, err)
	} else if mode := fst.Mode(); !mode.IsRegular() || mode&fs.ModeNamedPipe != 0 ||
		mode&fs.ModeSocket != 0 || mode&fs.ModeDevice != 0 || mode&fs.ModeCharDevice != 0 {
		return nil, fmt.Errorf("workspace: %q is not a regular file", rel)
	} else if n, ok := fileLinkCount(fst); ok && n > 1 {
		return nil, fmt.Errorf("workspace: %q is hardlinked (%d links): refusing", rel, n)
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
	// Serialize mutations: concurrent model dispatches must not interleave
	// temp staging/renames. Reads stay lock-free (os.Root is safe for
	// concurrent use) and may run alongside one serialized writer.
	w.mu.Lock()
	defer w.mu.Unlock()
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

func (w *Workspace) MkdirAll(rel string) error {
	if w == nil || w.root == nil {
		return fmt.Errorf("workspace: closed")
	}
	// Serialized with Write (see above): concurrent mkdir+write races on
	// shared parents must not interleave.
	w.mu.Lock()
	defer w.mu.Unlock()
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
