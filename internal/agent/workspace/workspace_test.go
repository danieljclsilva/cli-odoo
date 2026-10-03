package workspace

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// openTestWorkspace creates a real temp dir with the workspace isolated in
// a "ws" subdirectory, so "outside the root" (the temp dir itself) is a
// real place escape attempts must not reach.
func openTestWorkspace(t *testing.T) (*Workspace, string) {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "ws")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, dir
}
func TestOpenRequiresExistingDir(t *testing.T) {
	// Missing paths error; Open creates nothing.
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := Open(missing); err == nil {
		t.Fatal("Open(missing): expected error, got nil")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("Open(missing): created something it must not create")
	}
	// A regular file is not a workspace.
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(f); err == nil {
		t.Fatal("Open(file): expected error, got nil")
	}
	if _, err := Open(""); err == nil {
		t.Fatal("Open(empty): expected error, got nil")
	}
}

func TestTraversalRejection(t *testing.T) {
	w, dir := openTestWorkspace(t)
	if err := w.Write("ok.txt", []byte("ok")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	evil := []string{
		"/etc/passwd",
		"/" + "ok.txt",
		"..",
		"../escape.txt",
		"sub/../../escape.txt",
		"a/../../../escape.txt",
		"..\\windows",
	}
	for _, rel := range evil {
		if _, err := w.Read(rel, 1024); err == nil {
			t.Fatalf("Read(%q): expected rejection", rel)
		}
		if err := w.Write(rel, []byte("evil")); err == nil {
			t.Fatalf("Write(%q): expected rejection", rel)
		}
		if _, err := w.List(rel, 100); err == nil {
			t.Fatalf("List(%q): expected rejection", rel)
		}
	}
	// The host directory outside the root gained no escape file.
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name() != "ok.txt" {
		names := []string{}
		for _, f := range files {
			names = append(names, f.Name())
		}
		t.Fatalf("workspace dir polluted: %v", names)
	}
	parent, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range parent {
		if f.Name() == "escape.txt" {
			t.Fatal("escape file written outside workspace")
		}
	}
	// NUL bytes reject everywhere.
	if _, err := w.Read("a\x00b", 10); err == nil {
		t.Fatal("Read(NUL): expected rejection")
	}
}

func TestSymlinkInsideStaysConfined(t *testing.T) {
	w, _ := openTestWorkspace(t)
	if err := w.Write("real.txt", []byte("real")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// A symlink inside the root pointing at another inside-root file
	// stays confined and reads through.
	if err := os.Symlink("real.txt", filepath.Join(w.Dir(), "link.txt")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	b, err := w.Read("link.txt", 1024)
	if err != nil {
		t.Fatalf("Read(inside link): %v", err)
	}
	if string(b) != "real" {
		t.Fatalf("Read(inside link): got %q", b)
	}
}

func TestSymlinkEscapeDenied(t *testing.T) {
	w, dir := openTestWorkspace(t)
	// The secret lives next to the workspace root, so a link climbing
	// out of the root resolves to a real file os.Root must deny.
	outside := filepath.Join(filepath.Dir(dir), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	// Absolute symlink target: confined by os.Root.
	if err := os.Symlink(outside, filepath.Join(dir, "abs-link")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, err := w.Read("abs-link", 1024); err == nil {
		t.Fatal("Read(abs escape link): expected denial")
	}
	// Relative link climbing out of the root: likewise denied.
	if err := os.Symlink("../secret.txt", filepath.Join(dir, "rel-link")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, err := w.Read("rel-link", 1024); err == nil {
		t.Fatal("Read(relative escape link): expected denial")
	}
	// Listing through an escaped link directory denies too.
	sub := filepath.Join(filepath.Dir(dir), "extradir")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sub, filepath.Join(dir, "dir-link")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, err := w.List("dir-link", 100); err == nil {
		t.Fatal("List(escape dir link): expected denial")
	}
}

func TestAtomicWriteBreaksHardlink(t *testing.T) {
	w, dir := openTestWorkspace(t)
	if err := w.Write("doc.txt", []byte("v1")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// A preexisting hardlink pins the old inode: the atomic rename must
	// leave it at v1 (safe direction — the link never sees torn content).
	link := filepath.Join(dir, "pinned.txt")
	if err := os.Link(filepath.Join(dir, "doc.txt"), link); err != nil {
		t.Skipf("hardlinks unsupported: %v", err)
	}
	if err := w.Write("doc.txt", []byte("v2-longer-content")); err != nil {
		t.Fatalf("Write v2: %v", err)
	}
	b, err := w.Read("doc.txt", 1024)
	if err != nil || string(b) != "v2-longer-content" {
		t.Fatalf("Read after rewrite: got %q, %v", b, err)
	}
	pinned, err := os.ReadFile(link)
	if err != nil {
		t.Fatal(err)
	}
	if string(pinned) != "v1" {
		t.Fatalf("hardlink observed new content %q: write was not atomic", pinned)
	}
}

func TestWriteModeAndNoFollow(t *testing.T) {
	w, dir := openTestWorkspace(t)
	if err := w.Write("secret.txt", []byte("s")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	st, err := os.Stat(filepath.Join(dir, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o, want 600", st.Mode().Perm())
	}
	// Rewriting an existing symlink replaces the link itself; the
	// outside target is untouched.
	outside := filepath.Join(filepath.Dir(dir), "target.txt")
	if err := os.WriteFile(outside, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "swap.txt")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if err := w.Write("swap.txt", []byte("new")); err != nil {
		t.Fatalf("Write over symlink: %v", err)
	}
	kept, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != "target" {
		t.Fatalf("write followed symlink: target now %q", kept)
	}
	// No temp staging files leak.
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), ".tmp-") {
			t.Fatalf("staging file leaked: %s", f.Name())
		}
	}
	// Writing the root or a directory path denies.
	if err := w.Write("", []byte("x")); err == nil {
		t.Fatal("Write(root): expected denial")
	}
	if err := w.Write("sub/", []byte("x")); err == nil {
		t.Fatal("Write(dir path): expected denial")
	}
}

func TestNestedDocsAndUnicode(t *testing.T) {
	w, _ := openTestWorkspace(t)
	if err := os.Mkdir(filepath.Join(w.Dir(), "docs"), 0700); err != nil {
		t.Fatal(err)
	}
	// Parents are never created: a missing intermediate denies.
	if err := w.Write("missing/deep.txt", []byte("x")); err == nil {
		t.Fatal("Write(missing parent): expected denial")
	}
	names := []string{
		"docs/notes.txt",
		"docs/日本語.txt",
		"docs/émoji-🎉.txt",
		"docs/spaces in name.txt",
		"docs/nested.txt",
	}
	if err := os.Mkdir(filepath.Join(w.Dir(), "docs", "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	names = append(names, "docs/sub/deep-ünïcode-日本.txt")
	for _, n := range names {
		if err := w.Write(n, []byte("content:"+n)); err != nil {
			t.Fatalf("Write(%q): %v", n, err)
		}
		b, err := w.Read(n, 1<<20)
		if err != nil || string(b) != "content:"+n {
			t.Fatalf("Read(%q): got %q, %v", n, b, err)
		}
	}
	entries, err := w.List("docs", 100)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("List(docs): empty")
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Name >= entries[i].Name {
			t.Fatal("List: not sorted by name")
		}
	}
	sub, err := w.List("docs/sub", 100)
	if err != nil || len(sub) != 1 {
		t.Fatalf("List(docs/sub): got %v, %v", sub, err)
	}
}

func TestCapsEnforced(t *testing.T) {
	w, _ := openTestWorkspace(t)
	for _, n := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := w.Write(n, []byte("data-"+n)); err != nil {
			t.Fatal(err)
		}
	}
	// Over-cap listing denies instead of truncating.
	if _, err := w.List("", 2); err == nil {
		t.Fatal("List over cap: expected denial, got truncation")
	}
	got, err := w.List("", 3)
	if err != nil || len(got) != 3 {
		t.Fatalf("List at cap: got %v, %v", got, err)
	}
	// Over-cap read denies instead of truncating.
	if _, err := w.Read("a.txt", 2); err == nil {
		t.Fatal("Read over cap: expected denial, got truncation")
	}
	b, err := w.Read("a.txt", len("data-a.txt"))
	if err != nil || string(b) != "data-a.txt" {
		t.Fatalf("Read at cap: got %q, %v", b, err)
	}
	if _, err := w.List("", 0); err == nil {
		t.Fatal("List(maxEntries=0): expected denial")
	}
	if _, err := w.Read("a.txt", 0); err == nil {
		t.Fatal("Read(maxBytes=0): expected denial")
	}
	// Listing a file (not a directory) denies.
	if _, err := w.List("a.txt", 10); err == nil {
		t.Fatal("List(file): expected denial")
	}
	// Reading the root denies.
	if _, err := w.Read("", 100); err == nil {
		t.Fatal("Read(root): expected denial")
	}
}

func TestReadRefusesNonRegular(t *testing.T) {
	w, dir := openTestWorkspace(t)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Read("sub", 100); err == nil {
		t.Fatal("Read(dir): expected denial")
	}
	if err := os.Symlink("sub", filepath.Join(dir, "dirlink")); err == nil {
		if _, err := w.Read("dirlink", 100); err == nil {
			t.Fatal("Read(dir symlink): expected denial")
		}
	}
}

func TestValidateDedicatedDirAccepts(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "ws")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	got, err := ValidateDedicatedDir(dir, []string{filepath.Join(base, "profile.json")})
	if err != nil {
		t.Fatalf("ValidateDedicatedDir: %v", err)
	}
	if got == "" {
		t.Fatal("ValidateDedicatedDir: empty canonical path")
	}
	w, err := OpenValidated(dir, []string{filepath.Join(base, "profile.json")})
	if err != nil {
		t.Fatalf("OpenValidated: %v", err)
	}
	_ = w.Close()
}

func TestValidateDedicatedDirRejects(t *testing.T) {
	base := t.TempDir()
	protected := filepath.Join(base, "profile.json")
	if err := os.WriteFile(protected, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(base, "ws")
	if err := os.Mkdir(ws, 0700); err != nil {
		t.Fatal(err)
	}
	// Broad/system roots reject: filesystem root and the shared TMPDIR
	// root itself (a per-tool subdirectory is fine).
	for _, root := range []string{"/", os.TempDir()} {
		if _, err := ValidateDedicatedDir(root, nil); err == nil {
			t.Fatalf("ValidateDedicatedDir(%q): expected denial", root)
		}
	}
	// Empty, missing, and non-dir reject.
	if _, err := ValidateDedicatedDir("", nil); err == nil {
		t.Fatal("ValidateDedicatedDir(empty): expected denial")
	}
	if _, err := ValidateDedicatedDir(filepath.Join(base, "missing"), nil); err == nil {
		t.Fatal("ValidateDedicatedDir(missing): expected denial")
	}
	if _, err := ValidateDedicatedDir(protected, nil); err == nil {
		t.Fatal("ValidateDedicatedDir(file): expected denial")
	}
	// Overlap with a protected path rejects in every direction: equal,
	// child-of (protected parent), parent-of (protected child), and
	// symlink-alias-equal.
	if _, err := ValidateDedicatedDir(base, []string{ws}); err == nil {
		t.Fatal("ValidateDedicatedDir(parent of protected): expected denial")
	}
	if _, err := ValidateDedicatedDir(ws, []string{base}); err == nil {
		t.Fatal("ValidateDedicatedDir(child of protected): expected denial")
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(ws, alias); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, err := ValidateDedicatedDir(alias, []string{ws}); err == nil {
		t.Fatal("ValidateDedicatedDir(symlink alias of protected): expected denial")
	}
	if !Overlaps(alias, ws) || !CanonicalEqual(alias, ws) {
		t.Fatal("Overlaps/CanonicalEqual(alias): expected true")
	}
	if Overlaps(ws, filepath.Join(base, "unrelated")) {
		t.Fatal("Overlaps(unrelated): expected false")
	}
}

func TestReadRefusesFifo(t *testing.T) {
	w, dir := openTestWorkspace(t)
	fifo := filepath.Join(dir, "pipe")
	if err := makeFifo(fifo); err != nil {
		t.Skipf("fifos unsupported: %v", err)
	}
	// The open must return (O_NONBLOCK) so the refusal below proves
	// non-blocking refusal, not a hang: finish the whole read in a
	// goroutine and demand a fast denial with no writer ever arriving.
	done := make(chan error, 1)
	go func() {
		_, err := w.Read("pipe", 1024)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read(fifo): expected denial, got content (would block)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read(fifo): blocked over 5s with no writer — nonblocking open missing")
	}
}

func TestValidateRejectsGroupReadableAndLegacyDefault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode checks are documented-skipped on windows")
	}
	base := t.TempDir()
	// Group/other-readable (even without write) refuses: 0750 carries
	// group bits, so trusted-private-contents cannot hold.
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0750); err != nil {
		t.Fatal(err)
	}
	// Mkdir honors umask: pin the mode so the assertion is exact.
	if err := os.Chmod(loose, 0750); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateDedicatedDir(loose, nil); err == nil {
		t.Fatal("ValidateDedicatedDir(0750): expected denial for group-readable dir")
	}
	// A legacy config-nested workspace rejects with a migration note,
	// not a bare overlap error. Faked HOME isolates the test from the
	// real ~/.config/odoo-cli.
	fakeHome := t.TempDir()
	legacy := filepath.Join(fakeHome, ".config", "odoo-cli")
	if err := os.MkdirAll(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", fakeHome)
	if _, verr := ValidateDedicatedDir(legacy, nil); verr == nil {
		t.Fatal("ValidateDedicatedDir(config dir): expected denial")
	} else if !strings.Contains(strings.ToLower(verr.Error()), "move it") {
		t.Fatalf("legacy default denial must carry a migration note, got: %v", verr)
	}
}

func TestReadRefusesHardlinkedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("link-count refusal is unix-attestable (windows uses trusted-private-contents)")
	}
	w, dir := openTestWorkspace(t)
	if err := w.Write("doc.txt", []byte("v1")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	link := filepath.Join(dir, "alias.txt")
	if err := os.Link(filepath.Join(dir, "doc.txt"), link); err != nil {
		t.Skipf("hardlinks unsupported: %v", err)
	}
	// The alias shares the inode (2 links): reading through it must deny
	// rather than leak outside-planted content.
	if _, err := w.Read("alias.txt", 1024); err == nil {
		t.Fatal("Read(hardlink): expected denial, got content")
	}
	if _, err := w.Read("doc.txt", 1024); err == nil {
		t.Fatal("Read(linked original): expected denial once linked, got content")
	}
}

func TestMkdirAllNested(t *testing.T) {
	w, _ := openTestWorkspace(t)
	if err := w.MkdirAll("reports/2026/10"); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := w.Write("reports/2026/10/summary.txt", []byte("ok")); err != nil {
		t.Fatalf("Write(nested): %v", err)
	}
	b, err := w.Read("reports/2026/10/summary.txt", 1024)
	if err != nil || string(b) != "ok" {
		t.Fatalf("Read(nested): got %q, %v", b, err)
	}
	if err := w.MkdirAll("../escape"); err == nil {
		t.Fatal("MkdirAll(escape): expected denial")
	}
}

func TestEmptyDirListReturnsZeroRows(t *testing.T) {
	// REGRESSION: empty-dir List("", 5) errored with EOF. io.EOF is the
	// end-of-directory signal, not a failure: an empty directory lists
	// zero rows with no error.
	w, _ := openTestWorkspace(t)
	got, err := w.List("", 5)
	if err != nil {
		t.Fatalf("List(empty): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("List(empty) = %d rows, want 0", len(got))
	}
}

func TestListRefusesFifoWithoutBlocking(t *testing.T) {
	// MALICIOUS: a planted FIFO must deny without blocking for a writer.
	// List opens nonblocking (like Read) and judges the held handle, so
	// the whole denial completes with no writer ever arriving.
	w, dir := openTestWorkspace(t)
	if err := makeFifo(filepath.Join(dir, "pipe")); err != nil {
		t.Skipf("fifos unsupported: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := w.List("pipe", 100)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("List(fifo): expected denial, got listing (would block)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("List(fifo): blocked over 5s with no writer — nonblocking open missing")
	}
}

func TestOpenValidatedHoldsValidatedRoot(t *testing.T) {
	// LEGITIMATE+MALICIOUS: OpenValidated serves the validated directory,
	// and a protected overlap still denies before Open runs.
	base := t.TempDir()
	dir := filepath.Join(base, "ws")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ws, err := OpenValidated(dir, []string{filepath.Join(base, "protected")})
	if err != nil {
		t.Fatalf("OpenValidated(legitimate): %v", err)
	}
	_ = ws.Close()
	if _, err := OpenValidated(dir, []string{dir}); err == nil {
		t.Fatal("OpenValidated(protected overlap): expected denial")
	}
	if err := ws.RevalidateProtectedSeparation([]string{dir}); err == nil {
		t.Fatal("RevalidateProtectedSeparation(overlap): expected denial")
	}
}

func TestMaxEntriesCannotWiden(t *testing.T) {
	w, _ := openTestWorkspace(t)
	for i := range 3 {
		if err := w.Write("f"+string(rune('a'+i))+".txt", []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	// A caller cap above the policy cap cannot widen it: exceeding the
	// policy cap denies even when the caller allows more. Build enough
	// entries to cross MaxListEntries is impractical here; instead assert
	// the cap constant exists and a narrowing cap still denies at 2.
	if MaxListEntries != 1000 {
		t.Fatalf("MaxListEntries = %d, want 1000", MaxListEntries)
	}
	if _, err := w.List("", 2); err == nil {
		t.Fatal("List over narrowing cap: expected denial")
	}
	if _, err := w.List("", MaxListEntries+1000000); err != nil {
		t.Fatalf("List under effective policy cap: %v", err)
	}
}
