package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAttachmentFileCreate(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "a.bin")
	if err := writeAttachmentFile(out, []byte("hello"), false); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("content = %q, want %q", got, "hello")
	}
	if fi, err := os.Stat(out); err != nil {
		t.Fatalf("stat: %v", err)
	} else if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %04o, want 0600", perm)
	}
}

func TestWriteAttachmentFileNoForceRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "a.bin")
	if err := os.WriteFile(out, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAttachmentFile(out, []byte("new"), false); err == nil {
		t.Fatal("expected refusal to overwrite without --force")
	}
	got, _ := os.ReadFile(out)
	if string(got) != "old" {
		t.Fatalf("content = %q, want untouched %q", got, "old")
	}
}

func TestWriteAttachmentFileForceOverwrite(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "a.bin")
	if err := os.WriteFile(out, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAttachmentFile(out, []byte("new"), true); err != nil {
		t.Fatalf("force overwrite: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("content = %q, want %q", got, "new")
	}
	if fi, err := os.Lstat(out); err != nil {
		t.Fatalf("lstat: %v", err)
	} else {
		if fi.Mode()&os.ModeSymlink != 0 {
			t.Fatal("destination became a symlink")
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("mode = %04o, want 0600", perm)
		}
	}
	// No temp leftovers in the parent dir.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "a.bin" {
			t.Fatalf("leftover temp file %q", e.Name())
		}
	}
}

// A symlink already sitting at --out is refused outright (both modes):
// server-controlled bytes must never be written through the link.
func TestWriteAttachmentFileSymlinkRefused(t *testing.T) {
	for _, force := range []bool{false, true} {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.bin")
		if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "out.bin")
		if err := os.Symlink(target, out); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := writeAttachmentFile(out, []byte("attacker"), force); err == nil {
			t.Fatalf("force=%v: expected symlink refusal", force)
		}
		got, _ := os.ReadFile(target)
		if string(got) != "secret" {
			t.Fatalf("force=%v: link target overwritten: %q", force, got)
		}
		if fi, err := os.Lstat(out); err != nil {
			t.Fatal(err)
		} else if fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("force=%v: pre-existing symlink should be left in place on refusal", force)
		}
	}
}

// The raced-in case the temp+rename design defeats: even if a
// final-component symlink appears at --out after the temp file is
// created, commitAttachmentTemp's rename replaces the link itself
// instead of following it.
func TestCommitAttachmentTempReplacesRacedSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(target, []byte("secret"), 0o750); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.bin")
	if err := os.WriteFile(out, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp, err := os.CreateTemp(dir, ".attachment-get-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write([]byte("new")); err != nil {
		_ = tmp.Close()
		t.Fatal(err)
	}
	// Simulate the race window: after the temp file exists, the
	// destination is swapped for a symlink to the victim target.
	if err := os.Remove(out); err != nil {
		_ = tmp.Close()
		t.Fatal(err)
	}
	if err := os.Symlink(target, out); err != nil {
		_ = tmp.Close()
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := commitAttachmentTemp(tmp, out); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "secret" {
		t.Fatalf("link target overwritten through rename: %q", got)
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != before.Mode() {
		t.Fatalf("target mode changed: %v -> %v", before.Mode(), after.Mode())
	}
	if fi, err := os.Lstat(out); err != nil {
		t.Fatal(err)
	} else {
		if fi.Mode()&os.ModeSymlink != 0 {
			t.Fatal("expected the raced-in symlink to be replaced by a regular file")
		}
		if !fi.Mode().IsRegular() {
			t.Fatalf("out mode = %v, want regular file", fi.Mode())
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("mode = %04o, want 0600", perm)
		}
	}
	if got, _ := os.ReadFile(out); string(got) != "new" {
		t.Fatalf("content = %q, want %q", got, "new")
	}
	// No temp leftovers: only the victim target and the destination.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "target.bin" && e.Name() != "out.bin" {
			t.Fatalf("leftover temp file %q", e.Name())
		}
	}
}

// Force-overwriting a hardlinked destination must break the link rather
// than follow it: the linked copy keeps the old bytes.
func TestWriteAttachmentFileForceBreaksHardlink(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "a.bin")
	if err := os.WriteFile(out, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "linked.bin")
	if err := os.Link(out, linked); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	if err := writeAttachmentFile(out, []byte("new"), true); err != nil {
		t.Fatalf("force overwrite: %v", err)
	}
	if got, _ := os.ReadFile(linked); string(got) != "old" {
		t.Fatalf("linked copy = %q, want untouched %q", got, "old")
	}
	if got, _ := os.ReadFile(out); string(got) != "new" {
		t.Fatalf("content = %q, want %q", got, "new")
	}
	if fi, err := os.Lstat(out); err != nil {
		t.Fatal(err)
	} else if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %04o, want 0600", perm)
	}
}

// The force path carries CreateTemp's 0600 through to the destination
// even on a fresh create, with no temp leftovers.
func TestWriteAttachmentFileForceFreshCreateMode0600(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "a.bin")
	if err := writeAttachmentFile(out, []byte("hello"), true); err != nil {
		t.Fatalf("force create: %v", err)
	}
	if got, _ := os.ReadFile(out); string(got) != "hello" {
		t.Fatalf("content = %q, want %q", got, "hello")
	}
	if fi, err := os.Lstat(out); err != nil {
		t.Fatal(err)
	} else {
		if !fi.Mode().IsRegular() {
			t.Fatalf("out mode = %v, want regular file", fi.Mode())
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("mode = %04o, want 0600", perm)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "a.bin" {
			t.Fatalf("leftover temp file %q", e.Name())
		}
	}
}

func TestWriteAttachmentFileRefusesDirectory(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "sub")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeAttachmentFile(out, []byte("x"), true); err == nil {
		t.Fatal("expected refusal to overwrite a directory")
	}
}

func TestWriteAttachmentFileTrustedSymlinkedParent(t *testing.T) {
	for _, force := range []bool{false, true} {
		dir := t.TempDir()
		real := filepath.Join(dir, "real")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(real, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		out := filepath.Join(link, "a.bin")
		if force {
			if err := os.WriteFile(out, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := writeAttachmentFile(out, []byte("x"), force); err != nil {
			t.Fatalf("force=%v: trusted symlinked parent: %v", force, err)
		}
		if got, err := os.ReadFile(filepath.Join(real, "a.bin")); err != nil || string(got) != "x" {
			t.Fatalf("force=%v: content=%q, err=%v", force, got, err)
		}
	}
}

// Source-entry substitution is outside the trusted-directory guarantee, but
// the production commit must never chmod or write through the substituted link.
func TestCommitAttachmentTempSourceSwapLeavesOutsideTargetUntouched(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside.bin")
	if err := os.WriteFile(target, []byte("secret"), 0o750); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	tmp, err := os.CreateTemp(dir, ".attachment-get-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write([]byte("download")); err != nil {
		tmp.Close()
		t.Fatal(err)
	}
	if err := os.Remove(tmp.Name()); err != nil {
		tmp.Close()
		t.Skipf("open-file replacement unavailable: %v", err)
	}
	if err := os.Symlink(target, tmp.Name()); err != nil {
		tmp.Close()
		t.Skipf("symlinks unavailable: %v", err)
	}
	out := filepath.Join(dir, "out.bin")
	if err := commitAttachmentTemp(tmp, out); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "secret" {
		t.Fatalf("outside bytes=%q, err=%v", got, err)
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != before.Mode() {
		t.Fatalf("outside mode changed: %v -> %v", before.Mode(), after.Mode())
	}
	// Demonstrate the documented limitation rather than claiming source isolation.
	if fi, err := os.Lstat(out); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected substituted source link, info=%v, err=%v", fi, err)
	}
}
