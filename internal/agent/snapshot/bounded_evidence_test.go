package snapshot

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// writeRawBytes writes bytes verbatim (no validation) for over-cap fixtures.
func writeRawBytes(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return p
}

func TestReadBoundedFileSymlinkRefused(t *testing.T) {
	// A symlink is refused before any open can follow it: Lstat names the
	// refusal without blocking or reading the target.
	dir := t.TempDir()
	target := writeRawBytes(t, dir, "target.json", []byte(`{"ok":true}`))
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("fixture symlink: %v", err)
	}
	if _, err := ReadBoundedFile(link, 1<<20, "snapshot"); err == nil {
		t.Fatal("symlink read succeeded, want refusal")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink error = %v, want symlink refusal", err)
	}
}

func TestReadBoundedFileNonRegularRefused(t *testing.T) {
	// A directory (non-regular) is refused before any open/read runs.
	dir := t.TempDir()
	if _, err := ReadBoundedFile(dir, 1<<20, "snapshot"); err == nil {
		t.Fatal("directory read succeeded, want refusal")
	} else if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory error = %v, want non-regular refusal", err)
	}
}

func TestReadBoundedFileFIFORefusedWithoutBlocking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("FIFO fixture unavailable on windows")
	}
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := mkfifo(fifo); err != nil {
		t.Skipf("FIFO fixture unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadBoundedFile(fifo, 1<<20, "snapshot")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO read succeeded, want refusal")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO error = %v, want non-regular refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FIFO read blocked: must refuse without blocking")
	}
}

func TestReadBoundedFileLimitPlusOneDenied(t *testing.T) {
	// cap+1 bytes deny over-cap instead of allocating unboundedly: exactly
	// cap reads fine, cap+1 fails closed.
	dir := t.TempDir()
	const limit = int64(64)
	ok := writeRawBytes(t, dir, "ok.bin", []byte(strings.Repeat("a", int(limit))))
	if got, err := ReadBoundedFile(ok, limit, "snapshot"); err != nil {
		t.Fatalf("at-cap read: %v", err)
	} else if int64(len(got)) != limit {
		t.Fatalf("at-cap len = %d, want %d", len(got), limit)
	}
	over := writeRawBytes(t, dir, "over.bin", []byte(strings.Repeat("a", int(limit)+1)))
	if _, err := ReadBoundedFile(over, limit, "snapshot"); err == nil {
		t.Fatal("cap+1 read succeeded, want over-cap denial")
	} else if !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("cap+1 error = %v, want over-cap denial", err)
	}
}

func TestLoadSymlinkAndOverCapDenied(t *testing.T) {
	// The public Load entry inherits the same refusals: a symlinked
	// snapshot and a snapshot one byte past MaxFileBytes both fail closed
	// without decoding.
	dir := t.TempDir()
	good := writeTestSnapshot(t, validTestSnapshot())
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(good, link); err != nil {
		t.Fatalf("fixture symlink: %v", err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("Load(symlink) succeeded, want refusal")
	}
	big := make([]byte, int(MaxFileBytes)+1)
	for i := range big {
		big[i] = 'x'
	}
	if _, err := Load(writeRawBytes(t, dir, "big.json", big)); err == nil {
		t.Fatal("Load(over-cap) succeeded, want denial")
	}
}
