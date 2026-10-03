package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljclsilva/cli-odoo/internal/agent/lock"
)

// sealTestProfile seals payload under password and writes the envelope to
// dir/profile.json, returning its path.
func sealTestProfile(t *testing.T, dir, password string, payload []byte) string {
	t.Helper()
	prof, err := lock.Seal(payload, password)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	b, err := json.Marshal(prof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSetupProfileLockedDetects(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent.json")
	if agentSetupProfileLocked(missing) {
		t.Fatal("missing file: expected unlocked")
	}
	plain := filepath.Join(dir, "plain.json")
	if err := os.WriteFile(plain, []byte(`{"x":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if agentSetupProfileLocked(plain) {
		t.Fatal("unparseable file: expected unlocked (first-setup path stays open)")
	}
	locked := sealTestProfile(t, dir, "pw", []byte(`{"v":1}`))
	// sealTestProfile writes profile.json; use a second dir for the locked
	// path assertion to keep the helper simple.
	if !agentSetupProfileLocked(locked) {
		t.Fatal("sealed envelope: expected locked")
	}
}

func TestSetupRequireCurrentPassword(t *testing.T) {
	dir := t.TempDir()
	payload := []byte(`{"v":1}`)
	locked := sealTestProfile(t, dir, "correct", payload)
	prompter := &agentSetupPrompter{r: nil}
	readOK := func(confirm bool) (string, error) { return "correct", nil }
	got, reset, err := agentSetupRequireCurrentPassword(locked, false, readOK, prompter)
	if err != nil || reset || got != "correct" {
		t.Fatalf("current password: got %q,%v,%v", got, reset, err)
	}
	readBad := func(confirm bool) (string, error) { return "wrong", nil }
	if _, _, err := agentSetupRequireCurrentPassword(locked, false, readBad, prompter); err == nil {
		t.Fatal("wrong current password: expected denial")
	}
	// First setup (no file) passes through without a password.
	if _, _, err := agentSetupRequireCurrentPassword(filepath.Join(dir, "absent.json"), false, readBad, prompter); err != nil {
		t.Fatalf("first setup: %v", err)
	}
}

func TestSetupSecureReplace0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := agentSetupSecureReplace(path, []byte("new")); err != nil {
		t.Fatalf("SecureReplace: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "new" {
		t.Fatalf("content = %q, want new", b)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode = %04o, want 0600 (never preserve 0644)", st.Mode().Perm())
	}
	// A symlink at the destination is replaced, never followed.
	outside := filepath.Join(dir, "outside.txt")
	if err := os.WriteFile(outside, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if err := agentSetupSecureReplace(link, []byte("replaced")); err != nil {
		t.Fatalf("SecureReplace(link): %v", err)
	}
	kept, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != "target" {
		t.Fatalf("symlink followed: target now %q", kept)
	}
	if !strings.HasPrefix(func() string { b, _ := os.ReadFile(link); return string(b) }(), "replaced") {
		t.Fatal("link path was not replaced")
	}
}
