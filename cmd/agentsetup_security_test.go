package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/lock"
	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
	"github.com/danieljclsilva/cli-odoo/internal/agent/workspace"
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
	if _, _, err := agentSetupRequireCurrentPassword(filepath.Join(dir, "absent.json"), false, readBad, prompter); err != nil {
		t.Fatalf("first setup: %v", err)
	}
}

func TestSetupParseModelSpecCompanyless(t *testing.T) {
	sp, err := agentSetupParseModelSpec("res.partner:name:company_id:companyless")
	if err != nil {
		t.Fatalf("companyless parse: %v", err)
	}
	if !sp.IncludeCompanyless || sp.CompanyField != "company_id" {
		t.Fatalf("companyless parse = %+v, want field+flag", sp)
	}
	// Companyless on an independent model is meaningless: reject at parse.
	if _, err := agentSetupParseModelSpec("res.partner:name:independent:companyless"); err == nil {
		t.Fatal("independent+companyless: expected rejection")
	}
	if _, err := agentSetupParseModelSpec("res.partner:name:company_id:aggregate:bogus"); err == nil {
		t.Fatal("unknown qualifier: expected rejection")
	}
	if _, err := agentSetupParseModelSpec("res.partner:name:company_id:aggregate:companyless:extra"); err == nil {
		t.Fatal("6-part spec: expected rejection")
	}
}

func TestSetupResealStampsDigest(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.json")
	snap := snapshot.Snapshot{
		Instance:           "test",
		CapturedAt:         time.Now().UTC(),
		CapturedBy:         "test",
		AvailableCompanies: []snapshot.Company{{ID: 1, Name: "A"}, {ID: 2, Name: "B"}},
		EnabledCompanies:   []int{1, 2},
		DefaultCompany:     1,
		Models: map[string]snapshot.ModelMeta{
			"res.partner": {Name: "res.partner", Label: "Partner", Provenance: snapshot.ProvServer,
				Fields: map[string]snapshot.SFieldMeta{"name": {Name: "name", Type: "char", Label: "Name", Provenance: snapshot.ProvServer}}},
		},
		MethodManifest: []string{"search_read"},
	}
	pol := policy.Policy{
		Version: policy.PolicyVersion, Instance: "test",
		Operations:    map[policy.Operation]bool{policy.OpSearch: true},
		Models:        map[string]policy.ModelRule{"res.partner": {Fields: []string{"name"}, MaxLimit: 50, CompanyField: "company_id"}},
		Scope:         policy.CompanyScope{Enabled: []int{1, 2}, Default: 1},
		SharedRecords: policy.SharedDeny,
		Budgets:       policy.Budgets{MaxLimit: 100, MaxOffset: 1000, MaxRowsPerCall: 10, MaxResponseBytes: 1 << 20, MaxCallsPerSession: 100, MaxRowsPerSession: 1000},
		SnapshotPath:  filepath.Join(dir, "snap.json"),
	}
	if err := agentSnapshotReseal(profile, "pw", pol, snap); err != nil {
		t.Fatalf("Reseal: %v", err)
	}
	got, err := agentSetupOpenPolicy(profile, "pw")
	if err != nil {
		t.Fatalf("OpenPolicy: %v", err)
	}
	want, err := snapshot.CanonicalDigest(snap)
	if err != nil {
		t.Fatalf("CanonicalDigest: %v", err)
	}
	if got.SnapshotSHA256 != want {
		t.Fatalf("SnapshotSHA256 = %q, want digest %q (reseal forgot the stamp)", got.SnapshotSHA256, want)
	}
}

func TestSetupDefaultWorkspaceNonOverlapping(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	def := DefaultAgentWorkspaceDir()
	if strings.TrimSpace(def) == "" {
		t.Fatal("default workspace dir is empty")
	}
	cfg := filepath.Join(fakeHome, ".config", "odoo-cli")
	if workspace.Overlaps(def, cfg) {
		t.Fatalf("default workspace %q overlaps config dir %q", def, cfg)
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
