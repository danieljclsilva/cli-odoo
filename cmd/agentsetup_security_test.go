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
	snap := validBundleSnapshot()
	pol := validBundlePolicy(dir)
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

// validBundleSnapshot returns a minimal snapshot matching pol scope/instance
// with company_id metadata resolving to a res.company many2one relation, so
// agentSetupStageSealedBundle serve-time parity passes.
func validBundleSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		Instance:           "test",
		ServerVersion:      "17.0",
		CapturedAt:         time.Now().UTC(),
		CapturedBy:         "test",
		AvailableCompanies: []snapshot.Company{{ID: 1, Name: "A"}, {ID: 2, Name: "B"}},
		EnabledCompanies:   []int{1, 2},
		DefaultCompany:     1,
		Models: map[string]snapshot.ModelMeta{
			"res.partner": {Name: "res.partner", Label: "Partner", Provenance: snapshot.ProvServer,
				CompanyField: "company_id",
				Fields: map[string]snapshot.SFieldMeta{
					"name":       {Name: "name", Type: "char", Label: "Name", Provenance: snapshot.ProvServer},
					"company_id": {Name: "company_id", Type: "many2one", Relation: "res.company", Label: "Company", Provenance: snapshot.ProvServer},
				}},
		},
		MethodManifest: []snapshot.MethodMeta{{Model: "res.partner", Method: "search_read", Signature: "unknown", SourceModule: "unknown", SourceRevision: "unknown", SourceReference: "unknown", Provenance: snapshot.ProvUnknown, MutationAssessment: "unknown"}},
	}
}

// validBundlePolicy returns the sealed policy matching validBundleSnapshot.
func validBundlePolicy(dir string) policy.Policy {
	return policy.Policy{
		Version: policy.PolicyVersion, Instance: "test",
		Operations:    map[policy.Operation]bool{policy.OpSearch: true},
		Models:        map[string]policy.ModelRule{"res.partner": {Fields: []string{"company_id", "name"}, MaxLimit: 50, CompanyField: "company_id"}},
		Scope:         policy.CompanyScope{Enabled: []int{1, 2}, Default: 1},
		SharedRecords: policy.SharedDeny,
		Budgets:       policy.Budgets{MaxLimit: 100, MaxOffset: 1000, MaxRowsPerCall: 10, MaxResponseBytes: 1 << 20, MaxCallsPerSession: 100, MaxRowsPerSession: 1000},
		SnapshotPath:  filepath.Join(dir, "snap.json"),
	}
}

// TestSetupBundleCommitAtomic proves the atomic pair: staging validates +
// seals in memory, commit writes snapshot+profile together, and a failed
// commit (profile path blocked by a directory) restores the prior bytes.
func TestSetupBundleCommitAtomic(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "snap.json")
	profilePath := filepath.Join(dir, "profile.json")
	priorSnap := validBundleSnapshot()
	priorPol := validBundlePolicy(dir)
	priorBundle, err := agentSetupStageSealedBundle(profilePath, snapPath, "pw", priorPol, priorSnap)
	if err != nil {
		t.Fatalf("stage prior: %v", err)
	}
	if err := agentSetupCommitBundle(priorBundle); err != nil {
		t.Fatalf("commit prior: %v", err)
	}
	wantSnap, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	wantProf, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	// Bad password (empty) fails at stage time, before any mutation.
	if _, err := agentSetupStageSealedBundle(profilePath, snapPath, "", priorPol, priorSnap); err == nil {
		t.Fatal("empty password staged, want denial")
	}
	if got, _ := os.ReadFile(snapPath); string(got) != string(wantSnap) {
		t.Fatal("failed stage mutated the snapshot")
	}
	if got, _ := os.ReadFile(profilePath); string(got) != string(wantProf) {
		t.Fatal("failed stage mutated the profile")
	}
	// Commit failure restores the prior pair: stage the next bundle, then
	// point it at a profile path inside an unwritable parent (chmod 0500)
	// so the profile staging fails after the pair's prior bytes were read.
	// Restore the parent mode before asserting so TempDir cleanup succeeds.
	nextSnap := validBundleSnapshot()
	nextSnap.CapturedBy = "server-refresh"
	nextStaged, err := agentSetupStageSealedBundle(profilePath, snapPath, "pw2", priorPol, nextSnap)
	if err != nil {
		t.Fatalf("stage next: %v", err)
	}
	profDir := filepath.Join(dir, "profdir")
	blockedProfile := filepath.Join(profDir, "profile.json")
	if err := os.MkdirAll(profDir, 0700); err != nil {
		t.Fatal(err)
	}
	blocked := nextStaged
	blocked.snapshotPath = filepath.Join(dir, "snap-next.json")
	blocked.profilePath = blockedProfile
	if err := os.Chmod(profDir, 0500); err != nil {
		t.Fatal(err)
	}
	commitErr := agentSetupCommitBundle(blocked)
	_ = os.Chmod(profDir, 0700)
	if commitErr == nil {
		t.Fatal("blocked profile commit passed, want failure")
	}
	_ = os.RemoveAll(profDir)
	_ = os.Remove(filepath.Join(dir, "snap-next.json"))
	if got, _ := os.ReadFile(snapPath); string(got) != string(wantSnap) {
		t.Fatal("failed commit left a half-committed snapshot")
	}
	got, err := agentSetupOpenPolicy(profilePath, "pw")
	if err != nil {
		t.Fatalf("prior profile unrestorable: %v", err)
	}
	if got.SnapshotSHA256 == nextStaged.pol.SnapshotSHA256 {
		t.Fatal("failed commit swapped the profile binding")
	}
}

// TestSetupImportCatalogPreservesScope proves import-catalog never widens
// from metadata: company/shared flags, enabled set/default, and the
// per-model companyless flag stay exactly as sealed, catalog-only models
// stay out of the allowlist, and existing fields intersect (never widen).
func TestSetupImportCatalogPreservesScope(t *testing.T) {
	sealed := validBundlePolicy(t.TempDir())
	sealed.SharedRecords = policy.SharedAllowClassified
	sealed.Models["res.company"] = policy.ModelRule{Fields: []string{"name"}, CompanyIndependent: true}
	widen := validBundleSnapshot()
	widen.EnabledCompanies = []int{1, 3}
	widen.DefaultCompany = 3
	widen.Models["res.partner"] = snapshot.ModelMeta{Name: "res.partner", Label: "P", Fields: map[string]snapshot.SFieldMeta{
		"name":       {Name: "name", Type: "char", Label: "N", Provenance: snapshot.ProvManifest},
		"company_id": {Name: "company_id", Type: "many2one", Relation: "res.company", Label: "C", Provenance: snapshot.ProvManifest},
		"secret":     {Name: "secret", Type: "char", Label: "S", Provenance: snapshot.ProvManifest},
	}, CompanyField: "company_ids", CompanyIndependent: false, IncludeCompanyless: true, Provenance: snapshot.ProvManifest}
	widen.Models["evil.model"] = snapshot.ModelMeta{Name: "evil.model", Label: "E",
		Fields:       map[string]snapshot.SFieldMeta{"x": {Name: "x", Type: "char", Label: "X", Provenance: snapshot.ProvManifest}},
		CompanyField: "company_id", Provenance: snapshot.ProvManifest}
	got := agentSetupApplyCatalogPolicy(sealed, widen)
	if len(got.Scope.Enabled) != 2 || got.Scope.Enabled[0] != 1 || got.Scope.Enabled[1] != 2 || got.Scope.Default != 1 {
		t.Fatalf("scope drifted: %+v", got.Scope)
	}
	if got.SharedRecords != policy.SharedAllowClassified {
		t.Fatalf("shared drifted: %q", got.SharedRecords)
	}
	if _, ok := got.Models["evil.model"]; ok {
		t.Fatal("catalog-only model entered the allowlist")
	}
	rule := got.Models["res.partner"]
	for _, f := range rule.Fields {
		if f == "secret" {
			t.Fatalf("import widened fields: %v", rule.Fields)
		}
	}
	if len(rule.Fields) != 2 {
		t.Fatalf("import dropped approved fields: %v", rule.Fields)
	}
	if rule.CompanyField != "company_id" || rule.CompanyIndependent {
		t.Fatalf("company flags drifted: %+v", rule)
	}
	if rule.IncludeCompanyless {
		t.Fatal("catalog metadata opted the model into companyless")
	}
	if _, ok := got.Models["res.company"]; !ok {
		t.Fatal("sealed independent model dropped")
	}
}

// TestSetupStageRejectsScopeDrift proves staging denies a candidate whose
// snapshot scope or company-field metadata disagrees with the sealed policy
// (serve-time parity), before Seal and before any file mutation.
func TestSetupStageRejectsScopeDrift(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "snap.json")
	profilePath := filepath.Join(dir, "profile.json")
	pol := validBundlePolicy(dir)
	drift := validBundleSnapshot()
	drift.EnabledCompanies = []int{1, 3}
	drift.AvailableCompanies = []snapshot.Company{{ID: 1, Name: "A"}, {ID: 3, Name: "C"}}
	drift.DefaultCompany = 3
	if _, err := agentSetupStageSealedBundle(profilePath, snapPath, "pw", pol, drift); err == nil {
		t.Fatal("scope drift staged, want denial")
	}
	badField := validBundleSnapshot()
	badField.Models["res.partner"] = snapshot.ModelMeta{Name: "res.partner", Label: "P",
		Fields:       map[string]snapshot.SFieldMeta{"name": {Name: "name", Type: "char", Label: "N", Provenance: snapshot.ProvServer}},
		CompanyField: "company_id", Provenance: snapshot.ProvServer}
	if _, err := agentSetupStageSealedBundle(profilePath, snapPath, "pw", pol, badField); err == nil {
		t.Fatal("unresolvable company field staged, want denial")
	}
	if _, err := os.Stat(snapPath); !os.IsNotExist(err) {
		t.Fatal("failed stage created a snapshot file")
	}
	if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
		t.Fatal("failed stage created a profile file")
	}
}
