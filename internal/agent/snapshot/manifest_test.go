package snapshot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func manifestFixture() MethodMeta {
	return MethodMeta{Model: "x.logo.request", Method: "action_generate",
		Signature: "(self)", SourceModule: "logo_station", SourceRevision: "abc123",
		SourceReference: "addons/logo_station/models/request.py:42", Provenance: ProvManifest,
		Description: "Generate a production request", MutationAssessment: "likely_mutating",
		AssessmentEvidence: "Source calls create() on a production record"}
}

func TestStructuredManifestStrictBounds(t *testing.T) {
	valid := manifestFixture()
	cases := map[string]func(*MethodMeta){
		"bad model":              func(m *MethodMeta) { m.Model = "../x" },
		"bad method":             func(m *MethodMeta) { m.Method = "write()" },
		"missing signature":      func(m *MethodMeta) { m.Signature = "" },
		"missing module":         func(m *MethodMeta) { m.SourceModule = "" },
		"missing revision":       func(m *MethodMeta) { m.SourceRevision = "" },
		"missing reference":      func(m *MethodMeta) { m.SourceReference = "" },
		"control character":      func(m *MethodMeta) { m.Description = "bad\x1b[0m" },
		"oversized signature":    func(m *MethodMeta) { m.Signature = strings.Repeat("x", 4097) },
		"bad provenance":         func(m *MethodMeta) { m.Provenance = "verified" },
		"bad assessment":         func(m *MethodMeta) { m.MutationAssessment = "safe" },
		"unsupported assessment": func(m *MethodMeta) { m.AssessmentEvidence = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := valid
			mutate(&m)
			p := writeCatalogFile(t, string(mustMarshal(map[string]any{"manifest_version": 1, "methods": []MethodMeta{m}})))
			if _, err := ImportManifest(p); err == nil {
				t.Fatal("invalid entry accepted")
			}
		})
	}
	for _, body := range []string{
		`{"manifest_version":1,"methods":["read"]}`,
		`{"manifest_version":2,"methods":[]}`,
		`{"methods":[]}`,
		`{"manifest_version":1,"methods":null}`,
		`{"manifest_version":1,"methods":[]} {}`,
	} {
		if _, err := ImportManifest(writeCatalogFile(t, body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	data := string(mustMarshal(map[string]any{"manifest_version": 1, "methods": []MethodMeta{valid}}))
	data = strings.Replace(data, `"model":`, `"executable":true,"model":`, 1)
	if _, err := ImportManifest(writeCatalogFile(t, data)); err == nil {
		t.Fatal("execution flag accepted")
	}
	if err := validateMethods([]MethodMeta{valid, valid}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := validateMethods(make([]MethodMeta, MaxCatalogMethods+1)); err == nil {
		t.Fatal("over-cap accepted")
	}
	// Distinct overriding modules may describe the same model/method.
	override := valid
	override.SourceModule = "logo_station_override"
	if err := validateMethods([]MethodMeta{valid, override}); err != nil {
		t.Fatal(err)
	}
}

func TestManifestSnapshotImportPreservesMetadataAndBinding(t *testing.T) {
	base := validTestSnapshot()
	path := writeTestSnapshot(t, base)
	digest, _ := CanonicalDigest(base)
	prior, _ := os.ReadFile(path)
	methods := []MethodMeta{manifestFixture()}
	got, err := ImportManifestSnapshot(path, digest, methods)
	if err != nil {
		t.Fatal(err)
	}
	want := base
	want.MethodManifest = methods
	if !reflect.DeepEqual(got, want) {
		t.Fatal("import changed metadata outside method manifest")
	}
	newDigest, _ := CanonicalDigest(got)
	if digest == newDigest {
		t.Fatal("manifest not bound by digest")
	}
	if got.IsExecutable(methods[0].Model) {
		t.Fatal("import added a model permission")
	}
	if _, err := ImportManifestSnapshot(path, strings.Repeat("0", 64), methods); err == nil {
		t.Fatal("tampered binding accepted")
	}
	after, _ := os.ReadFile(path)
	if !reflect.DeepEqual(prior, after) {
		t.Fatal("staging changed existing file")
	}
	if err := Write(path, got); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || !reflect.DeepEqual(loaded.MethodManifest, methods) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestExplicitOfflineManifestMigration(t *testing.T) {
	base := validTestSnapshot()
	legacy := legacyManifestSnapshot{Instance: base.Instance, ServerVersion: base.ServerVersion,
		CapturedAt: base.CapturedAt, CapturedBy: base.CapturedBy, AvailableCompanies: base.AvailableCompanies,
		EnabledCompanies: base.EnabledCompanies, DefaultCompany: base.DefaultCompany, Models: base.Models,
		MethodManifest: []string{"search_read", "read"}}
	digest, _ := canonicalValueDigest(legacy)
	f := struct {
		Version int `json:"version"`
		legacyManifestSnapshot
	}{1, legacy}
	b, _ := json.Marshal(f)
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("normal load accepted legacy runtime format")
	}
	methods := []MethodMeta{manifestFixture()}
	s, err := ImportManifestSnapshot(path, digest, methods)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.MethodManifest, methods) || !reflect.DeepEqual(s.Models, base.Models) {
		t.Fatal("migration lost fields or fabricated legacy method evidence")
	}
	if err := Write(path, s); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}
