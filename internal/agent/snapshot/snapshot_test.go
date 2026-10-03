package snapshot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// validTestSnapshot returns a minimal snapshot that passes validation:
// discovery (available) kept distinct from authorization (enabled+default).
func validTestSnapshot() Snapshot {
	return Snapshot{
		Instance:      "test",
		ServerVersion: "17.0",
		CapturedAt:    time.Now().UTC(),
		AvailableCompanies: []Company{
			{ID: 1, Name: "Main"},
			{ID: 2, Name: "Branch"},
			{ID: 3, Name: "Dormant"},
		},
		EnabledCompanies: []int{1, 2},
		DefaultCompany:   1,
		Models: map[string]ModelMeta{
			"res.partner": {
				Name:               "res.partner",
				Label:              "Contact",
				Fields:             map[string]SFieldMeta{"name": {Name: "name", Type: "char", Label: "Name"}},
				CompanyField:       "company_id",
				CompanyIndependent: false,
				Provenance:         ProvServer,
			},
		},
		MethodManifest: []string{"search_read", "read"},
	}
}

// writeTestSnapshot persists s to a temp file and returns its path.
func writeTestSnapshot(t *testing.T, s Snapshot) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snap.json")
	if err := Write(path, s); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return path
}

func TestLoadRoundTrip(t *testing.T) {
	want := validTestSnapshot()
	got, err := Load(writeTestSnapshot(t, want))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Instance != want.Instance || got.DefaultCompany != want.DefaultCompany {
		t.Fatalf("round trip changed identity: %+v", got)
	}
	if len(got.AvailableCompanies) != 3 || len(got.EnabledCompanies) != 2 {
		t.Fatalf("round trip changed company sets: %+v", got)
	}
	m, ok := got.Models["res.partner"]
	if !ok || m.Fields["name"].Type != "char" || m.Provenance != ProvServer {
		t.Fatalf("round trip changed model metadata: %+v", got.Models)
	}
}

func TestLoadVersionMismatchDenies(t *testing.T) {
	// A file written for any other version is refused with no legacy
	// fallback, even if the body is otherwise valid.
	for _, version := range []string{"0", "2", "99"} {
		body := `{"version":` + version + `,"instance":"test",` +
			`"server_version":"17.0","captured_at":"2026-01-01T00:00:00Z",` +
			`"available_companies":[{"id":1,"name":"A"},{"id":2,"name":"B"}],` +
			`"enabled_companies":[1,2],"default_company":1,` +
			`"models":{"res.partner":{"name":"res.partner","label":"C",` +
			`"fields":{"name":{"name":"name","type":"char","relation":"","label":"N"}},` +
			`"company_field":"company_id","company_independent":false,"provenance":"server"}},` +
			`"method_manifest":[]}`
		path := filepath.Join(t.TempDir(), "snap.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("version %s: expected deny, got allow", version)
		}
	}
	// A missing version (zero value) denies too.
	missing := `{"instance":"test"}`
	path := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(path, []byte(missing), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("missing version: expected deny, got allow")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	// Deny-on-unknown: a typo'd hand edit fails closed instead of silently
	// changing meaning.
	path := writeTestSnapshot(t, validTestSnapshot())
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doctored := strings.Replace(string(b), `"default_company"`, `"default_company_typo"`, 1)
	if err := os.WriteFile(path, []byte(doctored), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown field: expected deny, got allow")
	}
}

func TestLoadScopeConsistency(t *testing.T) {
	cases := map[string]func(*Snapshot){
		"single enabled company": func(s *Snapshot) {
			s.EnabledCompanies = []int{1}
		},
		"default outside enabled": func(s *Snapshot) {
			s.DefaultCompany = 3
		},
		"enabled outside available": func(s *Snapshot) {
			s.EnabledCompanies = []int{1, 99}
		},
		"duplicate enabled": func(s *Snapshot) {
			s.EnabledCompanies = []int{1, 1, 2}
		},
		"non-positive enabled": func(s *Snapshot) {
			s.EnabledCompanies = []int{-1, 0}
			s.DefaultCompany = -1
		},
		"zero enabled": func(s *Snapshot) {
			s.EnabledCompanies = []int{0, 2}
		},
		"empty instance": func(s *Snapshot) {
			s.Instance = ""
		},
		"no models": func(s *Snapshot) {
			s.Models = map[string]ModelMeta{}
		},
		"bad provenance": func(s *Snapshot) {
			m := s.Models["res.partner"]
			m.Provenance = "auto"
			s.Models["res.partner"] = m
		},
		"empty provenance": func(s *Snapshot) {
			m := s.Models["res.partner"]
			m.Provenance = ""
			s.Models["res.partner"] = m
		},
		"key mismatches entry name": func(s *Snapshot) {
			m := s.Models["res.partner"]
			m.Name = "res.users"
			s.Models["res.partner"] = m
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := validTestSnapshot()
			mutate(&s)
			// Write must refuse invalid snapshots too, so persist by hand
			// with the valid envelope shape and let Load deny.
			valid := validTestSnapshot()
			if err := Write(filepath.Join(t.TempDir(), "ok.json"), valid); err != nil {
				t.Fatalf("control Write: %v", err)
			}
			path := writeRawSnapshot(t, s)
			if _, err := Load(path); err == nil {
				t.Fatalf("%s: expected deny, got allow", name)
			}
		})
	}
}

// writeRawSnapshot marshals s with the current FormatVersion without
// validation, so Load (not Write) delivers the verdict.
func writeRawSnapshot(t *testing.T, s Snapshot) string {
	t.Helper()
	f := snapshotFile{
		Version: FormatVersion, Instance: s.Instance,
		ServerVersion: s.ServerVersion, CapturedAt: s.CapturedAt,
		CapturedBy:         s.CapturedBy,
		AvailableCompanies: s.AvailableCompanies, EnabledCompanies: s.EnabledCompanies,
		DefaultCompany: s.DefaultCompany, Models: s.Models, MethodManifest: s.MethodManifest,
	}
	path := filepath.Join(t.TempDir(), "raw.json")
	if err := os.WriteFile(path, mustMarshal(f), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiscoverableNotExecutable(t *testing.T) {
	s, err := Load(writeTestSnapshot(t, validTestSnapshot()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Allowlisted model metadata is discoverable through the policy view.
	mv, ok := s.Model("res.partner")
	if !ok {
		t.Fatal("Model(res.partner): expected ok")
	}
	fm, ok := mv.Field("name")
	if !ok || fm.Type != "char" {
		t.Fatalf("Field(name): got %+v, %v", fm, ok)
	}
	// MethodManifest entries are informational only: they must NOT resolve
	// as models. Discovery is not execution.
	for _, method := range s.MethodManifest {
		if _, ok := s.Model(method); ok {
			t.Fatalf("Model(%q): manifest method must not resolve as a model", method)
		}
	}
	// Unknown and malformed names resolve to nothing.
	for _, name := range []string{"res.users", "", "  ", "../x", "res partner"} {
		if _, ok := s.Model(name); ok {
			t.Fatalf("Model(%q): expected miss, got hit", name)
		}
	}
	if _, ok := mv.Field("nope"); ok {
		t.Fatal("Field(nope): expected miss, got hit")
	}
	if _, ok := mv.Field("name; DROP"); ok {
		t.Fatal("Field(malicious): expected miss, got hit")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadTrailingDataDenies(t *testing.T) {
	path := writeTestSnapshot(t, validTestSnapshot())
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '{', '}'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("trailing data: expected deny, got allow")
	}
}

func writeCatalogFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestImportBoundedCatalogMixedProvenance(t *testing.T) {
	// A human-transcribed catalog with mixed provenance imports bounded:
	// unstated provenance defaults explicitly to unknown, labels are
	// preserved, and the display-only Executable flag does not authorize.
	body := `{"instance":"test","server_version":"17.0",` +
		`"available_companies":[{"id":1,"name":"A"},{"id":2,"name":"B"}],` +
		`"enabled_companies":[1,2],"default_company":1,` +
		`"models":{` +
		`"res.partner":{"label":"Contact","provenance":"manifest","executable":false,` +
		`"company_field":"company_id","fields":{` +
		`"name":{"type":"char","label":"Name","provenance":"manifest"},` +
		`"email":{"type":"char","label":"Email"}}},` +
		`"x.custom":{"label":"Custom","executable":false,"fields":{` +
		`"x_note":{"type":"text","label":"Note"}}}}` +
		`,"method_manifest":["search_read"]}`
	s, err := ImportCatalog(writeCatalogFile(t, body))
	if err != nil {
		t.Fatalf("ImportCatalog: %v", err)
	}
	pm, ok := s.Models["res.partner"]
	if !ok || pm.Provenance != ProvManifest {
		t.Fatalf("res.partner provenance = %q, want manifest", pm.Provenance)
	}
	if prov, ok := s.FieldProvenanceOf("res.partner", "name"); !ok || prov != ProvManifest {
		t.Fatalf("name provenance = %q,%v, want manifest,true", prov, ok)
	}
	// Unstated email + custom provenance default explicitly to unknown.
	if prov, ok := s.FieldProvenanceOf("res.partner", "email"); !ok || prov != ProvUnknown {
		t.Fatalf("email provenance = %q,%v, want unknown,true", prov, ok)
	}
	if prov, ok := s.ProvenanceOf("x.custom"); !ok || prov != ProvUnknown {
		t.Fatalf("x.custom provenance = %q,%v, want unknown,true", prov, ok)
	}
	// An unapproved custom model is describable here but never executable
	// by this flag: IsExecutable is display-only (false), and the broker
	// (not this package) denies read/call via Policy.Models.
	if s.IsExecutable("x.custom") {
		t.Fatal("IsExecutable(x.custom): got true, want false (display-only)")
	}
	if s.IsExecutable("res.partner") {
		t.Fatal("IsExecutable(res.partner): got true, want false")
	}
	if _, ok := s.Model("search_read"); ok {
		t.Fatal("manifest method resolved as a model")
	}
	if mprov, ok := s.ProvenanceOf("res.partner"); !ok || mprov != ProvManifest {
		t.Fatalf("ProvenanceOf(res.partner) = %q,%v", mprov, ok)
	}
	// The imported snapshot round-trips through Write/Load unchanged.
	path := filepath.Join(t.TempDir(), "imported.json")
	if err := Write(path, s); err != nil {
		t.Fatalf("Write(imported): %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load(imported): %v", err)
	}
	if prov, _ := got.ProvenanceOf("x.custom"); prov != ProvUnknown {
		t.Fatalf("round trip x.custom provenance = %q", prov)
	}
}

func TestImportCatalogBounds(t *testing.T) {
	// Unknown fields in the catalog reject.
	if _, err := ImportCatalog(writeCatalogFile(t, `{"instance":"x","bogus":1}`)); err == nil {
		t.Fatal("unknown catalog field: expected deny, got allow")
	}
	// Trailing data rejects.
	p := writeCatalogFile(t, `{"instance":"x"}garbage`)
	if _, err := ImportCatalog(p); err == nil {
		t.Fatal("trailing catalog data: expected deny, got allow")
	}
	// Bad provenance rejects.
	bad := `{"instance":"test","available_companies":[{"id":1,"name":"A"},{"id":2,"name":"B"}],` +
		`"enabled_companies":[1,2],"default_company":1,` +
		`"models":{"res.partner":{"provenance":"auto","fields":{"name":{"type":"char"}}}}}`
	if _, err := ImportCatalog(writeCatalogFile(t, bad)); err == nil {
		t.Fatal("bad provenance: expected deny, got allow")
	}
	// Over-cap model count rejects (build the body programmatically).
	var sb strings.Builder
	sb.WriteString(`{"instance":"test","available_companies":[{"id":1,"name":"A"},{"id":2,"name":"B"}],` +
		`"enabled_companies":[1,2],"default_company":1,"models":{`)
	for i := range MaxCatalogModels + 1 {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`"overcap.model.` + strconv.Itoa(i) + `":{"fields":{"f":{"type":"char"}}}`)
	}
	sb.WriteString(`}}`)
	if _, err := ImportCatalog(writeCatalogFile(t, sb.String())); err == nil {
		t.Fatal("over-cap models: expected deny, got allow")
	}
}

func TestImportManifestInformationalOnly(t *testing.T) {
	// A bounded method list imports for inspection; entries never resolve
	// as models and no Execute path takes names from this list.
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{"methods":["search_read","read"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	methods, err := ImportManifest(path)
	if err != nil {
		t.Fatalf("ImportManifest: %v", err)
	}
	if len(methods) != 2 || methods[0] != "search_read" {
		t.Fatalf("methods = %v", methods)
	}
	s := validTestSnapshot()
	for _, m := range methods {
		if _, ok := s.Model(m); ok {
			t.Fatalf("manifest entry %q resolved as a model", m)
		}
		if s.IsExecutable(m) {
			t.Fatalf("manifest entry %q executable", m)
		}
	}
	// Unknown fields reject; trailing data rejects.
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"methods":[],"bogus":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportManifest(bad); err == nil {
		t.Fatal("unknown manifest field: expected deny, got allow")
	}
}

func TestLoadRejectsEmptyProvenance(t *testing.T) {
	// An empty model provenance always denies on Load (explicit unknown
	// required), including through the raw-envelope path.
	s := validTestSnapshot()
	m := s.Models["res.partner"]
	m.Provenance = ""
	s.Models["res.partner"] = m
	if _, err := Load(writeRawSnapshot(t, s)); err == nil {
		t.Fatal("empty provenance: expected deny, got allow")
	}
	// A snapshot missing CapturedBy still loads (back-compat: Build always
	// sets it, Load does not require it), while Executable defaults false.
	path := writeTestSnapshot(t, validTestSnapshot())
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.IsExecutable("res.partner") {
		t.Fatal("IsExecutable default: got true, want false")
	}
}

func TestWriteIsAtomicSecure0600(t *testing.T) {
	// Write replaces atomically at 0600 and never preserves a looser mode.
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, validTestSnapshot()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode = %04o, want 0600", st.Mode().Perm())
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load(written): %v", err)
	}
	// No staging files leak.
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), ".tmp-") {
			t.Fatalf("staging file leaked: %s", f.Name())
		}
	}
}

func TestCanonicalDigestDeterminismAndMismatch(t *testing.T) {
	// Same value digests equally across calls; any mutation (companies,
	// fields, relations, company metadata, provenance) digests differently.
	// This is the broker's recompute-and-compare binding: a tampered
	// snapshot never matches the sealed Policy.SnapshotSHA256.
	base := validTestSnapshot()
	a, err := CanonicalDigest(base)
	if err != nil {
		t.Fatalf("CanonicalDigest: %v", err)
	}
	if len(a) != 64 {
		t.Fatalf("digest = %q, want 64 hex chars", a)
	}
	b, err := CanonicalDigest(base)
	if err != nil || a != b {
		t.Fatalf("determinism: %q vs %q, err=%v", a, b, err)
	}
	mutants := map[string]func(*Snapshot){
		"default company": func(s *Snapshot) {
			s.EnabledCompanies = []int{1, 3}
			s.DefaultCompany = 3
		},
		"field set": func(s *Snapshot) {
			m := s.Models["res.partner"]
			m.Fields["email"] = SFieldMeta{Name: "email", Type: "char", Label: "Email"}
			s.Models["res.partner"] = m
		},
		"relation": func(s *Snapshot) {
			m := s.Models["res.partner"]
			m.Fields["company_id"] = SFieldMeta{Name: "company_id", Type: "many2one", Relation: "res.company", Label: "Company"}
			s.Models["res.partner"] = m
		},
		"company field": func(s *Snapshot) {
			m := s.Models["res.partner"]
			m.CompanyField = "x_company_id"
			s.Models["res.partner"] = m
		},
		"provenance": func(s *Snapshot) {
			m := s.Models["res.partner"]
			m.Provenance = ProvManifest
			s.Models["res.partner"] = m
		},
	}
	for name, mutate := range mutants {
		t.Run(name, func(t *testing.T) {
			s := validTestSnapshot()
			s.CapturedAt = base.CapturedAt
			mutate(&s)
			got, err := CanonicalDigest(s)
			if err != nil {
				t.Fatalf("CanonicalDigest: %v", err)
			}
			baseAt := validTestSnapshot()
			baseAt.CapturedAt = base.CapturedAt
			want, _ := CanonicalDigest(baseAt)
			if got == want {
				t.Fatalf("mutation %q undetected: digest %q unchanged", name, got)
			}
		})
	}
}

func TestValidateRejectsNonPositiveScopeMirror(t *testing.T) {
	// Snapshot validate() mirrors the policy scope rule (positive unique
	// IDs, default in enabled) BEFORE any server use.
	for name, scope := range map[string]struct {
		enabled []int
		def     int
	}{
		"duplicates": {[]int{1, 1, 2}, 1},
		"negative":   {[]int{-1, 0}, -1},
		"zero":       {[]int{0, 2}, 2},
	} {
		t.Run(name, func(t *testing.T) {
			s := validTestSnapshot()
			s.EnabledCompanies = scope.enabled
			s.DefaultCompany = scope.def
			if _, err := Load(writeRawSnapshot(t, s)); err == nil {
				t.Fatalf("%s scope: expected deny, got allow", name)
			}
			if err := Write(filepath.Join(t.TempDir(), "bad.json"), s); err == nil {
				t.Fatalf("%s scope: Write accepted invalid snapshot", name)
			}
		})
	}
}
