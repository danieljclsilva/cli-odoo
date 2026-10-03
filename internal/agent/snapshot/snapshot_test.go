package snapshot

import (
	"encoding/json"
	"os"
	"path/filepath"
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
