package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
)

const ManifestVersion = 1

// MethodMeta is evidence for human review, never an execution permission.
// Source strings are opaque: importing or serving them never fetches a URL,
// reads source files, imports Python, or calls an Odoo method.
type MethodMeta struct {
	Model              string `json:"model"`
	Method             string `json:"method"`
	Signature          string `json:"signature"`
	SourceModule       string `json:"source_module"`
	SourceRevision     string `json:"source_revision"`
	SourceReference    string `json:"source_reference"`
	Provenance         string `json:"provenance"`
	Description        string `json:"description,omitempty"`
	MutationAssessment string `json:"mutation_assessment"`
	AssessmentEvidence string `json:"assessment_evidence,omitempty"`
}

func validateMethods(methods []MethodMeta) error {
	if len(methods) > MaxCatalogMethods {
		return fmt.Errorf("method manifest holds %d entries, over cap %d", len(methods), MaxCatalogMethods)
	}
	seen := make(map[string]bool, len(methods))
	for i, m := range methods {
		if norm, ok := policy.NormalizeName(m.Model); !ok || norm != m.Model || len(m.Model) > 128 {
			return fmt.Errorf("method manifest[%d]: invalid model", i)
		}
		if !pythonMethodName(m.Method) || len(m.Method) > 128 {
			return fmt.Errorf("method manifest[%d]: invalid method", i)
		}
		// One entry per implementation revision permits multiple addon overrides.
		key := m.Model + "\x00" + m.Method + "\x00" + m.SourceModule + "\x00" + m.SourceRevision
		if seen[key] {
			return fmt.Errorf("method manifest[%d]: duplicate implementation", i)
		}
		seen[key] = true
		for _, field := range []struct {
			name     string
			value    string
			limit    int
			required bool
		}{
			{"signature", m.Signature, 4096, true},
			{"source_module", m.SourceModule, 256, true},
			{"source_revision", m.SourceRevision, 256, true},
			{"source_reference", m.SourceReference, 2048, true},
			{"description", m.Description, 4096, false},
			{"assessment_evidence", m.AssessmentEvidence, 4096, false},
		} {
			if len(field.value) > field.limit || (field.required && strings.TrimSpace(field.value) == "") || strings.IndexFunc(field.value, unicode.IsControl) >= 0 {
				return fmt.Errorf("method manifest[%d]: invalid or over-cap %s", i, field.name)
			}
		}
		switch m.Provenance {
		case ProvServer, ProvManifest, ProvUnknown:
		default:
			return fmt.Errorf("method manifest[%d]: provenance must be server|manifest|unknown", i)
		}
		switch m.MutationAssessment {
		case "unknown":
		case "likely_read_only", "likely_mutating":
			if strings.TrimSpace(m.AssessmentEvidence) == "" {
				return fmt.Errorf("method manifest[%d]: assessment evidence required", i)
			}
		default:
			return fmt.Errorf("method manifest[%d]: invalid mutation assessment", i)
		}
	}
	return nil
}

func pythonMethodName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		if c != '_' && !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// ImportManifest strictly reads a bounded, versioned offline manifest.
func ImportManifest(path string) ([]MethodMeta, error) {
	b, err := ReadBoundedFile(path, MaxFileBytes, "manifest")
	if err != nil {
		return nil, err
	}
	var f struct {
		Version int          `json:"manifest_version"`
		Methods []MethodMeta `json:"methods"`
	}
	if err := strictManifestDecode(b, &f); err != nil {
		return nil, err
	}
	if f.Version != ManifestVersion || f.Methods == nil {
		return nil, fmt.Errorf("manifest_version must be %d and methods must be an array", ManifestVersion)
	}
	if err := validateMethods(f.Methods); err != nil {
		return nil, err
	}
	return f.Methods, nil
}

func strictManifestDecode(b []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("manifest decode (unknown fields rejected): %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("manifest: trailing data after document")
	}
	return nil
}

// legacyManifestSnapshot exists only for explicit offline migration by the
// human import command. Normal Load/serve reject v1; no legacy runtime fallback.
// Field order mirrors v1 Snapshot so its sealed canonical digest is verifiable.
type legacyManifestSnapshot struct {
	Instance           string               `json:"instance"`
	ServerVersion      string               `json:"server_version"`
	CapturedAt         time.Time            `json:"captured_at"`
	CapturedBy         string               `json:"captured_by"`
	AvailableCompanies []Company            `json:"available_companies"`
	EnabledCompanies   []int                `json:"enabled_companies"`
	DefaultCompany     int                  `json:"default_company"`
	Models             map[string]ModelMeta `json:"models"`
	MethodManifest     []string             `json:"method_manifest"`
}

// ImportManifestSnapshot replaces only method metadata in an integrity-checked
// existing snapshot. The caller must human-unlock and reseal the unchanged
// policy. v1 is accepted ONLY here for explicit migration; its unqualified
// method-name list is discarded, never converted into fabricated source facts.
func ImportManifestSnapshot(path, sealedDigest string, methods []MethodMeta) (Snapshot, error) {
	if err := validateMethods(methods); err != nil {
		return Snapshot{}, err
	}
	b, err := ReadBoundedFile(path, MaxFileBytes, "snapshot")
	if err != nil {
		return Snapshot{}, err
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &header); err != nil {
		return Snapshot{}, err
	}
	var s Snapshot
	var original any
	if header.Version == 1 {
		var f struct {
			Version int `json:"version"`
			legacyManifestSnapshot
		}
		if err := strictManifestDecode(b, &f); err != nil {
			return Snapshot{}, err
		}
		if len(f.MethodManifest) > MaxCatalogMethods {
			return Snapshot{}, fmt.Errorf("legacy method manifest exceeds cap")
		}
		original = f.legacyManifestSnapshot
		s = Snapshot{Instance: f.Instance, ServerVersion: f.ServerVersion,
			CapturedAt: f.CapturedAt, CapturedBy: f.CapturedBy,
			AvailableCompanies: f.AvailableCompanies, EnabledCompanies: f.EnabledCompanies,
			DefaultCompany: f.DefaultCompany, Models: f.Models}
	} else if header.Version == FormatVersion {
		var f snapshotFile
		if err := strictManifestDecode(b, &f); err != nil {
			return Snapshot{}, err
		}
		s = Snapshot{Instance: f.Instance, ServerVersion: f.ServerVersion,
			CapturedAt: f.CapturedAt, CapturedBy: f.CapturedBy,
			AvailableCompanies: f.AvailableCompanies, EnabledCompanies: f.EnabledCompanies,
			DefaultCompany: f.DefaultCompany, Models: f.Models, MethodManifest: f.MethodManifest}
		original = s
	} else {
		return Snapshot{}, fmt.Errorf("unsupported snapshot version %d", header.Version)
	}
	// Marshal the original shape, not the replacement, for binding verification.
	digest, err := canonicalValueDigest(original)
	if err != nil || digest != sealedDigest || sealedDigest == "" {
		return Snapshot{}, fmt.Errorf("snapshot digest does not match sealed profile")
	}
	if err := s.validate(); err != nil {
		return Snapshot{}, err
	}
	s.MethodManifest = append([]MethodMeta{}, methods...)
	return s, s.validate()
}
