// Bounded human-only catalog import for the agent boundary.
//
// ImportCatalog / ImportManifest let a human transcribe metadata from an
// offline manifest (rather than the live server) into a Snapshot. They are
// never on the model surface: the human runs them via setup-time tooling,
// reviews the result, and writes it with Write.
//
// Bounds (all fail-closed): the file must be a regular file of at most
// MaxFileBytes; at most MaxCatalogModels models; at most
// MaxCatalogFieldsPerModel fields per model; at most MaxCatalogCompanies
// companies; at most MaxCatalogMethods manifest entries. Decoding is strict
// (unknown fields rejected, exactly one JSON object + EOF).
//
// Provenance: a model or field entry without a provenance label is recorded
// explicitly as ProvUnknown, never silently approved as server-read. The
// provenance labels are preserved verbatim for human inspection.
//
// Discoverable is not executable: ImportCatalog preserves the display-only
// ModelMeta.Executable flag as transcribed, but that flag authorizes
// nothing. The broker's executable set (membership in Policy.Models) stays
// authoritative; use Snapshot.IsExecutable only for display, never for
// access decisions. MethodManifest (and anything returned by
// ImportManifest) is informational only: no Execute path may take a name
// from it.
package snapshot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
)

// catalogField is one human-transcribed field entry. Provenance may be
// omitted by the human transcriber and then defaults explicitly to
// ProvUnknown during import.
type catalogField struct {
	Type       string `json:"type"`
	Relation   string `json:"relation"`
	Label      string `json:"label"`
	Provenance string `json:"provenance"`
}

// catalogModel is one human-transcribed model entry. Executable is
// display-only (see package comment); it is preserved as transcribed.
type catalogModel struct {
	Label              string                  `json:"label"`
	Provenance         string                  `json:"provenance"`
	Executable         bool                    `json:"executable"`
	CompanyField       string                  `json:"company_field"`
	CompanyIndependent bool                    `json:"company_independent"`
	Fields             map[string]catalogField `json:"fields"`
}

// catalogFile is the human-authored import source. It is not a snapshot
// file (no version field): it is transcribed offline, validated here, and
// converted into a Snapshot the caller persists with Write.
type catalogFile struct {
	Instance           string                  `json:"instance"`
	CapturedBy         string                  `json:"captured_by"`
	ServerVersion      string                  `json:"server_version"`
	AvailableCompanies []Company               `json:"available_companies"`
	EnabledCompanies   []int                   `json:"enabled_companies"`
	DefaultCompany     int                     `json:"default_company"`
	Models             map[string]catalogModel `json:"models"`
	MethodManifest     []string                `json:"method_manifest"`
}

// manifestFile is the human-authored method list import source: pure data
// for human inspection, never executable.
type manifestFile struct {
	Methods []string `json:"methods"`
}

// IsExecutable reports the display-only catalog flag for model: whether a
// human marked this model executable in the catalog view. It authorizes
// nothing: the broker's executable set (membership in Policy.Models) stays
// authoritative, and a model merely described here is denied to read/call.
// Unknown or malformed names report false.
func (s Snapshot) IsExecutable(model string) bool {
	norm, ok := policy.NormalizeName(model)
	if !ok {
		return false
	}
	m, ok := s.Models[norm]
	if !ok {
		return false
	}
	return m.Executable
}

// ProvenanceOf reports the recorded model provenance for a described
// model. Unknown or malformed names report ok=false.
func (s Snapshot) ProvenanceOf(model string) (prov string, ok bool) {
	norm, ok := policy.NormalizeName(model)
	if !ok {
		return "", false
	}
	m, ok := s.Models[norm]
	if !ok {
		return "", false
	}
	return m.Provenance, true
}

// FieldProvenanceOf reports the recorded field provenance for a described
// model field. Entries imported before per-field provenance existed carry
// an empty provenance and report ok=false (unknown origin, not attested).
func (s Snapshot) FieldProvenanceOf(model, field string) (prov string, ok bool) {
	norm, ok := policy.NormalizeName(model)
	if !ok {
		return "", false
	}
	m, ok := s.Models[norm]
	if !ok {
		return "", false
	}
	fnorm, ok := policy.NormalizeName(field)
	if !ok {
		return "", false
	}
	f, ok := m.Fields[fnorm]
	if !ok || f.Provenance == "" {
		return "", false
	}
	return f.Provenance, true
}

// normalizeProvenance maps a human-transcribed provenance label to its
// canonical value: empty (unstated) becomes ProvUnknown explicitly, and
// anything outside server|manifest|unknown is rejected.
func normalizeProvenance(where, v string) (string, error) {
	t := strings.TrimSpace(v)
	if t == "" {
		return ProvUnknown, nil
	}
	switch t {
	case ProvServer, ProvManifest, ProvUnknown:
		return t, nil
	default:
		return "", fmt.Errorf("snapshot: %s: provenance %q must be server|manifest|unknown", where, v)
	}
}

// ImportCatalog reads a human-transcribed catalog file and converts it
// into a Snapshot. The result still requires review and must be persisted
// with Write; nothing here authorizes execution.
func ImportCatalog(path string) (Snapshot, error) {
	st, err := os.Stat(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: reading catalog %q: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return Snapshot{}, fmt.Errorf("snapshot: catalog %q is not a regular file", path)
	}
	if st.Size() > MaxFileBytes {
		return Snapshot{}, fmt.Errorf("snapshot: catalog %q is %d bytes, over cap %d", path, st.Size(), MaxFileBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: reading catalog %q: %w", path, err)
	}
	if int64(len(b)) > MaxFileBytes {
		return Snapshot{}, fmt.Errorf("snapshot: catalog %q is %d bytes, over cap %d", path, len(b), MaxFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f catalogFile
	if err := dec.Decode(&f); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: decoding catalog %q (unknown fields rejected): %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Snapshot{}, fmt.Errorf("snapshot: decoding catalog %q: trailing data after document", path)
	}
	if len(f.Models) > MaxCatalogModels {
		return Snapshot{}, fmt.Errorf("snapshot: catalog holds %d models, over cap %d", len(f.Models), MaxCatalogModels)
	}
	if len(f.AvailableCompanies) > MaxCatalogCompanies {
		return Snapshot{}, fmt.Errorf("snapshot: catalog holds %d companies, over cap %d", len(f.AvailableCompanies), MaxCatalogCompanies)
	}
	if len(f.MethodManifest) > MaxCatalogMethods {
		return Snapshot{}, fmt.Errorf("snapshot: catalog method manifest holds %d entries, over cap %d", len(f.MethodManifest), MaxCatalogMethods)
	}
	models := make(map[string]ModelMeta, len(f.Models))
	for key, cm := range f.Models {
		norm, ok := policy.NormalizeName(key)
		if !ok || norm != key {
			return Snapshot{}, fmt.Errorf("snapshot: catalog: invalid model key %q", key)
		}
		prov, err := normalizeProvenance(fmt.Sprintf("models %q", key), cm.Provenance)
		if err != nil {
			return Snapshot{}, err
		}
		if len(cm.Fields) > MaxCatalogFieldsPerModel {
			return Snapshot{}, fmt.Errorf("snapshot: catalog models %q holds %d fields, over cap %d", key, len(cm.Fields), MaxCatalogFieldsPerModel)
		}
		fields := make(map[string]SFieldMeta, len(cm.Fields))
		for fname, cf := range cm.Fields {
			fn, ok := policy.NormalizeName(fname)
			if !ok || fn != fname {
				return Snapshot{}, fmt.Errorf("snapshot: catalog models %q: invalid field name %q", key, fname)
			}
			fprov, err := normalizeProvenance(fmt.Sprintf("models %q field %q", key, fname), cf.Provenance)
			if err != nil {
				return Snapshot{}, err
			}
			ft := strings.TrimSpace(cf.Type)
			if ft == "" {
				ft = "unknown"
			}
			fl := strings.TrimSpace(cf.Label)
			if fl == "" {
				fl = fn
			}
			fields[fn] = SFieldMeta{
				Name: fn, Type: ft,
				Relation:   strings.TrimSpace(cf.Relation),
				Label:      fl,
				Provenance: fprov,
			}
		}
		label := strings.TrimSpace(cm.Label)
		if label == "" {
			label = norm
		}
		cf := strings.TrimSpace(cm.CompanyField)
		if cf != "" {
			if _, ok := policy.NormalizeName(cf); !ok {
				return Snapshot{}, fmt.Errorf("snapshot: catalog models %q: invalid company_field %q", key, cm.CompanyField)
			}
		}
		models[norm] = ModelMeta{
			Name: norm, Label: label, Fields: fields,
			CompanyField: cf, CompanyIndependent: cm.CompanyIndependent,
			Provenance: prov, Executable: cm.Executable,
		}
	}
	manifest := make([]string, 0, len(f.MethodManifest))
	for i, m := range f.MethodManifest {
		if strings.TrimSpace(m) == "" {
			return Snapshot{}, fmt.Errorf("snapshot: catalog method_manifest[%d] is empty", i)
		}
		manifest = append(manifest, m)
	}
	by := strings.TrimSpace(f.CapturedBy)
	if by == "" {
		by = "human:import"
	}
	s := Snapshot{
		Instance:           strings.TrimSpace(f.Instance),
		ServerVersion:      strings.TrimSpace(f.ServerVersion),
		CapturedAt:         time.Now().UTC(),
		CapturedBy:         by,
		AvailableCompanies: f.AvailableCompanies,
		EnabledCompanies:   f.EnabledCompanies,
		DefaultCompany:     f.DefaultCompany,
		Models:             models,
		MethodManifest:     manifest,
	}
	if err := s.validate(); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: invalid catalog %q: %w", path, err)
	}
	return s, nil
}

// ImportManifest reads a human-authored method-list file and returns its
// entries for inspection. The result is informational only: no Execute path
// may take a name from it. The file shape is {"methods": [...]}; decoding
// is strict and the entry count is capped at MaxCatalogMethods.
func ImportManifest(path string) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("snapshot: reading manifest %q: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("snapshot: manifest %q is not a regular file", path)
	}
	if st.Size() > MaxFileBytes {
		return nil, fmt.Errorf("snapshot: manifest %q is %d bytes, over cap %d", path, st.Size(), MaxFileBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("snapshot: reading manifest %q: %w", path, err)
	}
	if int64(len(b)) > MaxFileBytes {
		return nil, fmt.Errorf("snapshot: manifest %q is %d bytes, over cap %d", path, len(b), MaxFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f manifestFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("snapshot: decoding manifest %q (unknown fields rejected): %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("snapshot: decoding manifest %q: trailing data after document", path)
	}
	if len(f.Methods) > MaxCatalogMethods {
		return nil, fmt.Errorf("snapshot: manifest holds %d entries, over cap %d", len(f.Methods), MaxCatalogMethods)
	}
	out := make([]string, 0, len(f.Methods))
	for i, m := range f.Methods {
		if strings.TrimSpace(m) == "" {
			return nil, fmt.Errorf("snapshot: manifest methods[%d] is empty", i)
		}
		out = append(out, m)
	}
	return out, nil
}
