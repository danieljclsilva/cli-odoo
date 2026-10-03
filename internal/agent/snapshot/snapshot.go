// Package snapshot carries human-built Odoo metadata for the agent boundary.
//
// A Snapshot is built deliberately by a human (agent setup / agent snapshot
// refresh), never by the model: it records which companies exist
// (AvailableCompanies, read from res.company), which subset the human enabled
// (EnabledCompanies plus DefaultCompany), and per-model field metadata for
// human-approved models only. The broker serves Snapshot.Model as its
// policy.SchemaView; the policy allowlist stays authoritative and the schema
// only resolves dot-path traversals.
//
// AvailableCompanies and EnabledCompanies/DefaultCompany are kept DISTINCT on
// purpose: discovery (what the server has) must never imply authorization
// (what the model may touch). The broker enforces the enabled scope; this
// package only records the human's choice.
//
// Discoverable is not executable: MethodManifest lists method names as pure
// data for human inspection. Nothing in this package performs RPC on the
// model path and nothing here authorizes execution; the broker must never
// Execute a name taken from MethodManifest.
//
// Snapshot files are versioned JSON. Load uses strict decoding: unknown
// fields are rejected (deny-on-unknown, so a typo'd hand edit fails closed
// instead of silently changing meaning) and any version skew denies with no
// legacy fallback.
package snapshot

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/odoo"
)

// parentDir returns the parent directory of a file path.
func parentDir(path string) string {
	return filepath.Dir(path)
}

// tempPath mints a fresh staging name inside dir for O_EXCL creation.
func tempPath(dir string) string {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		// Uniqueness still holds via nanotime; randomness failure must
		// not block the write.
		return filepath.Join(dir, fmt.Sprintf(".tmp-%d.tmp", time.Now().UTC().UnixNano()))
	}
	return filepath.Join(dir, ".tmp-"+hex.EncodeToString(nonce[:])+".tmp")
}

// FormatVersion is the only snapshot file version Load accepts. There is no
// legacy fallback: a version skew denies.
const FormatVersion = 1

// Size and count caps. Snapshot and catalog files are human-handled inputs:
// anything over cap fails closed before decode completes.
const (
	// MaxFileBytes bounds any snapshot or catalog file read (Load,
	// ImportCatalog, ImportManifest).
	MaxFileBytes = 4 << 20 // 4 MiB
	// MaxCatalogModels bounds the models in one imported catalog.
	MaxCatalogModels = 512
	// MaxCatalogFieldsPerModel bounds the fields of one imported model.
	MaxCatalogFieldsPerModel = 2048
	// MaxCatalogMethods bounds one imported method manifest.
	MaxCatalogMethods = 1024
	// MaxCatalogCompanies bounds the companies in one imported catalog.
	MaxCatalogCompanies = 10000
)

// Field provenances recorded on ModelMeta.
const (
	// ProvServer marks metadata read live from the server by a human-invoked
	// builder run.
	ProvServer = "server"
	// ProvManifest marks metadata transcribed by a human from a manifest
	// rather than read live.
	ProvManifest = "manifest"
	// ProvUnknown marks metadata whose origin the human could not attest.
	// Unknown provenance is explicit, never a default: an empty provenance
	// is rejected by Load.
	ProvUnknown = "unknown"
)

// Company is one discovered res.company row.
type Company struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// SFieldMeta is approved metadata for one field: exact technical name plus
// display hints. It carries no values and no access rights. Provenance
// records the metadata origin (server|manifest|unknown); entries written
// before per-field provenance existed carry an empty provenance, which
// FieldProvenanceOf reports as unattested.
type SFieldMeta struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Relation   string `json:"relation"`
	Label      string `json:"label"`
	Provenance string `json:"provenance,omitempty"`
}

// ModelMeta is approved metadata for one human-allowlisted model.
// Executable is display-only: it records whether a human marked this model
// executable in the catalog view. It authorizes nothing. The broker's
// executable set (membership in Policy.Models) stays authoritative; a model
// described here with Executable=false (the default for files written
// before this flag existed) is denied to read/call by the broker.
// IncludeCompanyless is data-only: it records the human's per-model
// companyless opt-in for policy construction by the setup slice. It
// authorizes nothing here — not even on CompanyIndependent models
// (meaningless there, rejected later by policy Validate, same rule as
// policy.ModelRule).
type ModelMeta struct {
	Name               string                `json:"name"`
	Label              string                `json:"label"`
	Fields             map[string]SFieldMeta `json:"fields"`
	CompanyField       string                `json:"company_field"`
	CompanyIndependent bool                  `json:"company_independent"`
	IncludeCompanyless bool                  `json:"include_companyless"`
	Provenance         string                `json:"provenance"`
	Executable         bool                  `json:"executable"`
}

// Snapshot is the human-built metadata file: discovery kept distinct from
// authorization. MethodManifest is informational ONLY and never executable.
// CapturedBy names the human operator (or import run) that built the file.
// It is optional on Load so files written before it existed still load;
// BuildFromServer and ImportCatalog always set it.
type Snapshot struct {
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

// snapshotFile is the on-disk envelope: Snapshot plus the format version the
// file was written with. Snapshot itself carries no version field so a
// version can never be silently dropped by a marshal round-trip.
type snapshotFile struct {
	Version            int                  `json:"version"`
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

// modelView adapts ModelMeta to policy.ModelView for the broker's
// policy.SchemaView. Only allowlisted field metadata is exposed.
type modelView struct {
	fields map[string]SFieldMeta
}

// Field reports approved metadata for one field. Unknown or malformed names
// report ok=false; the policy allowlist remains authoritative.
func (m modelView) Field(name string) (policy.FieldMeta, bool) {
	norm, ok := policy.NormalizeName(name)
	if !ok {
		return policy.FieldMeta{}, false
	}
	f, ok := m.fields[norm]
	if !ok {
		return policy.FieldMeta{}, false
	}
	return policy.FieldMeta{Name: f.Name, Type: f.Type, Relation: f.Relation}, true
}

// Model exposes one allowlisted model's field metadata as a
// policy.ModelView. Unknown or malformed names report ok=false. Method
// names from MethodManifest are deliberately NOT exposed here: discovery is
// not execution.
func (s Snapshot) Model(name string) (policy.ModelView, bool) {
	norm, ok := policy.NormalizeName(name)
	if !ok {
		return nil, false
	}
	m, ok := s.Models[norm]
	if !ok {
		return nil, false
	}
	return modelView{fields: m.Fields}, true
}

// Load reads, strictly decodes, and validates a snapshot file: the file is
// size-capped (MaxFileBytes) and must be a regular file; unknown JSON fields
// are rejected and any version other than FormatVersion denies with no legacy
// fallback. A malformed file fails closed before any policy decision can
// consult it. A missing Executable defaults to false (display-only; the
// broker's executable set stays authoritative) and a missing CapturedBy is
// accepted for files written before it existed; an empty model provenance is
// always rejected.
func Load(path string) (Snapshot, error) {
	st, err := os.Stat(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: reading %q: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return Snapshot{}, fmt.Errorf("snapshot: %q is not a regular file", path)
	}
	if st.Size() > MaxFileBytes {
		return Snapshot{}, fmt.Errorf("snapshot: %q is %d bytes, over cap %d", path, st.Size(), MaxFileBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: reading %q: %w", path, err)
	}
	if int64(len(b)) > MaxFileBytes {
		return Snapshot{}, fmt.Errorf("snapshot: %q is %d bytes, over cap %d", path, len(b), MaxFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f snapshotFile
	if err := dec.Decode(&f); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: decoding %q (unknown fields rejected): %w", path, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Snapshot{}, fmt.Errorf("snapshot: decoding %q: trailing data after document", path)
	}
	if f.Version != FormatVersion {
		return Snapshot{}, fmt.Errorf("snapshot: version %d unsupported (want %d): refusing with no legacy fallback", f.Version, FormatVersion)
	}
	s := Snapshot{
		Instance:           f.Instance,
		ServerVersion:      f.ServerVersion,
		CapturedAt:         f.CapturedAt,
		CapturedBy:         f.CapturedBy,
		AvailableCompanies: f.AvailableCompanies,
		EnabledCompanies:   f.EnabledCompanies,
		DefaultCompany:     f.DefaultCompany,
		Models:             f.Models,
		MethodManifest:     f.MethodManifest,
	}
	if err := s.validate(); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: invalid %q: %w", path, err)
	}
	return s, nil
}

// Write validates s and persists it as versioned JSON with mode 0600 via
// the same atomic secure-replace as setup profiles (O_EXCL temp + fsync +
// rename, no symlink sink). The parent directory must already exist: Write
// creates no directories.
func Write(path string, s Snapshot) error {
	if err := s.validate(); err != nil {
		return fmt.Errorf("snapshot: refusing to write invalid snapshot: %w", err)
	}
	f := snapshotFile{
		Version:            FormatVersion,
		Instance:           s.Instance,
		ServerVersion:      s.ServerVersion,
		CapturedAt:         s.CapturedAt,
		CapturedBy:         s.CapturedBy,
		AvailableCompanies: s.AvailableCompanies,
		EnabledCompanies:   s.EnabledCompanies,
		DefaultCompany:     s.DefaultCompany,
		Models:             s.Models,
		MethodManifest:     s.MethodManifest,
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("snapshot: encoding: %w", err)
	}
	b = append(b, '\n')
	if int64(len(b)) > MaxFileBytes {
		return fmt.Errorf("snapshot: encoded snapshot %d bytes exceeds cap %d", len(b), MaxFileBytes)
	}
	if err := secureReplaceFile(path, b); err != nil {
		return fmt.Errorf("snapshot: writing %q: %w", path, err)
	}
	return nil
}

// MarshalFile validates s and returns the exact versioned JSON bytes Write
// would persist (0600 envelope, trailing newline), without touching disk.
// Staging callers (setup bundle commit) marshal first so validation and
// size-cap checks complete before any snapshot/profile mutation.
func MarshalFile(s Snapshot) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("snapshot: refusing to marshal invalid snapshot: %w", err)
	}
	f := snapshotFile{
		Version:            FormatVersion,
		Instance:           s.Instance,
		ServerVersion:      s.ServerVersion,
		CapturedAt:         s.CapturedAt,
		CapturedBy:         s.CapturedBy,
		AvailableCompanies: s.AvailableCompanies,
		EnabledCompanies:   s.EnabledCompanies,
		DefaultCompany:     s.DefaultCompany,
		Models:             s.Models,
		MethodManifest:     s.MethodManifest,
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("snapshot: encoding: %w", err)
	}
	b = append(b, '\n')
	if int64(len(b)) > MaxFileBytes {
		return nil, fmt.Errorf("snapshot: encoded snapshot %d bytes exceeds cap %d", len(b), MaxFileBytes)
	}
	return b, nil
}

// WriteBytes validates the pre-marshaled envelope bytes (strict decode +
// snapshot validate, version + cap checks) and persists them via the same
// atomic secure-replace as Write (O_EXCL temp + fsync + rename, no symlink
// sink). The parent directory must already exist: WriteBytes creates no
// directories. Bundle commit uses this so the bytes sealed into the profile
// digest are byte-identical to the bytes on disk.
func WriteBytes(path string, b []byte) error {
	if int64(len(b)) > MaxFileBytes {
		return fmt.Errorf("snapshot: staged snapshot %d bytes exceeds cap %d", len(b), MaxFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f snapshotFile
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("snapshot: staged snapshot decode: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("snapshot: staged snapshot: trailing data after document")
	}
	if f.Version != FormatVersion {
		return fmt.Errorf("snapshot: staged snapshot version %d (want %d)", f.Version, FormatVersion)
	}
	s := Snapshot{
		Instance:           f.Instance,
		ServerVersion:      f.ServerVersion,
		CapturedAt:         f.CapturedAt,
		CapturedBy:         f.CapturedBy,
		AvailableCompanies: f.AvailableCompanies,
		EnabledCompanies:   f.EnabledCompanies,
		DefaultCompany:     f.DefaultCompany,
		Models:             f.Models,
		MethodManifest:     f.MethodManifest,
	}
	if err := s.validate(); err != nil {
		return fmt.Errorf("snapshot: refusing to write invalid staged snapshot: %w", err)
	}
	if err := secureReplaceFile(path, b); err != nil {
		return fmt.Errorf("snapshot: writing %q: %w", path, err)
	}
	return nil
}

// CanonicalDigest returns the hex-encoded SHA-256 digest of the canonical
// JSON encoding of the Snapshot value. Canonical here means exactly what
// encoding/json emits for this shape: struct fields in declaration order,
// map keys sorted lexicographically, no whitespace, integers exact, and
// time in RFC 3339 — all deterministic for a fixed Snapshot value, so two
// equal Snapshots digest equally and any mutation (companies, fields,
// relations, company metadata, provenance) digests differently.
//
// The digest covers the Snapshot value only, not the on-disk envelope
// version: version skew is rejected separately by Load, and the sealed
// policy binds this digest via Policy.SnapshotSHA256. The setup slice
// stamps CanonicalDigest output into the policy after human review; the
// broker recomputes and compares before serving.
func CanonicalDigest(s Snapshot) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("snapshot: canonical digest: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// validate enforces snapshot shape: scope consistency (at least two enabled
// companies mirroring the policy scope rule — positive unique IDs, default
// a member of enabled, enabled a subset of discovered — checked BEFORE any
// server use), sane companies, and per-model metadata hygiene. It fills an
// empty model Label from the model name.
func (s *Snapshot) validate() error {
	if strings.TrimSpace(s.Instance) == "" {
		return fmt.Errorf("instance is empty")
	}
	if s.CapturedAt.IsZero() {
		return fmt.Errorf("captured_at is missing")
	}
	seen := map[int]bool{}
	for i, c := range s.AvailableCompanies {
		if c.ID <= 0 {
			return fmt.Errorf("available_companies[%d]: non-positive id %d", i, c.ID)
		}
		if strings.TrimSpace(c.Name) == "" {
			return fmt.Errorf("available_companies[%d]: empty name", i)
		}
		if seen[c.ID] {
			return fmt.Errorf("available_companies: duplicate id %d", c.ID)
		}
		seen[c.ID] = true
	}
	if len(s.EnabledCompanies) < 2 {
		return fmt.Errorf("enabled_companies: need at least two enabled companies, got %d", len(s.EnabledCompanies))
	}
	enabled := map[int]bool{}
	for _, id := range s.EnabledCompanies {
		if id <= 0 {
			return fmt.Errorf("enabled_companies: non-positive id %d", id)
		}
		if enabled[id] {
			return fmt.Errorf("enabled_companies: duplicate id %d", id)
		}
		enabled[id] = true
		if !seen[id] {
			return fmt.Errorf("enabled_companies: id %d was not in available_companies", id)
		}
	}
	if !enabled[s.DefaultCompany] {
		return fmt.Errorf("default_company %d is not in enabled_companies", s.DefaultCompany)
	}
	if len(s.Models) == 0 {
		return fmt.Errorf("models: at least one approved model is required")
	}
	for key, m := range s.Models {
		norm, ok := policy.NormalizeName(key)
		if !ok || norm != key {
			return fmt.Errorf("models: invalid model key %q", key)
		}
		if m.Name != key {
			return fmt.Errorf("models: key %q mismatches entry name %q", key, m.Name)
		}
		if m.Label == "" {
			m.Label = key
			s.Models[key] = m
		}
		switch m.Provenance {
		case ProvServer, ProvManifest, ProvUnknown:
		default:
			return fmt.Errorf("models %q: provenance %q must be server|manifest|unknown (empty rejected)", key, m.Provenance)
		}
		if len(m.Fields) == 0 {
			return fmt.Errorf("models %q: at least one approved field is required", key)
		}
		for fname, fm := range m.Fields {
			if _, ok := policy.NormalizeName(fname); !ok {
				return fmt.Errorf("models %q: invalid field name %q", key, fname)
			}
			if fm.Name != "" && fm.Name != fname {
				return fmt.Errorf("models %q: field key %q mismatches entry name %q", key, fname, fm.Name)
			}
			// Per-field provenance is optional for back-compat (entries
			// written before it existed carry empty = unattested). When
			// present it must be a known label.
			switch fm.Provenance {
			case "", ProvServer, ProvManifest, ProvUnknown:
			default:
				return fmt.Errorf("models %q field %q: provenance %q must be server|manifest|unknown", key, fname, fm.Provenance)
			}
		}
		if m.CompanyField != "" {
			if _, ok := policy.NormalizeName(m.CompanyField); !ok {
				return fmt.Errorf("models %q: invalid company_field %q", key, m.CompanyField)
			}
		}
		// NOTE: a model with no CompanyField and CompanyIndependent=false is
		// kept here but denies at authorize time (unenforceable company
		// scope). Load records the human's metadata; the policy gate decides.
	}
	return nil
}

// ModelSpec is one human-approved model for BuildFromServer: the exact
// technical name plus the exact fields the human approved. Only these models
// are ever described with fields_get; models outside this list are never
// touched, even if named on a model path elsewhere.
// IncludeCompanyless is the human's explicit per-model opt-in admitting
// company_id=false records alongside scoped records. It is data only here:
// carried into ModelMeta, meaningless on independent models, and rejected
// later by policy Validate on independent models (same rule as
// policy.ModelRule).
type ModelSpec struct {
	Name               string   `json:"name"`
	Label              string   `json:"label"`
	Fields             []string `json:"fields"`
	CompanyField       string   `json:"company_field"`
	CompanyIndependent bool     `json:"company_independent"`
	IncludeCompanyless bool     `json:"include_companyless"`
	AllowAggregate     bool     `json:"allow_aggregate"`
}

// snapshotMethodManifest is the fixed informational method list stamped into
// built snapshots. It is pure data for human inspection: presence in this
// list never authorizes execution and the broker must never Execute a name
// taken from it.
var snapshotMethodManifest = []string{
	"search_read", "read", "search_count", "read_group", "fields_get",
	"name_search", "check_access_rights", "version", "context_get",
}

// BuildFromServer builds a Snapshot from live server metadata. It is
// human-invoked (agent setup / agent snapshot refresh), never model-invoked:
// the human supplies the company scope and the per-model allowlist, and only
// those allowlisted models are described with fields_get. Static validation
// (scope, specs) runs before any RPC; discovery (res.company, server
// version, ir.model labels, per-model fields_get) follows. Custom models
// outside specs are never described, even if the server offers them.
func BuildFromServer(client *odoo.Client, instance string, scope policy.CompanyScope, specs []ModelSpec) (Snapshot, error) {
	if client == nil {
		return Snapshot{}, fmt.Errorf("snapshot: nil client")
	}
	if strings.TrimSpace(instance) == "" {
		return Snapshot{}, fmt.Errorf("snapshot: instance is empty")
	}
	if err := policy.ValidateScope(scope); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: %w", err)
	}
	if len(specs) == 0 {
		return Snapshot{}, fmt.Errorf("snapshot: at least one approved model is required")
	}
	seenModels := map[string]bool{}
	clean := make([]ModelSpec, 0, len(specs))
	for i, sp := range specs {
		norm, ok := policy.NormalizeName(sp.Name)
		if !ok || norm != strings.TrimSpace(sp.Name) {
			return Snapshot{}, fmt.Errorf("snapshot: specs[%d]: invalid model name %q", i, sp.Name)
		}
		if seenModels[norm] {
			return Snapshot{}, fmt.Errorf("snapshot: specs: duplicate model %q", norm)
		}
		seenModels[norm] = true
		if len(sp.Fields) == 0 {
			return Snapshot{}, fmt.Errorf("snapshot: specs %q: at least one approved field is required", norm)
		}
		fields := make([]string, 0, len(sp.Fields))
		seenFields := map[string]bool{}
		for _, f := range sp.Fields {
			fn, ok := policy.NormalizeName(f)
			if !ok {
				return Snapshot{}, fmt.Errorf("snapshot: specs %q: invalid field name %q", norm, f)
			}
			if !seenFields[fn] {
				seenFields[fn] = true
				fields = append(fields, fn)
			}
		}
		sort.Strings(fields)
		label := strings.TrimSpace(sp.Label)
		if label == "" {
			label = norm
		}
		cf := strings.TrimSpace(sp.CompanyField)
		if cf != "" {
			if _, ok := policy.NormalizeName(cf); !ok {
				return Snapshot{}, fmt.Errorf("snapshot: specs %q: invalid company_field %q", norm, sp.CompanyField)
			}
		}
		if sp.CompanyIndependent && sp.CompanyField != "" {
			return Snapshot{}, fmt.Errorf("snapshot: specs %q contradictory: company-independent with company field", norm)
		}
		// NOTE: IncludeCompanyless on an independent model is NOT rejected
		// here (data-only carry-through, same as ModelMeta): policy
		// construction in the setup slice rejects it via policy Validate.
		clean = append(clean, ModelSpec{
			Name: norm, Label: label, Fields: fields,
			CompanyField: cf, CompanyIndependent: sp.CompanyIndependent,
			IncludeCompanyless: sp.IncludeCompanyless,
			AllowAggregate:     sp.AllowAggregate,
		})
	}

	ver, err := client.ServerVersion()
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: server version: %w", err)
	}
	companyRows, err := client.Execute("res.company", "search_read",
		[]any{[]any{}, []any{"id", "name"}},
		map[string]any{"limit": 10000, "order": "id asc"})
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: reading res.company: %w", err)
	}
	available, err := snapshotCompanies(companyRows)
	if err != nil {
		return Snapshot{}, err
	}
	availableSet := map[int]bool{}
	for _, c := range available {
		availableSet[c.ID] = true
	}
	for _, id := range scope.Enabled {
		if !availableSet[id] {
			return Snapshot{}, fmt.Errorf("snapshot: enabled company %d not found on server", id)
		}
	}

	// One bounded ir.model query over exactly the approved names for labels.
	names := make([]any, 0, len(clean))
	for _, sp := range clean {
		names = append(names, sp.Name)
	}
	labels := map[string]string{}
	modelRows, err := client.Execute("ir.model", "search_read",
		[]any{[]any{[]any{"model", "in", names}}, []any{"model", "name"}},
		map[string]any{"limit": len(clean)})
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: reading ir.model: %w", err)
	}
	if rows, ok := modelRows.([]any); ok {
		for _, r := range rows {
			m, ok := r.(map[string]any)
			if !ok {
				continue
			}
			model, _ := m["model"].(string)
			label, _ := m["name"].(string)
			if model != "" && label != "" {
				labels[model] = label
			}
		}
	}

	models := make(map[string]ModelMeta, len(clean))
	for _, sp := range clean {
		// fields_get runs ONLY for this human-approved model, requesting
		// ONLY the human-approved fields. A missing field is an error
		// naming the field: BuildFromServer never synthesizes metadata for
		// absent fields (no silent approve).
		fieldArgs := make([]any, 0, len(sp.Fields))
		for _, f := range sp.Fields {
			fieldArgs = append(fieldArgs, f)
		}
		got, err := client.Execute(sp.Name, "fields_get", []any{fieldArgs},
			map[string]any{"attributes": []any{"string", "type", "relation"}})
		if err != nil {
			return Snapshot{}, fmt.Errorf("snapshot: fields_get %s: %w", sp.Name, err)
		}
		attrs, _ := got.(map[string]any)
		fields := make(map[string]SFieldMeta, len(sp.Fields))
		for _, f := range sp.Fields {
			am, ok := attrs[f].(map[string]any)
			if !ok {
				return Snapshot{}, fmt.Errorf("snapshot: fields_get %s: missing metadata for approved field %q", sp.Name, f)
			}
			typ, _ := am["type"].(string)
			if strings.TrimSpace(typ) == "" {
				return Snapshot{}, fmt.Errorf("snapshot: fields_get %s: missing type for approved field %q", sp.Name, f)
			}
			meta := SFieldMeta{Name: f, Type: typ, Provenance: ProvServer, Label: f}
			if r, _ := am["relation"].(string); r != "" {
				meta.Relation = r
			}
			if l, _ := am["string"].(string); strings.TrimSpace(l) != "" {
				meta.Label = l
			}
			fields[f] = meta
		}
		label := sp.Label
		if serverLabel, ok := labels[sp.Name]; ok && sp.Label == sp.Name {
			label = serverLabel
		}
		models[sp.Name] = ModelMeta{
			Name: sp.Name, Label: label, Fields: fields,
			CompanyField: sp.CompanyField, CompanyIndependent: sp.CompanyIndependent,
			IncludeCompanyless: sp.IncludeCompanyless,
			Provenance:         ProvServer,
		}
	}

	enabled := append([]int(nil), scope.Enabled...)
	sort.Ints(enabled)
	sort.Slice(available, func(i, j int) bool { return available[i].ID < available[j].ID })
	s := Snapshot{
		Instance:           strings.TrimSpace(instance),
		ServerVersion:      serverVersionString(ver),
		CapturedAt:         time.Now().UTC(),
		CapturedBy:         "server",
		AvailableCompanies: available,
		EnabledCompanies:   enabled,
		DefaultCompany:     scope.Default,
		Models:             models,
		MethodManifest:     append([]string(nil), snapshotMethodManifest...),
	}
	if err := s.validate(); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: built invalid snapshot: %w", err)
	}
	return s, nil
}

// snapshotCompanies coerces a res.company search_read result into Companies.
// Anything off-shape denies: metadata must be exact before it can gate.
func snapshotCompanies(v any) ([]Company, error) {
	rows, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("snapshot: unexpected res.company shape %T", v)
	}
	out := make([]Company, 0, len(rows))
	for i, r := range rows {
		m, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("snapshot: res.company row %d has shape %T", i, r)
		}
		id, err := snapshotInt(m["id"])
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("snapshot: res.company row %d has bad id", i)
		}
		name, _ := m["name"].(string)
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("snapshot: res.company row %d has empty name", i)
		}
		out = append(out, Company{ID: id, Name: name})
	}
	return out, nil
}

// snapshotInt coerces XML-RPC/JSON numerics to int. Non-integral floats and
// non-numeric shapes fail.
func snapshotInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		if math.Trunc(n) != n || n > math.MaxInt32 || n < math.MinInt32 {
			return 0, fmt.Errorf("snapshot: non-integral number %v", n)
		}
		return int(n), nil
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, fmt.Errorf("snapshot: bad number %q", n.String())
		}
		return int(i), nil
	default:
		return 0, fmt.Errorf("snapshot: bad number shape %T", v)
	}
}

// serverVersionString renders a ServerVersion result for the record. The
// common.version mapping carries server_version; anything else renders
// verbatim so the record never silently drops server identity.
func serverVersionString(v any) string {
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["server_version"].(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return fmt.Sprintf("%v", v)
}

// secureReplaceFile atomically replaces path with data (0600): the parent
// must already exist, the temp is created with O_CREATE|O_EXCL inside that
// same directory (never following a planted symlink at the temp name), set
// 0600, fsynced, and renamed over the target. Rename replaces a
// final-component symlink itself rather than following it, and breaks (not
// follows) preexisting hardlinks to the target. It never preserves an
// existing looser mode: the new file is always 0600.
func secureReplaceFile(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty path")
	}
	dir := parentDir(path)
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("parent %q: %w (create it first; secure replace creates no directories)", dir, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("parent %q is not a directory", dir)
	}
	tmp, err := os.OpenFile(tempPath(dir), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("staging temp: %w", err)
	}
	tmpName := tmp.Name()
	// The temp path is freshly created O_EXCL and held open; close/remove
	// on every failure path leaves no staging file behind.
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("staging temp: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("staging temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("staging temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("staging temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("committing: %w", err)
	}
	// The new file is always 0600 regardless of any preexisting mode or
	// umask: rename carries the temp's mode through.
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	return nil
}
