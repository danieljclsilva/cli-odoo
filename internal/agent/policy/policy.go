// Package policy is the deny-by-default authorization gate between model
// (agent) requests and Odoo data.
//
// A human builds a Policy out of band (companies, allowlisted operations and
// models, budgets) and seals it; the broker calls Policy.Authorize before any
// RPC. Authorize never touches the network, the keychain, or the filesystem:
// it is a pure function of the policy, a schema view, and the request.
//
// Denial precedes everything: any malformed input (zero-value policy, unknown
// operation/model, unallowlisted field, malformed domain, over-budget
// limit/offset, caller-supplied company selection, unenforceable company
// scope) denies. Decision.Reason values are fixed strings and carry no
// secrets — field/model names at most, never domain values or credentials.
package policy

import "strings"

// Operation is a typed model-surface operation. Only operations present in
// Policy.Operations may execute; workspace file operations are broker-level
// and additionally gated by Policy.AllowWorkspace.
type Operation string

// Typed operations on the model surface.
const (
	OpSearch    Operation = "search"
	OpRead      Operation = "read"
	OpCount     Operation = "count"
	OpAggregate Operation = "aggregate"
	OpMeta      Operation = "meta"
)

// Shared-record classifications for Policy.SharedRecords.
const (
	// SharedDeny forbids cross-company shared records unless the model
	// rule carries an enforceable CompanyField.
	SharedDeny = "deny"
	// SharedAllowClassified permits models a human reviewed as company
	// independent (ModelRule.CompanyIndependent) without an enforced
	// company fragment.
	SharedAllowClassified = "allow-classified"
)

// ModelRule is the per-model allowlist entry. Fields holds exact Odoo
// technical names (sorted by convention). CompanyField names the enforcing
// field (e.g. "company_id" or "company_ids"); "" means unknown.
// CompanyIndependent marks human-reviewed shared/global data.
type ModelRule struct {
	Fields             []string
	MaxLimit           int
	AllowAggregate     bool
	CompanyField       string
	CompanyIndependent bool
}

// CompanyScope is the human-chosen company set. At least two companies must
// be enabled so the model can never imply a single-company context, and the
// default must be a member of the enabled set.
type CompanyScope struct {
	Enabled []int
	Default int
}

// Budgets caps a single request. Session-level counters (MaxCallsPerSession,
// MaxRowsPerSession) are enforced by the broker at runtime, not by
// Authorize; per-request caps (MaxLimit, MaxOffset, MaxRowsPerCall,
// MaxResponseBytes) gate Authorize.
type Budgets struct {
	MaxLimit           int
	MaxOffset          int
	MaxRowsPerCall     int
	MaxResponseBytes   int
	MaxCallsPerSession int64
	MaxRowsPerSession  int64
}

// Policy is the sealed, human-built authorization policy.
type Policy struct {
	Version        int
	Instance       string
	Operations     map[Operation]bool
	Models         map[string]ModelRule
	Scope          CompanyScope
	SharedRecords  string
	Budgets        Budgets
	AllowWorkspace bool
	WorkspaceDir   string
	SnapshotPath   string
}

// Request is a single model request awaiting authorization. Domain is the
// decoded JSON domain array (nil or []any). CompanyIDs must always be empty:
// the model cannot select companies; the broker injects the enforced scope
// after authorization.
type Request struct {
	Operation  Operation
	Model      string
	Fields     []string
	Domain     any
	Order      string
	GroupBy    []string
	CompanyIDs []int
	Limit      int
	Offset     int
}

// Decision is the authorization outcome. Reason is a stable, secret-free
// string (see Reason* constants); it names operations/models/fields at most,
// never domain values, tokens, or credentials.
type Decision struct {
	Allow  bool
	Reason string
}

// FieldMeta describes one field for traversal checks.
type FieldMeta struct {
	Name     string
	Type     string
	Relation string
}

// ModelView exposes the fields of one model.
type ModelView interface {
	Field(name string) (FieldMeta, bool)
}

// SchemaView exposes models for dot-path traversal checks. It is advisory:
// the policy allowlist is authoritative, and the schema is consulted only to
// verify that intermediate dot-path segments are relational.
type SchemaView interface {
	Model(name string) (ModelView, bool)
}

// NormalizeName trims surrounding whitespace and accepts only exact Odoo
// technical names ([A-Za-z0-9._]+). There is no case folding and no interior
// whitespace tolerance: " Res.Partner " normalizes to "Res.Partner" (case
// preserved) while "res partner", "", and names with any other character are
// rejected.
func NormalizeName(s string) (string, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return "", false
	}
	for i := range t {
		c := t[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' {
			continue
		}
		return "", false
	}
	return t, true
}
