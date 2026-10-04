package policy

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Stable, secret-free decision reasons. Reasons name operations, models, or
// fields at most — never domain values, tokens, credentials, or company IDs.
const (
	// ReasonAllow marks an authorized request.
	ReasonAllow = "allow"
	// ReasonInvalidPolicy marks a zero-value or malformed policy
	// (bad version/instance, empty operations/models, unknown
	// SharedRecords, non-positive global MaxLimit, invalid CompanyScope).
	ReasonInvalidPolicy = "invalid-policy"
	// ReasonInvalidScope marks a policy whose CompanyScope fails
	// ValidateScope.
	ReasonInvalidScope = "invalid-scope"
	// ReasonOperationDenied marks an operation outside the policy allowlist.
	ReasonOperationDenied = "operation-denied"
	// ReasonInvalidModel marks a model name failing NormalizeName.
	ReasonInvalidModel = "invalid-model"
	// ReasonUnknownModel marks a well-formed model absent from the policy.
	ReasonUnknownModel = "unknown-model"
	// ReasonAggregateDenied marks an aggregate request on a model whose
	// rule forbids aggregation.
	ReasonAggregateDenied = "aggregate-denied"
	// ReasonFieldDenied marks a missing/empty field projection on
	// search/read, or a requested field outside the model rule
	// (wildcards, unallowlisted names, unapproved traversals).
	ReasonFieldDenied = "field-denied"
	// ReasonDomainDenied marks a malformed domain or one referencing a
	// field outside the model rule (dot-path traversals included).
	ReasonDomainDenied = "domain-denied"
	// ReasonOrderDenied marks a malformed order clause or one referencing
	// a field outside the model rule.
	ReasonOrderDenied = "order-denied"
	// ReasonGroupByDenied marks a group-by entry outside the model rule.
	ReasonGroupByDenied = "groupby-denied"
	// ReasonLimitDenied marks a missing, non-positive, or over-budget
	// limit (or any nonzero limit on count/meta, where paging is unused).
	ReasonLimitDenied = "limit-denied"
	// ReasonOffsetDenied marks a negative or over-budget offset (or any
	// nonzero offset on count/meta).
	ReasonOffsetDenied = "offset-denied"
	// ReasonCompanySelectDenied marks a request carrying caller-supplied
	// company selection: the model can never select companies.
	ReasonCompanySelectDenied = "company-select-denied"
	// ReasonCompanyDenied marks a model with no enforceable company scope
	// (neither classified-independent under allow-classified nor carrying
	// a usable CompanyField).
	ReasonCompanyDenied = "company-denied"
)

// isKnownOperation reports whether op belongs to the closed model-surface
// operation set. Validate rejects any Operations key outside it, and
// Authorize rejects any Request.Operation outside it without consulting
// the allowlist, so an unknown operation can never inherit the
// count/meta default path.
func isKnownOperation(op Operation) bool {
	switch op {
	case OpSearch, OpRead, OpCount, OpAggregate, OpMeta:
		return true
	default:
		return false
	}
}

// Validate rejects a contradictory or malformed policy centrally so the
// broker (New and Serve) and Authorize share one seal check: unknown
// version (exactly PolicyVersion is accepted, no legacy fallback — old
// profiles must be re-sealed via setup), empty instance, missing or
// malformed snapshot binding (SnapshotSHA256 must be the 64-char hex
// CanonicalDigest of the sealed snapshot; empty denies so pre-binding
// profiles must be re-sealed), empty operations or any unknown operation
// key (only search/read/count/aggregate/meta may appear), empty models,
// unknown SharedRecords (only deny|allow-classified), invalid
// CompanyScope, non-positive MaxLimit/MaxRowsPerCall/MaxResponseBytes,
// negative MaxOffset, negative session budgets
// (MaxCallsPerSession/MaxRowsPerSession — zero means unbounded, negative
// is malformed), and any per-model defect — empty Fields, a model, field,
// or CompanyField name that is not exactly canonical (stored text must
// equal its NormalizeName output, so padded aliases never seal),
// CompanyIndependent combined with a CompanyField, IncludeCompanyless on
// a CompanyIndependent model (meaningless there), or a negative
// per-model MaxLimit. A scoped model without a CompanyField is NOT a
// Validate error: the policy is well-formed but Authorize denies every
// request for that model with company-denied until a human supplies an
// enforcing field.
func (p *Policy) Validate() error {
	if p == nil {
		return fmt.Errorf("policy: nil policy")
	}
	if p.Version != PolicyVersion {
		return fmt.Errorf("policy: unsupported version %d (want %d): re-seal via setup", p.Version, PolicyVersion)
	}
	if strings.TrimSpace(p.Instance) == "" {
		return fmt.Errorf("policy: empty instance")
	}
	if len(p.SnapshotSHA256) != 64 {
		return fmt.Errorf("policy: snapshot binding must be 64 hex chars, got %d: re-seal via setup", len(p.SnapshotSHA256))
	}
	if _, err := hex.DecodeString(p.SnapshotSHA256); err != nil {
		return fmt.Errorf("policy: malformed snapshot binding: re-seal via setup")
	}
	if len(p.Operations) == 0 {
		return fmt.Errorf("policy: no operations allowlisted")
	}
	for op := range p.Operations {
		if !isKnownOperation(op) {
			return fmt.Errorf("policy: unknown operation %q", string(op))
		}
	}
	if len(p.Models) == 0 {
		return fmt.Errorf("policy: no models allowlisted")
	}
	if p.SharedRecords != SharedDeny && p.SharedRecords != SharedAllowClassified {
		return fmt.Errorf("policy: unknown shared-records classification %q", p.SharedRecords)
	}
	if p.Budgets.MaxLimit <= 0 {
		return fmt.Errorf("policy: non-positive global MaxLimit %d", p.Budgets.MaxLimit)
	}
	if p.Budgets.MaxConcurrentRPC < 0 || p.Budgets.MaxConcurrentRPC > 8 || p.Budgets.MinRPCIntervalMillis < 0 || p.Budgets.MinRPCIntervalMillis > 60000 {
		return fmt.Errorf("policy: invalid RPC concurrency/interval budget")
	}
	if p.Budgets.MaxRowsPerCall <= 0 {
		return fmt.Errorf("policy: non-positive MaxRowsPerCall %d", p.Budgets.MaxRowsPerCall)
	}
	if p.Budgets.MaxResponseBytes <= 0 {
		return fmt.Errorf("policy: non-positive MaxResponseBytes %d", p.Budgets.MaxResponseBytes)
	}
	if p.Budgets.MaxOffset < 0 {
		return fmt.Errorf("policy: negative MaxOffset %d", p.Budgets.MaxOffset)
	}
	if p.Budgets.MaxCallsPerSession < 0 {
		return fmt.Errorf("policy: negative MaxCallsPerSession %d", p.Budgets.MaxCallsPerSession)
	}
	if p.Budgets.MaxRowsPerSession < 0 {
		return fmt.Errorf("policy: negative MaxRowsPerSession %d", p.Budgets.MaxRowsPerSession)
	}
	if err := ValidateScope(p.Scope); err != nil {
		return err
	}
	for name, rule := range p.Models {
		if rule.LinkedEvidence && (!p.AllowLinkedEvidence || !IsEvidenceModel(name) || rule.CompanyField != "" || rule.CompanyIndependent || rule.IncludeCompanyless || rule.AllowAggregate) {
			return fmt.Errorf("policy: invalid linked evidence scope on %q", name)
		}
		norm, ok := NormalizeName(name)
		if !ok || norm != name {
			return fmt.Errorf("policy: bad model name %q", name)
		}
		if len(rule.Fields) == 0 {
			return fmt.Errorf("policy: model %q has no fields", name)
		}
		for _, f := range rule.Fields {
			nf, ok := NormalizeName(f)
			if !ok || nf != f {
				return fmt.Errorf("policy: model %q bad field %q", name, f)
			}
		}
		if rule.CompanyField != "" {
			cf, ok := NormalizeName(rule.CompanyField)
			if !ok || cf != rule.CompanyField {
				return fmt.Errorf("policy: model %q bad company field %q", name, rule.CompanyField)
			}
		}
		if rule.CompanyIndependent && rule.CompanyField != "" {
			return fmt.Errorf("policy: model %q contradictory: company-independent with company field", name)
		}
		if rule.CompanyIndependent && rule.IncludeCompanyless {
			return fmt.Errorf("policy: model %q meaningless companyless opt-in on independent model", name)
		}
		if rule.MaxLimit < 0 {
			return fmt.Errorf("policy: model %q negative MaxLimit %d", name, rule.MaxLimit)
		}
	}
	return nil
}

// Authorize is the deny-by-default gate. It is pure: no network, keychain,
// or filesystem access. Denial precedes everything, enforced in order:
//
//  1. The request operation must belong to the closed known set
//     (search/read/count/aggregate/meta). Anything else denies with
//     operation-denied without consulting the allowlist, so an unknown
//     operation can never inherit the count/meta default path — even on
//     a malformed allowlist carrying that key.
//  2. The sealed policy must Validate (nil receiver, bad
//     version/instance, empty or unknown-keyed operations, empty models,
//     non-canonical stored names, unknown SharedRecords,
//     non-positive budgets, invalid CompanyScope, contradictory model
//     rules). Scope failures report invalid-scope; all other seal
//     failures report invalid-policy.
//  3. The operation must be allowlisted in Policy.Operations.
//  4. The model name must normalize (NormalizeName) and be present in
//     Policy.Models (stored keys are canonical, so the normalized request
//     resolves to exactly one sealed rule). Aggregate additionally
//     requires ModelRule.AllowAggregate.
//  5. Field projection: search/read require a non-empty explicit
//     projection (omitted, nil, or empty Fields deny — there is no
//     default-all-fields). Every entry must normalize, must not contain
//     a wildcard, and must be single-segment: any dotted entry denies
//     under the minimum safe choice (no separately reviewed scoped
//     traversal implementation exists). Single `id` is structural and
//     always permitted; a projection lacking `id` is a legitimate exact
//     projection — the broker appends `id` (see EnsureID) because Odoo
//     implicitly returns it on search_read.
//  6. Every field referenced in Domain, Order, and GroupBy must be
//     single-segment and allowlisted (dotted references deny as above).
//     Malformed domain/order shapes — including unknown operators,
//     hierarchy operators (child_of, parent_of), and unbounded operands —
//     deny.
//  7. Limit/Offset must sit within budgets. Over-max DENIES — it never
//     clamps, because clamping would silently return a narrower slice
//     than the caller asked for and mask budget bypasses. Row-returning
//     operations (search/read/aggregate) require Limit in [1, effective
//     max] where effective max is the minimum of the positive caps among
//     Budgets.MaxLimit, ModelRule.MaxLimit, and Budgets.MaxRowsPerCall,
//     and Offset in [0, Budgets.MaxOffset]. Count/meta never page, so any
//     nonzero Limit/Offset on them denies.
//  8. Non-empty CompanyIDs denies: the model cannot select companies; the
//     broker injects the enforced scope after authorization.
//  9. Company rule: a human-reviewed CompanyIndependent model under
//     SharedRecords allow-classified with no CompanyField passes without
//     a fragment; an independent model with a CompanyField set denies
//     (contradictory — already rejected by Validate, failed closed here
//     too); otherwise a usable canonical CompanyField passes (the broker
//     ANDs the CompanyDomain fragment after the caller domain); anything
//     else denies. Scoped models NEVER pass without a fragment.
//
// A nil SchemaView only constrains dotted paths: single-segment fields
// resolve against the rule alone, while any dot-path traversal without a
// schema to verify it denies.
func (p *Policy) Authorize(schema SchemaView, r Request) Decision {
	deny := func(reason string) Decision { return Decision{Allow: false, Reason: reason} }
	if p == nil {
		return deny(ReasonInvalidPolicy)
	}
	if !isKnownOperation(r.Operation) {
		return deny(ReasonOperationDenied)
	}
	if err := p.Validate(); err != nil {
		if serr := ValidateScope(p.Scope); serr != nil {
			return deny(ReasonInvalidScope)
		}
		return deny(ReasonInvalidPolicy)
	}
	if r.Operation == OpMeta && strings.TrimSpace(r.Model) == "" {
		// Policy listing: no model data, only the sealed allowlist shape.
		// Still requires a well-formed policy/scope, the op allowlist,
		// zero paging, and no caller company selection.
		if !p.Operations[r.Operation] {
			return deny(ReasonOperationDenied)
		}
		if r.Limit != 0 || r.Offset != 0 {
			return deny(ReasonLimitDenied)
		}
		if len(r.CompanyIDs) != 0 {
			return deny(ReasonCompanySelectDenied)
		}
		return Decision{Allow: true, Reason: ReasonAllow}
	}
	if !p.Operations[r.Operation] {
		return deny(ReasonOperationDenied)
	}
	model, ok := NormalizeName(r.Model)
	if !ok {
		return deny(ReasonInvalidModel)
	}
	rule, ok := p.Models[model]
	if !ok {
		return deny(ReasonUnknownModel)
	}
	if rule.LinkedEvidence {
		return deny(ReasonCompanyDenied)
	}
	if p.RequireBoundedQueries && r.Operation != OpMeta && !rule.CompanyIndependent && !BoundedDomain(r.Domain) {
		return deny(ReasonDomainDenied)
	}
	if p.RequireBoundedQueries && (len(r.Fields) > 64 || len(r.GroupBy) > 3) {
		return deny(ReasonFieldDenied)
	}
	if r.Operation == OpAggregate && !rule.AllowAggregate {
		return deny(ReasonAggregateDenied)
	}
	allowed := make(map[string]bool, len(rule.Fields)+1)
	for _, f := range rule.Fields {
		if nf, ok := NormalizeName(f); ok {
			allowed[nf] = true
		}
	}
	if r.Operation == OpSearch || r.Operation == OpRead {
		if len(r.Fields) == 0 {
			return deny(ReasonFieldDenied)
		}
	}
	for _, f := range r.Fields {
		if strings.Contains(f, "*") {
			return deny(ReasonFieldDenied)
		}
		nf, ok := NormalizeName(f)
		if !ok {
			return deny(ReasonFieldDenied)
		}
		if strings.Contains(nf, ".") {
			if !checkPath(p, allowed, schema, model, nf) {
				return deny(ReasonFieldDenied)
			}
			continue
		}
		if nf == "id" {
			continue
		}
		if !allowed[nf] {
			return deny(ReasonFieldDenied)
		}
	}
	// "id" is structural: always permitted in filter/order/group references
	// (read-by-id, count, ordering) without granting it as returned data.
	refs := make(map[string]bool, len(allowed)+1)
	for k, v := range allowed {
		refs[k] = v
	}
	refs["id"] = true
	if !checkDomain(p, refs, schema, model, r.Domain) {
		return deny(ReasonDomainDenied)
	}
	if !checkOrder(p, refs, schema, model, r.Order) {
		return deny(ReasonOrderDenied)
	}
	for _, g := range r.GroupBy {
		if !checkPath(p, refs, schema, model, g) {
			return deny(ReasonGroupByDenied)
		}
	}
	switch r.Operation {
	case OpSearch, OpRead, OpAggregate:
		max := p.Budgets.MaxLimit
		if rule.MaxLimit > 0 && rule.MaxLimit < max {
			max = rule.MaxLimit
		}
		if p.Budgets.MaxRowsPerCall > 0 && p.Budgets.MaxRowsPerCall < max {
			max = p.Budgets.MaxRowsPerCall
		}
		if r.Limit <= 0 || r.Limit > max {
			return deny(ReasonLimitDenied)
		}
		if r.Offset < 0 || r.Offset > p.Budgets.MaxOffset {
			return deny(ReasonOffsetDenied)
		}
	case OpCount, OpMeta: // count, meta: row paging is unused, so it must be zero.
		if r.Limit != 0 {
			return deny(ReasonLimitDenied)
		}
		if r.Offset != 0 {
			return deny(ReasonOffsetDenied)
		}
	default: // Unreachable: unknown operations deny above. Fail closed.
		return deny(ReasonOperationDenied)
	}
	if len(r.CompanyIDs) != 0 {
		return deny(ReasonCompanySelectDenied)
	}
	if rule.CompanyIndependent {
		if p.SharedRecords == SharedAllowClassified && rule.CompanyField == "" {
			return Decision{Allow: true, Reason: ReasonAllow}
		}
		return deny(ReasonCompanyDenied)
	}
	if cf, ok := NormalizeName(rule.CompanyField); ok && cf == rule.CompanyField {
		return Decision{Allow: true, Reason: ReasonAllow}
	}
	return deny(ReasonCompanyDenied)
}

// validDomainOp reports whether op is a known Odoo domain operator in the
// strict allowlist. Unknown operators deny rather than pass through to the
// server, so a mistyped or server-specific operator can never widen a query.
// Hierarchy operators (child_of, parent_of) are deliberately absent: they
// authorize server-side hierarchy traversal and deny unconditionally under
// the minimum safe choice (no separately reviewed scoped implementation
// exists).
func validDomainOp(op string) bool {
	switch op {
	case "=", "!=", ">", "<", ">=", "<=",
		"in", "not in", "like", "ilike",
		"=like", "=ilike":
		return true
	default:
		return false
	}
}

// isDomainScalar reports whether v is a bounded domain operand: a JSON
// scalar (string, bool, nil, number) with no nesting. Numbers cover every
// Go numeric kind plus json.Number (decoders using UseNumber); anything
// else — maps, slices, structs — is not scalar.
func isDomainScalar(v any) bool {
	switch v.(type) {
	case nil, string, bool, json.Number,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return true
	default:
		return false
	}
}

// checkDomainValue bounds a leaf operand: scalars pass, as do flat arrays
// of scalars; nested arrays or maps as (or inside) the value deny. The
// `in` operator additionally requires an array value — a scalar `in`
// operand denies.
func checkDomainValue(op string, v any) bool {
	if arr, ok := v.([]any); ok {
		for _, e := range arr {
			if !isDomainScalar(e) {
				return false
			}
		}
		return true
	}
	if op == "in" {
		return false
	}
	if _, ok := v.(map[string]any); ok {
		return false
	}
	return isDomainScalar(v)
}

// checkDomain validates a decoded-JSON domain: nil or an empty array (no
// filter) or an array whose elements are logical prefix operators ("&",
// "|", "!") or leaf [field, operator, value] triples. Anything else —
// wrong top-level shape, wrong leaf arity, non-string field/operator,
// unknown operator, an unresolvable field path, an unbounded operand, or
// an arity-incomplete expression — fails closed. Values are bounded by
// checkDomainValue (never passed through blindly).
//
// Arity completeness matters because the broker appends the enforced company
// fragment AFTER the caller domain: ["|", leaf] alone would combine with the
// fragment as (leaf OR fragment) instead of narrowing. The stack check below
// requires the caller expression to reduce to exactly one complete
// expression (implicit AND of one or more complete terms), so the appended
// fragment always further narrows via AND.
func checkDomain(p *Policy, allowed map[string]bool, schema SchemaView, model string, d any) bool {
	if d == nil {
		return true
	}
	arr, ok := d.([]any)
	if !ok {
		return false
	}
	if len(arr) == 0 {
		return true
	}
	// Prefix arity: the domain is an implicit AND of one or more complete
	// prefix terms. Track open slots in the current term: a binary operator
	// adds one slot, "!" keeps one, a leaf fills one. A new term starts
	// whenever no slot is open. Trailing operators or dangling leaves deny.
	need := 0
	terms := 0
	for _, el := range arr {
		switch t := el.(type) {
		case string:
			if need == 0 {
				need = 1
				terms++
			}
			switch t {
			case "&", "|":
				need++
			case "!":
			default:
				return false
			}
		case []any:
			if len(t) != 3 {
				return false
			}
			field, ok := t[0].(string)
			if !ok {
				return false
			}
			op, ok := t[1].(string)
			if !ok || !validDomainOp(op) {
				return false
			}
			if !checkPath(p, allowed, schema, model, field) {
				return false
			}
			if !checkDomainValue(op, t[2]) {
				return false
			}
			if need == 0 {
				need = 1
				terms++
			}
			need--
		default:
			return false
		}
	}
	return terms > 0 && need == 0
}

// checkOrder validates a comma-separated order clause ("name asc, id desc").
// Each item's head is a field path resolved like any other reference;
// trailing tokens must each be asc/desc (case-insensitive). Empty clauses
// pass; empty items or bogus directions deny.
func checkOrder(p *Policy, allowed map[string]bool, schema SchemaView, model, order string) bool {
	if strings.TrimSpace(order) == "" {
		return true
	}
	for _, chunk := range strings.Split(order, ",") {
		toks := strings.Fields(chunk)
		if len(toks) == 0 {
			return false
		}
		for _, dir := range toks[1:] {
			if !strings.EqualFold(dir, "asc") && !strings.EqualFold(dir, "desc") {
				return false
			}
		}
		if !checkPath(p, allowed, schema, model, toks[0]) {
			return false
		}
	}
	return true
}

// checkPath resolves one single-segment field reference against the
// requesting model's allowlist. Dotted paths (e.g. "partner_id.name") are
// unconditionally denied under the minimum safe choice: cross-model
// references (domain, order, group-by, projection, aggregate) deny unless a
// separately reviewed complete scoped implementation exists. Discovery
// relationships (schema metadata, snapshot field relations) stay readable
// for display, but never authorize traversal. Single-segment names must
// normalize and sit in the rule allowlist; anything else denies.
func checkPath(p *Policy, allowed map[string]bool, schema SchemaView, model, path string) bool {
	raw := strings.Split(strings.TrimSpace(path), ".")
	segs := make([]string, 0, len(raw))
	for _, s := range raw {
		n, ok := NormalizeName(s)
		if !ok {
			return false
		}
		segs = append(segs, n)
	}
	if len(segs) == 0 {
		return false
	}
	if len(segs) != 1 {
		return false
	}
	return allowed[segs[0]]
}
