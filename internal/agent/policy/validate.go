package policy

import (
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

// Validate rejects a contradictory or malformed policy centrally so the
// broker (New and Serve) and Authorize share one seal check: bad
// version/instance, empty operations/models, unknown SharedRecords
// (only deny|allow-classified), invalid CompanyScope, non-positive
// MaxLimit/MaxRowsPerCall/MaxResponseBytes, negative MaxOffset, and any
// per-model defect — empty Fields, a field name failing NormalizeName, a
// CompanyField failing NormalizeName when set, CompanyIndependent combined
// with a CompanyField, IncludeCompanyless on a CompanyIndependent model
// (meaningless there), or a negative per-model MaxLimit. A scoped model
// without a CompanyField is NOT a Validate error: the policy is
// well-formed but Authorize denies every request for that model with
// company-denied until a human supplies an enforcing field.
func (p *Policy) Validate() error {
	if p == nil {
		return fmt.Errorf("policy: nil policy")
	}
	if p.Version <= 0 {
		return fmt.Errorf("policy: bad version %d", p.Version)
	}
	if strings.TrimSpace(p.Instance) == "" {
		return fmt.Errorf("policy: empty instance")
	}
	if len(p.Operations) == 0 {
		return fmt.Errorf("policy: no operations allowlisted")
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
	if p.Budgets.MaxRowsPerCall <= 0 {
		return fmt.Errorf("policy: non-positive MaxRowsPerCall %d", p.Budgets.MaxRowsPerCall)
	}
	if p.Budgets.MaxResponseBytes <= 0 {
		return fmt.Errorf("policy: non-positive MaxResponseBytes %d", p.Budgets.MaxResponseBytes)
	}
	if p.Budgets.MaxOffset < 0 {
		return fmt.Errorf("policy: negative MaxOffset %d", p.Budgets.MaxOffset)
	}
	if err := ValidateScope(p.Scope); err != nil {
		return err
	}
	for name, rule := range p.Models {
		if _, ok := NormalizeName(name); !ok {
			return fmt.Errorf("policy: bad model name %q", name)
		}
		if len(rule.Fields) == 0 {
			return fmt.Errorf("policy: model %q has no fields", name)
		}
		for _, f := range rule.Fields {
			if _, ok := NormalizeName(f); !ok {
				return fmt.Errorf("policy: model %q bad field %q", name, f)
			}
		}
		if rule.CompanyField != "" {
			if _, ok := NormalizeName(rule.CompanyField); !ok {
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
//  1. The sealed policy must Validate (nil receiver, bad
//     version/instance, empty operations/models, unknown SharedRecords,
//     non-positive budgets, invalid CompanyScope, contradictory model
//     rules). Scope failures report invalid-scope; all other seal
//     failures report invalid-policy.
//  2. The operation must be allowlisted in Policy.Operations.
//  3. The model name must normalize (NormalizeName) and be present in
//     Policy.Models. Aggregate additionally requires
//     ModelRule.AllowAggregate.
//  4. Field projection: search/read require a non-empty explicit
//     projection (omitted, nil, or empty Fields deny — there is no
//     default-all-fields). Every entry must normalize, must not contain
//     a wildcard, and dotted entries resolve via checkPath (root
//     allowlisted, intermediates relational, terminal explicitly
//     approved on an enforceable target). Single `id` is structural and
//     always permitted; a projection lacking `id` is a legitimate exact
//     projection — the broker appends `id` (see EnsureID) because Odoo
//     implicitly returns it on search_read.
//  5. Every field referenced in Domain, Order, and GroupBy must resolve
//     (dot-paths via checkPath with the same traversal rules).
//     Malformed domain/order shapes — including unknown operators and
//     unbounded operands — deny.
//  6. Limit/Offset must sit within budgets. Over-max DENIES — it never
//     clamps, because clamping would silently return a narrower slice
//     than the caller asked for and mask budget bypasses. Row-returning
//     operations (search/read/aggregate) require Limit in [1, effective
//     max] where effective max is the minimum of the positive caps among
//     Budgets.MaxLimit, ModelRule.MaxLimit, and Budgets.MaxRowsPerCall,
//     and Offset in [0, Budgets.MaxOffset]. Count/meta never page, so any
//     nonzero Limit/Offset on them denies.
//  7. Non-empty CompanyIDs denies: the model cannot select companies; the
//     broker injects the enforced scope after authorization.
//  8. Company rule: a human-reviewed CompanyIndependent model under
//     SharedRecords allow-classified with no CompanyField passes without
//     a fragment; an independent model with a CompanyField set denies
//     (contradictory — already rejected by Validate, failed closed here
//     too); otherwise a usable CompanyField passes (the broker ANDs the
//     CompanyDomain fragment after the caller domain); anything else
//     denies. Scoped models NEVER pass without a fragment.
//
// A nil SchemaView only constrains dotted paths: single-segment fields
// resolve against the rule alone, while any dot-path traversal without a
// schema to verify it denies.
func (p *Policy) Authorize(schema SchemaView, r Request) Decision {
	deny := func(reason string) Decision { return Decision{Allow: false, Reason: reason} }
	if p == nil {
		return deny(ReasonInvalidPolicy)
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
	default: // count, meta: row paging is unused, so it must be zero.
		if r.Limit != 0 {
			return deny(ReasonLimitDenied)
		}
		if r.Offset != 0 {
			return deny(ReasonOffsetDenied)
		}
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
	if _, ok := NormalizeName(rule.CompanyField); ok {
		return Decision{Allow: true, Reason: ReasonAllow}
	}
	return deny(ReasonCompanyDenied)
}

// validDomainOp reports whether op is a known Odoo domain operator in the
// strict allowlist. Unknown operators deny rather than pass through to the
// server, so a mistyped or server-specific operator can never widen a query.
func validDomainOp(op string) bool {
	switch op {
	case "=", "!=", ">", "<", ">=", "<=",
		"in", "not in", "like", "ilike",
		"=like", "=ilike", "child_of", "parent_of":
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

// targetEnforceable reports whether a traversal target model's rule carries
// its own enforceable company scope: human-reviewed independent under
// allow-classified with no company field, or a scoped rule with a usable
// CompanyField. Anything else (contradictory, fieldless scoped) denies the
// traversal.
func targetEnforceable(p *Policy, rule ModelRule) bool {
	if rule.CompanyIndependent {
		return p.SharedRecords == SharedAllowClassified && rule.CompanyField == ""
	}
	_, ok := NormalizeName(rule.CompanyField)
	return ok
}

// checkPath resolves one field reference. Single-segment names must
// normalize and sit in the rule allowlist. Dotted paths (e.g.
// "partner_id.name") default DENY and are allowed only when the full path
// is explicitly approved: the root sits in the requesting model's rule,
// every intermediate segment resolves through SchemaView to a relational
// field (Relation != ""), the terminal field exists on the target model AND
// is explicitly listed in the target model's Policy.Models entry
// (structural `id` is exempt from both terminal checks), and the target
// rule is itself enforceable via targetEnforceable. Schema existence alone
// never approves: a terminal present in the schema but absent from the
// target rule, or a target model absent from the policy, denies. Unknown
// models, missing fields, non-relational intermediates, missing schemas,
// and missing policies all deny.
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
	if !allowed[segs[0]] {
		return false
	}
	if len(segs) == 1 {
		return true
	}
	if p == nil || schema == nil {
		return false
	}
	cur, ok := schema.Model(model)
	if !ok {
		return false
	}
	target := ""
	for _, s := range segs[:len(segs)-1] {
		fm, ok := cur.Field(s)
		if !ok || fm.Relation == "" {
			return false
		}
		target = fm.Relation
		cur, ok = schema.Model(fm.Relation)
		if !ok {
			return false
		}
	}
	terminal := segs[len(segs)-1]
	if terminal != "id" {
		if _, ok := cur.Field(terminal); !ok {
			return false
		}
	}
	targetRule, ok := p.Models[target]
	if !ok {
		return false
	}
	if terminal != "id" {
		found := false
		for _, f := range targetRule.Fields {
			if nf, ok := NormalizeName(f); ok && nf == terminal {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return targetEnforceable(p, targetRule)
}
