package policy

import "strings"

// Stable, secret-free decision reasons. Reasons name operations, models, or
// fields at most — never domain values, tokens, credentials, or company IDs.
const (
	// ReasonAllow marks an authorized request.
	ReasonAllow = "allow"
	// ReasonInvalidPolicy marks a zero-value or malformed policy
	// (bad version/instance, empty operations/models, unknown
	// SharedRecords, non-positive global MaxLimit).
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
	// ReasonFieldDenied marks a requested field outside the model rule.
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

// Authorize is the deny-by-default gate. It is pure: no network, keychain,
// or filesystem access. Denial precedes everything, enforced in order:
//
//  1. Zero-value/malformed policy denies (nil receiver, bad
//     version/instance, empty operations/models, unknown SharedRecords,
//     non-positive global MaxLimit, invalid CompanyScope).
//  2. The operation must be allowlisted in Policy.Operations.
//  3. The model name must normalize (NormalizeName) and be present in
//     Policy.Models. Aggregate additionally requires
//     ModelRule.AllowAggregate.
//  4. Every requested field must normalize and be an exact member of the
//     model rule's Fields (top-level names; dotted entries match only if
//     literally listed).
//  5. Every field referenced in Domain, Order, and GroupBy must resolve
//     (dot-paths via checkPath: root allowlisted, every intermediate
//     segment relational through SchemaView, terminal present). Malformed
//     domain/order shapes deny.
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
//     SharedRecords allow-classified passes without a fragment; otherwise
//     a usable CompanyField passes (the broker ANDs the CompanyDomain
//     fragment after the caller domain); anything else denies.
//
// A nil SchemaView only constrains dotted paths: single-segment fields
// resolve against the rule alone, while any dot-path traversal without a
// schema to verify it denies.
func (p *Policy) Authorize(schema SchemaView, r Request) Decision {
	deny := func(reason string) Decision { return Decision{Allow: false, Reason: reason} }
	if p == nil || p.Version <= 0 || p.Instance == "" || len(p.Operations) == 0 || len(p.Models) == 0 {
		return deny(ReasonInvalidPolicy)
	}
	if p.SharedRecords != SharedDeny && p.SharedRecords != SharedAllowClassified {
		return deny(ReasonInvalidPolicy)
	}
	if p.Budgets.MaxLimit <= 0 {
		return deny(ReasonInvalidPolicy)
	}
	if err := ValidateScope(p.Scope); err != nil {
		return deny(ReasonInvalidScope)
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
	for _, f := range r.Fields {
		nf, ok := NormalizeName(f)
		if !ok || !allowed[nf] {
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
	if !checkDomain(refs, schema, model, r.Domain) {
		return deny(ReasonDomainDenied)
	}
	if !checkOrder(refs, schema, model, r.Order) {
		return deny(ReasonOrderDenied)
	}
	for _, g := range r.GroupBy {
		if !checkPath(refs, schema, model, g) {
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
	if rule.CompanyIndependent && p.SharedRecords == SharedAllowClassified {
		return Decision{Allow: true, Reason: ReasonAllow}
	}
	if _, ok := NormalizeName(rule.CompanyField); ok {
		return Decision{Allow: true, Reason: ReasonAllow}
	}
	return deny(ReasonCompanyDenied)
}

// validDomainOp reports whether op is a known Odoo domain operator.
// Unknown operators deny rather than pass through to the server, so a
// mistyped or server-specific operator can never widen a query.
func validDomainOp(op string) bool {
	switch op {
	case "=", "!=", "<>", ">", "<", ">=", "<=",
		"in", "not in", "like", "not like", "ilike", "not ilike",
		"=like", "=ilike", "child_of", "parent_of":
		return true
	default:
		return false
	}
}

// checkDomain validates a decoded-JSON domain: nil (no filter) or an array
// whose elements are logical prefix operators ("&", "|", "!") or leaf
// [field, operator, value] triples. Anything else — wrong top-level shape,
// wrong leaf arity, non-string field/operator, unknown operator, an
// unresolvable field path, or an arity-incomplete expression — fails closed.
// Values (third elements) are never inspected.
//
// Arity completeness matters because the broker appends the enforced company
// fragment AFTER the caller domain: ["|", leaf] alone would combine with the
// fragment as (leaf OR fragment) instead of narrowing. The stack check below
// requires the caller expression to reduce to exactly one complete
// expression (implicit AND of one or more complete terms), so the appended
// fragment always further narrows via AND.
func checkDomain(allowed map[string]bool, schema SchemaView, model string, d any) bool {
	if d == nil {
		return true
	}
	arr, ok := d.([]any)
	if !ok {
		return false
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
			if !checkPath(allowed, schema, model, field) {
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
func checkOrder(allowed map[string]bool, schema SchemaView, model, order string) bool {
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
		if !checkPath(allowed, schema, model, toks[0]) {
			return false
		}
	}
	return true
}

// checkPath resolves one field reference. Single-segment names must
// normalize and sit in the rule allowlist. Dotted paths (e.g.
// "partner_id.name") additionally require the root in the allowlist, every
// intermediate segment to resolve through SchemaView to a relational field
// (Relation != ""), and the terminal to exist on the final model. The
// terminal itself needs only to exist: it filters, it is never returned, so
// the rule allowlist governs returned fields while the schema governs
// traversal shape. Unknown models, missing fields, non-relational
// intermediates, and missing schemas all deny.
func checkPath(allowed map[string]bool, schema SchemaView, model, path string) bool {
	segs := strings.Split(strings.TrimSpace(path), ".")
	for _, s := range segs {
		if _, ok := NormalizeName(s); !ok {
			return false
		}
	}
	if !allowed[segs[0]] {
		return false
	}
	if len(segs) == 1 {
		return true
	}
	if schema == nil {
		return false
	}
	cur, ok := schema.Model(model)
	if !ok {
		return false
	}
	for _, s := range segs[:len(segs)-1] {
		fm, ok := cur.Field(s)
		if !ok || fm.Relation == "" {
			return false
		}
		cur, ok = schema.Model(fm.Relation)
		if !ok {
			return false
		}
	}
	_, ok = cur.Field(segs[len(segs)-1])
	return ok
}
