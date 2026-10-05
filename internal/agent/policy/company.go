package policy

import "fmt"

// ValidateScope rejects any company scope that would let the model imply or
// select a company context: fewer than two enabled companies, any
// non-positive ID, any duplicate ID, or a default outside the enabled set.
// Authorize treats an invalid scope as a malformed policy and denies
// everything.
func ValidateScope(s CompanyScope) error {
	if len(s.Enabled) < 2 {
		return fmt.Errorf("policy: company scope must enable at least two companies, got %d", len(s.Enabled))
	}
	seen := make(map[int]bool, len(s.Enabled))
	for _, id := range s.Enabled {
		if id <= 0 {
			return fmt.Errorf("policy: company scope has non-positive company id %d", id)
		}
		if seen[id] {
			return fmt.Errorf("policy: company scope has duplicate company id %d", id)
		}
		seen[id] = true
	}
	if !seen[s.Default] {
		return fmt.Errorf("policy: default company %d not in enabled set", s.Default)
	}
	return nil
}

// CompanyFilterFragment builds the enforcing company fragment the broker
// ANDs into the caller domain by appending AFTER the arity-complete caller
// domain (see checkDomain: the caller expression must reduce to exactly one
// complete expression so an appended fragment always further narrows via
// implicit AND). The scoped shape without the companyless opt-in is a single
// leaf [CompanyField, "in", Enabled]. With ModelRule.IncludeCompanyless
// (explicit per-model opt-in admitting company_id=false records alongside
// scoped records) the shape is a FLAT three-element prefix expression
// ["|", leafIn, leafFalse] — three appended elements, NOT one nested list:
// the "|" prefix operator applies to the two following leaves at the same
// domain level, so the whole fragment stays arity-complete and the broker's
// append-after-caller-domain ANDs correctly. (A nested [["|", ...]] list
// would be misclassified as a leaf by Odoo domain parsing.)
//
// enforce=false only for human-reviewed company-independent models
// (rule.CompanyIndependent): no fragment is needed because the model holds
// shared/global records, and Authorize only passes those when the policy
// classifies shared records as allow-classified.
//
// enforce=true with a non-nil fragment means the broker MUST append the
// fragment to the domain before any RPC. enforce=true with a nil fragment
// means enforcement is required but impossible (no usable CompanyField):
// the caller MUST deny. Fail-closed shapes: an empty Enabled list yields
// [field, "in", []] which matches nothing, and an invalid CompanyField is
// treated as unset. Scoped models NEVER pass without a fragment.
//
// The Enabled list is copied so later scope mutation cannot widen a fragment
// already handed out.
func CompanyFilterFragment(rule ModelRule, scope CompanyScope) (frag []any, enforce bool) {
	if rule.CompanyIndependent {
		if rule.CompanyField == "" {
			return nil, false
		}
		return nil, true
	}
	field, ok := NormalizeName(rule.CompanyField)
	if !ok || field != rule.CompanyField {
		return nil, true
	}
	ids := make([]any, 0, len(scope.Enabled))
	for _, id := range scope.Enabled {
		ids = append(ids, id)
	}
	if rule.IncludeCompanyless {
		leafIn := []any{field, "in", ids}
		leafFalse := []any{field, "=", false}
		if field == "product_tmpl_id.company_id" {
			return []any{[]any{"product_tmpl_id", "!=", false}, "|", leafIn, leafFalse}, true
		}
		return []any{"|", leafIn, leafFalse}, true
	}
	if field == "product_tmpl_id.company_id" {
		return []any{[]any{"product_tmpl_id", "!=", false}, []any{field, "in", ids}}, true
	}
	return []any{[]any{field, "in", ids}}, true
}

// CompanyDomain builds the enforcing company fragment the broker ANDs into
// the caller domain AFTER the caller domain (see CompanyFilterFragment,
// which supplies the scoped shapes including the companyless opt-in).
//
// A company-independent rule yields (nil, false) ONLY when no CompanyField
// is set; an independent rule with CompanyField set is contradictory
// (rejected by Validate) and yields (nil, true) here so callers deny.
// Anything else delegates to CompanyFilterFragment.
func CompanyDomain(rule ModelRule, scope CompanyScope) (frag []any, enforce bool) {
	if rule.CompanyIndependent {
		if rule.CompanyField == "" {
			return nil, false
		}
		return nil, true
	}
	return CompanyFilterFragment(rule, scope)
}

// CompanyFieldValid verifies that rule CompanyField (for model) normalizes
// AND resolves via schema to a many2one field whose relation is res.company
// (the direct company link, e.g. company_id). many2many company links
// (e.g. company_ids) FAIL CLOSED in this release: multi-company membership
// has no enforceable fragment shape yet, so a many2many field resolving to
// res.company is rejected as non-enforceable. A res.users company-field
// chain root is NOT accepted here: it names users, not companies, and would
// let a scoped rule pass on a field that does not itself filter by company.
// The broker calls this pre-credential (before any credential resolution or
// RPC) so a scoped rule with a syntactically valid but semantically
// non-company field denies before secrets are touched.
// Company-independent rules without a CompanyField pass trivially (nothing
// to verify); a contradictory independent rule WITH a CompanyField fails.
func (p *Policy) CompanyFieldValid(schema SchemaView, model string) error {
	if p == nil {
		return fmt.Errorf("policy: nil policy")
	}
	rule, ok := p.Models[model]
	if !ok {
		return fmt.Errorf("policy: unknown model %q", model)
	}
	if rule.LinkedEvidence && p.AllowLinkedEvidence && IsEvidenceModel(model) {
		return nil
	}
	if rule.CompanyIndependent {
		if rule.CompanyField != "" {
			return fmt.Errorf("policy: model %q contradictory: company-independent with company field", model)
		}
		return nil
	}
	field, ok := NormalizeName(rule.CompanyField)
	if !ok || field == "" || field != rule.CompanyField {
		return fmt.Errorf("policy: model %q has no usable company field", model)
	}
	if field == "product_tmpl_id.company_id" && (model == "product.template.attribute.line" || model == "product.template.attribute.value") {
		if schema == nil {
			return fmt.Errorf("policy: missing parent schema")
		}
		child, ok := schema.Model(model)
		if !ok {
			return fmt.Errorf("policy: missing child schema")
		}
		parent, ok := child.Field("product_tmpl_id")
		if !ok || parent.Type != "many2one" || parent.Relation != "product.template" {
			return fmt.Errorf("policy: invalid product parent")
		}
		target, ok := schema.Model("product.template")
		if !ok {
			return fmt.Errorf("policy: missing product schema")
		}
		company, ok := target.Field("company_id")
		if !ok || company.Type != "many2one" || company.Relation != "res.company" {
			return fmt.Errorf("policy: invalid product company scope")
		}
		return nil
	}
	if schema == nil {
		return fmt.Errorf("policy: model %q company field %q unverifiable without schema", model, field)
	}
	mv, ok := schema.Model(model)
	if !ok {
		return fmt.Errorf("policy: model %q not in schema", model)
	}
	fm, ok := mv.Field(field)
	if !ok {
		return fmt.Errorf("policy: model %q company field %q not in schema", model, field)
	}
	if fm.Relation != "res.company" {
		return fmt.Errorf("policy: model %q company field %q relation %q is not res.company", model, field, fm.Relation)
	}
	switch fm.Type {
	case "many2one":
		return nil
	case "many2many":
		return fmt.Errorf("policy: model %q company field %q is many2many: multi-company links are not enforceable in this release (only many2one company fields are supported)", model, field)
	default:
		return fmt.Errorf("policy: model %q company field %q type %q is not a company relation", model, field, fm.Type)
	}
}
