package policy

import "fmt"

// ValidateScope rejects any company scope that would let the model imply or
// select a company context: fewer than two enabled companies, or a default
// outside the enabled set. Authorize treats an invalid scope as a malformed
// policy and denies everything.
func ValidateScope(s CompanyScope) error {
	if len(s.Enabled) < 2 {
		return fmt.Errorf("policy: company scope must enable at least two companies, got %d", len(s.Enabled))
	}
	for _, id := range s.Enabled {
		if id == s.Default {
			return nil
		}
	}
	return fmt.Errorf("policy: default company %d not in enabled set", s.Default)
}

// CompanyFilterFragment builds the enforcing company fragment the broker
// ANDs into the caller domain AFTER the caller domain. The scoped shapes
// are [[CompanyField, "in", Enabled]] without the companyless opt-in, and
// [["|", [CompanyField, "in", Enabled], [CompanyField, "=", false]]]
// with ModelRule.IncludeCompanyless (explicit per-model opt-in admitting
// company_id=false records alongside scoped records).
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
	if !ok {
		return nil, true
	}
	ids := make([]any, 0, len(scope.Enabled))
	for _, id := range scope.Enabled {
		ids = append(ids, id)
	}
	if rule.IncludeCompanyless {
		return []any{[]any{"|", []any{field, "in", ids}, []any{field, "=", false}}}, true
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
