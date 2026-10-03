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

// CompanyDomain builds the enforcing company fragment the broker ANDs into
// the caller domain AFTER the caller domain:
//
//	[[CompanyField, "in", Enabled]]
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
// treated as unset.
//
// The Enabled list is copied so later scope mutation cannot widen a fragment
// already handed out.
func CompanyDomain(rule ModelRule, scope CompanyScope) (frag []any, enforce bool) {
	if rule.CompanyIndependent {
		return nil, false
	}
	field, ok := NormalizeName(rule.CompanyField)
	if !ok {
		return nil, true
	}
	ids := make([]any, 0, len(scope.Enabled))
	for _, id := range scope.Enabled {
		ids = append(ids, id)
	}
	return []any{[]any{field, "in", ids}}, true
}
