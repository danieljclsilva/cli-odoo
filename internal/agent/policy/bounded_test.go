package policy

import (
	"strings"
	"testing"
)

func TestBoundedDomainAdmission(t *testing.T) {
	leaf := func(field, op string, v any) []any { return []any{field, op, v} }
	for _, domain := range []any{
		[]any{leaf("id", "=", 4)}, []any{leaf("product_tmpl_id", "in", []any{float64(1), float64(2)})},
		[]any{leaf("create_date", ">=", "2026-10-01"), leaf("create_date", "<", "2026-11-01")},
	} {
		if !BoundedDomain(domain) {
			t.Fatalf("legitimate focused filter refused: %v", domain)
		}
	}
	for _, domain := range []any{
		nil, []any{}, []any{leaf("id", "=", false)}, []any{leaf("id", "=", -1)},
		[]any{"|", leaf("id", "=", 1), leaf("state", "=", "done")},
		[]any{"!", leaf("id", "=", 1)}, []any{leaf("id", "in", []any{})},
		[]any{leaf("name", "ilike", "%")},
		[]any{leaf("create_date", ">=", "2025-01-01"), leaf("create_date", "<=", "2026-01-01")},
	} {
		if BoundedDomain(domain) {
			t.Fatalf("unbounded filter admitted: %v", domain)
		}
	}
}

func TestBoundedDomainPerModelAnchors(t *testing.T) {
	leaf := func(field, op string, v any) []any { return []any{field, op, v} }
	// Reviewed anchor: stock.rule route_id only. helpdesk.ticket team_id
	// is NOT a standalone anchor: team-wide historical scans stay bounded
	// (mandate correction 2026-10-04) — ticket queries need an accepted
	// anchor or a <=31-day date window.
	for _, tc := range []struct {
		model  string
		domain []any
	}{
		{"stock.rule", []any{leaf("route_id", "in", []any{float64(66), float64(27)})}},
		{"stock.rule", []any{leaf("route_id", "=", 66)}},
		{"mrp.workorder", []any{leaf("production_id", "=", 66)}},
		{"mrp.workorder", []any{leaf("operation_id", "in", []any{float64(1), float64(2)})}},
		{"stock.move", []any{leaf("raw_material_production_id", "=", 66)}},
		{"stock.move", []any{leaf("workorder_id", "=", 66)}},
		{"stock.move", []any{leaf("production_id", "=", 66)}},
		{"stock.move.line", []any{leaf("production_id", "=", 66)}},
		{"stock.move.line", []any{leaf("workorder_id", "=", 66)}},
	} {
		if !BoundedDomainFor(tc.model, tc.domain) {
			t.Fatalf("reviewed anchor refused for %s: %v", tc.model, tc.domain)
		}
	}
	// Cross-model leakage denied: route_id is not an anchor elsewhere,
	// and the unscoped form keeps exact prior behavior.
	if BoundedDomainFor("res.partner", []any{leaf("route_id", "in", []any{float64(66)})}) {
		t.Fatal("per-model anchor leaked to another model")
	}
	if BoundedDomain([]any{leaf("route_id", "in", []any{float64(66)})}) {
		t.Fatal("unscoped BoundedDomain behavior changed")
	}
	// team_id-only ticket queries stay denied (negative control); team_id
	// PLUS a <=31-day window on the same date field admits (positive
	// control) via the existing date-window path.
	if BoundedDomainFor("helpdesk.ticket", []any{leaf("team_id", "=", 1891)}) {
		t.Fatal("team_id-only ticket query admitted (must stay bounded)")
	}
	if !BoundedDomainFor("helpdesk.ticket", []any{
		leaf("team_id", "=", 1891),
		leaf("create_date", ">=", "2026-09-03"), leaf("create_date", "<", "2026-10-04"),
	}) {
		t.Fatal("team_id plus 31-day window refused")
	}
	many := make([]any, 101)
	for i := range many {
		many[i] = float64(i + 1)
	}
	for _, tc := range []struct {
		model  string
		domain []any
	}{
		{"stock.rule", []any{leaf("route_id", "in", many)}},
		{"stock.rule", []any{"|", leaf("route_id", "=", 1), leaf("id", "=", 2)}},
		{"helpdesk.ticket", []any{leaf("team_id", "=", "1891")}},
		{"helpdesk.ticket", []any{leaf("other_rel", "=", 1)}},
		{"res.partner", []any{leaf("production_id", "=", 1)}},
		{"mrp.workorder", []any{leaf("production_id", "=", false)}},
		{"mrp.workorder", []any{leaf("production_id", "in", []any{float64(1), float64(-1)})}},
		{"stock.move", []any{leaf("raw_material_production_id", "in", many)}},
	} {
		if BoundedDomainFor(tc.model, tc.domain) {
			t.Fatalf("unbounded per-model filter admitted for %s: %v", tc.model, tc.domain)
		}
	}
	if h := BoundedHint("stock.rule"); !strings.Contains(h, "route_id") {
		t.Fatalf("hint missing anchor field: %q", h)
	}
	if h := BoundedHint("res.partner"); strings.Contains(h, "route_id") {
		t.Fatalf("hint leaked anchor field: %q", h)
	}
	if h := BoundedHint("helpdesk.ticket"); strings.Contains(h, "team_id") {
		t.Fatalf("hint leaked removed team_id anchor: %q", h)
	}
}

func TestLinkedEvidenceCannotUseGenericOperations(t *testing.T) {
	p := validPolicy()
	p.AllowLinkedEvidence = true
	p.Models["mail.message"] = ModelRule{Fields: []string{"id", "body"}, LinkedEvidence: true}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, op := range []Operation{OpSearch, OpRead, OpCount, OpAggregate} {
		decision := p.Authorize(nil, Request{Operation: op, Model: "mail.message", Fields: []string{"body"}, Domain: []any{[]any{"id", "=", 1}}, Limit: 1})
		if decision.Allow {
			t.Fatalf("raw evidence %s allowed", op)
		}
	}
	r := p.Models["mail.message"]
	r.CompanyIndependent = true
	p.Models["mail.message"] = r
	if err := p.Validate(); err == nil {
		t.Fatal("evidence can become unrestricted global data")
	}
}

func TestProductAttributeOwnedParentScope(t *testing.T) {
	p := validPolicy()
	p.Models["product.template.attribute.line"] = ModelRule{Fields: []string{"id", "product_tmpl_id"}, CompanyField: "product_tmpl_id.company_id", IncludeCompanyless: true}
	schema := testSchema{
		"product.template.attribute.line": testModel{"product_tmpl_id": {Name: "product_tmpl_id", Type: "many2one", Relation: "product.template"}},
		"product.template":                testModel{"company_id": {Name: "company_id", Type: "many2one", Relation: "res.company"}},
	}
	if err := p.CompanyFieldValid(schema, "product.template.attribute.line"); err != nil {
		t.Fatal(err)
	}
	frag, enforced := CompanyFilterFragment(p.Models["product.template.attribute.line"], p.Scope)
	if !enforced || len(frag) != 4 {
		t.Fatal("missing parent-existence/company fragment")
	}
	schema["product.template.attribute.line"]["product_tmpl_id"] = FieldMeta{Name: "product_tmpl_id", Type: "many2one", Relation: "res.users"}
	if err := p.CompanyFieldValid(schema, "product.template.attribute.line"); err == nil {
		t.Fatal("foreign parent scope accepted")
	}
}
