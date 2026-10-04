package policy

import "testing"

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
