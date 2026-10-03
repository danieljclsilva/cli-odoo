package policy

import (
	"strings"
	"testing"
)

type testModel map[string]FieldMeta

func (m testModel) Field(name string) (FieldMeta, bool) {
	fm, ok := m[name]
	return fm, ok
}

type testSchema map[string]testModel

func (s testSchema) Model(name string) (ModelView, bool) {
	m, ok := s[name]
	if !ok {
		return nil, false
	}
	return m, true
}

func testSchemaView() testSchema {
	return testSchema{
		"res.partner": testModel{
			"name":       {Name: "name", Type: "char"},
			"company_id": {Name: "company_id", Type: "many2one", Relation: "res.company"},
			"partner_id": {Name: "partner_id", Type: "many2one", Relation: "res.partner"},
		},
		"res.company": testModel{
			"name": {Name: "name", Type: "char"},
		},
	}
}

func validPolicy() *Policy {
	return &Policy{
		Version:  1,
		Instance: "prod",
		Operations: map[Operation]bool{
			OpSearch: true, OpRead: true, OpCount: true,
			OpAggregate: true, OpMeta: true,
		},
		Models: map[string]ModelRule{
			"res.partner": {
				Fields:         []string{"company_id", "id", "name", "partner_id"},
				MaxLimit:       50,
				AllowAggregate: true,
				CompanyField:   "company_id",
			},
			"res.company": {
				Fields:             []string{"id", "name"},
				CompanyIndependent: true,
			},
		},
		Scope:         CompanyScope{Enabled: []int{1, 2}, Default: 1},
		SharedRecords: SharedAllowClassified,
		Budgets:       Budgets{MaxLimit: 100, MaxOffset: 500, MaxRowsPerCall: 80, MaxResponseBytes: 1 << 20},
	}
}

func validSearch() Request {
	return Request{
		Operation: OpSearch, Model: "res.partner",
		Fields: []string{"id", "name"},
		Domain: []any{[]any{"name", "=", "x"}},
		Order:  "name asc",
		Limit:  10,
	}
}

func TestZeroPolicyDenies(t *testing.T) {
	var nilPolicy *Policy
	if d := nilPolicy.Authorize(nil, validSearch()); d.Allow || d.Reason != ReasonInvalidPolicy {
		t.Fatalf("nil policy = %+v, want deny invalid-policy", d)
	}
	for _, p := range []*Policy{
		{},
		{Version: 1, Instance: "prod"},
		func() *Policy { p := validPolicy(); p.Version = 0; return p }(),
		func() *Policy { p := validPolicy(); p.Instance = ""; return p }(),
		func() *Policy { p := validPolicy(); p.Operations = nil; return p }(),
		func() *Policy { p := validPolicy(); p.Models = nil; return p }(),
		func() *Policy { p := validPolicy(); p.SharedRecords = "sometimes"; return p }(),
		func() *Policy { p := validPolicy(); p.Budgets.MaxLimit = 0; return p }(),
		func() *Policy { p := validPolicy(); p.Scope = CompanyScope{Enabled: []int{1}, Default: 1}; return p }(),
		func() *Policy { p := validPolicy(); p.Scope = CompanyScope{Enabled: []int{1, 2}, Default: 9}; return p }(),
	} {
		if d := p.Authorize(nil, validSearch()); d.Allow {
			t.Fatalf("malformed policy allowed: %+v", d)
		}
	}
	if d := validPolicy().Authorize(nil, validSearch()); !d.Allow || d.Reason != ReasonAllow {
		t.Fatalf("valid policy denied: %+v", d)
	}
}

func TestUnknownOpAndModel(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	r := validSearch()
	r.Operation = "write"
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonOperationDenied {
		t.Fatalf("unknown op = %+v", d)
	}
	r = validSearch()
	r.Model = "not a model!"
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonInvalidModel {
		t.Fatalf("bad model name = %+v", d)
	}
	r = validSearch()
	r.Model = "res.users"
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonUnknownModel {
		t.Fatalf("unknown model = %+v", d)
	}
	r = validSearch()
	r.Operation = OpAggregate
	r.Model = "res.company" // AllowAggregate false
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonAggregateDenied {
		t.Fatalf("aggregate on non-aggregate model = %+v", d)
	}
}

func TestFieldSubset(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	r := validSearch()
	r.Fields = []string{"id", "secret_field"}
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonFieldDenied {
		t.Fatalf("unlisted field = %+v", d)
	}
	r = validSearch()
	r.Fields = []string{"id", " name "}
	if d := p.Authorize(schema, r); !d.Allow {
		t.Fatalf("edge-trimmed valid field denied: %+v (NormalizeName trims edges)", d)
	}
	r = validSearch()
	r.Fields = []string{"id", "na me"}
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonFieldDenied {
		t.Fatalf("interior-whitespace field = %+v (no interior forgiveness)", d)
	}
	r = validSearch()
	r.Fields = []string{"id", "Name"}
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonFieldDenied {
		t.Fatalf("case-variant field = %+v (no case forgiveness)", d)
	}
}

func TestDomainFieldExtraction(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	good := []any{
		"|",
		[]any{"name", "=", "x"},
		[]any{"partner_id.name", "ilike", "y"},
		"!",
		[]any{"company_id", "in", []any{1, 2}},
	}
	r := validSearch()
	r.Domain = good
	if d := p.Authorize(schema, r); !d.Allow {
		t.Fatalf("good domain denied: %+v", d)
	}
	bad := []struct {
		name   string
		domain any
		schema SchemaView
	}{
		{"unlisted-field", []any{[]any{"secret", "=", 1}}, schema},
		{"top-not-array", map[string]any{"name": "x"}, schema},
		{"top-string", "name", schema},
		{"leaf-arity-2", []any{[]any{"name", "="}}, schema},
		{"leaf-arity-4", []any{[]any{"name", "=", "x", 1}}, schema},
		{"leaf-nonstring-field", []any{[]any{1, "=", "x"}}, schema},
		{"leaf-nonstring-op", []any{[]any{"name", 1, "x"}}, schema},
		{"leaf-unknown-op", []any{[]any{"name", "contains", "x"}}, schema},
		{"bad-prefix", []any{"AND", []any{"name", "=", "x"}}, schema},
		{"nonrel-intermediate", []any{[]any{"name.first", "=", "x"}}, schema},
		{"missing-terminal", []any{[]any{"partner_id.nope", "=", "x"}}, schema},
		{"root-unlisted", []any{[]any{"secret.name", "=", "x"}}, schema},
		{"dot-no-schema", []any{[]any{"partner_id.name", "=", "x"}}, nil},
		{"unknown-model-schema", []any{[]any{"partner_id.name", "=", "x"}}, testSchema{}},
		{"element-int", []any{42}, schema},
		{"lone-or", []any{"|", []any{"name", "=", "x"}}, schema},
		{"trailing-op", []any{[]any{"name", "=", "x"}, "|"}, schema},
		{"dangling-not", []any{"!"}, schema},
	}
	for _, tc := range bad {
		r := validSearch()
		r.Domain = tc.domain
		if d := p.Authorize(tc.schema, r); d.Allow || d.Reason != ReasonDomainDenied {
			t.Fatalf("%s: = %+v, want deny domain-denied", tc.name, d)
		}
	}
	// Nil domain passes.
	r = validSearch()
	r.Domain = nil
	if d := p.Authorize(schema, r); !d.Allow {
		t.Fatalf("nil domain denied: %+v", d)
	}
}

func TestOrderAndGroupBy(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	for _, order := range []string{"", "name", "name asc, id desc", "partner_id.name DESC"} {
		r := validSearch()
		r.Order = order
		if d := p.Authorize(schema, r); !d.Allow {
			t.Fatalf("order %q denied: %+v", order, d)
		}
	}
	for _, order := range []string{"secret asc", "name sideways", "name asc,", " , ", "partner_id.secret asc"} {
		r := validSearch()
		r.Order = order
		if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonOrderDenied {
			t.Fatalf("order %q = %+v, want deny order-denied", order, d)
		}
	}
	r := validSearch()
	r.GroupBy = []string{"company_id", "partner_id.name"}
	if d := p.Authorize(schema, r); !d.Allow {
		t.Fatalf("good groupby denied: %+v", d)
	}
	r = validSearch()
	r.GroupBy = []string{"secret"}
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonGroupByDenied {
		t.Fatalf("bad groupby = %+v", d)
	}
	r = validSearch()
	r.GroupBy = []string{"name.first"}
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonGroupByDenied {
		t.Fatalf("non-relational groupby traversal = %+v", d)
	}
}

func TestCompanyExpansionRejected(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	r := validSearch()
	r.CompanyIDs = []int{1}
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonCompanySelectDenied {
		t.Fatalf("company select = %+v, want deny company-select-denied", d)
	}
}

func TestCompanyRule(t *testing.T) {
	schema := testSchemaView()
	// Independent + allow-classified passes without fragment.
	p := validPolicy()
	r := Request{Operation: OpSearch, Model: "res.company", Limit: 5}
	if d := p.Authorize(schema, r); !d.Allow {
		t.Fatalf("classified independent denied: %+v", d)
	}
	// Same model under deny without a company field must deny.
	p.SharedRecords = SharedDeny
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonCompanyDenied {
		t.Fatalf("independent under deny = %+v, want company-denied", d)
	}
	// Model with neither independence nor company field denies.
	p = validPolicy()
	p.Models["res.partner"] = ModelRule{Fields: []string{"id", "name"}}
	r = validSearch()
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonCompanyDenied {
		t.Fatalf("scopeless model = %+v, want company-denied", d)
	}
}

func TestOverBudgetDenies(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy() // effective max = min(100, 50, 80) = 50
	for _, lim := range []int{0, -1, 51, 81, 101, 10000} {
		r := validSearch()
		r.Limit = lim
		if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonLimitDenied {
			t.Fatalf("limit %d = %+v, want deny limit-denied", lim, d)
		}
	}
	for _, off := range []int{-1, 501, 100000} {
		r := validSearch()
		r.Offset = off
		if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonOffsetDenied {
			t.Fatalf("offset %d = %+v, want deny offset-denied", off, d)
		}
	}
	r := validSearch()
	r.Offset = 500 // boundary passes
	if d := p.Authorize(schema, r); !d.Allow {
		t.Fatalf("boundary offset denied: %+v", d)
	}
	// Count/meta never page.
	for _, op := range []Operation{OpCount, OpMeta} {
		r := Request{Operation: op, Model: "res.partner"}
		if d := p.Authorize(schema, r); !d.Allow {
			t.Fatalf("%s zero paging denied: %+v", op, d)
		}
		r = Request{Operation: op, Model: "res.partner", Limit: 10}
		if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonLimitDenied {
			t.Fatalf("%s nonzero limit = %+v", op, d)
		}
		r = Request{Operation: op, Model: "res.partner", Offset: 1}
		if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonOffsetDenied {
			t.Fatalf("%s nonzero offset = %+v", op, d)
		}
	}
}

func TestNormalizeNameEdges(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"res.partner", "res.partner", true},
		{" Res.Partner ", "Res.Partner", true}, // trim only, case preserved
		{"UPPER", "UPPER", true},
		{"a__b.c_d", "a__b.c_d", true},
		{"", "", false},
		{"   ", "", false},
		{"res partner", "", false},
		{"res\tpartner", "", false},
		{"a-b", "", false},
		{"a/b", "", false},
		{"a:b", "", false},
		{"a@b", "", false},
		{"résumé", "", false},
		{"a\nb", "", false},
	}
	for _, tc := range cases {
		got, ok := NormalizeName(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("NormalizeName(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestValidateScopeAndCompanyDomain(t *testing.T) {
	if err := ValidateScope(CompanyScope{Enabled: []int{1, 2}, Default: 2}); err != nil {
		t.Fatalf("valid scope: %v", err)
	}
	if err := ValidateScope(CompanyScope{Enabled: []int{1}, Default: 1}); err == nil {
		t.Fatal("single-company scope must fail")
	}
	if err := ValidateScope(CompanyScope{Enabled: nil, Default: 0}); err == nil {
		t.Fatal("empty scope must fail")
	}
	if err := ValidateScope(CompanyScope{Enabled: []int{1, 2}, Default: 9}); err == nil {
		t.Fatal("default outside enabled must fail")
	}
	frag, enforce := CompanyDomain(ModelRule{CompanyIndependent: true}, CompanyScope{Enabled: []int{1, 2}, Default: 1})
	if frag != nil || enforce {
		t.Fatalf("independent = (%v,%v), want (nil,false)", frag, enforce)
	}
	frag, enforce = CompanyDomain(ModelRule{CompanyField: "company_id"}, CompanyScope{Enabled: []int{1, 2}, Default: 1})
	if !enforce || len(frag) != 1 {
		t.Fatalf("enforced = (%v,%v)", frag, enforce)
	}
	leaf, ok := frag[0].([]any)
	if !ok || len(leaf) != 3 || leaf[0] != "company_id" || leaf[1] != "in" {
		t.Fatalf("fragment shape = %#v", frag)
	}
	if _, enforce := CompanyDomain(ModelRule{}, CompanyScope{Enabled: []int{1, 2}, Default: 1}); !enforce {
		t.Fatal("missing company field must still enforce (deny)")
	}
}

func TestReasonsSecretFree(t *testing.T) {
	d := validPolicy().Authorize(testSchemaView(), Request{
		Operation: OpSearch, Model: "res.partner",
		Domain: []any{[]any{"name", "=", "s3cr3t-value"}},
		Limit:  1,
	})
	if !d.Allow {
		t.Fatalf("baseline denied: %+v", d)
	}
	r := validSearch()
	r.Fields = []string{"nope"}
	d = validPolicy().Authorize(testSchemaView(), r)
	if !strings.Contains(d.Reason, "field") {
		t.Fatalf("field reason = %q", d.Reason)
	}
	if strings.Contains(d.Reason, "s3cr3t") {
		t.Fatalf("reason leaks domain value: %q", d.Reason)
	}
}
