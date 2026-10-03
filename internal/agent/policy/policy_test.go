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
			"secret":     {Name: "secret", Type: "char"},
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
		Version:        PolicyVersion,
		Instance:       "prod",
		SnapshotSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
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
		{Version: PolicyVersion, Instance: "prod"},
		func() *Policy { p := validPolicy(); p.Version = 0; return p }(),
		func() *Policy { p := validPolicy(); p.Version = PolicyVersion + 1; return p }(),
		func() *Policy { p := validPolicy(); p.SnapshotSHA256 = ""; return p }(),
		func() *Policy { p := validPolicy(); p.SnapshotSHA256 = "not-hex"; return p }(),
		func() *Policy { p := validPolicy(); p.Instance = ""; return p }(),
		func() *Policy { p := validPolicy(); p.Operations = nil; return p }(),
		func() *Policy { p := validPolicy(); p.Models = nil; return p }(),
		func() *Policy { p := validPolicy(); p.SharedRecords = "sometimes"; return p }(),
		func() *Policy { p := validPolicy(); p.Budgets.MaxLimit = 0; return p }(),
		func() *Policy { p := validPolicy(); p.Budgets.MaxCallsPerSession = -1; return p }(),
		func() *Policy { p := validPolicy(); p.Budgets.MaxRowsPerSession = -1; return p }(),
		func() *Policy { p := validPolicy(); p.Scope = CompanyScope{Enabled: []int{1}, Default: 1}; return p }(),
		func() *Policy { p := validPolicy(); p.Scope = CompanyScope{Enabled: []int{1, 2}, Default: 9}; return p }(),
		func() *Policy { p := validPolicy(); p.Scope = CompanyScope{Enabled: []int{1, 1}, Default: 1}; return p }(),
		func() *Policy {
			p := validPolicy()
			p.Scope = CompanyScope{Enabled: []int{-1, 0}, Default: -1}
			return p
		}(),
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
		[]any{"partner_id", "ilike", "y"},
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
		{"dotted-domain", []any{[]any{"partner_id.name", "=", "x"}}, schema},
		{"dotted-domain-nested", []any{[]any{"partner_id.company_id.name", "=", "x"}}, schema},
		{"child-of", []any{[]any{"company_id", "child_of", 1}}, schema},
		{"parent-of", []any{[]any{"company_id", "parent_of", 1}}, schema},
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
	for _, order := range []string{"", "name", "name asc, id desc", "partner_id asc"} {
		r := validSearch()
		r.Order = order
		if d := p.Authorize(schema, r); !d.Allow {
			t.Fatalf("order %q denied: %+v", order, d)
		}
	}
	for _, order := range []string{"secret asc", "name sideways", "name asc,", " , ", "partner_id.secret asc", "partner_id.name DESC", "company_id.name asc"} {
		r := validSearch()
		r.Order = order
		if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonOrderDenied {
			t.Fatalf("order %q = %+v, want deny order-denied", order, d)
		}
	}
	r := validSearch()
	r.GroupBy = []string{"company_id", "partner_id"}
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
	r := Request{Operation: OpSearch, Model: "res.company", Fields: []string{"name"}, Limit: 5}
	if d := p.Authorize(schema, r); !d.Allow {
		t.Fatalf("classified independent denied: %+v", d)
	}
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
	if err := ValidateScope(CompanyScope{Enabled: []int{1, 1}, Default: 1}); err == nil {
		t.Fatal("duplicate scope [1,1] must fail")
	}
	if err := ValidateScope(CompanyScope{Enabled: []int{-1, 0}, Default: -1}); err == nil {
		t.Fatal("non-positive scope [-1,0] must fail")
	}
	if err := ValidateScope(CompanyScope{Enabled: []int{0, 2}, Default: 2}); err == nil {
		t.Fatal("zero id scope must fail")
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
		Fields: []string{"name"},
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

func TestSearchReadRequireExplicitProjection(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	for _, op := range []Operation{OpSearch, OpRead} {
		for _, name := range []string{"omitted", "nil", "empty"} {
			var fields []string
			switch name {
			case "nil":
				fields = nil
			case "empty":
				fields = []string{}
			}
			r := Request{Operation: op, Model: "res.partner", Fields: fields,
				Domain: []any{[]any{"name", "=", "x"}}, Limit: 10}
			if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonFieldDenied {
				t.Fatalf("%s %s fields = %+v, want deny field-denied", op, name, d)
			}
		}
		// Legitimate exact projection (without `id`) is allowed: the
		// broker appends `id` because Odoo implicitly returns it.
		r := Request{Operation: op, Model: "res.partner", Fields: []string{"name"},
			Domain: []any{[]any{"name", "=", "x"}}, Limit: 10}
		if d := p.Authorize(schema, r); !d.Allow {
			t.Fatalf("%s exact projection denied: %+v", op, d)
		}
		// Unapproved name denies.
		r.Fields = []string{"name", "secret_field"}
		if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonFieldDenied {
			t.Fatalf("%s unapproved field = %+v", op, d)
		}
	}
	// Count needs no projection.
	if d := p.Authorize(schema, Request{Operation: OpCount, Model: "res.partner"}); !d.Allow {
		t.Fatalf("count without fields denied: %+v", d)
	}
}

func TestFieldWildcardDenied(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	for _, f := range []string{"*", "na*", "partner_id.*"} {
		r := validSearch()
		r.Fields = []string{f}
		if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonFieldDenied {
			t.Fatalf("wildcard %q = %+v, want deny field-denied", f, d)
		}
	}
}

func TestDottedFieldProjection(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	// Minimum safe choice: every dotted projection denies, even a fully
	// approved traversal (root allowlisted, relational intermediates,
	// terminal listed on an enforceable target).
	for _, f := range []string{"partner_id.name", "partner_id.secret", "partner_id.company_id.name"} {
		r := validSearch()
		r.Fields = []string{"name", f}
		if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonFieldDenied {
			t.Fatalf("dotted projection %q = %+v, want deny field-denied", f, d)
		}
	}
	// Legitimate same-model exact projection still passes.
	r := validSearch()
	r.Fields = []string{"name"}
	if d := p.Authorize(schema, r); !d.Allow {
		t.Fatalf("same-model projection denied: %+v", d)
	}
}

func TestEnsureID(t *testing.T) {
	got := EnsureID([]string{"name"})
	if len(got) != 2 || got[0] != "name" || got[1] != "id" {
		t.Fatalf("EnsureID appends id: %#v", got)
	}
	keep := []string{"name", "id"}
	if got := EnsureID(keep); len(got) != 2 {
		t.Fatalf("EnsureID keeps lists with id: %#v", got)
	}
}

func traversalSchema() testSchema {
	return testSchema{
		"sale.order": testModel{
			"partner_id": {Name: "partner_id", Type: "many2one", Relation: "res.partner"},
			"company_id": {Name: "company_id", Type: "many2one", Relation: "res.company"},
			"name":       {Name: "name", Type: "char"},
		},
		"res.partner": testModel{
			"name":       {Name: "name", Type: "char"},
			"secret":     {Name: "secret", Type: "char"},
			"company_id": {Name: "company_id", Type: "many2one", Relation: "res.company"},
			"partner_id": {Name: "partner_id", Type: "many2one", Relation: "res.partner"},
		},
		"res.company": testModel{
			"name": {Name: "name", Type: "char"},
		},
	}
}

func traversalPolicy() *Policy {
	p := validPolicy()
	p.Models["sale.order"] = ModelRule{
		Fields:       []string{"company_id", "name", "partner_id"},
		CompanyField: "company_id",
	}
	return p
}

func TestTraversalTargetApproval(t *testing.T) {
	schema := traversalSchema()
	// Minimum safe choice: every dotted domain denies, even the fully
	// approved full path (root allowlisted, terminal listed on an
	// enforceable target). Schema existence alone never approves.
	p := traversalPolicy()
	for _, path := range []string{"partner_id.name", "partner_id.secret", "partner_id.company_id.name"} {
		r := Request{Operation: OpSearch, Model: "sale.order", Fields: []string{"name"},
			Domain: []any{[]any{path, "=", "x"}}, Limit: 10}
		if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonDomainDenied {
			t.Fatalf("dotted domain %q = %+v, want deny domain-denied", path, d)
		}
	}
	// Same-model domain on the allowlisted field still passes.
	r := Request{Operation: OpSearch, Model: "sale.order", Fields: []string{"name"},
		Domain: []any{[]any{"name", "=", "x"}}, Limit: 10}
	if d := p.Authorize(schema, r); !d.Allow {
		t.Fatalf("same-model domain denied: %+v", d)
	}
}

func TestNestedTraversalPaths(t *testing.T) {
	schema := traversalSchema()
	p := traversalPolicy()
	// Minimum safe choice: every nested dotted path denies, even fully
	// approved ones. Same-model references on either path's root pass.
	for _, path := range []string{"partner_id.company_id.name", "company_id.name", "partner_id.name"} {
		r := Request{Operation: OpSearch, Model: "sale.order", Fields: []string{"name"},
			Domain: []any{[]any{path, "=", "x"}}, Limit: 10}
		if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonDomainDenied {
			t.Fatalf("dotted domain %q = %+v, want deny domain-denied", path, d)
		}
	}
	for _, field := range []string{"name", "company_id", "partner_id"} {
		r := Request{Operation: OpSearch, Model: "sale.order", Fields: []string{"name"},
			Domain: []any{[]any{field, "=", "x"}}, Limit: 10}
		if d := p.Authorize(schema, r); !d.Allow {
			t.Fatalf("same-model domain %q denied: %+v", field, d)
		}
	}
}

func TestEmptyDomainPasses(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	for _, d := range []any{nil, []any{}} {
		r := validSearch()
		r.Domain = d
		if got := p.Authorize(schema, r); !got.Allow {
			t.Fatalf("empty domain %#v denied: %+v", d, got)
		}
	}
}

func TestDomainOperandBounds(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	bad := []struct {
		name   string
		domain any
	}{
		{"unknown-op", []any{[]any{"name", "contains", "x"}}},
		{"not-like-op", []any{[]any{"name", "not like", "x"}}},
		{"child-of", []any{[]any{"company_id", "child_of", 1}}},
		{"parent-of", []any{[]any{"company_id", "parent_of", 1}}},
		{"dict-value", []any{[]any{"name", "=", map[string]any{"a": 1}}}},
		{"nested-array-value", []any{[]any{"name", "=", []any{[]any{1}}}}},
		{"in-scalar", []any{[]any{"name", "in", "x"}}},
	}
	for _, tc := range bad {
		r := validSearch()
		r.Domain = tc.domain
		if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonDomainDenied {
			t.Fatalf("%s: = %+v, want deny domain-denied", tc.name, d)
		}
	}
	good := []any{
		[]any{"name", "in", []any{"x", "y"}},
		[]any{"company_id", "=", 1},
		[]any{"name", "=", nil},
	}
	r := validSearch()
	r.Domain = good
	if d := p.Authorize(schema, r); !d.Allow {
		t.Fatalf("bounded operands denied: %+v", d)
	}
}

func TestSequence8DenyAllDottedAndHierarchy(t *testing.T) {
	schema := traversalSchema()
	p := traversalPolicy()
	base := func() Request {
		return Request{Operation: OpSearch, Model: "sale.order", Fields: []string{"name"},
			Domain: []any{[]any{"name", "=", "x"}}, Order: "name asc", Limit: 10}
	}
	// Malicious dotted count: sale.order partner_id.name in the domain.
	r := base()
	r.Domain = []any{[]any{"partner_id.name", "=", "x"}}
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonDomainDenied {
		t.Fatalf("dotted count domain = %+v, want deny domain-denied", d)
	}
	// Malicious dotted order/group-by/aggregate inputs.
	r = base()
	r.Order = "partner_id.name asc"
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonOrderDenied {
		t.Fatalf("dotted order = %+v, want deny order-denied", d)
	}
	r = base()
	r.GroupBy = []string{"partner_id.name"}
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonGroupByDenied {
		t.Fatalf("dotted groupby = %+v, want deny groupby-denied", d)
	}
	agg := base()
	agg.Operation = OpAggregate
	agg.Model = "res.partner"
	agg.GroupBy = []string{"partner_id.name"}
	ap := validPolicy()
	if d := ap.Authorize(schema, agg); d.Allow || d.Reason != ReasonGroupByDenied {
		t.Fatalf("dotted aggregate groupby = %+v, want deny groupby-denied", d)
	}
	// Hierarchy operators deny on the structural id and on scoped fields,
	// even nested under NOT/OR.
	for _, op := range []string{"child_of", "parent_of"} {
		for _, field := range []string{"id", "company_id"} {
			leaf := []any{[]any{field, op, 1}}
			for name, domain := range map[string]any{
				"leaf":     leaf,
				"not-leaf": []any{"!", leaf[0]},
				"or-leaf":  []any{"|", []any{"name", "=", "x"}, leaf[0]},
			} {
				r = base()
				r.Model = "res.partner"
				r.Domain = domain
				if d := validPolicy().Authorize(testSchemaView(), r); d.Allow || d.Reason != ReasonDomainDenied {
					t.Fatalf("%s %s %s = %+v, want deny domain-denied", op, field, name, d)
				}
			}
		}
	}
	// NOT/OR nesting of legitimate same-model leaves still passes, and the
	// empty domain stays allowed.
	r = base()
	r.Model = "res.partner"
	r.Domain = []any{"|", []any{"name", "=", "x"}, "!", []any{"company_id", "=", 1}}
	if d := validPolicy().Authorize(testSchemaView(), r); !d.Allow {
		t.Fatalf("legitimate NOT/OR domain denied: %+v", d)
	}
	for _, verb := range []Operation{OpSearch, OpRead, OpCount} {
		r := Request{Operation: verb, Model: "res.partner", Fields: []string{"name"}, Limit: 10}
		if verb == OpCount {
			r.Fields = nil
			r.Limit = 0
		}
		if d := validPolicy().Authorize(testSchemaView(), r); !d.Allow {
			t.Fatalf("legitimate %s denied: %+v", verb, d)
		}
	}
}

func TestValidateCentral(t *testing.T) {
	if err := validPolicy().Validate(); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(p *Policy)
	}{
		{"bad-version", func(p *Policy) { p.Version = 0 }},
		{"future-version", func(p *Policy) { p.Version = PolicyVersion + 1 }},
		{"missing-snapshot-binding", func(p *Policy) { p.SnapshotSHA256 = "" }},
		{"malformed-snapshot-binding", func(p *Policy) { p.SnapshotSHA256 = "xyz" }},
		{"bad-instance", func(p *Policy) { p.Instance = "" }},
		{"empty-ops", func(p *Policy) { p.Operations = nil }},
		{"empty-models", func(p *Policy) { p.Models = nil }},
		{"unknown-shared", func(p *Policy) { p.SharedRecords = "sometimes" }},
		{"bad-scope", func(p *Policy) { p.Scope = CompanyScope{Enabled: []int{1}, Default: 1} }},
		{"duplicate-scope", func(p *Policy) { p.Scope = CompanyScope{Enabled: []int{1, 1}, Default: 1} }},
		{"negative-scope", func(p *Policy) { p.Scope = CompanyScope{Enabled: []int{-1, 0}, Default: -1} }},
		{"nonpositive-limit", func(p *Policy) { p.Budgets.MaxLimit = 0 }},
		{"nonpositive-rows", func(p *Policy) { p.Budgets.MaxRowsPerCall = 0 }},
		{"nonpositive-bytes", func(p *Policy) { p.Budgets.MaxResponseBytes = 0 }},
		{"negative-offset", func(p *Policy) { p.Budgets.MaxOffset = -1 }},
		{"negative-session-calls", func(p *Policy) { p.Budgets.MaxCallsPerSession = -2 }},
		{"negative-session-rows", func(p *Policy) { p.Budgets.MaxRowsPerSession = -3 }},
		{"contradictory-rule", func(p *Policy) {
			p.Models["res.partner"] = ModelRule{Fields: []string{"name"}, CompanyField: "company_id", CompanyIndependent: true}
		}},
		{"companyless-on-independent", func(p *Policy) {
			p.Models["res.company"] = ModelRule{Fields: []string{"name"}, CompanyIndependent: true, IncludeCompanyless: true}
		}},
		{"empty-rule-fields", func(p *Policy) {
			p.Models["res.partner"] = ModelRule{Fields: nil, CompanyField: "company_id"}
		}},
		{"bad-rule-field", func(p *Policy) {
			p.Models["res.partner"] = ModelRule{Fields: []string{"na me"}, CompanyField: "company_id"}
		}},
		{"bad-company-field", func(p *Policy) {
			p.Models["res.partner"] = ModelRule{Fields: []string{"name"}, CompanyField: "no good"}
		}},
		{"negative-rule-limit", func(p *Policy) {
			p.Models["res.partner"] = ModelRule{Fields: []string{"name"}, CompanyField: "company_id", MaxLimit: -1}
		}},
	}
	for _, tc := range cases {
		p := validPolicy()
		tc.mutate(p)
		if err := p.Validate(); err == nil {
			t.Fatalf("%s: Validate passed, want error", tc.name)
		}
		if d := p.Authorize(testSchemaView(), validSearch()); d.Allow {
			t.Fatalf("%s: invalid policy allowed: %+v", tc.name, d)
		}
	}
	// Scoped model without a company field is well-formed (Validate
	// passes) but every request denies with company-denied.
	p := validPolicy()
	p.Models["res.partner"] = ModelRule{Fields: []string{"id", "name"}}
	if err := p.Validate(); err != nil {
		t.Fatalf("fieldless-scoped Validate: %v", err)
	}
	if d := p.Authorize(testSchemaView(), validSearch()); d.Allow || d.Reason != ReasonCompanyDenied {
		t.Fatalf("fieldless-scoped = %+v, want company-denied", d)
	}
}

func TestContradictoryRuleDenied(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	p.Models["res.partner"] = ModelRule{Fields: []string{"name"}, CompanyField: "company_id", CompanyIndependent: true}
	if err := p.Validate(); err == nil {
		t.Fatal("contradictory rule passed Validate")
	}
	if d := p.Authorize(schema, validSearch()); d.Allow {
		t.Fatalf("contradictory rule allowed: %+v", d)
	}
}

func TestCompanylessFragment(t *testing.T) {
	scope := CompanyScope{Enabled: []int{1, 2}, Default: 1}
	// Without the flag the fragment excludes companyless records.
	frag, enforce := CompanyDomain(ModelRule{CompanyField: "company_id"}, scope)
	if !enforce || len(frag) != 1 {
		t.Fatalf("scoped = (%v,%v)", frag, enforce)
	}
	leaf, ok := frag[0].([]any)
	if !ok || len(leaf) != 3 || leaf[0] != "company_id" || leaf[1] != "in" {
		t.Fatalf("scoped fragment shape = %#v", frag)
	}
	scopedIDs, ok := leaf[2].([]any)
	if !ok || len(scopedIDs) != 2 {
		t.Fatalf("scoped fragment must carry BOTH enabled ids: %#v", frag)
	}
	// With the flag the fragment is a FLAT three-element prefix expression
	// ["|", leafIn, leafFalse] — not one nested ["|",...] list — so the
	// broker's append-after-caller-domain ANDs correctly.
	frag, enforce = CompanyDomain(ModelRule{CompanyField: "company_id", IncludeCompanyless: true}, scope)
	if !enforce || len(frag) != 3 {
		t.Fatalf("companyless = (%v,%v), want 3 flat elements", frag, enforce)
	}
	if op, ok := frag[0].(string); !ok || op != "|" {
		t.Fatalf("companyless prefix = %#v, want \"|\"", frag)
	}
	leafIn, ok := frag[1].([]any)
	if !ok || len(leafIn) != 3 || leafIn[0] != "company_id" || leafIn[1] != "in" {
		t.Fatalf("companyless leafIn = %#v", frag)
	}
	ids, ok := leafIn[2].([]any)
	if !ok || len(ids) != 2 || ids[0] != 1 || ids[1] != 2 {
		t.Fatalf("companyless must carry BOTH enabled ids flat: %#v", frag)
	}
	leafFalse, ok := frag[2].([]any)
	if !ok || len(leafFalse) != 3 || leafFalse[0] != "company_id" || leafFalse[1] != "=" || leafFalse[2] != false {
		t.Fatalf("companyless OR-false branch = %#v, want [company_id = false]", frag)
	}
	if _, nested := frag[0].([]any); nested {
		t.Fatalf("companyless fragment must be flat, got nested: %#v", frag)
	}
	// The companyless flag is admitted by Authorize on scoped models.
	p := validPolicy()
	p.Models["res.partner"] = ModelRule{Fields: []string{"company_id", "id", "name"}, CompanyField: "company_id", IncludeCompanyless: true}
	if err := p.Validate(); err != nil {
		t.Fatalf("scoped companyless Validate: %v", err)
	}
	if d := p.Authorize(testSchemaView(), validSearch()); !d.Allow {
		t.Fatalf("scoped companyless denied: %+v", d)
	}
}

func TestIndependentCompanyFieldContradiction(t *testing.T) {
	_, enforce := CompanyDomain(
		ModelRule{CompanyField: "company_id", CompanyIndependent: true},
		CompanyScope{Enabled: []int{1, 2}, Default: 1})
	if !enforce {
		t.Fatal("independent with company field must still enforce (deny)")
	}
	p := validPolicy()
	p.Models["res.company"] = ModelRule{Fields: []string{"name"}, CompanyField: "company_id", CompanyIndependent: true}
	r := Request{Operation: OpSearch, Model: "res.company", Fields: []string{"name"}, Limit: 5}
	if d := p.Authorize(testSchemaView(), r); d.Allow {
		t.Fatalf("independent with company field allowed: %+v", d)
	}
}

func TestCompanyFieldValid(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	// res.partner.company_id is many2one -> res.company: valid.
	if err := p.CompanyFieldValid(schema, "res.partner"); err != nil {
		t.Fatalf("company_id valid: %v", err)
	}
	// Non-company relation denies: partner_id points at res.partner.
	bad := validPolicy()
	bad.Models["res.partner"] = ModelRule{Fields: []string{"partner_id", "name"}, CompanyField: "partner_id"}
	if err := bad.CompanyFieldValid(schema, "res.partner"); err == nil {
		t.Fatal("non-company relation passed, want deny")
	}
	// Non-relational field denies: name has no relation.
	bad.Models["res.partner"] = ModelRule{Fields: []string{"name"}, CompanyField: "name"}
	if err := bad.CompanyFieldValid(schema, "res.partner"); err == nil {
		t.Fatal("non-relational company field passed, want deny")
	}
	// Missing field denies; nil schema denies (unverifiable pre-credential).
	bad.Models["res.partner"] = ModelRule{Fields: []string{"name"}, CompanyField: "company_id"}
	if err := bad.CompanyFieldValid(testSchema{"res.partner": testModel{"name": {Name: "name", Type: "char"}}}, "res.partner"); err == nil {
		t.Fatal("absent company field passed, want deny")
	}
	if err := p.CompanyFieldValid(nil, "res.partner"); err == nil {
		t.Fatal("nil schema passed, want deny")
	}
	// Contradictory independent-with-field denies.
	contra := validPolicy()
	contra.Models["res.company"] = ModelRule{Fields: []string{"name"}, CompanyField: "company_id", CompanyIndependent: true}
	if err := contra.CompanyFieldValid(schema, "res.company"); err == nil {
		t.Fatal("contradictory rule passed CompanyFieldValid, want deny")
	}
	// Genuine independent without field passes trivially.
	if err := p.CompanyFieldValid(schema, "res.company"); err != nil {
		t.Fatalf("independent without field: %v", err)
	}
	// many2many company link also passes (company_ids multi-company).
	m2m := validPolicy()
	m2m.Models["res.partner"] = ModelRule{Fields: []string{"company_ids", "name"}, CompanyField: "company_ids"}
	m2mSchema := testSchema{"res.partner": testModel{
		"company_ids": {Name: "company_ids", Type: "many2many", Relation: "res.company"},
		"name":        {Name: "name", Type: "char"},
	}}
	if err := m2m.CompanyFieldValid(m2mSchema, "res.partner"); err != nil {
		t.Fatalf("company_ids many2many valid: %v", err)
	}
}

func TestDisabledCompanyNoBypass(t *testing.T) {
	schema := testSchemaView()
	p := validPolicy()
	// A caller-supplied disabled company is still caller selection: deny.
	r := validSearch()
	r.CompanyIDs = []int{3}
	if d := p.Authorize(schema, r); d.Allow || d.Reason != ReasonCompanySelectDenied {
		t.Fatalf("disabled company select = %+v, want deny company-select-denied", d)
	}
}
