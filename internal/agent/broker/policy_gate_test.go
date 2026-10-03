package broker

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/config"
)

// Real-gate request-shape evidence (director item 1): the genuine
// deny-by-default policy (policyGate, NOT fakeGate) decides, and fakeExec is
// a pure dispatch recorder — it proves routing/denial-before-RPC and the
func realGateBroker(t *testing.T, exec *fakeExec) *Broker {
	t.Helper()
	b, err := NewForTest(testPolicy(), &config.Instance{Name: "test"}, testSnapshot(), nil, exec)
	if err != nil {
		t.Fatalf("NewForTest: %v", err)
	}
	return b
}
func TestRealGateFieldProjection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		path   string
		body   string
		wantOK bool
	}{
		{"omitted fields denied", "/rpc/search", `{"model":"res.partner","limit":5}`, false},
		{"empty fields denied", "/rpc/search", `{"model":"res.partner","fields":[],"limit":5}`, false},
		{"null fields denied", "/rpc/search", `{"model":"res.partner","fields":null,"limit":5}`, false},
		{"unapproved field denied", "/rpc/search", `{"model":"res.partner","fields":["name","secret"],"limit":5}`, false},
		{"wildcard denied", "/rpc/search", `{"model":"res.partner","fields":["*"],"limit":5}`, false},
		{"legitimate exact projection routes", "/rpc/search", `{"model":"res.partner","fields":["name"],"limit":5}`, true},
		{"read omitted denied", "/rpc/read", `{"model":"res.partner","ids":[1]}`, false},
		{"read legitimate routes", "/rpc/read", `{"model":"res.partner","ids":[1],"fields":["name"]}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exec := &fakeExec{rows: []any{map[string]any{"id": 1, "name": "a"}}}
			b := realGateBroker(t, exec)
			tok, err := b.Grant(time.Hour)
			if err != nil {
				t.Fatalf("Grant: %v", err)
			}
			rec := post(t, b, tc.path, tok, tc.body)
			if tc.wantOK {
				if rec.Code != http.StatusOK {
					t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
				}
				if len(exec.calls) != 1 {
					t.Fatalf("want 1 dispatch, got %d", len(exec.calls))
				}
				return
			}
			if rec.Code == http.StatusOK {
				t.Fatalf("want denial, got 200 (%s)", rec.Body.String())
			}
			if len(exec.calls) != 0 {
				t.Fatalf("denial executed RPC: %d dispatches", len(exec.calls))
			}
		})
	}
}

func TestRealGateExactProjectionShape(t *testing.T) {
	exec := &fakeExec{rows: []any{map[string]any{"id": 1, "name": "a"}}}
	b := realGateBroker(t, exec)
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	rec := post(t, b, "/rpc/search", tok, `{"model":"res.partner","fields":["name"],"limit":5}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if len(exec.calls) != 1 {
		t.Fatalf("want 1 dispatch, got %d", len(exec.calls))
	}
	got, ok := exec.calls[0].kwargs["fields"].([]any)
	if !ok {
		t.Fatalf("fields kwarg missing or wrong type: %v", exec.calls[0].kwargs["fields"])
	}
	var names []string
	for _, f := range got {
		s, _ := f.(string)
		names = append(names, s)
	}
	// Exact authorized projection plus structural `id` (EnsureID invariant):
	// ["name","id"], nothing more.
	if len(names) != 2 || names[0] != "name" || names[1] != "id" {
		t.Fatalf("fields sent = %v, want [name id]", names)
	}
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("envelope decode: %v", err)
	}
	if ok, _ := env["success"].(bool); !ok {
		t.Fatalf("not a success envelope: %s", rec.Body.String())
	}
}

// realGateAggregateBroker serves the aggregate-enabled policy through the
// genuine policyGate with a dispatch-recorder exec. fakeExec is a dispatch
// recorder only (canned rows prove routing, never Odoo semantics).
func realGateAggregateBroker(t *testing.T, exec *fakeExec) *Broker {
	t.Helper()
	p := testPolicy()
	rule := p.Models["res.partner"]
	rule.AllowAggregate = true
	p.Models["res.partner"] = rule
	b, err := NewForTest(p, &config.Instance{Name: "test"}, testSnapshot(), nil, exec)
	if err != nil {
		t.Fatalf("NewForTest: %v", err)
	}
	return b
}
func TestRealGateDottedHierarchyMux(t *testing.T) {
	deny := []struct {
		name string
		path string
		body string
	}{
		{"dotted count domain", "/rpc/count", `{"model":"res.partner","domain":[["partner_id.name","=","probe"]]}`},
		{"child_of count", "/rpc/count", `{"model":"res.partner","domain":[["id","child_of",1]]}`},
		{"parent_of count NOT", "/rpc/count", `{"model":"res.partner","domain":["!",["id","parent_of",1]]]}`},
		{"dotted search order", "/rpc/search", `{"model":"res.partner","fields":["name"],"order":"partner_id.name asc","limit":5}`},
		{"dotted search domain OR", "/rpc/search", `{"model":"res.partner","fields":["name"],"domain":["|",["partner_id.name","=","x"],["name","=","y"]],"limit":5}`},
		{"dotted aggregate groupby", "/rpc/aggregate", `{"model":"res.partner","groupby":["partner_id.name"],"count":true,"limit":5}`},
		{"dotted aggregate sum", "/rpc/aggregate", `{"model":"res.partner","groupby":["name"],"sum":["partner_id.name"],"limit":5}`},
		{"hierarchy aggregate domain", "/rpc/aggregate", `{"model":"res.partner","groupby":["name"],"count":true,"limit":5,"domain":[["id","child_of",1]]}`},
	}
	for _, tc := range deny {
		t.Run(tc.name, func(t *testing.T) {
			exec := &fakeExec{rows: []any{map[string]any{"id": 1, "name": "a"}}}
			b := realGateBroker(t, exec)
			if tc.path == "/rpc/aggregate" {
				b = realGateAggregateBroker(t, exec)
			}
			tok, err := b.Grant(time.Hour)
			if err != nil {
				t.Fatalf("Grant: %v", err)
			}
			rec := post(t, b, tc.path, tok, tc.body)
			if rec.Code == http.StatusOK {
				t.Fatalf("want denial, got 200 (%s)", rec.Body.String())
			}
			if len(exec.calls) != 0 {
				t.Fatalf("denial executed RPC: %d dispatches", len(exec.calls))
			}
		})
	}
	allow := []struct {
		name string
		path string
		body string
	}{
		{"legit count empty domain", "/rpc/count", `{"model":"res.partner"}`},
		{"legit count same-model OR", "/rpc/count", `{"model":"res.partner","domain":["|",["name","=","x"],["name","=","y"]]}`},
		{"legit aggregate", "/rpc/aggregate", `{"model":"res.partner","groupby":["name"],"count":true,"limit":5}`},
		{"legit search NOT", "/rpc/search", `{"model":"res.partner","fields":["name"],"domain":["!",["name","=","x"]],"limit":5}`},
	}
	for _, tc := range allow {
		t.Run(tc.name, func(t *testing.T) {
			exec := &fakeExec{rows: []any{map[string]any{"id": 1, "name": "a"}}}
			b := realGateBroker(t, exec)
			if tc.path == "/rpc/aggregate" {
				b = realGateAggregateBroker(t, exec)
			}
			tok, err := b.Grant(time.Hour)
			if err != nil {
				t.Fatalf("Grant: %v", err)
			}
			rec := post(t, b, tc.path, tok, tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
			}
			if len(exec.calls) != 1 {
				t.Fatalf("want 1 dispatch, got %d", len(exec.calls))
			}
		})
	}
}
