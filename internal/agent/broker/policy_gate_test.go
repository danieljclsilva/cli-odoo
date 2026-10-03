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
// exact outgoing field projection, never Odoo semantics.
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
