package mcpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/broker"
	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
	"github.com/danieljclsilva/cli-odoo/internal/config"
)

// Protocol tests use an in-process broker (httptest, disposable profile, no
// prod/keychain): a dispatch recorder stands in for routing only (it
// records model/method, returns canned rows) and asserts no Odoo semantics.

// stubGate is an allow-all/deny-all stub for the Authorize step.
type stubGate struct {
	allow  bool
	reason string
}

func (f *stubGate) Authorize(_ policy.SchemaView, _ policy.Request) policy.Decision {
	if f.allow {
		return policy.Decision{Allow: true}
	}
	return policy.Decision{Allow: false, Reason: f.reason}
}

// stubExec records calls and returns canned rows (routing recorder, not an
// Odoo semantics mock).
type stubExec struct {
	calls []string
	rows  []any
}

func (f *stubExec) Execute(model, method string, _ []any, _ map[string]any) (any, error) {
	f.calls = append(f.calls, model+"/"+method)
	out := make([]any, len(f.rows))
	copy(out, f.rows)
	return out, nil
}

// testBrokerServer spins an in-process broker model mux over httptest and
// returns the server plus a minted token. No prod, no keychain, no network
// beyond loopback httptest.
func testBrokerServer(t *testing.T, gate *stubGate, exec *stubExec) (*httptest.Server, string) {
	t.Helper()
	p := &policy.Policy{
		Version:    1,
		Instance:   "test",
		Operations: map[policy.Operation]bool{policy.OpSearch: true, policy.OpMeta: true},
		Models: map[string]policy.ModelRule{
			"res.partner": {Fields: []string{"name"}, MaxLimit: 50, CompanyField: "company_id"},
		},
		Scope:         policy.CompanyScope{Enabled: []int{1, 2}, Default: 1},
		SharedRecords: policy.SharedDeny,
		Budgets:       policy.Budgets{MaxLimit: 100, MaxOffset: 1000, MaxRowsPerCall: 10, MaxResponseBytes: 1 << 20, MaxCallsPerSession: 100, MaxRowsPerSession: 1000},
	}
	snap := snapshot.Snapshot{
		Instance:           "test",
		CapturedAt:         time.Now(),
		AvailableCompanies: []snapshot.Company{{ID: 1, Name: "A"}, {ID: 2, Name: "B"}},
		EnabledCompanies:   []int{1, 2}, DefaultCompany: 1,
		Models: map[string]snapshot.ModelMeta{
			"res.partner": {Name: "res.partner", Label: "Partner", Provenance: snapshot.ProvServer,
				Fields: map[string]snapshot.SFieldMeta{"name": {Name: "name", Type: "char", Label: "Name"}}},
		},
		MethodManifest: []string{"search_read"},
	}
	digest, derr := snapshot.CanonicalDigest(snap)
	if derr != nil {
		t.Fatalf("CanonicalDigest: %v", derr)
	}
	p.SnapshotSHA256 = digest
	b, err := broker.NewForTest(p, &config.Instance{Name: "test"}, snap, gate, exec)
	if err != nil {
		t.Fatalf("broker test setup: %v", err)
	}
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	srv := httptest.NewServer(b.ModelMuxForTest())
	t.Cleanup(srv.Close)
	return srv, tok
}

// roundTrip runs one JSON-RPC request through the stdio server and decodes
// the single response.
func roundTrip(t *testing.T, srv *Server, req string) map[string]any {
	t.Helper()
	srv.In = strings.NewReader(req + "\n")
	var out bytes.Buffer
	srv.Out = &out
	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var res map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &res); err != nil {
		t.Fatalf("decode response %q: %v", out.String(), err)
	}
	return res
}

func TestToolsListTypedOnly(t *testing.T) {
	names := map[string]bool{}
	for _, tool := range Tools() {
		names[tool.Name] = true
	}
	for _, want := range []string{"search", "read", "count", "aggregate", "meta", "companies", "catalog", "workspace.list", "workspace.read", "workspace.write", "workspace.mkdir"} {
		if !names[want] {
			t.Fatalf("missing typed tool %q", want)
		}
	}
	for _, banned := range []string{"grant", "revoke", "admin", "exec", "raw", "shell"} {
		if names[banned] {
			t.Fatalf("forbidden tool %q listed", banned)
		}
	}
	// workspace.mkdir must map to the broker's POST /rpc/workspace/mkdir:
	// every documented endpoint needs a live caller on this surface.
	if m, p, ok := endpoint("workspace.mkdir"); !ok || m != "POST" || p != "/rpc/workspace/mkdir" {
		t.Fatalf("endpoint(workspace.mkdir) = %q %q %v, want POST /rpc/workspace/mkdir true", m, p, ok)
	}
	// initialize + tools/list over stdio.
	srv := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if res["result"] == nil {
		t.Fatalf("initialize: %+v", res)
	}
	srv2 := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	res = roundTrip(t, srv2, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	result, _ := res["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 11 {
		t.Fatalf("tools/list = %d tools, want 11", len(tools))
	}
}

func TestCallDeniedSurfacesDenial(t *testing.T) {
	exec := &stubExec{}
	srvURL, tok := testBrokerServer(t, &stubGate{allow: false, reason: "test-deny"}, exec)
	srv := New(Config{BaseURL: srvURL.URL, Token: tok})
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner","fields":["name"]}}}`)
	result, _ := res["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("denied call should be isError: %+v", res)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("Execute ran despite denial: %v", exec.calls)
	}
}

func TestCallSearchRoutes(t *testing.T) {
	exec := &stubExec{rows: []any{map[string]any{"id": 1, "name": "a"}}}
	srvURL, tok := testBrokerServer(t, &stubGate{allow: true}, exec)
	srv := New(Config{BaseURL: srvURL.URL, Token: tok})
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner","fields":["name"]}}}`)
	result, _ := res["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("valid search isError: %+v", res)
	}
	if len(exec.calls) != 1 || exec.calls[0] != "res.partner/search_read" {
		t.Fatalf("routing = %v, want [res.partner/search_read]", exec.calls)
	}
}

func TestCatalogCarriesManifestAndProvenance(t *testing.T) {
	// The catalog tool is a read-only pass-through: MethodManifest plus
	// per-model/per-field provenance must survive the adapter unchanged.
	// A catalog that dropped them would hide the informational manifest
	// and the origin labels the human reviews.
	exec := &stubExec{}
	srvURL, tok := testBrokerServer(t, &stubGate{allow: true}, exec)
	srv := New(Config{BaseURL: srvURL.URL, Token: tok})
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"catalog","arguments":{}}}`)
	result, _ := res["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("catalog isError: %+v", res)
	}
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("catalog: empty content: %+v", res)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	var out struct {
		Models map[string]struct {
			Provenance string `json:"provenance"`
			Fields     map[string]struct {
				Provenance string `json:"provenance"`
			} `json:"fields"`
		} `json:"models"`
		MethodManifest []string `json:"method_manifest"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("catalog text is not JSON: %v (%q)", err, text)
	}
	if len(out.MethodManifest) == 0 {
		t.Fatal("catalog: method_manifest missing from pass-through")
	}
	pm, ok := out.Models["res.partner"]
	if !ok || pm.Provenance == "" {
		t.Fatalf("catalog: model provenance missing: %+v", out.Models)
	}
	if pm.Fields["name"].Provenance == "" {
		t.Fatalf("catalog: field provenance missing: %+v", pm.Fields)
	}
}

func TestUnknownToolIsProtocolError(t *testing.T) {
	srv := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"grant","arguments":{}}}`)
	if res["error"] == nil {
		t.Fatalf("admin tool should be a protocol error: %+v", res)
	}
}

func TestTokenNeverLogged(t *testing.T) {
	exec := &stubExec{}
	_, tok := testBrokerServer(t, &stubGate{allow: true}, exec)
	if tok == "" {
		t.Fatal("empty token")
	}
	// No adapter path formats the token into output: tools/list and error
	// envelopes carry no credential material.
	srv := New(Config{BaseURL: "http://127.0.0.1:1", Token: tok})
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}}`)
	if strings.Contains(strings.ToLower(jsonString(res)), strings.ToLower(tok)) {
		t.Fatal("token echoed in tools/list")
	}
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
