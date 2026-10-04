package mcpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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

// serveInput runs Serve over input with a deadline and returns everything
// written before Serve returns (EOF or error). The deadline keeps a framing
// regression (hang or repeat-decode loop) from stalling the suite: Serve
// must return promptly either way.
func serveInput(t *testing.T, srv *Server, input string, timeout time.Duration) (string, error) {
	t.Helper()
	srv.In = strings.NewReader(input)
	var out bytes.Buffer
	srv.Out = &out
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background()) }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(timeout):
		t.Fatalf("Serve did not return within %v (input %d bytes)", timeout, len(input))
		return "", nil
	}
}

// roundTrip runs one JSON-RPC request through the stdio server and decodes
// the single response.
func roundTrip(t *testing.T, srv *Server, req string) map[string]any {
	t.Helper()
	got, err := serveInput(t, srv, req+"\n", 5*time.Second)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var res map[string]any
	if err := json.Unmarshal(bytes.TrimSpace([]byte(got)), &res); err != nil {
		t.Fatalf("decode response %q: %v", got, err)
	}
	return res
}

// initServer runs the full lifecycle against srv so the session reaches
// ready: initialize RESPONSE (which advances to awaiting-initialized) plus
// the notifications/initialized notification (which advances to ready).
// Every tools/list and tools/call test below must ready the session first:
// both are denied without dispatch until ready.
func initServer(t *testing.T, srv *Server) {
	t.Helper()
	readyServer(t, srv)
}

// readyServer drives initialize + notifications/initialized over one Serve
// invocation (the Serve loop owns both transitions), then asserts ready.
func readyServer(t *testing.T, srv *Server) {
	t.Helper()
	got, err := serveInput(t, srv,
		`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`+"\n"+
			`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`+"\n",
		5*time.Second)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 1 {
		t.Fatalf("want 1 response (initialize; notification is silent), got %d: %q", len(lines), got)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &res); err != nil || res["result"] == nil {
		t.Fatalf("initialize should succeed: %q err=%v", got, err)
	}
	if !srv.ready() {
		t.Fatal("session should be ready after initialize + notification")
	}
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
	// Full lifecycle then tools/list over stdio.
	srv := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	initServer(t, srv)
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	result, _ := res["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 11 {
		t.Fatalf("tools/list = %d tools, want 11", len(tools))
	}
}

func TestToolsListRequiresReady(t *testing.T) {
	exec := &stubExec{rows: []any{map[string]any{"id": 1}}}
	srvURL, tok := testBrokerServer(t, &stubGate{allow: true}, exec)
	srv := New(Config{BaseURL: srvURL.URL, Token: tok})
	// tools/list before any init: deterministic not-initialized error.
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":70,"method":"tools/list","params":{}}`)
	if res["error"] == nil {
		t.Fatalf("uninitialized tools/list should be an error: %+v", res)
	}
	if got := res["error"].(map[string]any)["message"].(string); got != errNotInitialized.Error() {
		t.Fatalf("uninitialized tools/list message = %q, want %q", got, errNotInitialized.Error())
	}
	if len(exec.calls) != 0 {
		t.Fatalf("uninitialized list dispatched: %v", exec.calls)
	}
	// Initialize RESPONSE alone still gates: awaiting-initialized is not ready.
	res = roundTrip(t, srv, `{"jsonrpc":"2.0","id":71,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`)
	if res["result"] == nil {
		t.Fatalf("initialize: %+v", res)
	}
	res = roundTrip(t, srv, `{"jsonrpc":"2.0","id":72,"method":"tools/list","params":{}}`)
	if res["error"] == nil {
		t.Fatalf("awaiting-initialized tools/list should be an error: %+v", res)
	}
	if got := res["error"].(map[string]any)["message"].(string); got != errNotInitialized.Error() {
		t.Fatalf("awaiting tools/list message = %q, want %q", got, errNotInitialized.Error())
	}
	// The notification completes the lifecycle: the next list is allowed.
	got, err := serveInput(t, srv, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`+"\n", 5*time.Second)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if strings.TrimSpace(got) != "" {
		t.Fatalf("notification should get no reply, got %q", got)
	}
	if !srv.ready() {
		t.Fatal("session should be ready after notification")
	}
	res = roundTrip(t, srv, `{"jsonrpc":"2.0","id":73,"method":"tools/list","params":{}}`)
	result, _ := res["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 11 {
		t.Fatalf("ready tools/list = %d tools, want 11", len(tools))
	}
}

func TestCallDeniedSurfacesDenial(t *testing.T) {
	exec := &stubExec{}
	srvURL, tok := testBrokerServer(t, &stubGate{allow: false, reason: "test-deny"}, exec)
	srv := New(Config{BaseURL: srvURL.URL, Token: tok})
	initServer(t, srv)
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
	exec := &stubExec{}
	srvURL, tok := testBrokerServer(t, &stubGate{allow: true}, exec)
	srv := New(Config{BaseURL: srvURL.URL, Token: tok})
	initServer(t, srv)
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
	initServer(t, srv)
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
	initServer(t, srv)
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

// errFailWriter fails every Encode so Serve must abort with an error (the
// host must exit non-zero, never silently drop responses).
type errFailWriter struct{}

func (errFailWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

// A single malformed frame costs one ParseError and Serve keeps framing:
// garbage, then a valid initialize, yields exactly one error + one result.
func TestMalformedInputRecovers(t *testing.T) {
	srv := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	got, err := serveInput(t, srv,
		"this is not json\n"+`{"jsonrpc":"2.0","id":11,"method":"initialize","params":{}}`+"\n",
		5*time.Second)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 responses (parse error + initialize), got %d: %q", len(lines), got)
	}
	var first, second map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("first line not JSON: %v", err)
	}
	if first["error"] == nil {
		t.Fatalf("malformed frame should be a protocol error: %q", lines[0])
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("second line not JSON: %v", err)
	}
	if second["result"] == nil {
		t.Fatalf("valid frame after garbage should succeed: %q", lines[1])
	}
}

// An over-cap frame is rejected once (one ParseError) and the loop
// resynchronizes on the next frame instead of spinning on a stuck decoder.
func TestOversizedFrameRejectedOnce(t *testing.T) {
	srv := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	big := strings.Repeat("x", maxFrameBytes+100)
	got, err := serveInput(t, srv,
		big+"\n"+`{"jsonrpc":"2.0","id":12,"method":"ping","params":{}}`+"\n",
		5*time.Second)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 responses (parse error + ping), got %d", len(lines))
	}
	var first, second map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil || first["error"] == nil {
		t.Fatalf("oversized frame should be one protocol error: %q", lines[0])
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil || second["result"] == nil {
		t.Fatalf("frame after oversize should succeed: %q", lines[1])
	}
}

// A failing writer must abort Serve promptly with an error (bounded time,
// no hang): the host learns its output path is broken via a non-zero exit.
func TestFailingWriterExitsPromptly(t *testing.T) {
	srv := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	srv.In = strings.NewReader(`{"jsonrpc":"2.0","id":13,"method":"ping","params":{}}` + "\n")
	srv.Out = errFailWriter{}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Serve over a failing writer should return an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve over a failing writer hung")
	}
}

// A failing writer on a parse-error path also aborts: the error reply
// itself cannot be delivered, so Serve must not loop forever.
func TestFailingWriterOnParseErrorExits(t *testing.T) {
	srv := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	srv.In = strings.NewReader("garbage\n")
	srv.Out = errFailWriter{}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Serve should return the encoder error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve hung on undeliverable parse error")
	}
}

// Cancellation aborts Serve promptly instead of blocking on input.
func TestCancelledContextExits(t *testing.T) {
	srv := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	pr, pw := io.Pipe()
	srv.In = pr
	var out bytes.Buffer
	srv.Out = &out
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := srv.Serve(ctx); err == nil {
		t.Fatal("cancelled Serve should return the context error")
	}
	_ = pw.Close()
}

// Schemas for no-required tools carry no required:null: an empty schema is
// an omitted key, never an explicit null (which fails JSON Schema
// validation in strict consumers).
func TestSchemasHaveNoRequiredNull(t *testing.T) {
	raw, err := json.Marshal(Tools())
	if err != nil {
		t.Fatalf("marshal Tools: %v", err)
	}
	if strings.Contains(string(raw), `"required":null`) {
		t.Fatalf("schema carries required:null: %s", raw)
	}
	for _, tool := range Tools() {
		if v, ok := tool.InputSchema["required"]; ok && v == nil {
			t.Fatalf("tool %q has nil required", tool.Name)
		}
	}
	for _, name := range []string{"meta", "companies", "catalog"} {
		for _, tool := range Tools() {
			if tool.Name != name {
				continue
			}
			if _, ok := tool.InputSchema["required"]; ok {
				t.Fatalf("tool %q takes optional/no args but declares required", name)
			}
		}
	}
}

// Unknown or wrong-typed arguments are rejected as InvalidParams before any
// broker dispatch (the dispatch recorder proves zero outgoing RPC).
func TestUnknownArgsRejected(t *testing.T) {
	exec := &stubExec{}
	srvURL, tok := testBrokerServer(t, &stubGate{allow: true}, exec)
	srv := New(Config{BaseURL: srvURL.URL, Token: tok})
	initServer(t, srv)
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner","fields":["name"],"admin":true}}}`)
	if res["error"] == nil {
		t.Fatalf("unknown arg should be InvalidParams: %+v", res)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("unknown-arg call dispatched: %v", exec.calls)
	}
	srv2 := New(Config{BaseURL: srvURL.URL, Token: tok})
	initServer(t, srv2)
	res = roundTrip(t, srv2, `{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner","fields":"name"}}}`)
	if res["error"] == nil {
		t.Fatalf("wrong-typed arg should be InvalidParams: %+v", res)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("wrong-typed call dispatched: %v", exec.calls)
	}
	// GET tools accept no stray body keys: companies with an argument denies.
	srv3 := New(Config{BaseURL: srvURL.URL, Token: tok})
	initServer(t, srv3)
	res = roundTrip(t, srv3, `{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"companies","arguments":{"model":"x"}}}`)
	if res["error"] == nil {
		t.Fatalf("GET stray arg should be InvalidParams: %+v", res)
	}
}

// A non-loopback broker URL is refused before dispatch (zero outgoing RPC):
// the session token must never travel beyond the local broker.
func TestNonLoopbackURLRefused(t *testing.T) {
	exec := &stubExec{}
	_, tok := testBrokerServer(t, &stubGate{allow: true}, exec)
	srv := New(Config{BaseURL: "http://192.168.1.10:8471", Token: tok})
	initServer(t, srv)
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner","fields":["name"]}}}`)
	result, _ := res["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("non-loopback URL should be a tool error: %+v", res)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("non-loopback call dispatched: %v", exec.calls)
	}
	for _, raw := range []string{"http://127.0.0.1:8471", "http://localhost:8471", "http://[::1]:8471", "http://127.0.0.2:9"} {
		if !isLoopbackURL(raw) {
			t.Fatalf("isLoopbackURL(%q) = false, want true", raw)
		}
	}
	for _, raw := range []string{"http://192.168.1.10:8471", "http://127.evil.com:8471", "ftp://127.0.0.1/x", "http://example.com", "::::", ""} {
		if isLoopbackURL(raw) {
			t.Fatalf("isLoopbackURL(%q) = true, want false", raw)
		}
	}
}

// Redirects are never followed: a 302 target must see zero requests while
// the caller gets a tool error (the token never moves off the broker).
func TestRedirectRefused(t *testing.T) {
	var evilHits int
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		evilHits++
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(evil.Close)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/evil", http.StatusFound)
	}))
	t.Cleanup(target.Close)
	exec := &stubExec{}
	_, tok := testBrokerServer(t, &stubGate{allow: true}, exec)
	srv := New(Config{BaseURL: target.URL, Token: tok})
	initServer(t, srv)
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner","fields":["name"]}}}`)
	result, _ := res["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("redirect should be a tool error: %+v", res)
	}
	if evilHits != 0 {
		t.Fatalf("redirect target hit %d times with the token attached", evilHits)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("redirect call dispatched: %v", exec.calls)
	}
}

// The meta model query is strictly parsed and QueryEscaped: a model with
// spaces/& rides the query string encoded, and an unknown trailing query key
// on a GET request never reaches the broker as a second filter.
func TestMetaQueryEscapedAndStrict(t *testing.T) {
	var gotQuery string
	seen := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Write([]byte(`{"success":true,"result":{"model":"res.partner"}}`))
	}))
	t.Cleanup(seen.Close)
	srv := New(Config{BaseURL: seen.URL, Token: "probe-token"})
	initServer(t, srv)
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":32,"method":"tools/call","params":{"name":"meta","arguments":{"model":"res.partner & co"}}}`)
	result, _ := res["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("meta isError: %+v", res)
	}
	if !strings.Contains(gotQuery, "model=res.partner+%26+co") && !strings.Contains(gotQuery, "model=res.partner%20%26%20co") {
		t.Fatalf("model query not QueryEscaped: %q", gotQuery)
	}
	if strings.Contains(gotQuery, " & ") {
		t.Fatalf("raw concatenation leaked into query: %q", gotQuery)
	}
}

// Token redaction: a broker denial echoing the token (raw) surfaces with
// "***" instead, never the credential.
func TestTokenRedactedFromErrors(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Write([]byte(`{"success":false,"error":"denied for ` + tok + ` repeat"}`))
	}))
	t.Cleanup(bad.Close)
	_, probe := testBrokerServer(t, &stubGate{allow: true}, &stubExec{})
	srv := New(Config{BaseURL: bad.URL, Token: probe})
	initServer(t, srv)
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":33,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner","fields":["name"]}}}`)
	result, _ := res["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("want isError: %+v", res)
	}
	content, _ := result["content"].([]any)
	text, _ := content[0].(map[string]any)["text"].(string)
	if strings.Contains(text, probe) {
		t.Fatalf("token echoed in tool error: %q", text)
	}
	if !strings.Contains(text, "***") {
		t.Fatalf("redaction marker missing: %q", text)
	}
}

// initialize negotiates deterministically: a supported client version echoes
// back, anything else (unknown, empty, missing, wrong-typed, non-object
// params) falls back to the default without error. ping answers anytime.
func TestInitializeNegotiationAndPing(t *testing.T) {
	srv := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":40,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`)
	result, _ := res["result"].(map[string]any)
	if result["protocolVersion"] != "2025-03-26" {
		t.Fatalf("negotiation = %+v, want 2025-03-26", result)
	}
	srv2 := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	res = roundTrip(t, srv2, `{"jsonrpc":"2.0","id":41,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}`)
	result, _ = res["result"].(map[string]any)
	if result["protocolVersion"] != defaultProtocolVersion {
		t.Fatalf("unknown version should fall back to %q: %+v", defaultProtocolVersion, result)
	}
	// Malformed init params are deterministic: missing, empty, wrong-typed,
	// and non-object params all answer with the default version, never an
	// error and never an echo of attacker-chosen text.
	for i, p := range []string{
		`{"jsonrpc":"2.0","id":44,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":44,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":44,"method":"initialize","params":{"protocolVersion":""}}`,
		`{"jsonrpc":"2.0","id":44,"method":"initialize","params":{"protocolVersion":42}}`,
		`{"jsonrpc":"2.0","id":44,"method":"initialize","params":[1,2]}`,
		`{"jsonrpc":"2.0","id":44,"method":"initialize","params":"2025-03-26"}`,
	} {
		srv := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
		res := roundTrip(t, srv, p)
		result, _ := res["result"].(map[string]any)
		if res["error"] != nil || result["protocolVersion"] != defaultProtocolVersion {
			t.Fatalf("case %d params %s = %+v, want default %q", i, p, res, defaultProtocolVersion)
		}
	}
	srv3 := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	res = roundTrip(t, srv3, `{"jsonrpc":"2.0","id":42,"method":"ping","params":{}}`)
	if res["result"] == nil {
		t.Fatalf("ping: %+v", res)
	}
	// A notifications/initialized frame gets no reply: one request in, one
	// response out, and the response belongs to the ping.
	srv4 := New(Config{BaseURL: "http://127.0.0.1:1", Token: "x"})
	got, err := serveInput(t, srv4,
		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`+"\n"+
			`{"jsonrpc":"2.0","id":43,"method":"ping","params":{}}`+"\n",
		5*time.Second)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if n := len(strings.Split(strings.TrimSpace(got), "\n")); n != 1 {
		t.Fatalf("notification should get no reply (want 1 line, got %d): %q", n, got)
	}
}

// tools/call lifecycle: denied before init (zero dispatch), still denied
// after the initialize RESPONSE alone (awaiting-initialized is not ready),
// then dispatches after notifications/initialized; a repeat initialize
// stays ready and dispatches again (never regresses, never widens).
func TestToolsCallRequiresInitialize(t *testing.T) {
	exec := &stubExec{rows: []any{map[string]any{"id": 1, "name": "a"}}}
	srvURL, tok := testBrokerServer(t, &stubGate{allow: true}, exec)
	srv := New(Config{BaseURL: srvURL.URL, Token: tok})
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner","fields":["name"]}}}`)
	if res["error"] == nil {
		t.Fatalf("uninitialized tools/call should be an error: %+v", res)
	}
	if got := res["error"].(map[string]any)["message"].(string); got != errNotInitialized.Error() {
		t.Fatalf("uninitialized tools/call message = %q, want %q", got, errNotInitialized.Error())
	}
	if len(exec.calls) != 0 {
		t.Fatalf("uninitialized call dispatched: %v", exec.calls)
	}
	res = roundTrip(t, srv, `{"jsonrpc":"2.0","id":54,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`)
	if res["result"] == nil {
		t.Fatalf("initialize: %+v", res)
	}
	res = roundTrip(t, srv, `{"jsonrpc":"2.0","id":55,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner","fields":["name"]}}}`)
	if res["error"] == nil {
		t.Fatalf("awaiting-initialized tools/call should be an error: %+v", res)
	}
	if got := res["error"].(map[string]any)["message"].(string); got != errNotInitialized.Error() {
		t.Fatalf("awaiting tools/call message = %q, want %q", got, errNotInitialized.Error())
	}
	if len(exec.calls) != 0 {
		t.Fatalf("awaiting-initialized call dispatched: %v", exec.calls)
	}
	got, err := serveInput(t, srv, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`+"\n", 5*time.Second)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if strings.TrimSpace(got) != "" {
		t.Fatalf("notification should get no reply, got %q", got)
	}
	res = roundTrip(t, srv, `{"jsonrpc":"2.0","id":51,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner","fields":["name"]}}}`)
	result, _ := res["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("ready search isError: %+v", res)
	}
	if len(exec.calls) != 1 || exec.calls[0] != "res.partner/search_read" {
		t.Fatalf("routing = %v, want [res.partner/search_read]", exec.calls)
	}
	// Repeated initialize stays ready: re-answers, keeps dispatching.
	initServer(t, srv)
	if !srv.ready() {
		t.Fatal("repeated initialize left ready session not-ready")
	}
	res = roundTrip(t, srv, `{"jsonrpc":"2.0","id":52,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner","fields":["name"]}}}`)
	result, _ = res["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("post-repeat-init search isError: %+v", res)
	}
	if len(exec.calls) != 2 {
		t.Fatalf("calls = %v, want 2 dispatches", exec.calls)
	}
}

// notifications/initialized with no prior initialize is a no-op: the session
// stays uninitialized (tools gated, ping still allowed).
func TestInitializedNotificationWithoutInitializeIsNoop(t *testing.T) {
	exec := &stubExec{rows: []any{map[string]any{"id": 1}}}
	srvURL, tok := testBrokerServer(t, &stubGate{allow: true}, exec)
	srv := New(Config{BaseURL: srvURL.URL, Token: tok})
	got, err := serveInput(t, srv, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`+"\n", 5*time.Second)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if strings.TrimSpace(got) != "" {
		t.Fatalf("notification should get no reply, got %q", got)
	}
	if srv.ready() {
		t.Fatal("notification without initialize reached ready")
	}
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":80,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner","fields":["name"]}}}`)
	if res["error"] == nil {
		t.Fatalf("tools/call after lone notification should be an error: %+v", res)
	}
	res = roundTrip(t, srv, `{"jsonrpc":"2.0","id":81,"method":"tools/list","params":{}}`)
	if res["error"] == nil {
		t.Fatalf("tools/list after lone notification should be an error: %+v", res)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("lone-notification session dispatched: %v", exec.calls)
	}
	res = roundTrip(t, srv, `{"jsonrpc":"2.0","id":82,"method":"ping","params":{}}`)
	if res["result"] == nil {
		t.Fatalf("ping after lone notification: %+v", res)
	}
}

// ping is allowed pre-init and never dispatches.
func TestPingPreInitAllowed(t *testing.T) {
	exec := &stubExec{rows: []any{map[string]any{"id": 1}}}
	srvURL, tok := testBrokerServer(t, &stubGate{allow: true}, exec)
	srv := New(Config{BaseURL: srvURL.URL, Token: tok})
	res := roundTrip(t, srv, `{"jsonrpc":"2.0","id":90,"method":"ping","params":{}}`)
	if res["result"] == nil {
		t.Fatalf("pre-init ping: %+v", res)
	}
	if len(exec.calls) != 0 {
		t.Fatalf("ping dispatched: %v", exec.calls)
	}
}

// Whole-response overflow: an exact-cap body is accepted, while a valid JSON
// prefix plus whitespace plus one extra byte over the cap is denied before
// any decode, for both success and error envelopes. The over-cap fixture is
// exactly the truncation trap: a cap+1 body whose first cap bytes are valid
// JSON plus trailing whitespace (which json.Unmarshal would accept), so a
// truncate-then-decode reader would decode the attacker-chosen prefix.
func TestBrokerResponseOverflowDenied(t *testing.T) {
	newSrv := func(body string) *Server {
		t.Helper()
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(body))
		}))
		t.Cleanup(upstream.Close)
		srv := New(Config{BaseURL: upstream.URL, Token: "probe-token"})
		initServer(t, srv)
		return srv
	}
	callSearch := `{"jsonrpc":"2.0","id":60,"method":"tools/call","params":{"name":"search","arguments":{"model":"res.partner"}}}`
	// Exact-cap valid body accepted.
	exactPrefix := `{"success":true,"result":"`
	exactBody := exactPrefix + strings.Repeat("a", maxBrokerResponseBytes-len(exactPrefix)-len(`"}`)) + `"` + "}"
	if len(exactBody) != maxBrokerResponseBytes {
		t.Fatalf("fixture = %d bytes, want cap %d", len(exactBody), maxBrokerResponseBytes)
	}
	res := roundTrip(t, newSrv(exactBody), callSearch)
	if result, _ := res["result"].(map[string]any); result["isError"] == true {
		t.Fatalf("exact-cap success body denied: %+v", res)
	}
	// Valid-prefix + whitespace + 1 byte over cap denied (success envelope):
	// the first cap bytes are valid JSON with trailing whitespace, which a
	// truncating reader would decode as success.
	validCore := `{"success":true,"result":"` + strings.Repeat("a", maxBrokerResponseBytes-1-len(`{"success":true,"result":"`)-len(`"}`)) + `"` + "}"
	if len(validCore) != maxBrokerResponseBytes-1 {
		t.Fatalf("core = %d bytes, want cap-1 %d", len(validCore), maxBrokerResponseBytes-1)
	}
	overSuccess := validCore + " " + "X"
	if len(overSuccess) != maxBrokerResponseBytes+1 {
		t.Fatalf("fixture = %d bytes, want cap+1 %d", len(overSuccess), maxBrokerResponseBytes+1)
	}
	res = roundTrip(t, newSrv(overSuccess), callSearch)
	result, _ := res["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("prefix+whitespace+1-byte over-cap success body accepted: %+v", res)
	}
	content, _ := result["content"].([]any)
	text, _ := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "exceeds 4 MiB") {
		t.Fatalf("over-cap success denial text = %q, want 4 MiB bound", text)
	}
	// Over-cap error envelope denied the same way (never decoded).
	errCore := `{"success":false,"error":"` + strings.Repeat("e", maxBrokerResponseBytes-1-len(`{"success":false,"error":"`)-len(`"}`)) + `"` + "}"
	if len(errCore) != maxBrokerResponseBytes-1 {
		t.Fatalf("core = %d bytes, want cap-1 %d", len(errCore), maxBrokerResponseBytes-1)
	}
	overErr := errCore + " " + "X"
	if len(overErr) != maxBrokerResponseBytes+1 {
		t.Fatalf("fixture = %d bytes, want cap+1 %d", len(overErr), maxBrokerResponseBytes+1)
	}
	res = roundTrip(t, newSrv(overErr), callSearch)
	result, _ = res["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("over-cap error envelope accepted: %+v", res)
	}
	content, _ = result["content"].([]any)
	text, _ = content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "exceeds 4 MiB") {
		t.Fatalf("over-cap error denial text = %q, want 4 MiB bound", text)
	}
}

// Overflow denial lives in callTool, independent of session state: without
// any initialize, a direct callTool against a valid-prefix + whitespace + 1
// byte over-cap body is still denied before decode (never dispatched past
// the bound, never truncated-then-decoded).
func TestBrokerResponseOverflowDeniedWithoutInitialize(t *testing.T) {
	core := `{"success":true,"result":"` + strings.Repeat("a", maxBrokerResponseBytes-1-len(`{"success":true,"result":"`)-len(`"}`)) + `"` + "}"
	if len(core) != maxBrokerResponseBytes-1 {
		t.Fatalf("core = %d bytes, want cap-1 %d", len(core), maxBrokerResponseBytes-1)
	}
	body := core + " " + "X"
	if len(body) != maxBrokerResponseBytes+1 {
		t.Fatalf("fixture = %d bytes, want cap+1 %d", len(body), maxBrokerResponseBytes+1)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(upstream.Close)
	srv := New(Config{BaseURL: upstream.URL, Token: "probe-token"})
	text, toolErr, perr := srv.callTool(context.Background(), "search", map[string]any{"model": "res.partner"})
	if perr != nil {
		t.Fatalf("over-cap body should be a tool error, not a protocol error: %+v", perr)
	}
	if !toolErr {
		t.Fatalf("prefix+whitespace+1-byte over-cap body accepted without initialize: %q", text)
	}
	if !strings.Contains(text, "exceeds 4 MiB") {
		t.Fatalf("over-cap denial text = %q, want 4 MiB bound", text)
	}
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
