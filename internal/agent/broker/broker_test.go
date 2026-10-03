package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
	"github.com/danieljclsilva/cli-odoo/internal/config"
)

// Protocol tests use a FAKE policy.Gate/Execute seam (a protocol harness,
// not an Odoo semantics mock): they assert denial ordering, loopback
// refusal, context overwrite, read-to-search_read conversion, unknown-token
// denial, and response caps — never Odoo behavior.

// fakeGate is an allow-all/deny-all stub for the Authorize step.
type fakeGate struct {
	allow  bool
	reason string
	seen   []policy.Request
}

func (f *fakeGate) Authorize(_ policy.SchemaView, r policy.Request) policy.Decision {
	f.seen = append(f.seen, r)
	if f.allow {
		return policy.Decision{Allow: true}
	}
	return policy.Decision{Allow: false, Reason: f.reason}
}

// fakeExec records calls and returns canned rows.
type fakeExec struct {
	calls  []execCall
	rows   []any
	err    error
	errMsg string
}

type execCall struct {
	model, method string
	args          []any
	kwargs        map[string]any
}

func (f *fakeExec) Execute(model, method string, args []any, kwargs map[string]any) (any, error) {
	f.calls = append(f.calls, execCall{model, method, args, kwargs})
	if f.err != nil {
		return nil, f.err
	}
	out := make([]any, len(f.rows))
	copy(out, f.rows)
	return out, nil
}

func testPolicy() *policy.Policy {
	return &policy.Policy{
		Version:    1,
		Instance:   "test",
		Operations: map[policy.Operation]bool{policy.OpSearch: true, policy.OpRead: true, policy.OpCount: true, policy.OpAggregate: true, policy.OpMeta: true},
		Models: map[string]policy.ModelRule{
			"res.partner": {Fields: []string{"name"}, MaxLimit: 50, CompanyField: "company_id"},
		},
		Scope:         policy.CompanyScope{Enabled: []int{1, 2}, Default: 1},
		SharedRecords: policy.SharedDeny,
		Budgets:       policy.Budgets{MaxLimit: 100, MaxOffset: 1000, MaxRowsPerCall: 10, MaxResponseBytes: 1 << 20, MaxCallsPerSession: 100, MaxRowsPerSession: 1000},
	}
}

func testBroker(t *testing.T, gate *fakeGate, exec *fakeExec) *Broker {
	t.Helper()
	b, err := New(testPolicy(), &config.Instance{Name: "test"}, snapshot.Snapshot{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b.authz = gate
	b.frag = policy.CompanyDomain
	if exec != nil {
		b.exec = exec
	}
	return b
}

func grantToken(t *testing.T, b *Broker) string {
	t.Helper()
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return tok
}

func post(t *testing.T, b *Broker, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	b.modelMux().ServeHTTP(rec, req)
	return rec
}

func TestGrantCheckExpiryRevocation(t *testing.T) {
	b, err := New(testPolicy(), &config.Instance{Name: "test"}, snapshot.Snapshot{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if len(tok) != 64 {
		t.Fatalf("token len = %d, want 64 (256-bit hex)", len(tok))
	}
	if err := b.Check(tok); err != nil {
		t.Fatalf("Check live: %v", err)
	}
	if err := b.Check("nope"); !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("Check unknown = %v, want ErrSessionUnknown", err)
	}
	short, err := b.Grant(time.Millisecond)
	if err != nil {
		t.Fatalf("Grant short: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := b.Check(short); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Check expired = %v, want ErrSessionExpired", err)
	}
	b.Revoke(tok)
	if err := b.Check(tok); !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("Check revoked = %v, want ErrSessionUnknown", err)
	}
	if _, err := b.Grant(0); err == nil {
		t.Fatal("zero ttl granted")
	}
}

func TestRevokePrefixUnambiguousOnly(t *testing.T) {
	b, _ := New(testPolicy(), &config.Instance{Name: "test"}, snapshot.Snapshot{})
	a, _ := b.Grant(time.Hour)
	// Full tokens always work.
	if err := b.revokePrefix(a); err != nil {
		t.Fatalf("revoke full: %v", err)
	}
	if err := b.Check(a); !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("revoked token still live: %v", err)
	}
	// Unknown prefix fails.
	if err := b.revokePrefix("zzzz"); !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("unknown prefix = %v", err)
	}
	if err := b.revokePrefix(""); !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("empty prefix = %v", err)
	}
	// Multi-match prefix fails without revoking anything: plant two
	// sessions sharing a prefix directly in the ledger.
	b.sessions["ab12cd00"] = &sess{expires: time.Now().Add(time.Hour), version: 1}
	b.sessions["ab12ef00"] = &sess{expires: time.Now().Add(time.Hour), version: 1}
	if err := b.revokePrefix("ab12"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("multi-match prefix = %v, want ambiguity error", err)
	}
	if err := b.Check("ab12cd00"); err != nil {
		t.Fatalf("ambiguous revoke dropped a session: %v", err)
	}
	if err := b.Check("ab12ef00"); err != nil {
		t.Fatalf("ambiguous revoke dropped a session: %v", err)
	}
	// The shared prefix minus one char is still ambiguous; a longer
	// unique prefix revokes exactly one.
	if err := b.revokePrefix("ab12cd"); err != nil {
		t.Fatalf("unique prefix revoke: %v", err)
	}
	if err := b.Check("ab12cd00"); !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("unique prefix did not revoke")
	}
}

func TestSessionBudgetHeadroom(t *testing.T) {
	p := testPolicy()
	p.Budgets.MaxCallsPerSession = 1
	b, _ := New(p, &config.Instance{Name: "test"}, snapshot.Snapshot{})
	tok, _ := b.Grant(time.Hour)
	if err := b.Check(tok); err != nil {
		t.Fatalf("pre-call Check: %v", err)
	}
	b.record(tok, 0) // reservation from Check stands; rows add nothing
	if err := b.Check(tok); !errors.Is(err, ErrSessionBudget) {
		t.Fatalf("post-budget Check = %v, want ErrSessionBudget", err)
	}
}

func TestLoopbackBindRefusal(t *testing.T) {
	for _, addr := range []string{
		"0.0.0.0:8080", "192.168.1.5:8080", "[::]:8080", ":8080",
		"example.com:80", "127.erp.example.com:80", "not-an-addr",
	} {
		if err := checkLoopbackAddr(addr); err == nil {
			t.Fatalf("non-loopback %q accepted", addr)
		}
	}
	for _, addr := range []string{
		"127.0.0.1:8080", "127.0.0.2:1", "[::1]:8080", "localhost:8080",
		"LOCALHOST:8080", "[::ffff:127.0.0.1]:8080",
	} {
		if err := checkLoopbackAddr(addr); err != nil {
			t.Fatalf("loopback %q refused: %v", addr, err)
		}
	}
}

func TestUnknownTokenDeniedBeforeRPC(t *testing.T) {
	gate := &fakeGate{allow: true}
	exec := &fakeExec{rows: []any{map[string]any{"id": 1}}}
	b := testBroker(t, gate, exec)
	rec := post(t, b, "/rpc/search", "bogus", `{"model":"res.partner"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if len(exec.calls) != 0 {
		t.Fatal("Execute called for unknown token")
	}
	rec = post(t, b, "/rpc/search", "", `{"model":"res.partner"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token code = %d, want 401", rec.Code)
	}
}

func TestDeniedBeforeRPCOrdering(t *testing.T) {
	gate := &fakeGate{allow: false, reason: "test-deny"}
	exec := &fakeExec{rows: []any{map[string]any{"id": 1}}}
	b := testBroker(t, gate, exec)
	tok := grantToken(t, b)
	for _, tc := range []struct{ path, body string }{
		{"/rpc/search", `{"model":"res.partner"}`},
		{"/rpc/read", `{"model":"res.partner","ids":[1]}`},
		{"/rpc/count", `{"model":"res.partner"}`},
		{"/rpc/aggregate", `{"model":"res.partner","groupby":["name"],"count":true}`},
	} {
		rec := post(t, b, tc.path, tok, tc.body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s code = %d, want 403", tc.path, rec.Code)
		}
	}
	if len(exec.calls) != 0 {
		t.Fatalf("Execute called %d times despite denial", len(exec.calls))
	}
}

func TestContextOverwrite(t *testing.T) {
	gate := &fakeGate{allow: true}
	exec := &fakeExec{rows: []any{map[string]any{"id": 1, "name": "a"}}}
	b := testBroker(t, gate, exec)
	tok := grantToken(t, b)
	// Caller-supplied context/CompanyIDs are unknown fields: rejected.
	rec := post(t, b, "/rpc/search", tok, `{"model":"res.partner","context":{"company_id":99}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("caller context code = %d, want 400", rec.Code)
	}
	if len(exec.calls) != 0 {
		t.Fatal("Execute called with caller context")
	}
	rec = post(t, b, "/rpc/search", tok, `{"model":"res.partner","domain":[["name","=","acme"]]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("search code = %d: %s", rec.Code, rec.Body.String())
	}
	if len(exec.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(exec.calls))
	}
	kw := exec.calls[0].kwargs
	ctx, ok := kw["context"].(map[string]any)
	if !ok {
		t.Fatalf("no injected context: %#v", kw)
	}
	if ctx["company_id"] != 1 {
		t.Fatalf("company_id = %v, want 1 (Default)", ctx["company_id"])
	}
	ids, ok := ctx["allowed_company_ids"].([]any)
	if !ok || len(ids) != 2 {
		t.Fatalf("allowed_company_ids = %v, want [1 2]", ctx["company_id"])
	}
	dom, _ := kw["domain"].([]any)
	found := false
	for _, cond := range dom {
		if arr, ok := cond.([]any); ok && len(arr) == 3 && arr[0] == "company_id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("enforced company fragment missing from domain: %v", dom)
	}
	if exec.calls[0].method != "search_read" {
		t.Fatalf("method = %q, want search_read", exec.calls[0].method)
	}
}

// Reviewer-driven: the company fragment must AND, never OR, with caller
// prefix operators. An arity-incomplete domain denies at the real gate
func TestPrefixCaptureDeniedAtRealGate(t *testing.T) {
	b, err := New(testPolicy(), &config.Instance{Name: "test"}, snapshot.Snapshot{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b.exec = &fakeExec{rows: []any{}}
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	for _, body := range []string{
		`{"model":"res.partner","domain":["|",["name","=","x"]]}`,
		`{"model":"res.partner","domain":["!"]}`,
		`{"model":"res.partner","domain":[["name","=","x"],"|"]}`,
	} {
		rec := post(t, b, "/rpc/search", tok, body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("prefix-capture %s code = %d, want 403", body, rec.Code)
		}
	}
	if fx, ok := b.exec.(*fakeExec); ok && len(fx.calls) != 0 {
		t.Fatalf("Execute called %d times for arity-incomplete domains", len(fx.calls))
	}
}

func TestReadConvertsToSearchRead(t *testing.T) {
	gate := &fakeGate{allow: true}
	exec := &fakeExec{rows: []any{map[string]any{"id": 7}}}
	b := testBroker(t, gate, exec)
	tok := grantToken(t, b)
	rec := post(t, b, "/rpc/read", tok, `{"model":"res.partner","ids":[7,8]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("read code = %d: %s", rec.Code, rec.Body.String())
	}
	if len(exec.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(exec.calls))
	}
	c := exec.calls[0]
	if c.method != "search_read" {
		t.Fatalf("read used raw method %q, want scoped search_read", c.method)
	}
	dom, _ := c.kwargs["domain"].([]any)
	hasID, hasCompany := false, false
	for _, cond := range dom {
		if arr, ok := cond.([]any); ok && len(arr) == 3 {
			if arr[0] == "id" {
				hasID = true
			}
			if arr[0] == "company_id" {
				hasCompany = true
			}
		}
	}
	if !hasID || !hasCompany {
		t.Fatalf("read domain missing id/company scoping: %v", dom)
	}
	// The gate saw op read (not search) so per-model read rules apply.
	if len(gate.seen) != 1 || gate.seen[0].Operation != policy.OpRead {
		t.Fatalf("gate saw %+v, want one OpRead", gate.seen)
	}
}

func TestOversizedResponseCap(t *testing.T) {
	p := testPolicy()
	p.Budgets.MaxRowsPerCall = 2
	p.Budgets.MaxResponseBytes = 1 << 20
	gate := &fakeGate{allow: true}
	rows := make([]any, 5)
	for i := range rows {
		rows[i] = map[string]any{"id": i}
	}
	b, _ := New(p, &config.Instance{Name: "test"}, snapshot.Snapshot{})
	b.authz = gate
	b.frag = policy.CompanyDomain
	b.exec = &fakeExec{rows: rows}
	tok := grantToken(t, b)
	rec := post(t, b, "/rpc/search", tok, `{"model":"res.partner"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var env struct {
		Success bool             `json:"success"`
		Result  []map[string]any `json:"result"`
		Count   int              `json:"count"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Count != 2 || len(env.Result) != 2 {
		t.Fatalf("count = %d rows = %d, want capped at 2", env.Count, len(env.Result))
	}
}

func TestByteCapTrimsRows(t *testing.T) {
	p := testPolicy()
	p.Budgets.MaxRowsPerCall = 100
	p.Budgets.MaxResponseBytes = 60 // tiny: forces trimming
	gate := &fakeGate{allow: true}
	rows := []any{
		map[string]any{"id": 1, "name": "abcdefghijklmnopqrstuvwxyz"},
		map[string]any{"id": 2, "name": "abcdefghijklmnopqrstuvwxyz"},
	}
	b, _ := New(p, &config.Instance{Name: "test"}, snapshot.Snapshot{})
	b.authz = gate
	b.frag = policy.CompanyDomain
	b.exec = &fakeExec{rows: rows}
	tok := grantToken(t, b)
	rec := post(t, b, "/rpc/search", tok, `{"model":"res.partner"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var env struct {
		Success bool  `json:"success"`
		Result  []any `json:"result"`
		Count   int   `json:"count"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Count >= len(rows) {
		t.Fatalf("byte cap did not trim: count = %d", env.Count)
	}
}

func TestHealthzNoAuthNoSecret(t *testing.T) {
	b := testBroker(t, &fakeGate{}, nil)
	rec := httptest.NewRecorder()
	b.modelMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "token") || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("healthz leaks: %s", rec.Body.String())
	}
}

func TestRedactMirrorsSanitize(t *testing.T) {
	inst := &config.Instance{URL: "https://u:pw@example.com", Password: "s3cret-pw", APIKey: "key-1234"}
	got := brokerSecrets(inst)
	for _, want := range []string{"s3cret-pw", "key-1234"} {
		found := false
		for _, s := range got {
			if s == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("secrets missing %q: %v", want, got)
		}
	}
	b, _ := New(testPolicy(), &config.Instance{Name: "test"}, snapshot.Snapshot{})
	b.secrets = got
	err := b.sanitizeBrokerErr(fmt.Errorf("dial failed with s3cret-pw at host"))
	if strings.Contains(err.Error(), "s3cret-pw") {
		t.Fatalf("secret echoed: %v", err)
	}
	if !strings.Contains(err.Error(), "***") {
		t.Fatalf("no redaction marker: %v", err)
	}
}

func TestMethodGuards(t *testing.T) {
	b := testBroker(t, &fakeGate{allow: true}, &fakeExec{})
	tok := grantToken(t, b)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/rpc/search", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	b.modelMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on POST endpoint = %d", rec.Code)
	}
}
