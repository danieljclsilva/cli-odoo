package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
	"github.com/danieljclsilva/cli-odoo/internal/agent/workspace"
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
	snap := testSnapshot()
	digest, err := snapshot.CanonicalDigest(snap)
	if err != nil {
		panic("test digest: " + err.Error())
	}
	return &policy.Policy{
		Version:    1,
		Instance:   "test",
		Operations: map[policy.Operation]bool{policy.OpSearch: true, policy.OpRead: true, policy.OpCount: true, policy.OpAggregate: true, policy.OpMeta: true},
		Models: map[string]policy.ModelRule{
			"res.partner": {Fields: []string{"name"}, MaxLimit: 50, CompanyField: "company_id"},
		},
		Scope:          policy.CompanyScope{Enabled: []int{1, 2}, Default: 1},
		SharedRecords:  policy.SharedDeny,
		Budgets:        policy.Budgets{MaxLimit: 100, MaxOffset: 1000, MaxRowsPerCall: 10, MaxResponseBytes: 1 << 20, MaxCallsPerSession: 100, MaxRowsPerSession: 1000},
		SnapshotSHA256: digest,
	}
}

// testSnapshot is the human-built metadata backing testPolicy's digest
// binding: res.partner.company_id resolves to a res.company many2one so
// CompanyFieldValid passes, and mixed field provenance exercises the
// catalog's per-field provenance + unknown-provenance entries.
func testSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		Instance:           "test",
		AvailableCompanies: []snapshot.Company{{ID: 1, Name: "A"}, {ID: 2, Name: "B"}},
		EnabledCompanies:   []int{1, 2},
		DefaultCompany:     1,
		Models: map[string]snapshot.ModelMeta{
			"res.partner": {
				Name: "res.partner", Label: "Partner", Provenance: snapshot.ProvServer,
				CompanyField: "company_id",
				Fields: map[string]snapshot.SFieldMeta{
					"name":       {Name: "name", Type: "char", Label: "Name"},
					"company_id": {Name: "company_id", Type: "many2one", Relation: "res.company", Label: "Company", Provenance: snapshot.ProvServer},
				},
			},
		},
		MethodManifest: []string{"search_read", "read"},
	}
}

func testBroker(t *testing.T, gate *fakeGate, exec *fakeExec) *Broker {
	t.Helper()
	b, err := New(testPolicy(), &config.Instance{Name: "test"}, testSnapshot())
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
	b, err := New(testPolicy(), &config.Instance{Name: "test"}, testSnapshot())
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
	// Sub-minute TTLs clamp to 1 minute (no sub-second sessions): a 1ms
	// grant stays live past 5ms.
	short, err := b.Grant(time.Millisecond)
	if err != nil {
		t.Fatalf("Grant short: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := b.Check(short); err != nil {
		t.Fatalf("clamped short TTL expired early: %v", err)
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
	b, _ := New(testPolicy(), &config.Instance{Name: "test"}, testSnapshot())
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
	b, _ := New(p, &config.Instance{Name: "test"}, testSnapshot())
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
		{"/rpc/search", `{"model":"res.partner","fields":["name"]}`},
		{"/rpc/read", `{"model":"res.partner","ids":[1],"fields":["name"]}`},
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
	rec = post(t, b, "/rpc/search", tok, `{"model":"res.partner","fields":["name"],"domain":[["name","=","acme"]]}`)
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
	b, err := New(testPolicy(), &config.Instance{Name: "test"}, testSnapshot())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b.exec = &fakeExec{rows: []any{}}
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	for _, body := range []string{
		`{"model":"res.partner","fields":["name"],"domain":["|",["name","=","x"]]}`,
		`{"model":"res.partner","fields":["name"],"domain":["!"]}`,
		`{"model":"res.partner","fields":["name"],"domain":[["name","=","x"],"|"]}`,
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
	rec := post(t, b, "/rpc/read", tok, `{"model":"res.partner","ids":[7,8],"fields":["name"]}`)
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

func TestOversizedResultDeniesInsteadOfFalseComplete(t *testing.T) {
	p := testPolicy()
	p.Budgets.MaxRowsPerCall = 2
	p.Budgets.MaxResponseBytes = 1 << 20
	gate := &fakeGate{allow: true}
	rows := make([]any, 5)
	for i := range rows {
		rows[i] = map[string]any{"id": i}
	}
	b, _ := New(p, &config.Instance{Name: "test"}, testSnapshot())
	b.authz = gate
	b.frag = policy.CompanyDomain
	b.exec = &fakeExec{rows: rows}
	tok := grantToken(t, b)
	// Five rows against a MaxRowsPerCall=2 cap: no silent truncation to a
	// false-complete count=2 — the request denies (fail closed, still billed).
	rec := post(t, b, "/rpc/search", tok, `{"model":"res.partner"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("code = %d, want 429 deny (no silent truncation)", rec.Code)
	}
	if len(b.exec.(*fakeExec).calls) != 1 {
		t.Fatalf("calls = %d, want 1 (denial is post-RPC, attempt billed)", len(b.exec.(*fakeExec).calls))
	}
	b.mu.Lock()
	rowsBilled := b.sessions[tok].rows
	b.mu.Unlock()
	if rowsBilled <= 0 {
		t.Fatalf("rows = %d, want billed reservation kept on deny", rowsBilled)
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
	b, _ := New(p, &config.Instance{Name: "test"}, testSnapshot())
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
	b, _ := New(testPolicy(), &config.Instance{Name: "test"}, testSnapshot())
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

func TestNewRejectsInvalidPolicy(t *testing.T) {
	bad := testPolicy()
	bad.Budgets.MaxResponseBytes = 0
	if _, err := New(bad, &config.Instance{Name: "test"}, testSnapshot()); err == nil {
		t.Fatal("New accepted zero MaxResponseBytes")
	}
	contra := testPolicy()
	contra.Models["res.partner"] = policy.ModelRule{Fields: []string{"name"}, CompanyIndependent: true, CompanyField: "company_id"}
	if _, err := New(contra, &config.Instance{Name: "test"}, testSnapshot()); err == nil {
		t.Fatal("New accepted contradictory rule")
	}
}

func TestSessionTTLClampedAndCapped(t *testing.T) {
	b, err := New(testPolicy(), &config.Instance{Name: "test"}, testSnapshot())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 70; i++ {
		if _, err := b.Grant(time.Hour); err != nil {
			t.Fatalf("Grant %d: %v", i, err)
		}
	}
	if n, _, _, _ := b.sessionStats(); n > 64 {
		t.Fatalf("sessions = %d, want cap 64", n)
	}
}

func TestReserveRowsDeniedWhenExhausted(t *testing.T) {
	p := testPolicy()
	p.Budgets.MaxRowsPerSession = 2
	b, _ := New(p, &config.Instance{Name: "test"}, testSnapshot())
	tok, _ := b.Grant(time.Hour)
	if err := b.Check(tok); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := b.ReserveRows(tok, 3); !errors.Is(err, ErrSessionBudget) {
		t.Fatalf("ReserveRows over-remaining = %v, want budget", err)
	}
	if err := b.ReserveRows(tok, 0); !errors.Is(err, ErrSessionBudget) {
		t.Fatalf("ReserveRows zero = %v, want budget", err)
	}
}

func TestRowReservationBilledOnRPCFailure(t *testing.T) {
	gate := &fakeGate{allow: true}
	exec := &fakeExec{err: errors.New("boom")}
	b := testBroker(t, gate, exec)
	tok := grantToken(t, b)
	rec := post(t, b, "/rpc/search", tok, `{"model":"res.partner","fields":["name"]}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", rec.Code)
	}
	b.mu.Lock()
	calls, rows := b.sessions[tok].calls, b.sessions[tok].rows
	b.mu.Unlock()
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (attempt billed)", calls)
	}
	if rows <= 0 {
		t.Fatalf("rows = %d, want reserved rows kept on failure", rows)
	}
}

func TestRevokedBeforeWriteDeniedButBilled(t *testing.T) {
	gate := &fakeGate{allow: true}
	exec := &fakeExec{rows: []any{map[string]any{"id": 1}}}
	b := testBroker(t, gate, exec)
	tok := grantToken(t, b)
	revoking := &revokeAfterRPC{inner: exec, b: b, tok: tok}
	b.exec = revoking
	rec := post(t, b, "/rpc/search", tok, `{"model":"res.partner","fields":["name"]}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 revoked-before-write", rec.Code)
	}
	b.mu.Lock()
	_, live := b.sessions[tok]
	b.mu.Unlock()
	if live {
		t.Fatal("revoked session still live")
	}
}

// revokeAfterRPC revokes the token inside Execute: the RPC ran, so the
// admitted call stays billed while the response denies.
type revokeAfterRPC struct {
	inner *fakeExec
	b     *Broker
	tok   string
}

func (r *revokeAfterRPC) Execute(model, method string, args []any, kwargs map[string]any) (any, error) {
	out, err := r.inner.Execute(model, method, args, kwargs)
	r.b.Revoke(r.tok)
	return out, err
}

func TestStrictDecodeRejectsTrailingData(t *testing.T) {
	b := testBroker(t, &fakeGate{allow: true}, &fakeExec{})
	tok := grantToken(t, b)
	for _, body := range []string{
		`{"model":"res.partner"}{}`,
		`{"model":"res.partner"} null`,
		`{"model":"res.partner"} garbage`,
		`null`,
		``,
	} {
		rec := post(t, b, "/rpc/search", tok, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q code = %d, want 400", body, rec.Code)
		}
	}
	rec := post(t, b, "/rpc/search", tok, "{\"model\":\"res.partner\"} \n\t ")
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("trailing whitespace denied: %d", rec.Code)
	}
}

func TestCheckScopeMatchRefusesMismatch(t *testing.T) {
	p := testPolicy()
	snap := testSnapshot()
	snap.Instance = "other"
	digest, _ := snapshot.CanonicalDigest(snap)
	p.SnapshotSHA256 = digest
	b, _ := New(p, &config.Instance{Name: "test"}, snap)
	if err := b.checkScopeMatch(); err == nil {
		t.Fatal("instance mismatch accepted")
	}
	snap2 := testSnapshot()
	snap2.DefaultCompany = 9
	digest2, _ := snapshot.CanonicalDigest(snap2)
	p.SnapshotSHA256 = digest2
	b2, _ := New(p, &config.Instance{Name: "test"}, snap2)
	if err := b2.checkScopeMatch(); err == nil {
		t.Fatal("default mismatch accepted")
	}
	b3, _ := New(testPolicy(), &config.Instance{Name: "wrong"}, testSnapshot())
	if err := b3.checkScopeMatch(); err == nil {
		t.Fatal("config instance mismatch accepted")
	}
}
func TestDiscoveryCatalogMarksExecutable(t *testing.T) {
	p := testPolicy()
	snap := testSnapshot()
	snap.Models["discover.only"] = snapshot.ModelMeta{
		Name: "discover.only", Label: "Only", Provenance: snapshot.ProvServer,
		Fields: map[string]snapshot.SFieldMeta{"name": {Name: "name", Type: "char", Label: "Name"}},
	}
	digest, err := snapshot.CanonicalDigest(snap)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	p.SnapshotSHA256 = digest
	gate := &fakeGate{allow: true}
	b, _ := New(p, &config.Instance{Name: "test"}, snap)
	b.authz = gate
	b.exec = &fakeExec{rows: []any{map[string]any{"id": 1}}}
	tok := grantToken(t, b)
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		b.modelMux().ServeHTTP(rec, req)
		return rec
	}
	if rec := get("/rpc/companies"); rec.Code != http.StatusOK {
		t.Fatalf("companies = %d: %s", rec.Code, rec.Body.String())
	} else {
		var env struct {
			Success bool `json:"success"`
			Result  struct {
				Available []map[string]any `json:"available"`
				Enabled   []map[string]any `json:"enabled"`
				Default   int              `json:"default"`
			} `json:"result"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
			t.Fatalf("decode companies: %v", err)
		}
		if len(env.Result.Available) != 2 || len(env.Result.Enabled) != 2 || env.Result.Default != 1 {
			t.Fatalf("companies shape: %+v", env.Result)
		}
	}
	rec := get("/rpc/catalog")
	if rec.Code != http.StatusOK {
		t.Fatalf("catalog = %d: %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Success bool `json:"success"`
		Result  struct {
			Models map[string]struct {
				Executable        bool           `json:"executable"`
				Fields            map[string]any `json:"fields"`
				UnknownProvenance []string       `json:"unknown_provenance"`
				Provenance        string         `json:"provenance"`
			} `json:"models"`
			MethodManifest []string `json:"method_manifest"`
		} `json:"result"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if !env.Result.Models["res.partner"].Executable {
		t.Fatal("res.partner should be executable")
	}
	if env.Result.Models["discover.only"].Executable {
		t.Fatal("discover.only must list executable:false")
	}
	// Per-model MethodManifest is present and informational (never
	// executable): the manifest lists method names only.
	if len(env.Result.MethodManifest) == 0 {
		t.Fatal("catalog method_manifest missing")
	}
	for _, m := range env.Result.MethodManifest {
		if _, isModel := env.Result.Models[m]; isModel && m != "read" {
			t.Fatalf("manifest method %q must not resolve as an executable model entry point", m)
		}
	}
	// Per-field provenance: server-attested company_id carries its
	// provenance; unattested name lands in unknown_provenance.
	partner := env.Result.Models["res.partner"]
	if partner.UnknownProvenance == nil {
		t.Fatal("res.partner must carry unknown_provenance for unattested fields")
	}
	// Discoverable-only model read denies (unknown-model at the gate).
	b.authz = &fakeGate{allow: false, reason: "unknown-model"}
	denied := post(t, b, "/rpc/read", tok, `{"model":"discover.only","ids":[1],"fields":["name"]}`)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("discover-only read = %d, want 403", denied.Code)
	}
	if len(b.exec.(*fakeExec).calls) != 0 {
		t.Fatal("Execute ran for discoverable-only model")
	}
	// Unknown-model catalog queries still deny.
	unknown := get("/rpc/catalog?model=no.such.model")
	if unknown.Code != http.StatusForbidden {
		t.Fatalf("unknown-model catalog = %d, want 403", unknown.Code)
	}
}

func TestEnvelopeCapDeniesInsteadOfSending(t *testing.T) {
	p := testPolicy()
	p.Budgets.MaxRowsPerCall = 100
	p.Budgets.MaxResponseBytes = 40 // smaller than any success envelope
	gate := &fakeGate{allow: true}
	b, _ := New(p, &config.Instance{Name: "test"}, testSnapshot())
	b.authz = gate
	b.exec = &fakeExec{rows: []any{map[string]any{"id": 1}}}
	tok := grantToken(t, b)
	req := httptest.NewRequest(http.MethodGet, "/rpc/meta", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	b.modelMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("over-cap meta = %d, want 502 deny", rec.Code)
	}
}

func TestWorkspaceCallerCannotWidenCap(t *testing.T) {
	p := testPolicy()
	p.AllowWorkspace = true
	p.Budgets.MaxRowsPerCall = 2
	b, _ := New(p, &config.Instance{Name: "test"}, testSnapshot())
	ws, err := workspace.Open(t.TempDir())
	if err != nil {
		t.Fatalf("workspace.Open: %v", err)
	}
	for i := range 5 {
		if err := ws.Write(fmt.Sprintf("f%d.txt", i), []byte("x")); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	b.ws = ws
	tok := grantToken(t, b)
	rec := post(t, b, "/rpc/workspace/list", tok, `{"path":".","max_entries":100}`)
	// Five entries with a policy cap of 2: the caller asks for 100, but
	// effective = min(100, 2) = 2, so the listing denies (5 > 2). Without
	// the clamp the caller would have widened to 100 and succeeded.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("widened list = %d, want 400 deny", rec.Code)
	}
}

func TestReserveForLimitDeniesBeforeDispatch(t *testing.T) {
	// Reservation-deny-before-dispatch: when the requested want exceeds the
	// remaining row budget, the reservation denies and the handler returns
	// before Execute (no dispatch). The fakeExec dispatch recorder proves
	// no RPC ran; settle keeps only delivered rows.
	p := testPolicy()
	p.Budgets.MaxRowsPerSession = 3
	p.Budgets.MaxRowsPerCall = 100
	gate := &fakeGate{allow: true}
	exec := &fakeExec{rows: []any{map[string]any{"id": 1}}}
	b, err := New(p, &config.Instance{Name: "test"}, testSnapshot())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b.authz = gate
	b.exec = exec
	tok := grantToken(t, b)
	// Consume 2 rows directly: the admitted search reserves its want.
	if err := b.Check(tok); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := b.ReserveRows(tok, 2); err != nil {
		t.Fatalf("ReserveRows: %v", err)
	}
	before := len(exec.calls)
	// Remaining = 1, want = 5: reservation must deny; handler path denies
	// 429 without dispatch.
	if _, err := b.reserveForLimit(tok, 5); !errors.Is(err, ErrSessionBudget) {
		t.Fatalf("reserveForLimit over-remaining = %v, want budget deny", err)
	}
	b.release(tok)
	rec := post(t, b, "/rpc/search", tok, `{"model":"res.partner","fields":["name"],"limit":5}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-remaining search = %d, want 429 deny-before-dispatch", rec.Code)
	}
	if len(exec.calls) != before {
		t.Fatalf("Execute dispatched despite budget deny: %d calls", len(exec.calls))
	}
}

func TestAdminSocketPathRefusal(t *testing.T) {
	// Admin-path refusal: stale-socket cleanup and teardown remove ONLY a
	// proven-owned unix socket. A regular file (or anything non-socket) at
	// the socket path denies instead of unlinking.
	dir := t.TempDir()
	sockPath := dir + "/admin.sock"
	if err := os.WriteFile(sockPath, []byte("planted"), 0600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := removeOnlyOwnedSocket(sockPath); err == nil {
		t.Fatal("removeOnlyOwnedSocket unlinked a regular file")
	}
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("planted file removed: %v", err)
	}
	if err := removeOnlyOwnedSocket(dir + "/missing.sock"); err != nil {
		t.Fatalf("missing socket should be a no-op: %v", err)
	}
	// An explicit --socket escaping the admin dir denies at resolve time.
	if _, err := resolveAdminSocketPath(dir+"/../escape.sock", dir); err == nil {
		t.Fatal("escaping socket path accepted")
	}
}

func TestServingDigestMismatchDenies(t *testing.T) {
	// Digest-mismatch deny with the real CanonicalDigest: the sealed
	// binding covers testSnapshot(); any mutation (here: an added model)
	// must fail verification before credentials resolve.
	p := testPolicy()
	mutated := testSnapshot()
	mutated.Models["x.extra"] = snapshot.ModelMeta{
		Name: "x.extra", Label: "Extra", Provenance: snapshot.ProvServer,
		Fields: map[string]snapshot.SFieldMeta{"name": {Name: "name", Type: "char", Label: "Name"}},
	}
	if err := verifyServingDigest(p, mutated); err == nil {
		t.Fatal("mutated snapshot passed digest verification")
	}
	if err := verifyServingDigest(p, testSnapshot()); err != nil {
		t.Fatalf("bound snapshot denied: %v", err)
	}
}

func TestWorkspaceMkdirBillsOneRow(t *testing.T) {
	// Typed mkdir: bounded MkdirAll through the capped envelope, billing
	// exactly 1 row via the atomic reservation (settle to 1 on success).
	p := testPolicy()
	p.AllowWorkspace = true
	b, _ := New(p, &config.Instance{Name: "test"}, testSnapshot())
	b.authz = &fakeGate{allow: true}
	base := t.TempDir()
	wsDir := base + "/ws"
	if err := os.Mkdir(wsDir, 0700); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	ws, err := workspace.Open(wsDir)
	if err != nil {
		t.Fatalf("workspace.Open: %v", err)
	}
	b.ws = ws
	tok := grantToken(t, b)
	rec := post(t, b, "/rpc/workspace/mkdir", tok, `{"path":"reports/2026/10"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("mkdir = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(wsDir + "/reports/2026/10"); err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	b.mu.Lock()
	rows := b.sessions[tok].rows
	b.mu.Unlock()
	if rows != 1 {
		t.Fatalf("rows = %d, want 1 (mkdir bills one row)", rows)
	}
}
