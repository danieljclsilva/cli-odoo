package broker

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/agent/workspace"
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

func TestDomainDenialCarriesSafeHint(t *testing.T) {
	// Response4 item 8: the denial path exposes the model-specific
	// accepted-shape hint (fields only, never user domain values).
	p := testPolicy()
	p.RequireBoundedQueries = true
	b, err := NewForTest(p, &config.Instance{Name: "test"}, testSnapshot(), nil, &fakeExec{})
	if err != nil {
		t.Fatalf("NewForTest: %v", err)
	}
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	rec := post(t, b, "/rpc/count", tok, `{"model":"res.partner","domain":[["team_id","=",1891]]}`)
	body := rec.Body.String()
	if !strings.Contains(body, "domain-denied") {
		t.Fatalf("denial reason missing: %s", body)
	}
	if !strings.Contains(body, "31-day") && !strings.Contains(body, "flat AND") {
		t.Fatalf("accepted-shape hint missing: %s", body)
	}
	if strings.Contains(body, "1891") {
		t.Fatalf("user domain value echoed in denial: %s", body)
	}
}

func TestErrorMetaSurvivesFittingEnvelope(t *testing.T) {
	// Response5 item 5: the actual broker error writer preserves
	// error_meta when it fits; unknown upstream FAKE-secret text is
	// never echoed (structured fields only).
	p := testPolicy()
	b, err := New(p, &config.Instance{Name: "test"}, testSnapshot())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rpc/evidence", nil)
	meta := map[string]any{
		"phase": "messages", "model": "mail.message", "request_id": "deadbeef",
		"category": "unknown", "retryable": false, "status": 502,
	}
	b.writeErrorMeta(rec, req, http.StatusBadGateway, "linked messages read failed for mail.message (req deadbeef); retryable:false", meta)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	var env struct {
		Success   bool           `json:"success"`
		Error     string         `json:"error"`
		ErrorMeta map[string]any `json:"error_meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("envelope decode: %v", err)
	}
	if env.ErrorMeta["phase"] != "messages" || env.ErrorMeta["request_id"] != "deadbeef" {
		t.Fatalf("error_meta dropped: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "FAKE") {
		t.Fatalf("upstream text leaked: %s", rec.Body.String())
	}
}

func TestErrorMetaFallsBackUnderTinyCap(t *testing.T) {
	// Tiny caps keep strict behavior: meta-less denial, status kept.
	p := testPolicy()
	p.Budgets.MaxResponseBytes = 10
	b, err := New(p, &config.Instance{Name: "test"}, testSnapshot())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rpc/evidence", nil)
	b.writeErrorMeta(rec, req, http.StatusBadGateway, "linked messages read failed", map[string]any{"phase": "messages"})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if body := rec.Body.Bytes(); len(body) > 10 && len(body) != 0 {
		t.Fatalf("cap violated: %d bytes", len(body))
	}
}

// seqExec serves rows for the first n dispatches, then fails: parent
// re-link succeeds while the linked phase faults, exercising the exact
// phase path (dispatch recorder + fault injector, never Odoo semantics).
type seqExec struct {
	rows      []any
	seq       [][]any
	failAfter int
	failErr   error
	calls     int
}

func (f *seqExec) Execute(model, method string, args []any, kwargs map[string]any) (any, error) {
	f.calls++
	if len(f.seq) > 0 {
		idx := f.calls - 1
		if idx >= len(f.seq) {
			idx = len(f.seq) - 1
		}
		out := make([]any, len(f.seq[idx]))
		copy(out, f.seq[idx])
		return out, nil
	}
	if f.failAfter > 0 && f.calls > f.failAfter {
		return nil, f.failErr
	}
	out := make([]any, len(f.rows))
	copy(out, f.rows)
	return out, nil
}

func TestEvidenceHandlerFailureEnvelope(t *testing.T) {
	p := testPolicy()
	p.Budgets.MaxRowsPerCall = 100
	p.AllowLinkedEvidence = true
	p.Models["mail.message"] = policy.ModelRule{Fields: []string{"id", "body"}, LinkedEvidence: true}
	exec := &seqExec{rows: []any{map[string]any{"id": 1}}, failAfter: 1, failErr: errors.New("upstream FAKE-SECRET-boom")}
	b, err := NewForTest(p, &config.Instance{Name: "test"}, testSnapshot(), nil, exec)
	if err != nil {
		t.Fatalf("NewForTest: %v", err)
	}
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	rec := post(t, b, "/rpc/evidence", tok, `{"model":"res.partner","id":1,"kind":"chatter"}`)
	if rec.Code == http.StatusOK {
		t.Fatalf("want error envelope, got 200 (%s)", rec.Body.String())
	}
	var env struct {
		Success   bool           `json:"success"`
		Error     string         `json:"error"`
		ErrorMeta map[string]any `json:"error_meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("envelope decode: %v", err)
	}
	if env.Success || env.Error == "" {
		t.Fatalf("not an error envelope: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "FAKE-SECRET") {
		t.Fatalf("raw upstream fault leaked: %s", rec.Body.String())
	}
	if env.ErrorMeta["phase"] != "messages" {
		t.Fatalf("wrong phase (want messages): %s", rec.Body.String())
	}
	if env.ErrorMeta["category"] != "unknown" || env.ErrorMeta["retryable"] != false {
		t.Fatalf("unknown must stay unknown/retryable:false: %s", rec.Body.String())
	}
	if env.ErrorMeta["request_id"] == nil || env.ErrorMeta["request_id"] == "" {
		t.Fatalf("request_id missing: %s", rec.Body.String())
	}
}

func TestEvidenceDownloadDeniedWithoutDatas(t *testing.T) {
	// Response6 item 4: datas denial through the actual handler when the
	// sealed rule omits datas — no content fetch, no bytes, no hash.
	p := testPolicy()
	p.AllowLinkedEvidence = true
	p.AllowWorkspace = true
	p.Models["ir.attachment"] = policy.ModelRule{Fields: []string{"id", "name"}, LinkedEvidence: true}
	p.SharedRecords = policy.SharedAllowClassified
	dexec := &seqExec{seq: [][]any{
		{map[string]any{"id": 1}},
		{map[string]any{"id": 7, "name": "ticket.pdf", "file_size": 4, "type": "binary"}},
	}}
	b, err := NewForTest(p, &config.Instance{Name: "test"}, testSnapshot(), nil, dexec)
	if err != nil {
		t.Fatalf("NewForTest: %v", err)
	}
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	rec := post(t, b, "/rpc/evidence", tok, `{"model":"res.partner","id":1,"kind":"download","attachment_id":7,"path":"ticket-7.pdf"}`)
	if rec.Code == http.StatusOK {
		t.Fatalf("want datas denial, got 200 (%s)", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "attachment content not enabled") {
		t.Fatalf("wrong denial: %s", rec.Body.String())
	}
	if dexec.calls != 2 {
		t.Fatalf("want parent+meta dispatches only, got %d (datas must never fetch)", dexec.calls)
	}
}

func TestEvidenceDownloadSuccessMetadata(t *testing.T) {
	// Response6 item 4: through the actual download handler with datas
	// enabled — descriptor/bytes/hash exact, text metadata sanitized.
	p := testPolicy()
	p.AllowLinkedEvidence = true
	p.AllowWorkspace = true
	p.Models["ir.attachment"] = policy.ModelRule{Fields: []string{"id", "name", "mimetype", "file_size", "type", "datas"}, LinkedEvidence: true}
	p.SharedRecords = policy.SharedAllowClassified
	dexec := &seqExec{seq: [][]any{
		{map[string]any{"id": 1}},
		{map[string]any{"id": 7, "name": "ticket.pdf", "mimetype": "text/plain;password=FAKE-SECRET", "file_size": 5, "type": "binary"}},
		{map[string]any{"id": 7, "datas": "aGVsbG8="}},
	}}
	b, err := NewForTest(p, &config.Instance{Name: "test"}, testSnapshot(), nil, dexec)
	if err != nil {
		t.Fatalf("NewForTest: %v", err)
	}
	dir := t.TempDir()
	ws, err := workspace.Open(dir)
	if err != nil {
		t.Fatalf("workspace.Open: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })
	b.ws = ws
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	rec := post(t, b, "/rpc/evidence", tok, `{"model":"res.partner","id":1,"kind":"download","attachment_id":7,"path":"ticket-7.txt"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var env struct {
		Success bool `json:"success"`
		Result  struct {
			Path     string `json:"path"`
			Bytes    int    `json:"bytes"`
			Sha256   string `json:"sha256"`
			Name     string `json:"name"`
			Mimetype string `json:"mimetype"`
		} `json:"result"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("envelope decode: %v", err)
	}
	if !env.Success || env.Count != 1 {
		t.Fatalf("not a success count=1 envelope: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "FAKE-SECRET") {
		t.Fatalf("stored mimetype secret crossed raw: %s", rec.Body.String())
	}
	if !strings.Contains(env.Result.Mimetype, RedactionMarker) {
		t.Fatalf("mimetype marker missing: %s", rec.Body.String())
	}
	if env.Result.Path != "ticket-7.txt" || env.Result.Bytes != 5 || env.Result.Name != "ticket.pdf" {
		t.Fatalf("descriptor semantics changed: %s", rec.Body.String())
	}
	if env.Result.Sha256 != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("sha256 wrong (want sha256(hello)): %s", rec.Body.String())
	}
	data, err := ws.Read("ticket-7.txt", 1<<20)
	if err != nil {
		t.Fatalf("workspace.Read: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("workspace bytes changed: %q", data)
	}
}
