package broker

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	// Fetched-row scan reservations scale with limit (default 50):
	// allow the reservation so the test reaches the fault path.
	p.Budgets.MaxRowsPerCall = 1000
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

func TestEvidenceChatterPagesAreDisjointAndOrdered(t *testing.T) {
	// Continuation uses requested-based source accounting: page 2 starts
	// exactly where page 1's requested source range ended, so windows
	// are disjoint and concatenation is exact and duplicate-free. The
	// fake serves canned rows per offset (routing stub: proves offset
	// arithmetic and envelope wiring, never Odoo filtering semantics).
	// Total 5 with limit 3: page 1 returns 3 rows + resume at 3 with
	// has_more true and complete false; page 2 returns 2 rows with
	// has_more false, complete true, next -1.
	pexec := &pageExec{total: 5, pages: map[int][]any{
		0: {map[string]any{"id": 1}, map[string]any{"id": 2}, map[string]any{"id": 3}},
		3: {map[string]any{"id": 4}, map[string]any{"id": 5}},
	}}
	p := testPolicy()
	p.Budgets.MaxRowsPerCall = 100
	p.AllowLinkedEvidence = true
	p.Models["mail.message"] = policy.ModelRule{Fields: []string{"id", "body"}, LinkedEvidence: true}
	b, err := NewForTest(p, &config.Instance{Name: "test"}, testSnapshot(), nil, pexec)
	if err != nil {
		t.Fatalf("NewForTest: %v", err)
	}
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	ordered := []int{}
	off := 0
	for i := 0; i < 3; i++ {
		rec := post(t, b, "/rpc/evidence", tok, `{"model":"res.partner","id":1,"kind":"chatter","limit":3,"offset":`+strconv.Itoa(off)+`}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("page at %d: want 200, got %d (%s)", off, rec.Code, rec.Body.String())
		}
		var env struct {
			Success bool           `json:"success"`
			Count   int            `json:"count"`
			Result  map[string]any `json:"result"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("envelope decode: %v", err)
		}
		for _, r := range env.Result["rows"].([]any) {
			ordered = append(ordered, int(r.(map[string]any)["id"].(float64)))
		}
		hm := env.Result["has_more"].(bool)
		no := int(env.Result["next_offset"].(float64))
		if i == 0 {
			if !hm || no != 3 {
				t.Fatalf("page 1 must continue at source offset 3: %s", rec.Body.String())
			}
			if env.Result["complete"] != false {
				t.Fatalf("page 1 (3 of 5) must not claim complete: %s", rec.Body.String())
			}
			off = no
			continue
		}
		// Page 2 holds 2 of 5: has_more stays true with a forward
		// resume cursor — the broker cannot see the caller's first
		// page. The WALK stops via the caller-side cumulative rule
		// below (3+2 >= visible_total), so offset 9 is never
		// requested.
		if !hm || no != 7 {
			t.Fatalf("page 2 must resume forward at source offset 7: %s", rec.Body.String())
		}
		if env.Result["complete"] != false {
			t.Fatalf("page 2 (2 of 5 this page) must not claim complete: %s", rec.Body.String())
		}
		if env.Result["visible_total"].(float64) != 5 {
			t.Fatalf("visible_total must be 5: %s", rec.Body.String())
		}
		// Caller stops here: cumulative 3+2 >= visible_total, so
		// offset 7 is never requested (the fake would serve it empty
		// — equally inconclusive, never claimed exhausted).
		break
	}
	// Caller-side termination: cumulative distinct ids >= visible_total
	// ends the walk without requesting offset 7.
	want := []int{1, 2, 3, 4, 5}
	if len(ordered) != len(want) {
		t.Fatalf("ordered = %v, want %v (exact, no duplicates)", ordered, want)
	}
	for i := range want {
		if ordered[i] != want[i] {
			t.Fatalf("ordered = %v, want %v (exact, no duplicates)", ordered, want)
		}
	}
}

func TestEvidenceChatterMixedSparseDenseKeepsAllIds(t *testing.T) {
	// Data-loss regression: every scan page must request only the
	// remaining capacity. Limit 3 with a sparse first window ([2]) and
	// a dense second window ([4,5,6]): page 1 collects [2,4,5] and
	// resumes at source offset 5 — ID 6 stays unconsumed and reachable.
	// Requesting a full limit again would consume [4,5,6], keep [4,5],
	// drop 6, and resume at 6 with 6 lost.
	pexec := &pageExec{total: 4, pages: map[int][]any{
		0: {map[string]any{"id": 2}},
		3: {map[string]any{"id": 4}, map[string]any{"id": 5}, map[string]any{"id": 6}},
		5: {map[string]any{"id": 6}},
	}}
	p := testPolicy()
	p.Budgets.MaxRowsPerCall = 100
	p.AllowLinkedEvidence = true
	p.Models["mail.message"] = policy.ModelRule{Fields: []string{"id", "body"}, LinkedEvidence: true}
	b, err := NewForTest(p, &config.Instance{Name: "test"}, testSnapshot(), nil, pexec)
	if err != nil {
		t.Fatalf("NewForTest: %v", err)
	}
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	ordered := []int{}
	off := 0
	for i := 0; i < 3; i++ {
		rec := post(t, b, "/rpc/evidence", tok, `{"model":"res.partner","id":1,"kind":"chatter","limit":3,"offset":`+strconv.Itoa(off)+`}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("page at %d: want 200, got %d (%s)", off, rec.Code, rec.Body.String())
		}
		var env struct {
			Success bool           `json:"success"`
			Count   int            `json:"count"`
			Result  map[string]any `json:"result"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("envelope decode: %v", err)
		}
		for _, r := range env.Result["rows"].([]any) {
			ordered = append(ordered, int(r.(map[string]any)["id"].(float64)))
		}
		hm := env.Result["has_more"].(bool)
		no := int(env.Result["next_offset"].(float64))
		if i == 0 {
			// [2,4,5] with resume at 5: ID 6 unconsumed.
			if !hm || no != 5 {
				t.Fatalf("mixed page 1 must resume at source offset 5: %s", rec.Body.String())
			}
			off = no
			continue
		}
		// Page 2 at offset 5 collects [6]; cumulative 3+1 >= 4 ends
		// the walk (caller-side rule) without further requests.
		break
	}
	want := []int{2, 4, 5, 6}
	if len(ordered) != len(want) {
		t.Fatalf("ordered = %v, want %v (ID 6 must survive)", ordered, want)
	}
	for i := range want {
		if ordered[i] != want[i] {
			t.Fatalf("ordered = %v, want %v (ID 6 must survive)", ordered, want)
		}
	}
}

func TestEvidenceOffsetsRestorePerKind(t *testing.T) {
	// The shared values/attachments fetch must honor its own dimension:
	// tracking values page at tracking_offset (not the message offset),
	// attachments at offset. The fake records offsets per model and
	// serves one row; assertions are on dispatch kwargs (wiring), with
	// totals that keep every dimension incomplete so both pages stay
	// addressable.
	oexec := &offsetExec{}
	p := testPolicy()
	p.Budgets.MaxRowsPerCall = 100
	p.AllowLinkedEvidence = true
	p.Models["mail.message"] = policy.ModelRule{Fields: []string{"id"}, LinkedEvidence: true}
	p.Models["mail.tracking.value"] = policy.ModelRule{Fields: []string{"id"}, LinkedEvidence: true}
	p.Models["ir.attachment"] = policy.ModelRule{Fields: []string{"id", "name"}, LinkedEvidence: true}
	b, err := NewForTest(p, &config.Instance{Name: "test"}, testSnapshot(), nil, oexec)
	if err != nil {
		t.Fatalf("NewForTest: %v", err)
	}
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	// Tracking: message offset 7, tracking offset 4. Values fetch must
	// use offset 4; message scan starts at 7.
	rec := post(t, b, "/rpc/evidence", tok, `{"model":"res.partner","id":1,"kind":"tracking","limit":2,"offset":7,"tracking_offset":4}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("tracking: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if oexec.valuesOffset != 4 {
		t.Fatalf("tracking values fetched at offset %d, want tracking_offset 4", oexec.valuesOffset)
	}
	if oexec.messageFirstOffset != 7 {
		t.Fatalf("message scan started at offset %d, want message offset 7", oexec.messageFirstOffset)
	}
	// Attachments: offset 6 must reach the fetch.
	oexec2 := &offsetExec{}
	b2, err := NewForTest(p, &config.Instance{Name: "test"}, testSnapshot(), nil, oexec2)
	if err != nil {
		t.Fatalf("NewForTest: %v", err)
	}
	tok2, err := b2.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	rec = post(t, b2, "/rpc/evidence", tok2, `{"model":"res.partner","id":1,"kind":"attachments","limit":2,"offset":6}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("attachments: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if oexec2.attachOffset != 6 {
		t.Fatalf("attachments fetched at offset %d, want 6", oexec2.attachOffset)
	}
}

func TestEvidenceScanBillsFetchedRows(t *testing.T) {
	// Billing counts fetched rows, not dispatches: parent(1) +
	// count(1) + scan fetched(2+1 across two pages) + projection(3) = 8
	// (dispatch billing would give 7), while the envelope count stays 3
	// returned.
	pexec := &pageExec{total: 3, pages: map[int][]any{
		0: {map[string]any{"id": 1}, map[string]any{"id": 2}},
		3: {map[string]any{"id": 3}},
	}}
	p := testPolicy()
	p.Budgets.MaxRowsPerCall = 100
	p.AllowLinkedEvidence = true
	p.Models["mail.message"] = policy.ModelRule{Fields: []string{"id", "body"}, LinkedEvidence: true}
	b, err := NewForTest(p, &config.Instance{Name: "test"}, testSnapshot(), nil, pexec)
	if err != nil {
		t.Fatalf("NewForTest: %v", err)
	}
	tok, err := b.Grant(time.Hour)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	rec := post(t, b, "/rpc/evidence", tok, `{"model":"res.partner","id":1,"kind":"chatter","limit":3,"offset":0}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	b.mu.Lock()
	billed := b.sessions[tok].rows
	b.mu.Unlock()
	if billed != 8 {
		t.Fatalf("billed = %d, want 8 (parent+count+scan fetched+projection)", billed)
	}
}

// pageExec serves canned windows per source offset plus a canned visible
// total: a routing/wiring stub asserting offset arithmetic, envelope
// shape, and billing. It proves nothing about Odoo filtering.
type pageExec struct {
	total int
	pages map[int][]any
}

func (f *pageExec) Execute(model, method string, args []any, kwargs map[string]any) (any, error) {
	if model == "res.partner" {
		return []any{map[string]any{"id": 1}}, nil
	}
	if method == "search_count" {
		return f.total, nil
	}
	dom, _ := kwargs["domain"].([]any)
	for _, leaf := range dom {
		clause, _ := leaf.([]any)
		if len(clause) == 3 && clause[0] == "id" && clause[1] == "in" {
			out := []any{}
			for _, v := range clause[2].([]any) {
				out = append(out, map[string]any{"id": v})
			}
			return out, nil
		}
	}
	off, _ := kwargs["offset"].(int)
	lim, _ := kwargs["limit"].(int)
	if rows, ok := f.pages[off]; ok {
		// Honor the requested limit like a real window: at most lim rows.
		n := len(rows)
		if lim >= 0 && n > lim {
			n = lim
		}
		out := make([]any, n)
		copy(out, rows[:n])
		return out, nil
	}
	return []any{}, nil
}

// offsetExec records which offset each evidence fetch used: wiring
// assertions for per-kind offsets, one canned row per fetch.
type offsetExec struct {
	valuesOffset       int
	valuesSeen         bool
	messageFirstOffset int
	messageSeen        bool
	attachOffset       int
	attachSeen         bool
}

func (f *offsetExec) Execute(model, method string, args []any, kwargs map[string]any) (any, error) {
	if model == "res.partner" {
		return []any{map[string]any{"id": 1}}, nil
	}
	if method == "search_count" {
		return 99, nil
	}
	off, _ := kwargs["offset"].(int)
	switch model {
	case "mail.tracking.value":
		f.valuesOffset, f.valuesSeen = off, true
		return []any{map[string]any{"id": 901}}, nil
	case "mail.message":
		if !f.messageSeen {
			f.messageFirstOffset, f.messageSeen = off, true
		}
		return []any{map[string]any{"id": 41}}, nil
	case "ir.attachment":
		f.attachOffset, f.attachSeen = off, true
		return []any{map[string]any{"id": 71, "name": "a"}}, nil
	}
	return []any{}, nil
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
