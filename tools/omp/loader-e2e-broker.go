//go:build ignore

// Disposable harness: real in-process broker (REAL policy gate via
// NewForTest with nil authorizer, REAL transport via httptest) serving the
// model mux over loopback, plus a dispatch recorder for outgoing RPC only
// (counts Execute calls, returns canned rows — never fake Odoo rows as
// semantics). Prints BROKER_URL and BROKER_TOKEN on stdout for the bun
// loader driver. No prod, no keychain, no user config, no network beyond
// loopback.
//
// Usage: go run ./tools/omp/loader-e2e-broker.go <workspace-dir>
// Cleanup: the process exits after the driver finishes (parent kills it).
package main

import (
	"fmt"
	"net/http/httptest"
	"os"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/broker"
	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
	"github.com/danieljclsilva/cli-odoo/internal/agent/workspace"
	"github.com/danieljclsilva/cli-odoo/internal/config"
)

// dispatchRecorder counts outgoing RPC dispatches only. It returns canned
// rows for routing proof and asserts no Odoo semantics.
type dispatchRecorder struct {
	calls int
}

func (d *dispatchRecorder) Execute(model, method string, _ []any, _ map[string]any) (any, error) {
	d.calls++
	return []any{map[string]any{"id": 1, "name": "a"}}, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: loader-e2e-broker <workspace-dir>")
		os.Exit(2)
	}
	snap := snapshot.Snapshot{
		Instance:           "test",
		CapturedAt:         time.Now(),
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
	digest, err := snapshot.CanonicalDigest(snap)
	if err != nil {
		panic(err)
	}
	// REAL policy gate: nil authorizer means NewForTest keeps policyGate,
	// the genuine deny-by-default policy. Workspace enabled for the
	// snapshot+workspace evidence calls.
	p := &policy.Policy{
		Version:    1,
		Instance:   "test",
		Operations: map[policy.Operation]bool{policy.OpSearch: true, policy.OpRead: true, policy.OpCount: true, policy.OpAggregate: true, policy.OpMeta: true},
		Models: map[string]policy.ModelRule{
			"res.partner": {Fields: []string{"name"}, MaxLimit: 50, CompanyField: "company_id"},
		},
		Scope:          policy.CompanyScope{Enabled: []int{1, 2}, Default: 1},
		SharedRecords:  policy.SharedDeny,
		Budgets:        policy.Budgets{MaxLimit: 100, MaxOffset: 1000, MaxRowsPerCall: 10, MaxResponseBytes: 1 << 20, MaxCallsPerSession: 100, MaxRowsPerSession: 1000},
		AllowWorkspace: true,
		SnapshotSHA256: digest,
	}
	rec := &dispatchRecorder{}
	b, err := broker.NewForTest(p, &config.Instance{Name: "test"}, snap, nil, rec)
	if err != nil {
		panic(err)
	}
	ws, err := workspace.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	b.SetWorkspaceForTest(ws)
	tok, err := b.Grant(time.Hour)
	if err != nil {
		panic(err)
	}
	srv := httptest.NewServer(b.ModelMuxForTest())
	defer srv.Close()
	fmt.Println("BROKER_URL=" + srv.URL)
	fmt.Println("BROKER_TOKEN=" + tok)
	fmt.Println("READY")
	select {}
}
