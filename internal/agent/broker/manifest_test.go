package broker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
	"github.com/danieljclsilva/cli-odoo/internal/config"
)

func TestManifestDiscoveryCannotGrantExecution(t *testing.T) {
	s := testSnapshot()
	s.MethodManifest = []snapshot.MethodMeta{{Model: "x.logo.request", Method: "write",
		Signature: "(self, vals)", SourceModule: "custom", SourceRevision: "abc",
		SourceReference: "custom.py:10", Provenance: snapshot.ProvManifest,
		MutationAssessment: "likely_read_only", AssessmentEvidence: "An untrusted claim"}}
	p := testPolicy()
	p.SnapshotSHA256, _ = snapshot.CanonicalDigest(s)
	b, err := New(p, &config.Instance{Name: "test"}, s)
	if err != nil {
		t.Fatal(err)
	}
	// No RPC executor: metadata and denials must work entirely offline.
	tok := grantToken(t, b)
	for _, path := range []string{"/rpc/catalog", "/rpc/catalog?model=x.logo.request"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		b.modelMux().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		var env struct {
			Result struct {
				Executable     bool            `json:"executable"`
				MethodManifest []catalogMethod `json:"method_manifest"`
			} `json:"result"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if env.Result.Executable || len(env.Result.MethodManifest) != 1 || env.Result.MethodManifest[0].Executable {
			t.Fatal("manifest acquired execution permission")
		}
		if env.Result.MethodManifest[0].SourceRevision != "abc" {
			t.Fatal("source evidence lost")
		}
	}
	if _, exists := b.pol.Models["x.logo.request"]; exists {
		t.Fatal("catalog added policy rule")
	}
	denied := post(t, b, "/rpc/read", tok, `{"model":"x.logo.request","ids":[1],"fields":["name"]}`)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("manifest model read = %d", denied.Code)
	}
	call := post(t, b, "/rpc/call", tok, `{"model":"x.logo.request","method":"write"}`)
	if call.Code != http.StatusNotFound {
		t.Fatalf("raw call route appeared: %d", call.Code)
	}
}
