package cmd

import (
	"slices"
	"strings"
	"testing"

	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
)

// These are pure permission-compilation tests over metadata values. They do
// not emulate an Odoo server or assert ORM behavior.
func TestInvestigationStoredFieldsAndScope(t *testing.T) {
	defs := investigationModels()
	installed := map[string]bool{"product.product": true, "product.template": true, "uom.uom": true, "mail.message": true, "ir.attachment": true, "product.template.attribute.line": true, "mrp.workorder": true}
	rows := []any{}
	add := func(model, name, typ, relation string, stored bool) {
		rows = append(rows, map[string]any{"model": model, "name": name, "ttype": typ, "relation": relation, "store": stored})
	}
	for _, n := range []string{"product.product", "product.template"} {
		add(n, "id", "integer", "", true)
		add(n, "name", "char", "", true)
		add(n, "company_id", "many2one", "res.company", false)
	}
	add("product.product", "x_base_product", "many2one", "product.product", true)
	add("product.product", "x_computed", "char", "", false)
	add("product.product", "x_api_token", "char", "", true)
	add("product.product", "image_1920", "binary", "", true)
	add("uom.uom", "name", "char", "", true)
	add("mail.message", "id", "integer", "", true)
	add("mail.message", "body", "html", "", true)
	add("mail.message", "model", "char", "", true)
	add("mail.message", "res_id", "many2one_reference", "", true)
	add("ir.attachment", "res_model", "char", "", true)
	add("ir.attachment", "res_id", "many2one_reference", "", true)
	add("ir.attachment", "file_size", "integer", "", true)
	add("ir.attachment", "type", "selection", "", true)
	add("ir.attachment", "datas", "binary", "", false)
	add("ir.attachment", "res_field", "char", "", true)
	add("mrp.workorder", "company_id", "many2one", "res.company", true)
	add("mrp.workorder", "production_id", "many2one", "mrp.production", true)
	add("mrp.workorder", "operation_id", "many2one", "mrp.routing.workcenter", true)
	add("product.template.attribute.line", "product_tmpl_id", "many2one", "product.template", true)
	specs, metadata, notes, err := agentCompileInvestigation(defs, installed, rows, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, sp := range specs {
		found[sp.Name] = true
		if sp.Name == "product.product" {
			fields := strings.Join(sp.Fields, ",")
			for _, want := range []string{"company_id", "x_base_product"} {
				if !strings.Contains(fields, want) {
					t.Fatalf("missing %s", want)
				}
			}
			for _, deny := range []string{"x_computed", "x_api_token", "image_1920"} {
				if strings.Contains(fields, deny) {
					t.Fatalf("enabled %s", deny)
				}
			}
			if sp.CompanyField != "company_id" || !sp.IncludeCompanyless {
				t.Fatal("product scope lost")
			}
		}
		if sp.Name == "product.template.attribute.line" && sp.CompanyField != "product_tmpl_id.company_id" {
			t.Fatal("attribute scope lost")
		}
		if (sp.Name == "mail.message" || sp.Name == "ir.attachment") && (sp.CompanyIndependent || sp.CompanyField != "") {
			t.Fatal("evidence exposed as global/direct model")
		}
		if sp.Name == "ir.attachment" && !slices.Contains(sp.Fields, "res_field") {
			t.Fatal("field-backed evidence selector missing from proposal")
		}
		if sp.Name == "mrp.workorder" && (sp.CompanyField != "company_id" || sp.IncludeCompanyless || !slices.Contains(sp.Fields, "production_id")) {
			t.Fatal("work-order discovery lost scope or manufacturing linkage")
		}
	}
	if !found["uom.uom"] || len(notes) == 0 || metadata["product.product"]["x_computed"].Type != "char" {
		t.Fatal("discovery information lost")
	}
	if !found["mail.message"] || !found["ir.attachment"] || !found["mrp.workorder"] {
		t.Fatal("Odoo 17 evidence fields refused")
	}
	for _, raw := range rows {
		r := raw.(map[string]any)
		if r["name"] == "res_id" {
			r["ttype"] = "integer"
		}
	}
	if _, _, _, err := agentCompileInvestigation(defs, installed, rows, nil); err != nil {
		t.Fatalf("integer parent IDs refused: %v", err)
	}
	// A changed linkage type must abort instead of enabling an evidence
	// route whose fixed parent domain is no longer meaningful.
	for _, model := range []string{"mail.message", "ir.attachment"} {
		for _, raw := range rows {
			r := raw.(map[string]any)
			if r["model"] == model && r["name"] == "res_id" {
				r["ttype"] = "char"
			}
		}
		if _, _, _, err := agentCompileInvestigation(defs, installed, rows, nil); err == nil {
			t.Fatalf("accepted changed evidence linkage on %s", model)
		}
		for _, raw := range rows {
			r := raw.(map[string]any)
			if r["model"] == model && r["name"] == "res_id" {
				r["ttype"] = "many2one_reference"
			}
		}
	}
}

func TestInvestigationReconcilesUnavailableOptionalFields(t *testing.T) {
	sp := snapshot.ModelSpec{Name: "res.partner", Fields: []string{"id", "name", "company_id", "signup_expiration"}, CompanyField: "company_id"}
	metadata := map[string]snapshot.SFieldMeta{
		"name": {Type: "char"}, "company_id": {Type: "many2one", Relation: "res.company"},
		"signup_expiration": {Type: "datetime"}, "x_computed": {Type: "char"},
	}
	live := map[string]any{
		"id":         map[string]any{"type": "integer"},
		"name":       map[string]any{"type": "char"},
		"company_id": map[string]any{"type": "many2one", "relation": "res.company"},
		"x_computed": map[string]any{"type": "char"},
		"x_new":      map[string]any{"type": "char"},
	}
	clean, advisory, omitted, err := agentReconcileInvestigation(sp, metadata, live)
	if err != nil || strings.Join(clean.Fields, ",") != "id,name,company_id" || strings.Join(omitted, ",") != "signup_expiration" {
		t.Fatalf("unexpected reconciliation: %+v %v %v", clean, omitted, err)
	}
	if _, ok := advisory["signup_expiration"]; ok {
		t.Fatal("stale field retained in advisory metadata")
	}
	if _, ok := advisory["x_computed"]; !ok {
		t.Fatal("available metadata-only field lost")
	}
	if strings.Contains(strings.Join(clean.Fields, ","), "x_") {
		t.Fatal("reconciliation granted new permissions")
	}
	for _, invalid := range []any{nil, map[string]any{"type": "many2one", "relation": "res.users"}} {
		live["company_id"] = invalid
		if _, _, _, err := agentReconcileInvestigation(sp, metadata, live); err == nil {
			t.Fatal("missing/changed company scope accepted")
		}
	}
}

func TestInvestigationRequiresLiveEvidenceLinks(t *testing.T) {
	sp := snapshot.ModelSpec{Name: "mail.message", Fields: []string{"id", "model", "res_id"}}
	metadata := map[string]snapshot.SFieldMeta{"model": {Type: "char"}, "res_id": {Type: "many2one_reference"}}
	live := map[string]any{"id": map[string]any{"type": "integer"}, "model": map[string]any{"type": "char"}, "res_id": map[string]any{"type": "many2one_reference"}}
	if _, _, _, err := agentReconcileInvestigation(sp, metadata, live); err != nil {
		t.Fatal(err)
	}
	delete(live, "res_id")
	if _, _, _, err := agentReconcileInvestigation(sp, metadata, live); err == nil {
		t.Fatal("missing evidence link accepted")
	}
}

func TestInvestigationRequiresCoreAndRequestedModel(t *testing.T) {
	if _, _, _, err := agentCompileInvestigation(investigationModels(), map[string]bool{}, nil, nil); err == nil {
		t.Fatal("accepted absent core models")
	}
	if _, err := agentFindPreset("warehouse"); err == nil {
		t.Fatal("obsolete preset retained")
	}
	if _, err := agentFindPreset("all"); err == nil {
		t.Fatal("accepted unknown profile")
	}
	first, _ := agentFindPreset("investigation")
	first.Models[0] = "x_mutated"
	second, _ := agentFindPreset("investigation")
	if second.Models[0] == "x_mutated" {
		t.Fatal("shared mutable recipe")
	}
}
