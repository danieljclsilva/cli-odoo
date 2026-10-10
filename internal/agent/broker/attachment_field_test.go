package broker

import (
	"reflect"
	"testing"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
)

// Pure admission/domain tests: these do not imitate an Odoo server.
func TestAttachmentFieldAdmission(t *testing.T) {
	b := &Broker{snap: snapshot.Snapshot{Models: map[string]snapshot.ModelMeta{
		"mrp.routing.workcenter": {Fields: map[string]snapshot.SFieldMeta{
			"worksheet": {Type: "binary"}, "note": {Type: "html"}, "x_api_token": {Type: "binary"},
		}},
	}}}
	evidence := policy.ModelRule{LinkedEvidence: true, Fields: []string{"id", "res_field", "datas"}}
	for _, kind := range []string{"attachments", "download"} {
		in := evidenceBody{Model: "mrp.routing.workcenter", ID: 8, Kind: kind, Field: "worksheet"}
		got, err := b.attachmentEvidenceDomain(in, evidence)
		want := []any{[]any{"res_model", "=", in.Model}, []any{"res_id", "=", 8}, []any{"res_field", "=", "worksheet"}}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("field linkage lost: %v %v", got, err)
		}
		in.Field = ""
		got, err = b.attachmentEvidenceDomain(in, evidence)
		want[2] = []any{"res_field", "=", false}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("ordinary attachment could bypass field constraint: %v %v", got, err)
		}
	}
	for _, field := range []string{"missing", "note", "x_api_token", "parent.worksheet", " worksheet", "Worksheet"} {
		if _, err := b.attachmentEvidenceDomain(evidenceBody{Model: "mrp.routing.workcenter", ID: 8, Kind: "attachments", Field: field}, evidence); err == nil {
			t.Fatalf("invalid binary selector admitted: %q", field)
		}
	}
	in := evidenceBody{Model: "mrp.routing.workcenter", ID: 8, Kind: "attachments", Field: "worksheet"}
	if _, err := b.attachmentEvidenceDomain(in, policy.ModelRule{Fields: []string{"id", "datas"}}); err == nil {
		t.Fatal("old profile gained field-backed evidence without human approval")
	}
	in.Kind = "chatter"
	if _, err := b.attachmentEvidenceDomain(in, evidence); err == nil {
		t.Fatal("field selector accepted on chatter")
	}
}

func TestBinaryCatalogEvidencePermission(t *testing.T) {
	p := &policy.Policy{AllowLinkedEvidence: true, Operations: map[policy.Operation]bool{policy.OpRead: true}, Models: map[string]policy.ModelRule{
		"ir.attachment": {LinkedEvidence: true, Fields: []string{"res_field"}},
	}}
	b := &Broker{pol: p}
	entry := map[string]any{"fields": map[string]any{
		"worksheet": map[string]any{"type": "binary"},
		"x_secret":  map[string]any{"type": "binary"},
		"note":      map[string]any{"type": "html"},
	}}
	catalogPermissions(entry, policy.ModelRule{Fields: []string{"note"}}, true)
	b.catalogAttachmentPermissions(entry, true)
	fields := entry["fields"].(map[string]any)
	worksheet := fields["worksheet"].(map[string]any)
	if worksheet["attachment_evidence"] != true || worksheet["readable"] != false || fields["x_secret"].(map[string]any)["attachment_evidence"] != false {
		t.Fatal("binary evidence and generic projections confused")
	}
	b.catalogAttachmentPermissions(entry, false)
	if worksheet["attachment_evidence"] != false {
		t.Fatal("discovery-only parent gained evidence access")
	}
	p.Models["ir.attachment"] = policy.ModelRule{LinkedEvidence: true, Fields: []string{"id"}}
	b.catalogAttachmentPermissions(entry, true)
	if worksheet["attachment_evidence"] != false {
		t.Fatal("old attachment policy gained evidence access")
	}
}
