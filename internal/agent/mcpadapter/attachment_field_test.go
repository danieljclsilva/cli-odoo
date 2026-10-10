package mcpadapter

import "testing"

// Validate the tool contract locally without emulating Odoo behavior.
func TestEvidenceBinaryFieldContract(t *testing.T) {
	args := map[string]any{"model": "mrp.routing.workcenter", "id": float64(1), "kind": "attachments", "field": "worksheet"}
	if err := validateArgs("evidence", args); err != nil {
		t.Fatalf("field selector refused: %v", err)
	}
	args["field"] = float64(1)
	if err := validateArgs("evidence", args); err == nil {
		t.Fatal("non-string field selector accepted")
	}
	for _, tool := range Tools() {
		if tool.Name == "evidence" {
			props := tool.InputSchema["properties"].(map[string]any)
			if _, ok := props["field"]; !ok {
				t.Fatal("field selector missing from tool schema")
			}
			return
		}
	}
	t.Fatal("evidence tool missing")
}
