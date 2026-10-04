package broker

import (
	"testing"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
)

func TestRPCPacingIsGlobalAndNoBurstAfterIdle(t *testing.T) {
	b := &Broker{pol: &policy.Policy{Budgets: policy.Budgets{MinRPCIntervalMillis: 1000}}, inflight: make(chan struct{}, 1)}
	if !b.tryAcquireInflight() {
		t.Fatal("first RPC refused")
	}
	if b.tryAcquireInflight() {
		t.Fatal("concurrency cap bypassed")
	}
	b.releaseInflight()
	if b.tryAcquireInflight() {
		t.Fatal("cadence bypassed by another request/session")
	}
	b.mu.Lock()
	b.nextRPC = time.Now().Add(-time.Second)
	b.mu.Unlock()
	if !b.tryAcquireInflight() {
		t.Fatal("legitimate next request refused")
	}
	b.releaseInflight()
	if b.tryAcquireInflight() {
		t.Fatal("idle interval accumulated a burst")
	}
}

func TestEvidenceIdentifiersRejectWrongShapes(t *testing.T) {
	if !evidenceIDEquals(float64(7), 7) || !evidenceIDEquals(int64(7), 7) {
		t.Fatal("integer IDs refused")
	}
	for _, value := range []any{"7", float64(7.5), nil, true, map[string]any{"id": 7}} {
		if evidenceIDEquals(value, 7) {
			t.Fatalf("accepted invalid ID %v", value)
		}
	}
}

func TestAttachmentEncodingBoundaries(t *testing.T) {
	for _, input := range []any{"SGVsbG8=", []byte("SGVsbG8=")} {
		got, err := decodeAttachmentDatas(input)
		if err != nil || string(got) != "Hello" {
			t.Fatalf("valid payload: %v", err)
		}
	}
	for _, input := range []any{false, nil, "not base64!", make([]byte, 3*maxAttachmentBytes)} {
		if _, err := decodeAttachmentDatas(input); err == nil {
			t.Fatal("invalid or oversized payload accepted")
		}
	}
}

func TestCatalogLabelsSeparateDiscoveryAndEvidence(t *testing.T) {
	entry := map[string]any{"fields": map[string]any{
		"name": map[string]any{}, "x_computed": map[string]any{},
	}}
	rule := policy.ModelRule{Fields: []string{"name"}}
	catalogPermissions(entry, rule, true)
	fields := entry["fields"].(map[string]any)
	if entry["executable"] != true || fields["name"].(map[string]any)["readable"] != true || fields["x_computed"].(map[string]any)["readable"] != false {
		t.Fatal("discovery implies unapproved value access")
	}
	rule.LinkedEvidence = true
	catalogPermissions(entry, rule, true)
	if entry["executable"] != false || entry["linked_evidence_only"] != true || fields["name"].(map[string]any)["readable"] != false {
		t.Fatal("evidence advertised as a generic read")
	}
}
