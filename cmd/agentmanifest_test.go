package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
)

func TestOfflineManifestApplyPreservesSealedPermissions(t *testing.T) {
	dir := t.TempDir()
	p := validBundlePolicy(dir)
	s := validBundleSnapshot()
	profilePath := filepath.Join(dir, "profile.json")
	bundle, err := agentSetupStageSealedBundle(profilePath, p.SnapshotPath, "test-admin", p, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := agentSetupCommitBundle(bundle); err != nil {
		t.Fatal(err)
	}
	methods := []snapshot.MethodMeta{{Model: "x.logo.request", Method: "action_prepare",
		Signature: "unknown", SourceModule: "unknown", SourceRevision: "unknown",
		SourceReference: "unknown", Provenance: snapshot.ProvUnknown, MutationAssessment: "unknown"}}
	data, _ := json.Marshal(map[string]any{"manifest_version": snapshot.ManifestVersion, "methods": methods})
	manifestPath := filepath.Join(dir, "methods.json")
	if err := os.WriteFile(manifestPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.CreateTemp(dir, "admin-stdin-")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err := input.WriteString("test-admin\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	priorStdin := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = priorStdin }()
	c := newAgentSnapshotImportManifestCmd()
	c.SetArgs([]string{"--manifest", manifestPath, "--apply", "--profile", profilePath, "--admin-password-stdin"})
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	gotPolicy, err := agentSetupOpenPolicy(profilePath, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	gotSnapshot, err := snapshot.Load(p.SnapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	wantPolicy := bundle.pol
	wantPolicy.SnapshotSHA256, _ = snapshot.CanonicalDigest(gotSnapshot)
	if !reflect.DeepEqual(gotPolicy, wantPolicy) {
		t.Fatal("manifest import changed sealed permissions")
	}
	if !reflect.DeepEqual(gotSnapshot.MethodManifest, methods) {
		t.Fatal("method evidence not persisted")
	}
	if _, allowed := gotPolicy.Models[methods[0].Model]; allowed {
		t.Fatal("manifest granted model access")
	}
}
