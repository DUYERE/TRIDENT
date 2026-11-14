package sca

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"trident/internal/project"
)

func artifactFixture(t *testing.T) (*project.Snapshot, string) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", "java-artifact-hash"))
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "source")
	copyTree(t, filepath.Join(root, "project"), copied)
	destination := filepath.Join(t.TempDir(), "snapshot")
	imported, err := project.Import(context.Background(), copied, destination)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := project.Open(context.Background(), destination, imported.Hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	return snapshot, filepath.Join(root, "repo")
}

func TestInspectHashesLocalArtifacts(t *testing.T) {
	snapshot, repo := artifactFixture(t)
	report, err := Inspect(context.Background(), snapshot, Options{MavenRepo: repo})
	if err != nil {
		t.Fatal(err)
	}
	if report.Coverage.ArtifactHashes != "observed" || len(report.Artifacts) != 2 {
		t.Fatalf("artifact coverage: %s %+v", report.Coverage.ArtifactHashes, report.Artifacts)
	}
	want := "org/apache/commons/commons-text/1.9/commons-text-1.9.jar"
	for _, artifact := range report.Artifacts {
		if artifact.Kind == "jar" && artifact.Path != want {
			t.Fatalf("jar path: %+v", artifact)
		}
		if artifact.Status != "observed" || artifact.Source != "local_repository" || artifact.Bytes == 0 {
			t.Fatalf("artifact not observed: %+v", artifact)
		}
		data, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(artifact.Path)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if artifact.SHA256 != hex.EncodeToString(sum[:]) || artifact.Bytes != int64(len(data)) {
			t.Fatalf("artifact digest mismatch: %+v", artifact)
		}
	}
	first, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := Inspect(context.Background(), snapshot, Options{MavenRepo: repo})
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(repeated)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("artifact report is not deterministic")
	}
}

func TestInspectArtifactCatalogMismatchAndMissing(t *testing.T) {
	snapshot, repo := artifactFixture(t)
	catalog := filepath.Join(t.TempDir(), "catalog.json")
	document := `{"schema_version":1,"artifacts":[{"group_id":"org.apache.commons","artifact_id":"commons-text","version":"1.9","kind":"jar","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}`
	if err := os.WriteFile(catalog, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(context.Background(), snapshot, Options{MavenRepo: repo, HashCatalogPath: catalog})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial || report.Coverage.ArtifactHashes != "partial" {
		t.Fatalf("mismatch should be partial: %s %+v", report.Coverage.ArtifactHashes, report.Coverage)
	}
	matched := false
	for _, artifact := range report.Artifacts {
		if artifact.Kind == "jar" && artifact.CatalogMatch == "mismatch" && artifact.Status == "mismatch" {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("catalog mismatch not reported: %+v", report.Artifacts)
	}

	empty := t.TempDir()
	missing, err := Inspect(context.Background(), snapshot, Options{MavenRepo: empty})
	if err != nil {
		t.Fatal(err)
	}
	if missing.Coverage.ArtifactHashes != "unavailable" {
		t.Fatalf("missing repository should be unavailable: %+v", missing.Coverage)
	}
	for _, artifact := range missing.Artifacts {
		if artifact.Status != "missing" || artifact.Source != "unavailable" {
			t.Fatalf("missing artifact record: %+v", artifact)
		}
	}
}

func TestLoadHashCatalogRejectsUnsafeInput(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"unknown.json": `{"schema_version":1,"artifacts":[],"unexpected":true}`,
		"kind.json":    `{"schema_version":1,"artifacts":[{"group_id":"g","artifact_id":"a","version":"1","kind":"zip","sha256":"` + hex.EncodeToString(make([]byte, 32)) + `"}]}`,
		"hex.json":     `{"schema_version":1,"artifacts":[{"group_id":"g","artifact_id":"a","version":"1","kind":"jar","sha256":"xyz"}]}`,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadHashCatalog(path); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
