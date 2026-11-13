package reach

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"trident/internal/project"
)

func fixtureSnapshot(t *testing.T) *project.Snapshot {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", "java-maven"))
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "source")
	copyTree(t, source, copied)
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
	return snapshot
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(source, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		data, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInspectImportReachability(t *testing.T) {
	snapshot := fixtureSnapshot(t)
	mapPath := filepath.Join(t.TempDir(), "map.json")
	if err := os.WriteFile(mapPath, []byte(`{"schema_version":1,"dependencies":{"org.apache.commons:commons-text":["org.apache.commons.text"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(context.Background(), snapshot, Options{PackageMapPath: mapPath})
	if err != nil {
		t.Fatal(err)
	}
	if report.Coverage.ImportsParsed == 0 || report.Coverage.ImportReachable < 2 {
		t.Fatalf("import coverage: %+v", report.Coverage)
	}
	var matched int
	for _, dependency := range report.Dependencies {
		if dependency.Dependency != "org.apache.commons:commons-text" {
			continue
		}
		if dependency.Classification == "import_reachable" && len(dependency.MatchedImports) > 0 {
			matched++
		}
	}
	if matched < 2 {
		t.Fatalf("commons-text import reachability: %+v", report.Dependencies)
	}
	if report.RuntimeStatus != "not_run" {
		t.Fatalf("runtime status: %s", report.RuntimeStatus)
	}

	unmapped, err := Inspect(context.Background(), snapshot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if unmapped.Coverage.Unverified != unmapped.Coverage.Dependencies || unmapped.Coverage.ImportReachable != 0 {
		t.Fatalf("unmapped dependencies must stay unverified: %+v", unmapped.Coverage)
	}
}

func TestLoadPackageMapRejectsUnsafeEntries(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"bad.json":     `{"schema_version":1,"dependencies":{"g:a":["../escape"]}}`,
		"unknown.json": `{"schema_version":1,"dependencies":{},"unexpected":true}`,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPackageMap(path); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
