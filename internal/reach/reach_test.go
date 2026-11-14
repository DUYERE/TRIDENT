package reach

import (
	"context"
	"encoding/json"
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

func TestInspectBoundedReachability(t *testing.T) {
	snapshot := fixtureSnapshot(t)
	mapPath := filepath.Join(t.TempDir(), "map.json")
	if err := os.WriteFile(mapPath, []byte(`{"schema_version":1,"dependencies":{"org.apache.commons:commons-text":["org.apache.commons.text"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(context.Background(), snapshot, Options{PackageMapPath: mapPath})
	if err != nil {
		t.Fatal(err)
	}
	if report.Coverage.ImportsParsed == 0 || report.Coverage.ClassesIndexed == 0 || report.Coverage.Entrypoints == 0 {
		t.Fatalf("call graph coverage: %+v", report.Coverage)
	}
	// FixtureText imports commons-text but no controller reaches it; the
	// advisory-control module has no entrypoint at all.
	if report.Coverage.Reachable != 0 || report.Coverage.Unreachable == 0 || report.Coverage.Unknown == 0 {
		t.Fatalf("bounded reachability coverage: %+v", report.Coverage)
	}
	states := map[string]string{}
	for _, dependency := range report.Dependencies {
		if dependency.Dependency == "org.apache.commons:commons-text" {
			states[dependency.Module] = dependency.Reachability
		}
	}
	if states["jdbc-app"] != "unreachable" || states["advisory-control"] != "unknown" {
		t.Fatalf("commons-text reachability: %+v", report.Dependencies)
	}
	if report.RuntimeStatus != "not_run" {
		t.Fatalf("runtime status: %s", report.RuntimeStatus)
	}

	unmapped, err := Inspect(context.Background(), snapshot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if unmapped.Coverage.Unknown != unmapped.Coverage.Dependencies || unmapped.Coverage.Reachable != 0 {
		t.Fatalf("unmapped dependencies must stay unknown: %+v", unmapped.Coverage)
	}
}

func TestReachabilityFixtureThreeStates(t *testing.T) {
	source, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", "java-reachability"))
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
	mapPath := filepath.Join(t.TempDir(), "map.json")
	if err := os.WriteFile(mapPath, []byte(`{"schema_version":1,"dependencies":{"org.example:lib":["org.example.lib"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(context.Background(), snapshot, Options{PackageMapPath: mapPath})
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]Reachability{}
	for _, item := range report.Dependencies {
		if item.Dependency == "org.example:lib" {
			states[item.Module] = item
		}
	}
	reachable := states["reachable-app"]
	if reachable.Reachability != "reachable" || len(reachable.Paths) == 0 {
		t.Fatalf("reachable-app: %+v", reachable)
	}
	path := reachable.Paths[0]
	if len(path.Steps) != 2 || path.Steps[0].Relation != "entry" || path.Steps[1].Relation != "same_package" {
		t.Fatalf("reachability path steps: %+v", path.Steps)
	}
	for _, step := range path.Steps {
		if len(step.SHA256) != 64 || step.Line < 1 {
			t.Fatalf("reachability step lacks digest or line: %+v", step)
		}
	}
	if path.Import.Import != "org.example.lib.LibApi" || path.Import.Line < 1 {
		t.Fatalf("reachability import: %+v", path.Import)
	}
	if states["unused-app"].Reachability != "unreachable" {
		t.Fatalf("unused-app: %+v", states["unused-app"])
	}
	if states["reflect-app"].Reachability != "unknown" || states["reflect-app"].Reason != "reflection_not_resolved" {
		t.Fatalf("reflect-app: %+v", states["reflect-app"])
	}
	if report.Coverage.Reachable != 1 || report.Coverage.Unreachable != 1 || report.Coverage.Unknown != 1 {
		t.Fatalf("fixture coverage: %+v", report.Coverage)
	}
	first, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := Inspect(context.Background(), snapshot, Options{PackageMapPath: mapPath})
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(repeated)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("reachability report is not deterministic")
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
