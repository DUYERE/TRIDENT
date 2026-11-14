package sca

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/project"
)

func upgradeSnapshotFrom(t *testing.T, source string) *project.Snapshot {
	t.Helper()
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

func TestPlanUpgradeMavenPropertyAndPatch(t *testing.T) {
	snapshot, _ := fixtureSnapshot(t)
	plan, err := PlanUpgrade(context.Background(), snapshot, UpgradeOptions{
		Module: "jdbc-app", Dependency: "org.apache.commons:commons-text", ToVersion: "1.10.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != "prepared" || plan.FromVersion != "1.9" || plan.ToVersion != "1.10.0" {
		t.Fatalf("plan: %+v", plan)
	}
	if plan.Change.File != "pom.xml" || plan.Change.Kind != "maven_property" || plan.Property != "commons-text.version" {
		t.Fatalf("change: %+v", plan.Change)
	}
	if !strings.Contains(plan.Patch, "<commons-text.version>1.10.0</commons-text.version>") {
		t.Fatalf("patch: %s", plan.Patch)
	}
	if plan.PatchSHA256 == "" || plan.PatchBytes != len(plan.Patch) || plan.RuntimeStatus != "not_run" {
		t.Fatalf("patch metadata: %+v", plan)
	}
}

func TestPlanUpgradeGradleString(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", "java-gradle"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := upgradeSnapshotFrom(t, root)
	plan, err := PlanUpgrade(context.Background(), snapshot, UpgradeOptions{
		Module: "jdbc-app", Dependency: "org.apache.commons:commons-text", ToVersion: "1.10.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Change.File != "jdbc-app/build.gradle" || plan.Change.Kind != "gradle_string" {
		t.Fatalf("change: %+v", plan.Change)
	}
	if !strings.Contains(plan.Patch, "commons-text:1.10.0") {
		t.Fatalf("patch: %s", plan.Patch)
	}
}

func TestPlanUpgradeRejectsEqualOrMissingTargets(t *testing.T) {
	snapshot, _ := fixtureSnapshot(t)
	if _, err := PlanUpgrade(context.Background(), snapshot, UpgradeOptions{
		Module: "jdbc-app", Dependency: "org.apache.commons:commons-text", ToVersion: "1.9",
	}); err == nil {
		t.Fatal("equal target version accepted")
	}
	if _, err := PlanUpgrade(context.Background(), snapshot, UpgradeOptions{
		Module: "jdbc-app", Dependency: "org.example:missing", ToVersion: "1.0.0",
	}); err == nil {
		t.Fatal("missing dependency accepted")
	}
	if _, err := PlanUpgrade(context.Background(), snapshot, UpgradeOptions{
		Module: "jdbc-app", Dependency: "org.apache.commons:commons-text", ToVersion: "1.10.0\n+malicious",
	}); err == nil {
		t.Fatal("non-literal target version accepted")
	}
}
