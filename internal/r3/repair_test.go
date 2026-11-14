package r3

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestRepairStopsOnModelFailureWithoutRetry(t *testing.T) {
	snapshot, imported, _ := testSnapshot(t, map[string]string{"src/main/java/demo/A.java": originalJava})
	client := &fakeCompletion{err: errors.New("model unavailable")}
	workspaceRoot := t.TempDir()
	report, err := Repair(context.Background(), RepairOptions{
		Snapshot: snapshot, SnapshotDir: imported.Path, WorkspaceRoot: workspaceRoot, MaxRounds: 3, Client: client,
		Propose: ProposeOptions{Paths: []string{"src/main/java/demo/A.java"}, Goal: "fix", Model: "fake", MaxOutputTokens: 128},
		Verify:  VerifyOptions{Profile: "javac", MainClass: "demo.A", ApproveExecution: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.FinalStatus != "proposal_failed" || len(report.Rounds) != 1 || report.Rounds[0].ProposalError == "" {
		t.Fatalf("repair failure handling: %+v", report)
	}
	if report.RuntimeStatus != "not_run" {
		t.Fatalf("runtime status: %s", report.RuntimeStatus)
	}
}

func TestRepairBoundsAndWorkspaceContainment(t *testing.T) {
	snapshot, imported, _ := testSnapshot(t, map[string]string{"src/main/java/demo/A.java": originalJava})
	client := &fakeCompletion{err: errors.New("unused")}
	if _, err := Repair(context.Background(), RepairOptions{Snapshot: snapshot, SnapshotDir: imported.Path, WorkspaceRoot: t.TempDir(), MaxRounds: 0, Client: client}); err == nil {
		t.Fatal("zero rounds accepted")
	}
	if _, err := Repair(context.Background(), RepairOptions{Snapshot: snapshot, SnapshotDir: imported.Path, WorkspaceRoot: imported.Path, MaxRounds: 1, Client: client}); err == nil {
		t.Fatal("workspace root inside snapshot accepted")
	}
	if !insideSnapshotPath(imported.Path, filepath.Join(imported.Path, "sub")) || insideSnapshotPath(imported.Path, filepath.Dir(imported.Path)) {
		t.Fatal("snapshot containment check is wrong")
	}
}

func TestScorePatchHeuristics(t *testing.T) {
	validation := ValidationResult{
		Status:      ValidationPassed,
		TestSummary: &TestRunSummary{Tests: 1, Failures: 0},
	}
	patch := PatchResult{Files: []FileChange{{Path: "A.java", Additions: 1, Deletions: 1}}}
	quality := scorePatch(validation, patch)
	if quality.Score != 100 || quality.Grade != "A" || len(quality.Dimensions) == 0 {
		t.Fatalf("quality: %+v", quality)
	}
	if validation.TestSummary.Tests != 1 {
		t.Fatalf("scorePatch mutated test summary: %+v", validation.TestSummary)
	}
	combined := ValidationResult{
		Status: ValidationPassed, TestSummary: &TestRunSummary{Tests: 4},
		JUnitXML: &JUnitXMLSummary{Tests: 4},
	}
	_ = scorePatch(combined, patch)
	if combined.TestSummary.Tests != 4 {
		t.Fatalf("scorePatch double-counted tests: %+v", combined.TestSummary)
	}
	failed := scorePatch(ValidationResult{Status: ValidationFailed}, PatchResult{Files: []FileChange{{Path: "A.java", Additions: 100, Deletions: 100}}})
	if failed.Score >= quality.Score || failed.Grade == "A" {
		t.Fatalf("failed validation quality: %+v", failed)
	}
}
