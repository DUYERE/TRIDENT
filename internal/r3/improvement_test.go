package r3

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A later file whose context does not match must not leave the earlier file
// half-patched: Apply validates every file before writing any of them.
func TestApplyIsAtomicWhenALaterFileFails(t *testing.T) {
	workspace := t.TempDir()
	first := filepath.Join(workspace, "A.java")
	second := filepath.Join(workspace, "B.java")
	if err := os.WriteFile(first, []byte("package demo;\nclass A {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("package demo;\nclass B {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	patch := `--- a/A.java
+++ b/A.java
@@ -1,2 +1,2 @@
 package demo;
-class A {}
+class A { int fixed = 1; }
--- a/B.java
+++ b/B.java
@@ -1,2 +1,2 @@
 package demo;
-class B { int different = 9; }
+class B {}
`
	if _, err := Apply(workspace, []byte(patch)); err == nil {
		t.Fatal("expected the second file to fail")
	}
	for path, want := range map[string]string{
		first:  "package demo;\nclass A {}\n",
		second: "package demo;\nclass B {}\n",
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s was written before validation finished: %q", filepath.Base(path), got)
		}
	}
}

func TestRepairRequiresApproveExecution(t *testing.T) {
	missing := RepairOptions{MaxRounds: 2}.validate()
	if missing == nil || !strings.Contains(missing.Error(), "approve-execution") {
		t.Fatalf("repair accepted execution without approval: %v", missing)
	}
	snapshot, _, _ := testSnapshot(t, map[string]string{
		"src/main/java/demo/A.java": originalJava,
	})
	if err := (RepairOptions{Snapshot: snapshot, MaxRounds: 2, ApproveExecution: true}).validate(); err != nil {
		t.Fatalf("approved repair options rejected: %v", err)
	}
}

func TestVerifyRemovesFailedWorkspaceUnlessKept(t *testing.T) {
	snapshot, imported, _ := testSnapshot(t, map[string]string{
		"src/main/java/demo/A.java": originalJava,
	})
	_ = snapshot
	patchPath := filepath.Join(t.TempDir(), "bad.patch")
	if err := os.WriteFile(patchPath, []byte(`--- a/src/main/java/demo/A.java
+++ b/src/main/java/demo/A.java
@@ -1,2 +1,2 @@
 package demo;
-public class A { int x = 9; }
+public class A { int x = 2; }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	workspace := filepath.Join(parent, "workspace")
	report, err := Verify(context.Background(), VerifyOptions{
		SnapshotDir: imported.Path, SnapshotHash: imported.Hash,
		Workspace: workspace, PatchPath: patchPath, ApproveExecution: true,
	})
	if err == nil {
		t.Fatalf("bad context must fail: %+v", report.Status)
	}
	if _, statErr := os.Stat(workspace); !os.IsNotExist(statErr) {
		t.Fatalf("failed workspace was kept: %v", statErr)
	}
	kept := filepath.Join(parent, "kept")
	_, err = Verify(context.Background(), VerifyOptions{
		SnapshotDir: imported.Path, SnapshotHash: imported.Hash,
		Workspace: kept, PatchPath: patchPath, ApproveExecution: true, KeepWorkspace: true,
	})
	if err == nil {
		t.Fatal("bad context must still fail with KeepWorkspace")
	}
	if info, statErr := os.Stat(kept); statErr != nil || !info.IsDir() {
		t.Fatalf("KeepWorkspace did not preserve the copy: %v", statErr)
	}
}
