package r3

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/project"
)

func testSnapshot(t *testing.T, files map[string]string) (*project.Snapshot, project.ImportResult, string) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		file := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	imported, err := project.Import(context.Background(), source, filepath.Join(root, "snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := project.Open(context.Background(), imported.Path, imported.Hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	return snapshot, imported, source
}

const originalJava = "package demo;\npublic class A { int x = 1; }"

const safePatch = `--- a/src/main/java/demo/A.java
+++ b/src/main/java/demo/A.java
@@ -1,2 +1,2 @@
 package demo;
-public class A { int x = 1; }
+public class A { int x = 2; }
`

func TestApplyNormalizesHunkCounts(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "A.java"), []byte(originalJava), 0o600); err != nil {
		t.Fatal(err)
	}
	// The body has one removal and one addition; the header deliberately lies
	// about the counts. Exact context matching remains the safety boundary.
	patch := []byte(`--- a/A.java
+++ b/A.java
@@ -1,9 +1,9 @@
 package demo;
-public class A { int x = 1; }
+public class A { int x = 2; }
`)
	changed, err := Apply(root, patch)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed.Files) != 1 || changed.Files[0].Additions != 1 || changed.Files[0].Deletions != 1 {
		t.Fatalf("changes: %+v", changed)
	}
	after, err := os.ReadFile(filepath.Join(root, "A.java"))
	if err != nil || string(after) != "package demo;\npublic class A { int x = 2; }" {
		t.Fatalf("after = %q, err = %v", after, err)
	}
}

func TestApplyRejectsMismatchedContext(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "A.java"), []byte(originalJava), 0o600); err != nil {
		t.Fatal(err)
	}
	patch := []byte(`--- a/A.java
+++ b/A.java
@@ -1,99 +1,99 @@
 package demo;
-public class A { int x = 9; }
+public class A { int x = 2; }
`)
	if _, err := Apply(root, patch); err == nil {
		t.Fatal("mismatched removal was accepted")
	}
}

func TestWorkspaceAndPatchSlice(t *testing.T) {
	snapshot, imported, source := testSnapshot(t, map[string]string{
		"src/main/java/demo/A.java": originalJava,
		"README.txt":                "fixture\n",
	})
	parent := t.TempDir()
	workspace := filepath.Join(parent, "workspace")
	info, err := CreateWorkspace(context.Background(), snapshot, imported.Path, workspace)
	if err != nil {
		t.Fatal(err)
	}
	if info.Files != 2 || info.Bytes == 0 {
		t.Fatalf("workspace info: %+v", info)
	}
	if _, err = os.Stat(filepath.Join(workspace, ".trident-manifest.json")); !os.IsNotExist(err) {
		t.Fatal("manifest copied into workspace")
	}
	result, err := Apply(workspace, []byte(safePatch))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 || result.Files[0].Additions != 1 || result.Files[0].Deletions != 1 {
		t.Fatalf("patch result: %+v", result)
	}
	patched, err := os.ReadFile(filepath.Join(workspace, "src/main/java/demo/A.java"))
	if err != nil {
		t.Fatal(err)
	}
	if string(patched) != "package demo;\npublic class A { int x = 2; }" {
		t.Fatalf("patched content: %q", patched)
	}
	original, err := os.ReadFile(filepath.Join(source, "src/main/java/demo/A.java"))
	if err != nil {
		t.Fatal(err)
	}
	if string(original) != originalJava {
		t.Fatal("original source changed")
	}
	if !snapshotIntact(context.Background(), imported.Path, imported.Hash) {
		t.Fatal("snapshot integrity changed")
	}
}

func TestApplyPreservesCRLF(t *testing.T) {
	workspace := t.TempDir()
	target := filepath.Join(workspace, "A.java")
	original := "package demo;\r\npublic class A { int x = 1; }\r\n"
	if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	patch := "--- a/A.java\n+++ b/A.java\n@@ -1,2 +1,2 @@\n package demo;\n-public class A { int x = 1; }\n+public class A { int x = 2; }\n"
	if _, err := Apply(workspace, []byte(patch)); err != nil {
		t.Fatal(err)
	}
	patched, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(patched) != "package demo;\r\npublic class A { int x = 2; }\r\n" {
		t.Fatalf("CRLF not preserved: %q", patched)
	}
}

func TestApplyAcceptsUTF8BOM(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "A.java"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	patch := "\ufeff--- a/A.java\n+++ b/A.java\n@@ -1,1 +1,1 @@\n-x\n+y\n"
	if _, err := Apply(workspace, []byte(patch)); err != nil {
		t.Fatalf("UTF-8 BOM patch rejected: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(workspace, "A.java"))
	if err != nil || string(content) != "y\n" {
		t.Fatalf("BOM patch result: %q %v", content, err)
	}
}

func TestApplyCreatesNewFileAndRejectsOverwrite(t *testing.T) {
	workspace := t.TempDir()
	patch := "--- /dev/null\n+++ b/src/main/java/demo/New.java\n@@ -0,0 +1,2 @@\n+package demo;\n+public class New {}\n"
	result, err := Apply(workspace, []byte(patch))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 || result.Files[0].Path != "src/main/java/demo/New.java" || result.Files[0].Additions != 2 || result.Files[0].Deletions != 0 {
		t.Fatalf("creation result: %+v", result)
	}
	content, err := os.ReadFile(filepath.Join(workspace, "src/main/java/demo/New.java"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "package demo;\npublic class New {}\n" {
		t.Fatalf("created content: %q", content)
	}
	if _, err = Apply(workspace, []byte(patch)); err == nil {
		t.Fatal("overwriting an existing file was accepted")
	}
	if _, err = Apply(workspace, []byte("--- a/src/main/java/demo/New.java\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-package demo;\n-public class New {}\n")); err == nil {
		t.Fatal("deletion patch was accepted")
	}
}

func TestWorkspaceRejectsUnsafeDestinations(t *testing.T) {
	snapshot, imported, _ := testSnapshot(t, map[string]string{"a.txt": "a\n"})
	if _, err := CreateWorkspace(context.Background(), snapshot, imported.Path, filepath.Join(imported.Path, "workspace")); err == nil {
		t.Fatal("workspace inside snapshot accepted")
	}
	existing := t.TempDir()
	if _, err := CreateWorkspace(context.Background(), snapshot, imported.Path, existing); err == nil {
		t.Fatal("existing workspace accepted")
	}
}

func TestPatchRejectsTraversalAndMismatch(t *testing.T) {
	snapshot, imported, _ := testSnapshot(t, map[string]string{"src/main/java/demo/A.java": originalJava})
	workspace := filepath.Join(t.TempDir(), "workspace")
	if _, err := CreateWorkspace(context.Background(), snapshot, imported.Path, workspace); err != nil {
		t.Fatal(err)
	}
	traversal := strings.Replace(safePatch, "+++ b/src/main/java/demo/A.java", "+++ b/../escape.java", 1)
	if _, err := Apply(workspace, []byte(traversal)); err == nil {
		t.Fatal("traversal patch accepted")
	}
	mismatch := strings.Replace(safePatch, "package demo;\n-public class A { int x = 1; }", "package demo;\n-public class A { int x = 9; }", 1)
	if _, err := Apply(workspace, []byte(mismatch)); err == nil {
		t.Fatal("context mismatch accepted")
	}
	created, err := Apply(workspace, []byte("--- /dev/null\n+++ b/new.java\n@@ -0,0 +1,1 @@\n+x\n"))
	if err != nil {
		t.Fatalf("file creation rejected: %v", err)
	}
	if len(created.Files) != 1 || created.Files[0].Path != "new.java" {
		t.Fatalf("creation result: %+v", created)
	}
	if content, err := os.ReadFile(filepath.Join(workspace, "new.java")); err != nil || string(content) != "x\n" {
		t.Fatalf("created file: %q %v", content, err)
	}
	after, err := os.ReadFile(filepath.Join(workspace, "src/main/java/demo/A.java"))
	if err != nil || string(after) != originalJava {
		t.Fatal("failed patch changed the workspace")
	}
}

func TestValidationRequiresExplicitApprovalAndValidProfile(t *testing.T) {
	workspace := t.TempDir()
	if _, err := Validate(context.Background(), workspace, ValidationOptions{Profile: "javac", MainClass: "demo.Main"}); err == nil {
		t.Fatal("execution without approval accepted")
	}
	if _, err := Validate(context.Background(), workspace, ValidationOptions{Profile: "other", MainClass: "demo.Main", ApproveExecution: true}); err == nil {
		t.Fatal("invalid profile accepted")
	}
	if _, err := Validate(context.Background(), workspace, ValidationOptions{Profile: "javac", MainClass: "demo/../../Main", ApproveExecution: true}); err == nil {
		t.Fatal("invalid main class accepted")
	}
	if _, err := Validate(context.Background(), workspace, ValidationOptions{Profile: "junit", TestClass: "demo.Main", ApproveExecution: true}); err == nil {
		t.Fatal("junit without test classpath accepted")
	}
}

func TestRollbackPlanRecordsOriginalHashes(t *testing.T) {
	plan := rollbackPlan("snapshot-hash", PatchResult{Files: []FileChange{
		{Path: "src/main/java/demo/A.java", SHA256Before: "before", SHA256After: "after"},
		{Path: "src/main/java/demo/New.java", SHA256Before: "", SHA256After: "created"},
	}})
	if plan == nil || plan.SnapshotHash != "snapshot-hash" || len(plan.Steps) != 2 {
		t.Fatalf("rollback plan: %+v", plan)
	}
	if plan.Steps[0].Action != "restore_original" || plan.Steps[0].SHA256Before != "before" {
		t.Fatalf("restore step: %+v", plan.Steps[0])
	}
	if plan.Steps[1].Action != "remove_created_file" || plan.Steps[1].SHA256Before != "" {
		t.Fatalf("created-file step: %+v", plan.Steps[1])
	}
	if !strings.Contains(plan.Note, "does not execute") {
		t.Fatalf("rollback note must stay manual: %q", plan.Note)
	}
}

func TestModuleDirectoryStaysInsideWorkspace(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "service-a"), 0o700); err != nil {
		t.Fatal(err)
	}
	absolute, relative, err := moduleDirectory(root, "service-a")
	if err != nil || relative != "service-a" || absolute != filepath.Join(root, "service-a") {
		t.Fatalf("module resolution: %q %q %v", absolute, relative, err)
	}
	for _, module := range []string{"../escape", "a/../../escape", filepath.Join(root, "service-a"), "absent"} {
		if _, _, err := moduleDirectory(root, module); err == nil {
			t.Fatalf("unsafe module accepted: %q", module)
		}
	}
}

func TestGradleProfileRequiresBuildFile(t *testing.T) {
	workspace := t.TempDir()
	if _, err := Validate(context.Background(), workspace, ValidationOptions{
		Profile: "gradle-test", ApproveExecution: true,
	}); err == nil {
		t.Fatal("gradle profile without build file accepted")
	}
	if err := os.WriteFile(filepath.Join(workspace, "build.gradle"), []byte("plugins { id 'java' }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !hasGradleBuild(workspace) {
		t.Fatal("build.gradle not detected")
	}
}

func TestValidateModulesRejectsUnsafeSelection(t *testing.T) {
	workspace := t.TempDir()
	if _, err := Validate(context.Background(), workspace, ValidationOptions{
		Profile: "maven-compile", ApproveExecution: true, Modules: []string{"../escape"},
	}); err == nil {
		t.Fatal("escaping module accepted")
	}
	modules := []string{}
	for index := 0; index < MaxModules+1; index++ {
		modules = append(modules, "module")
	}
	if _, err := Validate(context.Background(), workspace, ValidationOptions{
		Profile: "maven-compile", ApproveExecution: true, Modules: modules,
	}); err == nil {
		t.Fatal("module count above the bound accepted")
	}
}
