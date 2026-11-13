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
	if _, err := Apply(workspace, []byte("--- /dev/null\n+++ b/new.java\n@@ -0,0 +1,1 @@\n+x\n")); err == nil {
		t.Fatal("file creation accepted")
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
