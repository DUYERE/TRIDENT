package r3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultPolicyBoundsPatch(t *testing.T) {
	policy := DefaultPolicy()
	patch := "--- a/src/A.java\n+++ b/src/A.java\n@@ -1,1 +1,1 @@\n-old\n+new\n"
	result := PatchResult{Files: []FileChange{{Path: "src/A.java", Additions: 1, Deletions: 1}}}
	if err := policy.ValidatePatch(patch, result); err != nil {
		t.Fatalf("valid patch rejected: %v", err)
	}
	forbidden := "--- a/src/A.java\n+++ b/src/A.java\n@@ -1,1 +1,1 @@\n-old\n+Runtime.getRuntime().exec(cmd);\n"
	if err := policy.ValidatePatch(forbidden, result); err == nil {
		t.Fatal("forbidden added API accepted")
	}
	tooMany := PatchResult{Files: make([]FileChange, policy.MaxFiles+1)}
	if err := policy.ValidatePatch(patch, tooMany); err == nil {
		t.Fatal("file count bound not enforced")
	}
	tooLarge := PatchResult{Files: []FileChange{{Path: "src/A.java", Additions: policy.MaxChangedLines + 1}}}
	if err := policy.ValidatePatch(patch, tooLarge); err == nil {
		t.Fatal("changed-line bound not enforced")
	}
}

func TestLoadPolicyStrictAndBounded(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "policy.json")
	content := `{"schema_version":1,"max_files":2,"max_changed_lines":20,"forbidden_patterns":["(?i)Runtime"],"preferred_strategies":{"sql":"parameterize"},"require_validation":true}`
	if err := os.WriteFile(valid, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := LoadPolicy(valid)
	if err != nil || policy.MaxFiles != 2 || policy.PreferredStrategies["sql"] != "parameterize" {
		t.Fatalf("load: %+v %v", policy, err)
	}
	unknown := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(unknown, []byte(strings.Replace(content, `"max_files":2`, `"max_files":2,"unexpected":true`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(unknown); err == nil {
		t.Fatal("unknown policy field accepted")
	}
	invalid := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalid, []byte(`{"schema_version":1,"max_files":0,"max_changed_lines":20,"forbidden_patterns":[],"preferred_strategies":{},"require_validation":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(invalid); err == nil {
		t.Fatal("invalid policy bounds accepted")
	}
}
