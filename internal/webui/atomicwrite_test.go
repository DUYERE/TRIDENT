package webui

import (
	"os"
	"path/filepath"
	"testing"
)

// A fixed temp name is a local-attacker primitive: pre-creating
// "console.json.tmp" as a hard link to another file makes the save write
// through it and truncate the victim. The save path must not reuse a
// predictable temp name.
func TestSaveWorkspaceConfigDoesNotFollowExistingTempLink(t *testing.T) {
	workspace := t.TempDir()
	victim := filepath.Join(workspace, "victim.txt")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, workspaceConfigPath(workspace)+".tmp"); err != nil {
		t.Skipf("hard link unsupported here: %v", err)
	}
	if err := saveWorkspaceConfig(workspace, workspaceFile{AdvisoryPath: "advisory.json"}); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(victim); err != nil || string(content) != "keep" {
		t.Fatalf("victim file was overwritten through the predictable temp link: %q %v", content, err)
	}
}

func TestSaveModelKeysDoesNotFollowExistingTempLink(t *testing.T) {
	workspace := t.TempDir()
	victim := filepath.Join(workspace, "victim.txt")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, modelKeysPath(workspace)+".tmp"); err != nil {
		t.Skipf("hard link unsupported here: %v", err)
	}
	if err := saveModelKeys(workspace, map[string]string{"profile-1": "sk-test"}); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(victim); err != nil || string(content) != "keep" {
		t.Fatalf("victim file was overwritten through the predictable temp link: %q %v", content, err)
	}
	keys, err := loadModelKeys(workspace)
	if err != nil || keys["profile-1"] != "sk-test" {
		t.Fatalf("keys were not saved: %v %v", keys, err)
	}
}
