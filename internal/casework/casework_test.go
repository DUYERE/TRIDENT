package casework

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCaseFixture(t *testing.T, root, id string) string {
	t.Helper()
	dir := filepath.Join(root, id)
	for _, name := range []string{"findings", "evidence", "upstream"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("README.md", "# Synthetic case\n\nOne source-backed finding.\n")
	write("finding.json", `{"repository":"example/edu","vulnerable_version":"1.0.0","fixed_reference":{"version":"1.0.1"}}`)
	write("findings/F-1.json", `{"finding_id":"F-1","title":"Reports LFI","severity":"critical","status":"confirmed","source_evidence":[{"file":"index.php","lines":"10-12","observation":"include path"}],"runtime_proof":{"result":"VULNERABLE"}}`)
	write("evidence/lfi-run.json", `{"result":"VULNERABLE","marker_observed":true}`)
	write("patch.diff", "--- a/index.php\n+++ b/index.php\n@@ -1 +1 @@\n-old\n+new\n")
	write("patch_meta.json", `{"generator":"manual","upstream_submitted":false,"checks":{"patch_apply_check":"passed","result":"FULL_CASE_VERIFIED"},"files":[{"path":"index.php"}]}`)
	write("verify.log", `{"result":"FULL_CASE_VERIFIED","patched":{"login_ok":true,"tracking_page_ok":true,"sqli_neutralized":true,"lfi_blocked":true}}`)
	write("upstream/advisory.md", "# Advisory\n")
	write("upstream/repro.md", "# Repro\n")
	return dir
}

func TestCatalogListsAndLoadsEvidenceChain(t *testing.T) {
	root := t.TempDir()
	writeCaseFixture(t, root, "edu-1")
	catalog := NewCatalog(root, "")
	summaries, err := catalog.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].ID != "edu-1" {
		t.Fatalf("summaries: %+v", summaries)
	}
	if summaries[0].Status != "verified" || summaries[0].FindingCount != 1 {
		t.Fatalf("summary status: %+v", summaries[0])
	}
	detail, err := catalog.Get("edu-1")
	if err != nil {
		t.Fatal(err)
	}
	if detail.Status != "verified" {
		t.Fatalf("detail status: %s", detail.Status)
	}
	if detail.Patch == nil || detail.Patch.Bytes == 0 || len(detail.Patch.Files) != 1 || detail.Patch.Files[0] != "index.php" {
		t.Fatalf("patch: %+v", detail.Patch)
	}
	if detail.Validation == nil || detail.Validation.Result != "FULL_CASE_VERIFIED" {
		t.Fatalf("validation: %+v", detail.Validation)
	}
	if detail.Upstream == nil || !detail.Upstream.Present || detail.Upstream.Submitted {
		t.Fatalf("upstream: %+v", detail.Upstream)
	}
	stages := map[string]string{}
	for _, stage := range detail.Stages {
		stages[stage.Key] = stage.Status
	}
	for key, want := range map[string]string{
		"finding": "verified", "poc": "verified", "patch": "ready",
		"validation": "verified", "upstream": "draft",
	} {
		if stages[key] != want {
			t.Fatalf("stage %s=%s want %s (%+v)", key, stages[key], want, detail.Stages)
		}
	}
}

func TestNewFindingCaseAndSaveAreWorkspaceBacked(t *testing.T) {
	workspace := t.TempDir()
	catalog := NewCatalog("", workspace)
	raw := json.RawMessage(`{"finding_id":"F-9","title":"Prompt injection","severity":"high","status":"open"}`)
	detail, err := NewFindingCase("F-9", "Finding from current snapshot", raw)
	if err != nil {
		t.Fatal(err)
	}
	if detail.ID == "" || detail.Status != "in_progress" || detail.Stages[0].Status != "verified" {
		t.Fatalf("created: %+v", detail)
	}
	if catalog.Available() != false || catalog.StoreDir == "" {
		t.Fatalf("catalog root/store: root=%q store=%q", catalog.Root, catalog.StoreDir)
	}
	saved, err := catalog.Save(detail)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(saved.ID, "finding-") || saved.Source != "workspace" {
		t.Fatalf("saved: %+v", saved)
	}
	if _, err := catalog.Save(detail); err != ErrExists {
		t.Fatalf("second save must not overwrite: %v", err)
	}
	loaded, err := catalog.Get(saved.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Title != "Finding from current snapshot" || len(loaded.RawFindings) != 1 {
		t.Fatalf("loaded: %+v", loaded)
	}
	if _, err := catalog.Get("../Escape"); err != nil {
		if err != ErrInvalid {
			t.Fatalf("traversal error: %v", err)
		}
	}
}

func TestReadFileRejectsTraversalAndStaysInsideCase(t *testing.T) {
	root := t.TempDir()
	dir := writeCaseFixture(t, root, "edu-1")
	if err := os.WriteFile(filepath.Join(filepath.Dir(dir), "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := NewCatalog(root, "")
	text, err := catalog.ReadFile("edu-1", "patch.diff")
	if err != nil || !strings.Contains(text, "+++ b/index.php") {
		t.Fatalf("read patch: %q %v", text, err)
	}
	if _, err := catalog.ReadFile("edu-1", "../secret.txt"); err != ErrInvalid {
		t.Fatalf("traversal read: %v", err)
	}
	if _, err := catalog.ReadFile("edu-1", "missing.txt"); err != ErrNotFound {
		t.Fatalf("missing read: %v", err)
	}
}
