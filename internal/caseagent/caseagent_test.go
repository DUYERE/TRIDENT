package caseagent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trident/internal/casework"
	"trident/internal/model"
	"trident/internal/project"
	"trident/internal/r3"
	"trident/internal/tools"
)

type fakeCompletion struct{}

func (fakeCompletion) Complete(context.Context, model.Request) (model.Response, error) {
	return model.Response{}, errors.New("fake model must not be called")
}

func repairFixture(t *testing.T) (workspace, snapshotDir string, registry *Registry) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "index.php"), []byte("<?php echo $x;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshotDir = filepath.Join(root, "snapshot")
	imported, err := project.Import(context.Background(), source, snapshotDir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := project.Open(context.Background(), snapshotDir, imported.Hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Close() })

	casesRoot := filepath.Join(root, "cases")
	writeRepairCase(t, casesRoot, "case-1")
	catalog := casework.NewCatalog(casesRoot, "")
	workspace = filepath.Join(root, "workspace")
	registry, err = New(Options{
		Base: tools.New(snapshot), Snapshot: snapshot, SnapshotDir: snapshotDir,
		Workspace: workspace, Catalog: catalog, Approve: true, MaxOutput: 1024,
		Client: fakeCompletion{},
		Propose: func(context.Context, *project.Snapshot, r3.CompletionClient, r3.ProposeOptions) (r3.Proposal, error) {
			fakePatch := "--- a/index.php\n+++ b/index.php\n@@ -1 +1 @@\n-<?php echo $x;\n+<?php echo htmlspecialchars($x);\n"
			return r3.Proposal{
				Patch:       fakePatch,
				PatchSHA256: patchDigest([]byte(fakePatch)),
				Files:       []r3.FileChange{{Path: "index.php"}},
			}, nil
		},
		Verify: func(ctx context.Context, opts r3.VerifyOptions) (r3.Report, error) {
			if !opts.ApproveExecution {
				t.Fatal("verify called without approval")
			}
			if !strings.Contains(opts.Workspace, filepath.Join("workspace", "repairs", "case-1", "verify")) {
				t.Fatalf("verify workspace not in Case work copy: %s", opts.Workspace)
			}
			return r3.Report{Status: r3.ValidationPassed, RuntimeStatus: "isolated_validation_only", OriginalSnapshotIntact: true, Limitations: []string{"isolated_copy_only"}}, nil
		},
		Now: func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return workspace, snapshotDir, registry
}

func writeRepairCase(t *testing.T, root, id string) {
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
	write("finding.json", `{"repository":"example/edu","vulnerable_version":"1.0.0","fixed_reference":{"version":"1.0.1"}}`)
	write("findings/F-1.json", `{"finding_id":"F-1","title":"Echo sink","severity":"high","status":"confirmed","source_evidence":[{"file":"index.php","lines":"1-1","observation":"echo executes user input"}]}`)
	write("patch.diff", "--- a/index.php\n+++ b/index.php\n@@ -1 +1 @@\n-old\n+new\n")
	write("upstream/advisory.md", "# Advisory\n")
	write("upstream/repro.md", "# Repro\n")
}

func decodeMap(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestRepairToolsRequireApprovalAndDoNotTouchDisk(t *testing.T) {
	_, _, registry := repairFixture(t)
	registry.approve = false
	for _, def := range registry.Definitions() {
		if def.Name == "propose_patch" || def.Name == "verify_patch" || def.Name == "export_case" {
			t.Fatalf("write tool exposed without approval: %s", def.Name)
		}
	}
	raw, err := registry.Execute(context.Background(), "propose_patch", json.RawMessage(`{"case_id":"case-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeMap(t, raw)["status"]; got != "approval_required" {
		t.Fatalf("status=%v want approval_required", got)
	}
	if _, err := os.Stat(filepath.Join(registry.workspace, "repairs")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unapproved tool created work directory: %v", err)
	}
}

func TestProposeVerifyExportStayInWorkCopyAndAudit(t *testing.T) {
	workspace, snapshotDir, registry := repairFixture(t)
	before, err := os.ReadFile(filepath.Join(snapshotDir, "index.php"))
	if err != nil {
		t.Fatal(err)
	}

	raw, err := registry.Execute(context.Background(), "propose_patch", json.RawMessage(`{"case_id":"case-1","goal":"fix echo"}`))
	if err != nil {
		t.Fatal(err)
	}
	proposal := decodeMap(t, raw)
	if proposal["status"] != "patch_proposed" {
		t.Fatalf("propose result: %+v", proposal)
	}
	patchPath, _ := proposal["patch_path"].(string)
	if !strings.Contains(patchPath, filepath.Join("workspace", "repairs", "case-1", "proposals")) {
		t.Fatalf("patch path escaped work copy: %s", patchPath)
	}
	if _, err := os.Stat(patchPath); err != nil {
		t.Fatal(err)
	}

	raw, err = registry.Execute(context.Background(), "verify_patch", json.RawMessage(`{"case_id":"case-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	verification := decodeMap(t, raw)
	if verification["status"] != "validation_passed" || verification["claim"] != "isolated_profile_result_only; this does not prove the vulnerability is fixed" {
		t.Fatalf("verify result: %+v", verification)
	}
	reportPath, _ := verification["report_path"].(string)
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(snapshotDir, "index.php"))
	if err != nil || string(before) != string(after) {
		t.Fatalf("pinned snapshot changed before=%q after=%q err=%v", before, after, err)
	}

	raw, err = registry.Execute(context.Background(), "export_case", json.RawMessage(`{"case_id":"case-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	exportOne := decodeMap(t, raw)
	if exportOne["status"] != "case_exported" {
		t.Fatalf("export result: %+v", exportOne)
	}
	if exportOne["patch_sha256"] != proposal["patch_sha256"] {
		t.Fatalf("export patch sha mismatch: proposal=%v export=%v", proposal["patch_sha256"], exportOne["patch_sha256"])
	}
	exportPath, _ := exportOne["export_path"].(string)
	exported, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if exportOne["export_sha256"] != patchDigest(exported) {
		t.Fatalf("export file sha mismatch: result=%v actual=%s", exportOne["export_sha256"], patchDigest(exported))
	}
	if bytes, ok := exportOne["export_bytes"].(float64); !ok || int(bytes) != len(exported) {
		t.Fatalf("export bytes mismatch: result=%v actual=%d", exportOne["export_bytes"], len(exported))
	}
	var document map[string]any
	if err := json.Unmarshal(exported, &document); err != nil {
		t.Fatal(err)
	}
	if document["patch_source"] != "case_work_copy" || document["patch"] == "" {
		t.Fatalf("export missing patch: %+v", document)
	}
	raw, err = registry.Execute(context.Background(), "export_case", json.RawMessage(`{"case_id":"case-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	exportTwo := decodeMap(t, raw)
	if exportTwo["export_path"] == exportPath {
		t.Fatal("export overwrote existing work-copy file")
	}

	audit, err := os.ReadFile(filepath.Join(workspace, "repairs", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"propose_patch", "verify_patch", "export_case", `"approval":true`} {
		if !strings.Contains(string(audit), want) {
			t.Fatalf("audit missing %s: %s", want, audit)
		}
	}
}

func TestVerifyRejectsPatchOutsideCaseWorkCopy(t *testing.T) {
	_, _, registry := repairFixture(t)
	raw, err := registry.Execute(context.Background(), "verify_patch", json.RawMessage(`{"case_id":"case-1","patch_path":"../../snapshot/index.php"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeMap(t, raw)["status"]; got != "invalid_patch_path" {
		t.Fatalf("status=%v want invalid_patch_path", got)
	}
}
