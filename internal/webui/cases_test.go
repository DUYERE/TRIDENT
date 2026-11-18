package webui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/casework"
)

func writeCaseAPIFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "edu-1")
	for _, name := range []string{"findings", "evidence", "upstream"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"README.md":             "# API case\n\nSource-backed finding.\n",
		"finding.json":          `{"repository":"example/edu","vulnerable_version":"1.0.0","fixed_reference":{"version":"1.0.1"}}`,
		"findings/F-1.json":     `{"finding_id":"F-1","title":"Reports LFI","severity":"critical","status":"confirmed","runtime_proof":{"result":"VULNERABLE"}}`,
		"evidence/lfi-run.json": `{"result":"VULNERABLE","marker_observed":true}`,
		"patch.diff":            "--- a/index.php\n+++ b/index.php\n@@ -1 +1 @@\n-old\n+new\n",
		"patch_meta.json":       `{"generator":"manual","upstream_submitted":false,"checks":{"patch_apply_check":"passed","result":"FULL_CASE_VERIFIED"},"files":[{"path":"index.php"}]}`,
		"verify.log":            `{"result":"FULL_CASE_VERIFIED","patched":{"login_ok":true,"tracking_page_ok":true,"sqli_neutralized":true,"lfi_blocked":true}}`,
		"upstream/advisory.md":  "# Advisory\n",
		"upstream/repro.md":     "# Repro\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCaseAPIsAreUsableWithoutProjectAndReadOnly(t *testing.T) {
	casesRoot := writeCaseAPIFixture(t)
	workspace := t.TempDir()
	console, err := New(context.Background(), Options{
		Workspace: workspace, CasesDir: casesRoot,
		Token: "test-token-0123456789abcdef", Version: "test-build",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = console.Close() })
	server := httptest.NewServer(console.Handler())
	defer server.Close()

	do := func(method, path string, payload any) (*http.Response, []byte) {
		t.Helper()
		var body *strings.Reader
		if payload != nil {
			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			body = strings.NewReader(string(data))
		} else {
			body = strings.NewReader("")
		}
		request, err := http.NewRequest(method, server.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(TokenHeader, console.Token())
		request.Header.Set(RequestHeader, "console")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var data []byte
		data, err = io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response, data
	}

	response, body := do(http.MethodGet, "/api/cases", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("cases: %d %s", response.StatusCode, body)
	}
	var list caseListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if !list.Available || len(list.Cases) != 1 || list.Cases[0].ID != "edu-1" {
		t.Fatalf("cases response: %+v", list)
	}

	response, body = do(http.MethodGet, "/api/case?id=edu-1", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("case: %d %s", response.StatusCode, body)
	}
	var detail casework.CaseDetail
	if err := json.Unmarshal(body, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Status != "verified" || detail.Patch == nil || detail.Validation == nil {
		t.Fatalf("case detail: %+v", detail)
	}

	response, body = do(http.MethodPost, "/api/case/propose", map[string]string{"id": "edu-1"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("propose: %d %s", response.StatusCode, body)
	}
	var action caseActionResponse
	if err := json.Unmarshal(body, &action); err != nil {
		t.Fatal(err)
	}
	if action.Stage != "patch" || action.Status != "ready" || action.Patch == nil {
		t.Fatalf("propose response: %+v", action)
	}

	response, body = do(http.MethodPost, "/api/case/verify", map[string]string{"id": "edu-1"})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("verify: %d %s", response.StatusCode, body)
	}
	if err := json.Unmarshal(body, &action); err != nil {
		t.Fatal(err)
	}
	if action.Stage != "validation" || action.Status != "verified" || action.Source != "recorded" {
		t.Fatalf("verify response: %+v", action)
	}

	response, body = do(http.MethodGet, "/api/case/export?id=edu-1", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("export: %d %s", response.StatusCode, body)
	}
	var export caseExportResponse
	if err := json.Unmarshal(body, &export); err != nil {
		t.Fatal(err)
	}
	if export.Case.ID != "edu-1" || !strings.Contains(export.Patch, "+++ b/index.php") || export.UpstreamFiles["advisory.md"] == "" {
		t.Fatalf("export response: %+v", export)
	}

	response, body = do(http.MethodPost, "/api/case/propose", map[string]string{"id": "../escape"})
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid propose: %d %s", response.StatusCode, body)
	}
}
