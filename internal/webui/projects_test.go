package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func fixtureSource(t *testing.T, name string) string {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(source); err != nil || !info.IsDir() {
		t.Fatalf("fixture %s is missing: %v", name, err)
	}
	return source
}

func newEmptyWorkspaceConsole(t *testing.T) (*Console, string) {
	t.Helper()
	workspace := t.TempDir()
	console, err := New(context.Background(), Options{
		Token: "test-token-0123456789abcdef", Version: "test-build", Workspace: workspace,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = console.Close() })
	return console, workspace
}

// A workspace console may start with no project: project management stays
// reachable, analysis routes answer 409 instead of dereferencing a nil snapshot.
func TestWorkspaceConsoleStartsWithNoProject(t *testing.T) {
	console, _ := newEmptyWorkspaceConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/config", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("config without project: %d %s", response.StatusCode, body)
	}
	var config struct {
		Mode    string `json:"mode"`
		Project struct {
			Hash string `json:"hash"`
		} `json:"project"`
		Features struct {
			ProjectImport bool `json:"project_import"`
		} `json:"features"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatal(err)
	}
	if config.Mode != "workspace" || config.Project.Hash != "" || !config.Features.ProjectImport {
		t.Fatalf("unexpected empty-workspace config: %+v", config)
	}

	response, body = c.do(http.MethodGet, "/api/overview", true, true)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("analysis without project must be 409, got %d %s", response.StatusCode, body)
	}
	var failure struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &failure); err != nil || failure.Code != "no_project" {
		t.Fatalf("expected no_project code: %s", body)
	}

	response, body = c.do(http.MethodGet, "/api/projects", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("projects list: %d %s", response.StatusCode, body)
	}
	var list struct {
		Total    int `json:"total"`
		Projects []struct {
			Hash string `json:"hash"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 0 || len(list.Projects) != 0 {
		t.Fatalf("empty workspace must list no projects: %+v", list)
	}

	response, body = c.do(http.MethodGet, "/api/fs", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("filesystem picker must work before the first import: %d %s", response.StatusCode, body)
	}
}

func TestProjectImportSelectAndForget(t *testing.T) {
	console, _ := newEmptyWorkspaceConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	first := fixtureSource(t, "java-maven")
	second := fixtureSource(t, "java-ast-model")

	response, body := c.postJSON("/api/projects", map[string]string{"source": first})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("import first: %d %s", response.StatusCode, body)
	}
	var imported struct {
		Project projectEntry `json:"project"`
	}
	if err := json.Unmarshal(body, &imported); err != nil {
		t.Fatal(err)
	}
	if imported.Project.Hash == "" || imported.Project.Files == 0 || imported.Project.Source != first {
		t.Fatalf("unexpected import result: %+v", imported.Project)
	}
	firstHash := imported.Project.Hash

	// The console must serve analysis immediately after the import.
	response, body = c.do(http.MethodGet, "/api/overview", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("overview after import: %d %s", response.StatusCode, body)
	}

	response, body = c.postJSON("/api/projects", map[string]string{"source": second})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("import second: %d %s", response.StatusCode, body)
	}
	var secondImport struct {
		Project projectEntry `json:"project"`
	}
	if err := json.Unmarshal(body, &secondImport); err != nil {
		t.Fatal(err)
	}
	if secondImport.Project.Hash == firstHash {
		t.Fatal("distinct sources must produce distinct snapshots")
	}

	response, body = c.do(http.MethodGet, "/api/projects", true, true)
	var list struct {
		Current  string         `json:"current"`
		Total    int            `json:"total"`
		Projects []projectEntry `json:"projects"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 2 || list.Current != secondImport.Project.Hash || list.Projects[0].Hash != secondImport.Project.Hash {
		t.Fatalf("registry must list both projects with the newest current: %+v", list)
	}

	// Switching back must reuse the existing snapshot instead of re-importing.
	response, body = c.postJSON("/api/projects/select", map[string]string{"hash": firstHash})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("select first: %d %s", response.StatusCode, body)
	}
	response, body = c.do(http.MethodGet, "/api/config", true, true)
	var config struct {
		Project struct {
			Hash  string `json:"hash"`
			Files int    `json:"files"`
		} `json:"project"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatal(err)
	}
	if config.Project.Hash != firstHash || config.Project.Files != imported.Project.Files {
		t.Fatalf("switch did not take effect: %+v", config.Project)
	}

	// Forgetting keeps snapshot files and refuses to drop the active project.
	response, body = c.postJSON("/api/projects/forget", map[string]string{"hash": secondImport.Project.Hash})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("forget inactive: %d %s", response.StatusCode, body)
	}
	response, body = c.postJSON("/api/projects/forget", map[string]string{"hash": firstHash})
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("forget active must be rejected: %d %s", response.StatusCode, body)
	}
	if _, err := os.Stat(filepath.Join(console.workspace, "snapshots", secondImport.Project.Hash)); err != nil {
		t.Fatalf("forget must not delete snapshot files: %v", err)
	}
}

func TestFilesystemPickerRejectsInvalidPaths(t *testing.T) {
	console, _ := newEmptyWorkspaceConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/fs?path="+filepath.Join(t.TempDir(), "absent"), true, true)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing directory must be 400: %d %s", response.StatusCode, body)
	}
	// A file path must be rejected as well: the picker only walks directories.
	file := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	response, body = c.do(http.MethodGet, "/api/fs?path="+file, true, true)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("file path must be 400: %d %s", response.StatusCode, body)
	}
}
