package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// postJSON sends a JSON body with the token and console header. It exists
// beside client.do because the shared helper is body-less by design.
func (c *client) postJSON(path string, payload any) (*http.Response, []byte) {
	c.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		c.t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, c.server.URL+path, bytes.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	request.Header.Set(TokenHeader, c.token)
	request.Header.Set(RequestHeader, "console")
	request.Header.Set("Content-Type", "application/json")
	response, err := c.server.Client().Do(request)
	if err != nil {
		c.t.Fatal(err)
	}
	data, err := readAll(response)
	if err != nil {
		c.t.Fatal(err)
	}
	return response, data
}

func readAll(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	buffer := new(bytes.Buffer)
	_, err := buffer.ReadFrom(response.Body)
	return buffer.Bytes(), err
}

func newWorkspaceConsole(t *testing.T) (*Console, string) {
	t.Helper()
	destination, advisoryPath, _ := writeFixture(t)
	source := filepath.Join(filepath.Dir(destination), "source")
	workspace := t.TempDir()
	snapshotDir, hash, err := ImportProject(context.Background(), workspace, source)
	if err != nil {
		t.Fatal(err)
	}
	console, err := New(context.Background(), Options{
		SnapshotDir: snapshotDir, SnapshotHash: hash, AdvisoryPath: advisoryPath,
		Token: "test-token-0123456789abcdef", Version: "test-build",
		Workspace: workspace, ProjectSource: source,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = console.Close() })
	return console, source
}

func TestConsoleExposesAuthzAndModelViews(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/authz", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authz: %d %s", response.StatusCode, body)
	}
	var authzView struct {
		Total       int              `json:"total"`
		Counts      map[string]int   `json:"counts"`
		Endpoints   []map[string]any `json:"endpoints"`
		Limitations []string         `json:"limitations"`
	}
	if err := json.Unmarshal(body, &authzView); err != nil {
		t.Fatal(err)
	}
	if authzView.Total == 0 || authzView.Counts["unprotected"] == 0 {
		t.Fatalf("expected an unprotected endpoint in the fixture: %+v", authzView.Counts)
	}
	if len(authzView.Limitations) == 0 {
		t.Fatal("authz view must carry limitations")
	}

	response, body = c.do(http.MethodGet, "/api/model?limit=10", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("model: %d %s", response.StatusCode, body)
	}
	var modelView struct {
		Enabled bool `json:"enabled"`
		Total   int  `json:"total"`
		Types   []struct {
			FQN string `json:"fqn"`
		} `json:"types"`
	}
	if err := json.Unmarshal(body, &modelView); err != nil {
		t.Fatal(err)
	}
	if !modelView.Enabled || modelView.Total != 1 || modelView.Types[0].FQN != "demo.App" {
		t.Fatalf("unexpected model view: %+v", modelView)
	}

	response, body = c.do(http.MethodGet, "/api/model/type?fqn=demo.App", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("model type: %d %s", response.StatusCode, body)
	}
	response, _ = c.do(http.MethodGet, "/api/model/type?fqn=demo.Missing", true, true)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown type must be 404, got %d", response.StatusCode)
	}
}

func TestPinnedConsoleRejectsConfigurationChanges(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.postJSON("/api/config", map[string]string{"advisories_path": ""})
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("pinned console must reject config updates: %d %s", response.StatusCode, body)
	}
	response, body = c.postJSON("/api/projects", map[string]string{"source": t.TempDir()})
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("pinned console must reject imports: %d %s", response.StatusCode, body)
	}
}

func TestWorkspaceConfigurationRoundTrip(t *testing.T) {
	console, source := newWorkspaceConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/config", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("config: %d %s", response.StatusCode, body)
	}
	var config struct {
		Mode    string `json:"mode"`
		Project struct {
			Source string `json:"source"`
			Hash   string `json:"hash"`
		} `json:"project"`
		Features struct {
			ProjectImport bool `json:"project_import"`
		} `json:"features"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatal(err)
	}
	if config.Mode != "workspace" || !config.Features.ProjectImport || config.Project.Source != source {
		t.Fatalf("unexpected workspace config: %+v", config)
	}

	// An advisory directory is accepted and counted before it is persisted.
	advisoryDir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "java-maven", "advisories", "CVE-2022-42889.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(advisoryDir, "cve.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	response, body = c.postJSON("/api/config", map[string]string{"advisories_path": advisoryDir})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("config update: %d %s", response.StatusCode, body)
	}
	var updated struct {
		Paths struct {
			AdvisoriesDir   string `json:"advisories_dir"`
			AdvisoriesCount int    `json:"advisories_count"`
		} `json:"paths"`
	}
	if err = json.Unmarshal(body, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Paths.AdvisoriesCount != 1 || updated.Paths.AdvisoriesDir != advisoryDir {
		t.Fatalf("advisory directory not applied: %+v", updated.Paths)
	}

	// A missing path must be rejected without dropping the working config.
	response, body = c.postJSON("/api/config", map[string]string{"advisories_path": filepath.Join(advisoryDir, "absent.json")})
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing advisory path must be rejected: %d %s", response.StatusCode, body)
	}
	response, body = c.do(http.MethodGet, "/api/config", true, true)
	if err = json.Unmarshal(body, &updated); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || updated.Paths.AdvisoriesCount != 1 {
		t.Fatalf("rejected update must not change stored config: %d %+v", response.StatusCode, updated.Paths)
	}

	// Re-analysis is immediate and returns the new counts.
	response, body = c.postJSON("/api/analysis/rerun", map[string]any{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("rerun: %d %s", response.StatusCode, body)
	}
	var rerun struct {
		Analysis struct {
			Findings  int `json:"findings"`
			Endpoints int `json:"endpoints"`
		} `json:"analysis"`
	}
	if err = json.Unmarshal(body, &rerun); err != nil {
		t.Fatal(err)
	}
	if rerun.Analysis.Findings == 0 || rerun.Analysis.Endpoints == 0 {
		t.Fatalf("rerun produced no analysis: %+v", rerun.Analysis)
	}

	// Importing the same source converges on the same digest and keeps serving.
	response, body = c.postJSON("/api/projects", map[string]string{"source": source})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("import: %d %s", response.StatusCode, body)
	}
	var imported struct {
		Project struct {
			Hash  string `json:"hash"`
			Files int    `json:"files"`
		} `json:"project"`
	}
	if err = json.Unmarshal(body, &imported); err != nil {
		t.Fatal(err)
	}
	if imported.Project.Hash != config.Project.Hash || imported.Project.Files == 0 {
		t.Fatalf("re-import must converge on the same snapshot: %+v", imported)
	}
	response, body = c.do(http.MethodGet, "/api/overview", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("overview after import: %d %s", response.StatusCode, body)
	}
}

func TestWorkspaceConfigPersistsAcrossRestart(t *testing.T) {
	console, source := newWorkspaceConsole(t)
	workspace := console.workspace
	server := httptest.NewServer(console.Handler())
	c := &client{t: t, server: server, token: console.Token()}

	packageMap := filepath.Join(t.TempDir(), "map.json")
	if err := os.WriteFile(packageMap, []byte(`{"schema_version":1,"dependencies":{"org.apache.commons:commons-text":["org.apache.commons.text"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	response, body := c.postJSON("/api/config", map[string]string{"package_map_path": packageMap})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("config update: %d %s", response.StatusCode, body)
	}
	server.Close()
	_ = console.Close()

	persistedSource, snapshotDir, hash, err := WorkspaceProject(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if persistedSource != source || snapshotDir == "" || hash == "" {
		t.Fatalf("project not persisted: %q %q %q", persistedSource, snapshotDir, hash)
	}
	reopened, err := New(context.Background(), Options{
		SnapshotDir: snapshotDir, SnapshotHash: hash,
		Token: "test-token-0123456789abcdef", Version: "test-build", Workspace: workspace,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.currentConfig().PackageMapPath; got != packageMap {
		t.Fatalf("package map not restored: %q", got)
	}
}
