package webui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"trident/internal/findings"
	"trident/internal/project"
)

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func writeFixture(t *testing.T) (string, string, string) {
	t.Helper()
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	javaDir := filepath.Join(source, "src", "main", "java", "demo")
	if err := os.MkdirAll(javaDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pom := `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>demo</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency>
  </dependencies>
</project>`
	controller := `package demo;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
@RestController
public class App {
    private Connection connection;
    @GetMapping("/users")
    public void users(@RequestParam("name") String name) throws Exception {
        Statement statement = connection.createStatement();
        statement.executeQuery("SELECT * FROM users WHERE name='" + name + "'");
    }
}
`
	if err := os.WriteFile(filepath.Join(source, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(javaDir, "App.java"), []byte(controller), 0o600); err != nil {
		t.Fatal(err)
	}
	advisory, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "java-maven", "advisories", "CVE-2022-42889.json"))
	if err != nil {
		t.Fatal(err)
	}
	advisoryPath := filepath.Join(parent, "advisory.json")
	if err = os.WriteFile(advisoryPath, advisory, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "snapshot")
	result, err := project.Import(context.Background(), source, destination)
	if err != nil {
		t.Fatal(err)
	}
	return destination, advisoryPath, result.Hash
}

func newTestConsole(t *testing.T) (*Console, string) {
	t.Helper()
	destination, advisoryPath, hash := writeFixture(t)
	console, err := New(context.Background(), Options{SnapshotDir: destination, SnapshotHash: hash, AdvisoryPath: advisoryPath, Token: "test-token-0123456789abcdef", Version: "test-build"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = console.Close() })
	return console, hash
}

type client struct {
	t      *testing.T
	server *httptest.Server
	token  string
}

func (c *client) do(method, path string, token, consoleHeader bool) (*http.Response, []byte) {
	c.t.Helper()
	request, err := http.NewRequest(method, c.server.URL+path, nil)
	if err != nil {
		c.t.Fatal(err)
	}
	if token {
		request.Header.Set(TokenHeader, c.token)
	}
	if consoleHeader {
		request.Header.Set(RequestHeader, "console")
	}
	response, err := c.server.Client().Do(request)
	if err != nil {
		c.t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		c.t.Fatal(err)
	}
	return response, body
}

func TestConsoleRequiresTokenAndConsoleHeader(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/overview", false, false)
	if response.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "unauthorized") {
		t.Fatalf("missing token: %d %s", response.StatusCode, body)
	}
	response, _ = c.do(http.MethodGet, "/api/overview", true, false)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("missing console header: %d", response.StatusCode)
	}
	response, _ = c.do(http.MethodGet, "/api/overview", false, true)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("header without token: %d", response.StatusCode)
	}
	response, body = c.do(http.MethodGet, "/api/overview", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authorized overview: %d %s", response.StatusCode, body)
	}
}

func TestConsoleServesAssetsWithSecurityHeaders(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/", false, false)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "TRIDENT") {
		t.Fatalf("index: %d", response.StatusCode)
	}
	if response.Header.Get("Content-Security-Policy") == "" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("security headers missing: %v", response.Header)
	}
	response, body = c.do(http.MethodGet, "/assets/app.js", false, false)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "read-only console") {
		t.Fatalf("app.js: %d", response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Fatalf("js content type: %s", response.Header.Get("Content-Type"))
	}
	for _, asset := range []string{"/assets/brand.png", "/assets/favicon.png"} {
		response, body = c.do(http.MethodGet, asset, false, false)
		if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "image/png" || len(body) < 512 {
			t.Fatalf("brand asset %s: %d %q %d bytes", asset, response.StatusCode, response.Header.Get("Content-Type"), len(body))
		}
	}
	response, _ = c.do(http.MethodGet, "/assets/", false, false)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("directory listing must be rejected: %d", response.StatusCode)
	}
	response, _ = c.do(http.MethodGet, "/assets/../index.html", false, false)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("asset traversal must be rejected: %d", response.StatusCode)
	}
}

func TestConsoleSessionCookie(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()

	body := strings.NewReader(`{"token":"wrong-token-0123456789"}`)
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/session", body)
	request.Header.Set(RequestHeader, "console")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", response.StatusCode)
	}

	trailing := strings.NewReader(`{"token":"` + console.Token() + `"}{"token":"again"}`)
	request, _ = http.NewRequest(http.MethodPost, server.URL+"/api/session", trailing)
	request.Header.Set(RequestHeader, "console")
	request.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("trailing session payload: %d", response.StatusCode)
	}

	body = strings.NewReader(`{"token":"` + console.Token() + `"}`)
	request, _ = http.NewRequest(http.MethodPost, server.URL+"/api/session", body)
	request.Header.Set(RequestHeader, "console")
	request.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("session: %d", response.StatusCode)
	}
	cookies := response.Cookies()
	if len(cookies) != 1 || cookies[0].Name != SessionCookie || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie: %+v", cookies)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/health", nil)
	request.Header.Set(RequestHeader, "console")
	request.AddCookie(cookies[0])
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(payload), `"status":"ok"`) {
		t.Fatalf("cookie health: %d %s", response.StatusCode, payload)
	}
}

func TestConsoleOverviewAndFindings(t *testing.T) {
	console, hash := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/overview", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("overview: %d %s", response.StatusCode, body)
	}
	var overview overviewResponse
	if err := json.Unmarshal(body, &overview); err != nil {
		t.Fatal(err)
	}
	if overview.Snapshot.Hash != hash || overview.Snapshot.TotalFiles != 2 {
		t.Fatalf("snapshot: %+v", overview.Snapshot)
	}
	if overview.Counts.Total != 3 || overview.Counts.Confirmed != 1 || overview.Counts.Inconclusive != 2 {
		t.Fatalf("counts: %+v", overview.Counts)
	}
	if overview.Analysis.RuntimeStatus != "not_run" || overview.Analysis.ToolVersions.Findings == "" {
		t.Fatalf("analysis: %+v", overview.Analysis)
	}
	categories := map[string]categorySummary{}
	for _, category := range overview.Categories {
		categories[category.Key] = category
	}
	if categories["sql"].Confirmed != 1 || categories["dependency"].Total != 1 || categories["authz"].Total != 1 {
		t.Fatalf("categories: %+v", categories)
	}

	response, body = c.do(http.MethodGet, "/api/findings?status=static_confirmed&limit=10", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("findings: %d %s", response.StatusCode, body)
	}
	var list findingsResponse
	var err error
	if err = json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	// The findings page merges the multi-language rule report; this fixture's
	// App.java triggers one code finding besides the dataflow one.
	if list.Filtered != 2 {
		t.Fatalf("confirmed list: %+v", list)
	}
	seenKinds := map[string]bool{}
	for _, item := range list.Items {
		if item.Status != "static_confirmed" {
			t.Fatalf("non-confirmed item in confirmed list: %+v", item)
		}
		seenKinds[item.Kind] = true
	}
	if !seenKinds["sql_injection"] || !seenKinds["java.sql.statement"] {
		t.Fatalf("dataflow/code merge incomplete: %+v", list)
	}
	response, body = c.do(http.MethodGet, "/api/findings?category=dependency", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dependency filter: %d", response.StatusCode)
	}
	if err = json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Filtered != 1 || list.Items[0].Kind != "vulnerable_dependency" {
		t.Fatalf("dependency list: %+v", list)
	}
	response, body = c.do(http.MethodGet, "/api/findings?q=commons-text", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("query filter: %d", response.StatusCode)
	}
	if err = json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Filtered != 1 || list.Items[0].Component == nil {
		t.Fatalf("query list: %+v", list)
	}

	findingID := list.Items[0].ID
	response, body = c.do(http.MethodGet, "/api/finding?id="+url.QueryEscape(findingID), true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("finding detail: %d %s", response.StatusCode, body)
	}
	var finding findings.Finding
	if err = json.Unmarshal(body, &finding); err != nil {
		t.Fatal(err)
	}
	if finding.RuntimeStatus != "not_run" || len(finding.Evidence) == 0 || len(finding.Hypotheses) == 0 {
		t.Fatalf("finding detail payload: %+v", finding)
	}
	response, _ = c.do(http.MethodGet, "/api/finding?id=missing", true, true)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("missing finding: %d", response.StatusCode)
	}
}

func TestConsoleEndpointsAndDependencies(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/endpoints", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("endpoints: %d %s", response.StatusCode, body)
	}
	var endpoints endpointsResponse
	if err := json.Unmarshal(body, &endpoints); err != nil {
		t.Fatal(err)
	}
	if endpoints.Total != 1 || endpoints.Items[0].Path != "/users" || endpoints.Items[0].Parameters[0].BindingName != "name" {
		t.Fatalf("endpoint payload: %+v", endpoints)
	}
	if endpoints.EntryTotal < 1 || len(endpoints.Entries) == 0 {
		t.Fatalf("unified endpoint evidence missing: %+v", endpoints)
	}
	foundAnnotation := false
	for _, item := range endpoints.Entries {
		if item.Kind == "annotation_route" && item.Path == "/users" {
			foundAnnotation = true
		}
	}
	if !foundAnnotation {
		t.Fatalf("unified Java annotation missing: %+v", endpoints.Entries)
	}

	response, body = c.do(http.MethodGet, "/api/dependencies", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dependencies: %d %s", response.StatusCode, body)
	}
	var dependencies dependenciesResponse
	if err := json.Unmarshal(body, &dependencies); err != nil {
		t.Fatal(err)
	}
	if dependencies.Report.Project.BuildSystem != "Maven" || len(dependencies.Report.Dependencies) != 1 {
		t.Fatalf("dependency report: %+v", dependencies.Report)
	}
	if dependencies.Report.Dependencies[0].ArtifactID != "commons-text" || dependencies.Report.Dependencies[0].Version != "1.9" {
		t.Fatalf("dependency: %+v", dependencies.Report.Dependencies[0])
	}
	if len(dependencies.Report.AdvisoryMatches) != 1 || dependencies.Report.AdvisoryMatches[0].FindingStatus != "candidate" {
		t.Fatalf("advisory matches: %+v", dependencies.Report.AdvisoryMatches)
	}
}

func TestConsoleFilesSearchAndReport(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/files?limit=10", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("files: %d %s", response.StatusCode, body)
	}
	var list project.ListResult
	var err error
	if err = json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 2 || len(list.Entries) != 2 {
		t.Fatalf("file list: %+v", list)
	}

	response, body = c.do(http.MethodGet, "/api/file?path=pom.xml&limit=5", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("read: %d %s", response.StatusCode, body)
	}
	var read project.ReadResult
	if err := json.Unmarshal(body, &read); err != nil {
		t.Fatal(err)
	}
	if read.Path != "pom.xml" || len(read.Lines) == 0 || read.SHA256 == "" {
		t.Fatalf("read payload: %+v", read)
	}

	response, _ = c.do(http.MethodGet, "/api/file?path="+url.QueryEscape("../pom.xml"), true, true)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("traversal: %d", response.StatusCode)
	}
	response, _ = c.do(http.MethodGet, "/api/file?path=missing.java", true, true)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("missing file: %d", response.StatusCode)
	}

	response, body = c.do(http.MethodGet, "/api/search?q=RestController", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("search: %d %s", response.StatusCode, body)
	}
	var search project.SearchResult
	if err = json.Unmarshal(body, &search); err != nil {
		t.Fatal(err)
	}
	if len(search.Matches) == 0 || search.Matches[0].Path != "src/main/java/demo/App.java" {
		t.Fatalf("search payload: %+v", search)
	}

	response, body = c.do(http.MethodGet, "/api/report", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("report: %d", response.StatusCode)
	}
	if !strings.Contains(response.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("report disposition: %s", response.Header.Get("Content-Disposition"))
	}
	var report findings.Report
	if err = json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.Coverage.FindingsTotal != 3 {
		t.Fatalf("report coverage: %+v", report.Coverage)
	}

	response, body = c.do(http.MethodGet, "/api/sbom", true, true)
	if response.StatusCode != http.StatusOK || !strings.Contains(response.Header.Get("Content-Disposition"), ".cdx.json") {
		t.Fatalf("sbom: %d %s", response.StatusCode, response.Header.Get("Content-Disposition"))
	}
	var document struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []any  `json:"components"`
	}
	if err = json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	if document.BOMFormat != "CycloneDX" || document.SpecVersion != "1.5" || len(document.Components) != 1 {
		t.Fatalf("sbom payload: %+v", document)
	}

	response, _ = c.do(http.MethodGet, "/api/findings?limit=0", true, true)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid limit: %d", response.StatusCode)
	}
}

func TestConsoleCachesAnalysisConcurrently(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()

	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			request, err := http.NewRequest(http.MethodGet, server.URL+"/api/overview", nil)
			if err != nil {
				t.Errorf("concurrent request: %v", err)
				return
			}
			request.Header.Set(TokenHeader, console.Token())
			request.Header.Set(RequestHeader, "console")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Errorf("concurrent overview: %v", err)
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Errorf("concurrent overview status: %d", response.StatusCode)
			}
		}()
	}
	wait.Wait()
}

func writeTokenFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// Force a distinct mtime signature so the reload check cannot miss the
	// rewrite even on filesystems with coarse timestamps.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleTokenFileRotationAndAuditLog(t *testing.T) {
	destination, advisoryPath, hash := writeFixture(t)
	parent := filepath.Dir(destination)
	tokensPath := filepath.Join(parent, "tokens.json")
	logPath := filepath.Join(parent, "access.log")
	writeTokenFile(t, tokensPath, `[
		{"id":"alice","role":"reviewer","token_hash":"`+tokenHash("alice-token-0123456789")+`"},
		{"id":"bob","role":"auditor","token_hash":"`+tokenHash("bob-token-0123456789")+`"}
	]`)
	console, err := New(context.Background(), Options{SnapshotDir: destination, SnapshotHash: hash, AdvisoryPath: advisoryPath, TokensFile: tokensPath, AccessLog: logPath, Version: "test-build"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = console.Close() }()
	if !console.MultiToken() || console.Token() != "" {
		t.Fatalf("file mode must not expose a plaintext token: multi=%v token=%q", console.MultiToken(), console.Token())
	}
	server := httptest.NewServer(console.Handler())
	defer server.Close()

	request := func(token, path string) (*http.Response, []byte) {
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set(TokenHeader, token)
		}
		req.Header.Set(RequestHeader, "console")
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return response, body
	}

	if response, _ := request("alice-token-0123456789", "/api/overview"); response.StatusCode != http.StatusOK {
		t.Fatalf("alice overview: %d", response.StatusCode)
	}
	if response, _ := request("bob-token-0123456789", "/api/health"); response.StatusCode != http.StatusOK {
		t.Fatalf("bob health: %d", response.StatusCode)
	}
	if response, _ := request("charlie-token-0123456789", "/api/overview"); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown user must be rejected: %d", response.StatusCode)
	}
	if response, _ := request("", "/api/overview"); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token must be rejected: %d", response.StatusCode)
	}

	// Rotation: alice gets a new hash, bob is revoked, carol joins.
	writeTokenFile(t, tokensPath, `[
		{"id":"alice","role":"reviewer","token_hash":"`+tokenHash("alice-token-rotated-123456")+`"},
		{"id":"carol","role":"reviewer","token_hash":"`+tokenHash("carol-token-0123456789")+`"}
	]`)
	if response, _ := request("alice-token-0123456789", "/api/overview"); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("rotated-out token must be rejected: %d", response.StatusCode)
	}
	if response, _ := request("bob-token-0123456789", "/api/overview"); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token must be rejected: %d", response.StatusCode)
	}
	if response, _ := request("alice-token-rotated-123456", "/api/overview"); response.StatusCode != http.StatusOK {
		t.Fatalf("rotated-in token must be accepted: %d", response.StatusCode)
	}
	if response, _ := request("carol-token-0123456789", "/api/overview"); response.StatusCode != http.StatusOK {
		t.Fatalf("added user must be accepted: %d", response.StatusCode)
	}
	ids := console.TokenIDs()
	if len(ids) != 2 || ids[0] != "alice" || ids[1] != "carol" {
		t.Fatalf("token ids after rotation: %v", ids)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logged := string(data)
	var records []struct {
		Time    string `json:"time"`
		TokenID string `json:"token_id"`
		Method  string `json:"method"`
		Path    string `json:"path"`
		Status  int    `json:"status"`
	}
	for _, line := range strings.Split(strings.TrimSpace(logged), "\n") {
		var record struct {
			Time    string `json:"time"`
			TokenID string `json:"token_id"`
			Method  string `json:"method"`
			Path    string `json:"path"`
			Status  int    `json:"status"`
		}
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			t.Fatalf("access log line %q: %v", line, err)
		}
		if decoder.More() {
			t.Fatalf("access log line must be a single JSON object: %q", line)
		}
		records = append(records, record)
	}
	seen := map[string]bool{}
	for _, record := range records {
		if record.Time == "" || record.Method == "" || record.Path == "" || record.Status == 0 {
			t.Fatalf("incomplete access record: %+v", record)
		}
		if strings.Contains(record.Path, "?") {
			t.Fatalf("access record must not contain a query string: %+v", record)
		}
		seen[record.TokenID] = true
	}
	for _, id := range []string{"alice", "carol", ""} {
		if !seen[id] {
			t.Fatalf("access log missing token_id %q: %v", id, seen)
		}
	}
	for _, secret := range []string{"alice-token-0123456789", "alice-token-rotated-123456", "bob-token-0123456789", "carol-token-0123456789"} {
		if strings.Contains(logged, secret) {
			t.Fatalf("access log must never contain a token value: %s", secret)
		}
	}
}

func TestConsoleTokenFileValidation(t *testing.T) {
	destination, advisoryPath, hash := writeFixture(t)
	parent := filepath.Dir(destination)
	tokensPath := filepath.Join(parent, "tokens.json")
	build := func(content string) error {
		writeTokenFile(t, tokensPath, content)
		console, err := New(context.Background(), Options{SnapshotDir: destination, SnapshotHash: hash, AdvisoryPath: advisoryPath, TokensFile: tokensPath, Version: "test-build"})
		if err != nil {
			return err
		}
		_ = console.Close()
		return nil
	}
	cases := map[string]string{
		"invalid json":   `[{"id":"alice","role":"reviewer","token_hash":"nothex"}]`,
		"empty array":    `[]`,
		"missing role":   `[{"id":"alice","token_hash":"` + tokenHash("x") + `"}]`,
		"bad id charset": `[{"id":"bad id","role":"reviewer","token_hash":"` + tokenHash("x") + `"}]`,
		"short hash":     `[{"id":"alice","role":"reviewer","token_hash":"` + strings.Repeat("a", 63) + `"}]`,
		"duplicate id":   `[{"id":"alice","role":"reviewer","token_hash":"` + tokenHash("x") + `"},{"id":"alice","role":"reviewer","token_hash":"` + tokenHash("y") + `"}]`,
		"duplicate hash": `[{"id":"alice","role":"reviewer","token_hash":"` + tokenHash("x") + `"},{"id":"bob","role":"reviewer","token_hash":"` + tokenHash("x") + `"}]`,
		"unknown field":  `[{"id":"alice","role":"reviewer","token_hash":"` + tokenHash("x") + `","token":"plaintext"}]`,
	}
	for name, content := range cases {
		if err := build(content); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
	if err := build(`[{"id":"alice","role":"reviewer","token_hash":"` + tokenHash("valid-token-0123456789") + `"}]`); err != nil {
		t.Fatalf("valid token file rejected: %v", err)
	}
	if _, err := New(context.Background(), Options{SnapshotDir: destination, SnapshotHash: hash, Token: "single-token-0123456789", TokensFile: tokensPath}); err == nil {
		t.Fatal("--token and --tokens must be mutually exclusive")
	}
}

func TestConsoleExportReportDeterministic(t *testing.T) {
	console, hash := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/export/report", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("export: %d %s", response.StatusCode, body)
	}
	if response.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("export content type: %s", response.Header.Get("Content-Type"))
	}
	if disposition := response.Header.Get("Content-Disposition"); !strings.Contains(disposition, "attachment") || !strings.Contains(disposition, ".html") {
		t.Fatalf("export disposition: %s", disposition)
	}
	response, second := c.do(http.MethodGet, "/export/report", true, true)
	if response.StatusCode != http.StatusOK || string(second) != string(body) {
		t.Fatalf("export must be byte-identical across requests: %d", response.StatusCode)
	}
	page := string(body)
	if !strings.Contains(page, hash[:12]) {
		t.Fatalf("export must pin the snapshot hash")
	}
	if !strings.Contains(page, "sql_injection") {
		t.Fatalf("export must contain finding details")
	}
	for _, banned := range []string{"http://", "https://", "<script", "src=\"", "generated_at"} {
		if strings.Contains(page, banned) {
			t.Fatalf("export must not contain %q", banned)
		}
	}
	if matched := regexp.MustCompile(`20\d{2}-\d{2}-\d{2}T`).FindString(page); matched != "" {
		t.Fatalf("export must not contain ISO timestamps: %s", matched)
	}
	response, _ = c.do(http.MethodGet, "/export/report", false, true)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("export without token: %d", response.StatusCode)
	}
	response, _ = c.do(http.MethodGet, "/export/report", true, false)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("export without console header: %d", response.StatusCode)
	}
}
