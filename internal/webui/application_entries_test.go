package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"trident/internal/project"
)

func TestConsoleEndpointsIncludesApplicationEntries(t *testing.T) {
	source := t.TempDir()
	files := map[string]string{
		"public/index.php": `<?php
require __DIR__ . '/../thinkphp/start.php';
$app = new think\App();
$app->run();
`,
		"public/router.php": `<?php
if (is_file($_SERVER['DOCUMENT_ROOT'] . $_SERVER['PATH_INFO'])) {
    return false;
}
require __DIR__ . '/index.php';
`,
		"vendor/example/index.php": `<?php
// Dependency example must not be reported.
`,
		"public/request.php": `<?php
$id = $_POST['id'];
`,
	}
	for name, content := range files {
		full := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	destination := filepath.Join(t.TempDir(), "snapshot")
	imported, err := project.Import(context.Background(), source, destination)
	if err != nil {
		t.Fatal(err)
	}
	console, err := New(context.Background(), Options{SnapshotDir: destination, SnapshotHash: imported.Hash, Token: "test-token-0123456789abcdef", Version: "test-build"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = console.Close() })

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
	if endpoints.Total != 0 {
		t.Fatalf("PHP snapshot must not invent Java endpoints: %+v", endpoints)
	}
	if len(endpoints.ApplicationEntries) != 3 {
		t.Fatalf("application entries: %+v", endpoints.ApplicationEntries)
	}
	byPath := map[string]string{}
	for _, entry := range endpoints.ApplicationEntries {
		byPath[entry.Path] = entry.Framework
	}
	if byPath["public/index.php"] != "ThinkPHP" {
		t.Fatalf("PHP entry framework: %+v", endpoints.ApplicationEntries)
	}
	if byPath["public/request.php"] != "PHP" {
		t.Fatalf("PHP request script framework: %+v", endpoints.ApplicationEntries)
	}
	if _, ok := byPath["vendor/example/index.php"]; ok {
		t.Fatalf("vendor entry leaked: %+v", endpoints.ApplicationEntries)
	}
	if endpoints.EntryTotal != 3 || len(endpoints.Entries) != 3 {
		t.Fatalf("unified entries: total=%d entries=%+v", endpoints.EntryTotal, endpoints.Entries)
	}
	requestScripts := 0
	for _, entry := range endpoints.Entries {
		if entry.Source != "application_entry" || entry.PathStatus != "not_applicable" {
			t.Fatalf("unified application entry: %+v", entry)
		}
		switch entry.Kind {
		case "application_entry":
			if entry.Authz != nil {
				t.Fatalf("application entry must not receive request-script authz: %+v", entry)
			}
		case "request_script":
			requestScripts++
			if entry.Confidence != "request_script_heuristic" {
				t.Fatalf("request script confidence: %+v", entry)
			}
			if entry.Authz == nil || entry.Authz.Decision != "unprotected" ||
				entry.Authz.Reason != "php_script_no_recognized_guard_before_request_access" {
				t.Fatalf("request script authz missing: %+v", entry)
			}
		default:
			t.Fatalf("unexpected unified entry kind: %+v", entry)
		}
	}
	if requestScripts != 1 {
		t.Fatalf("request scripts: %d entries=%+v", requestScripts, endpoints.Entries)
	}
	if len(endpoints.EntryCoverage) == 0 {
		t.Fatalf("unified coverage missing: %+v", endpoints)
	}
	if len(endpoints.EntryLimitations) == 0 {
		t.Fatalf("unified limitations missing: %+v", endpoints)
	}

	response, body = c.do(http.MethodGet, "/api/overview", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("overview: %d %s", response.StatusCode, body)
	}
	var overview overviewResponse
	if err := json.Unmarshal(body, &overview); err != nil {
		t.Fatal(err)
	}
	if overview.Analysis.ApplicationEntries != 3 || overview.Analysis.ApplicationEntryLangs != 1 {
		t.Fatalf("overview entry summary: %+v", overview.Analysis)
	}
}
