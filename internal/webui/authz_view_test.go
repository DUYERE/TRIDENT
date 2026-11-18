package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"trident/internal/project"
)

// newFixtureConsole imports one tests/fixtures directory and returns a console
// bound to that snapshot.
func newFixtureConsole(t *testing.T, name string) *Console {
	t.Helper()
	parent := t.TempDir()
	source := filepath.Join("..", "..", "tests", "fixtures", name)
	destination := filepath.Join(parent, "snapshot")
	result, err := project.Import(context.Background(), source, destination)
	if err != nil {
		t.Fatalf("import fixture %s: %v", name, err)
	}
	console, err := New(context.Background(), Options{
		SnapshotDir:  destination,
		SnapshotHash: result.Hash,
		Token:        "test-token-0123456789abcdef",
		Version:      "test-build",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = console.Close() })
	return console
}

// The authz page must present the same entry-level decisions as
// /api/endpoints: language adapters attach an entry kind, non-entry file
// observations are split out, and all seven languages report counts.
func TestAuthzViewAttachesLanguageAdaptersToEntries(t *testing.T) {
	console := newFixtureConsole(t, "php-script-authz")
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/authz", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authz: %d %s", response.StatusCode, body)
	}
	var view struct {
		LanguageAdapters []struct {
			Language  string `json:"language"`
			File      string `json:"file"`
			EntryKind string `json:"entry_kind"`
			Decision  string `json:"decision"`
		} `json:"language_adapters"`
		FileEvidence []struct {
			File string `json:"file"`
		} `json:"file_evidence"`
		LanguageCounts []struct {
			Language     string `json:"language"`
			Total        int    `json:"total"`
			FileEvidence int    `json:"file_evidence"`
		} `json:"language_counts"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if len(view.LanguageAdapters) == 0 {
		t.Fatalf("expected request-script adapters, got none: %s", body)
	}
	for _, adapter := range view.LanguageAdapters {
		if adapter.EntryKind == "" {
			t.Fatalf("adapter without entry kind: %+v", adapter)
		}
	}
	attached := false
	for _, adapter := range view.LanguageAdapters {
		if adapter.File != "public/protected.php" {
			continue
		}
		attached = true
		if adapter.EntryKind != "request_script" {
			t.Fatalf("protected.php entry kind = %q", adapter.EntryKind)
		}
		if adapter.Decision != "protected" {
			t.Fatalf("protected.php decision = %q", adapter.Decision)
		}
	}
	if !attached {
		t.Fatalf("public/protected.php not attached: %+v", view.LanguageAdapters)
	}
	if len(view.LanguageCounts) != 7 {
		t.Fatalf("language counts = %+v", view.LanguageCounts)
	}
	wantLanguages := map[string]bool{"java": true, "php": true, "csharp": true, "python": true, "javascript": true, "typescript": true, "go": true}
	for _, count := range view.LanguageCounts {
		if !wantLanguages[count.Language] {
			t.Fatalf("unexpected language row: %+v", count)
		}
		delete(wantLanguages, count.Language)
	}
	if len(wantLanguages) != 0 {
		t.Fatalf("missing language rows: %+v", wantLanguages)
	}
}
