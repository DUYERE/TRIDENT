package authz

import (
	"context"
	"strings"
	"testing"
)

func TestPHPScriptAuthzDecisions(t *testing.T) {
	report, err := Analyze(context.Background(), fixtureSnapshotNamed(t, "php-script-authz"))
	if err != nil {
		t.Fatal(err)
	}
	scripts := map[string]LanguageAdapter{}
	for _, adapter := range report.LanguageAdapters {
		if adapter.Language == "php" && adapter.Scope == "request_script" {
			scripts[adapter.File] = adapter
		}
	}
	want := map[string]struct {
		decision    string
		requirement string
		control     string
		line        int
		reason      string
	}{
		"public/protected.php":    {"protected", RequirementAuthenticated, "session_guard", 7, "php_script_guard_before_request_access"},
		"public/public.php":       {"public", RequirementPublic, "explicit_public", 3, "php_script_explicit_public_marker"},
		"public/open.php":         {"unprotected", RequirementUnknown, "none", 2, "php_script_no_recognized_guard_before_request_access"},
		"public/late.php":         {"unknown", RequirementUnknown, "none", 2, "php_script_guard_after_request_access"},
		"public/require-auth.php": {"protected", RequirementAuthenticated, "auth_file", 3, "php_script_guard_before_request_access"},
		"public/role.php":         {"protected", RequirementRole, "role_check", 6, "php_script_guard_before_request_access"},
		"public/permission.php":   {"protected", RequirementRole, "permission_check", 5, "php_script_guard_before_request_access"},
		"public/conflict.php":     {"unknown", RequirementUnknown, "none", 6, "php_script_conflicting_controls"},
		"public/same-line.php":    {"unknown", RequirementUnknown, "none", 1, "php_script_guard_at_request_line"},
	}
	if len(scripts) != len(want) {
		t.Fatalf("php scripts=%d want=%d all=%+v", len(scripts), len(want), report.LanguageAdapters)
	}
	for file, expected := range want {
		adapter, ok := scripts[file]
		if !ok {
			t.Fatalf("missing %s in %+v", file, scripts)
		}
		if adapter.Decision != expected.decision || adapter.Requirement != expected.requirement ||
			adapter.Control != expected.control || adapter.Line != expected.line || adapter.Reason != expected.reason {
			t.Fatalf("%s = %+v, want %+v", file, adapter, expected)
		}
		if expected.decision == "protected" && adapter.ControlLine == 0 {
			t.Fatalf("%s missing control line: %+v", file, adapter)
		}
	}
	if _, ok := scripts["public/no-request.php"]; ok {
		t.Fatalf("file without request access received a script decision: %+v", scripts["public/no-request.php"])
	}
	if _, ok := scripts["public/static/lib.php"]; ok {
		t.Fatalf("static library received a script decision: %+v", scripts["public/static/lib.php"])
	}
	if _, ok := scripts["public/thinkphp/library/think/Request.php"]; ok {
		t.Fatalf("framework library received a script decision: %+v", scripts["public/thinkphp/library/think/Request.php"])
	}
	for _, wantLimit := range []string{"php_script_authz_file_local", "php_script_unprotected_inconclusive"} {
		found := false
		for _, limitation := range report.Limitations {
			if strings.HasPrefix(limitation, wantLimit) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing limitation %s: %+v", wantLimit, report.Limitations)
		}
	}
}

func TestLanguageAuthAdaptersFixture(t *testing.T) {
	report, err := Analyze(context.Background(), fixtureSnapshotNamed(t, "multi-authz"))
	if err != nil {
		t.Fatal(err)
	}
	if report.Coverage.LanguageFilesScanned < 5 {
		t.Fatalf("language files = %d", report.Coverage.LanguageFilesScanned)
	}
	if len(report.LanguageAdapters) < 5 {
		t.Fatalf("language adapters = %+v", report.LanguageAdapters)
	}
	seen := map[string]LanguageAdapter{}
	for _, adapter := range report.LanguageAdapters {
		seen[adapter.Language] = adapter
		if adapter.Decision != "protected" && adapter.Decision != "public" && adapter.Decision != "unprotected" && adapter.Decision != "unknown" {
			t.Fatalf("invalid decision: %+v", adapter)
		}
	}
	for _, language := range []string{"php", "csharp", "python", "javascript", "go"} {
		if _, ok := seen[language]; !ok {
			t.Fatalf("missing %s adapter: %+v", language, report.LanguageAdapters)
		}
	}
}

// A plain class with public methods is not a route. Treating it as one floods
// /api/authz with "unprotected" model files that are never HTTP entries.
func TestPHPRoutePatternSkipsPlainClassMethods(t *testing.T) {
	for _, content := range []string{
		"<?php\nclass Admin extends Model {\n    public function index() { }\n}\n",
		"<?php\nclass Admin {\n    public function save($data) { return $data; }\n}\n",
	} {
		if languageHasRoute("php", content) {
			t.Fatalf("plain class method treated as a route: %q", content)
		}
	}
	for _, content := range []string{
		"<?php\nRoute::rule('reports/archive', 'Reports/archive');\n",
		"<?php\nreturn $this->fetch('reports/archive');\n",
	} {
		if !languageHasRoute("php", content) {
			t.Fatalf("route declaration not recognized: %q", content)
		}
	}
}
