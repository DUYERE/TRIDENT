package entry

import (
	"context"
	"strings"
	"testing"

	"trident/internal/audit"
	"trident/internal/authz"
	"trident/internal/codescan"
	"trident/internal/entrypoint"
	"trident/internal/evidence"
)

func TestBuildNormalizesEntryProviders(t *testing.T) {
	input := Input{
		JavaAudit: &audit.Report{
			Endpoints: []audit.Endpoint{{
				Path: "/users", PathStatus: "resolved", HTTPMethods: []string{"GET"},
				File: "src/App.java", Class: "Demo", Method: "users", Symbol: "Demo#users",
				SHA256: "java-sha", StartLine: 1, EndLine: 20, MethodLine: 12, Annotation: "GetMapping",
				Parameters: []audit.Parameter{{Name: "name", Type: "String", Bindings: []string{"RequestParam"}, BindingName: "name"}},
			}},
			Coverage:    audit.Coverage{JavaFilesScanned: 2, JavaFilesRejected: 1},
			Limitations: []string{"lexical_annotation_inventory_not_ast"},
		},
		Authz: &authz.Report{Endpoints: []authz.EndpointDecision{{
			Symbol: "Demo#users", Decision: "protected", Requirement: "role=admin", Reason: "matched",
			MatchedControls: []string{"security-config"}, RuntimeStatus: "not_run",
		}}},
		CodeAudit: &codescan.Report{
			Routes: []codescan.Route{{
				Language: "php", Path: "/api/upload", HTTPMethods: []string{"POST"},
				Symbol: "Route::post", File: "routes/web.php", Line: 4, Kind: "call", SHA256: "php-sha",
			}},
			Languages:   []codescan.LanguageSummary{{Language: "php", FilesScanned: 2, Routes: 1, Status: "scanned"}},
			Limitations: []string{"route_declaration_not_deployment"},
		},
		ApplicationEntries: &entrypoint.Report{Entries: []entrypoint.Entry{{
			Language: "php", Framework: "ThinkPHP", Path: "public/index.php", Line: 23,
			Reason: "known_http_entry_filename", SHA256: "entry-sha",
		}}},
	}
	report, err := NewRegistry().Build(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Entries) != 3 {
		t.Fatalf("entries: %+v", report.Entries)
	}
	byKind := map[string]evidence.Entry{}
	for _, item := range report.Entries {
		byKind[item.Kind] = item
	}
	java := byKind[evidence.KindAnnotationRoute]
	if java.Authz == nil || java.Authz.Decision != "protected" {
		t.Fatalf("java authz: %+v", java)
	}
	if len(java.Parameters) != 1 || java.Parameters[0].BindingName != "name" {
		t.Fatalf("java parameters: %+v", java.Parameters)
	}
	route := byKind[evidence.KindRouteDeclaration]
	if route.Language != "php" || route.Path != "/api/upload" || route.PathStatus != "declared" {
		t.Fatalf("route declaration: %+v", route)
	}
	app := byKind[evidence.KindApplicationEntry]
	if app.File != "public/index.php" || app.PathStatus != "not_applicable" {
		t.Fatalf("application entry: %+v", app)
	}
	if report.Partial {
		t.Fatalf("unexpected partial: %+v", report)
	}
	if len(report.Coverage) != 3 {
		t.Fatalf("coverage: %+v", report.Coverage)
	}
	if !contains(report.Limitations, "entry_normalized_from_providers") ||
		!contains(report.Limitations, "route_declaration_not_deployment") ||
		!contains(report.Limitations, "entry_candidate_not_deployed_route") {
		t.Fatalf("limitations: %+v", report.Limitations)
	}
}

func TestBuildSuppressesDuplicateRouteEvidence(t *testing.T) {
	input := Input{
		JavaAudit: &audit.Report{Endpoints: []audit.Endpoint{{
			Path: "/users", PathStatus: "resolved", HTTPMethods: []string{"GET"},
			File: "src/App.java", Class: "Demo", Method: "users", Symbol: "Demo#users",
			StartLine: 12, EndLine: 20, MethodLine: 12,
		}}},
		CodeAudit: &codescan.Report{Routes: []codescan.Route{{
			Language: "java", Path: "/users", HTTPMethods: []string{"GET"},
			Symbol: "Demo#users", File: "src/App.java", Line: 12, Kind: "annotation",
		}}},
	}
	report, err := NewRegistry().Build(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Entries) != 1 || report.Entries[0].Kind != evidence.KindAnnotationRoute {
		t.Fatalf("duplicate not suppressed: %+v", report.Entries)
	}
	if !contains(report.Limitations, "entry_duplicate_suppressed") {
		t.Fatalf("duplicate limitation missing: %+v", report.Limitations)
	}
}

func TestBuildPreservesDynamicRouteStatus(t *testing.T) {
	report, err := NewRegistry().Build(context.Background(), Input{
		CodeAudit: &codescan.Report{Routes: []codescan.Route{{
			Language: "php", Path: "<dynamic>", PathStatus: "dynamic_unresolved", Reason: "route_path_not_literal",
			Symbol: "Route::rule", File: "app/route.php", Line: 13, Kind: "call",
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Entries) != 1 {
		t.Fatalf("entries = %+v", report.Entries)
	}
	entry := report.Entries[0]
	if entry.PathStatus != "dynamic_unresolved" || entry.Reason != "route_path_not_literal" {
		t.Fatalf("dynamic entry lost its status: %+v", entry)
	}
}

func TestBuildMarksMissingOptionalProviders(t *testing.T) {
	report, err := NewRegistry().Build(context.Background(), Input{})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(report.Limitations, "code_audit_not_run") ||
		!contains(report.Limitations, "entrypoint_not_run") ||
		!contains(report.Limitations, "java_audit_not_run") {
		t.Fatalf("missing provider limitations: %+v", report.Limitations)
	}
}

func TestCodeRoutePartialIgnoresSymbolLimits(t *testing.T) {
	report, err := NewRegistry().Build(context.Background(), Input{
		CodeAudit: &codescan.Report{
			Partial: true,
			Routes: []codescan.Route{{
				Language: "php", Path: "/api/upload", HTTPMethods: []string{"POST"},
				Symbol: "Route::post", File: "routes/web.php", Line: 4, Kind: "call",
			}},
			Limitations: []string{"symbol_limit", "call_limit", "unresolved_limit", "symbol_index_lexical"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial {
		t.Fatalf("symbol cap leaked into entry_partial: %+v", report)
	}
	if contains(report.Limitations, "symbol_limit") || contains(report.Limitations, "call_limit") {
		t.Fatalf("symbol-only limits leaked into entry limitations: %+v", report.Limitations)
	}

	report, err = NewRegistry().Build(context.Background(), Input{
		CodeAudit: &codescan.Report{
			Partial:     true,
			Routes:      []codescan.Route{{Language: "php", Path: "/x", File: "routes.php", Line: 1}},
			Limitations: []string{"file_limit"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial {
		t.Fatalf("file limit must make entry_partial true: %+v", report)
	}
}

func TestRegistryRejectsDuplicateProvider(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(JavaAuditProvider{}); err == nil {
		t.Fatal("duplicate provider accepted")
	}
}

func TestApplicationEntryProviderAttachesPHPScriptAuthz(t *testing.T) {
	report, err := (ApplicationEntryProvider{}).Collect(Input{
		ApplicationEntries: &entrypoint.Report{Entries: []entrypoint.Entry{{
			Language: "php", Framework: "PHP", Path: "public/protected.php", Kind: "request_script",
			Line: 7, Reason: "php_request_superglobal_observed", SHA256: "sha",
		}}},
		Authz: &authz.Report{LanguageAdapters: []authz.LanguageAdapter{{
			Language: "php", File: "public/protected.php", Line: 7, Scope: "request_script",
			Decision: "protected", Requirement: authz.RequirementAuthenticated,
			Reason: "php_script_guard_before_request_access", MatchedControls: []string{"session_guard@3"},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Entries) != 1 || report.Entries[0].Authz == nil {
		t.Fatalf("PHP script authz missing: %+v", report.Entries)
	}
	decision := report.Entries[0].Authz
	if decision.Decision != "protected" || decision.Requirement != authz.RequirementAuthenticated ||
		len(decision.MatchedControls) != 1 || decision.MatchedControls[0] != "session_guard@3" {
		t.Fatalf("PHP script authz mismatch: %+v", decision)
	}
}

func TestApplicationEntryProviderPreservesRequestScriptConfidence(t *testing.T) {
	report, err := (ApplicationEntryProvider{}).Collect(Input{
		ApplicationEntries: &entrypoint.Report{Entries: []entrypoint.Entry{{
			Language: "php", Framework: "PHP", Path: "modules/Reports/archive.php", Kind: "request_script",
			Line: 2, Reason: "php_request_superglobal_observed", SHA256: "sha",
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Entries) != 1 {
		t.Fatalf("entries: %+v", report.Entries)
	}
	entry := report.Entries[0]
	if entry.Kind != evidence.KindRequestScript || entry.Confidence != "request_script_heuristic" {
		t.Fatalf("request script confidence lost: %+v", entry)
	}
	if entry.Reason != "php_request_superglobal_observed" || entry.PathStatus != "not_applicable" {
		t.Fatalf("request script reason lost: %+v", entry)
	}
	if len(report.Coverage) != 1 || report.Coverage[0].Status != "request_script_heuristic" ||
		report.Coverage[0].Reason != "php_request_superglobal_observed" {
		t.Fatalf("request script coverage lost: %+v", report.Coverage)
	}
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
