package correlate

import (
	"encoding/json"
	"strings"
	"testing"
)

func findingsJSON(t *testing.T, entries ...map[string]any) []byte {
	t.Helper()
	doc := map[string]any{
		"schema_version": 1,
		"analysis_kind":  FindingsAnalysisKind,
		"findings":       entries,
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	return data
}

func runtimeJSON(t *testing.T, results ...map[string]any) []byte {
	t.Helper()
	doc := map[string]any{
		"schema_version": 1,
		"analysis_kind":  RuntimeAnalysisKind,
		"plan_name":      "unit-plan",
		"origin":         "http://127.0.0.1:1",
		"status":         "passed",
		"runtime_status": "observed",
		"results":        results,
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal runtime: %v", err)
	}
	return data
}

func findingEntry(id, path string, methods []string, evidence ...map[string]any) map[string]any {
	entry := map[string]any{
		"id": id, "kind": "sql_injection", "status": "static_confirmed",
		"runtime_status": "not_run", "evidence": evidence,
	}
	if path != "" {
		entry["endpoint"] = map[string]any{
			"path": path, "http_methods": methods, "file": "src/App.java",
			"sha256": "abc", "start_line": 10, "end_line": 20,
		}
	}
	return entry
}

func runtimeEntry(id, method, path string) map[string]any {
	return map[string]any{
		"id": id, "method": method, "path": path, "status": "passed",
		"observed_status": 200, "body_sha256": "def",
	}
}

func entriesJSON(t *testing.T, entries ...map[string]any) []byte {
	t.Helper()
	doc := map[string]any{"schema_version": 1, "entries": entries}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal entries: %v", err)
	}
	return data
}

// A code finding has no endpoint of its own; when its sink file has exactly one
// route declaration, correlation may use that route as a file-scoped candidate
// but must record the derivation and language explicitly.
func TestCorrelateDerivesLanguageRouteFromUnifiedEntries(t *testing.T) {
	findings := findingsJSON(t, map[string]any{
		"id": "code:php.sql.query:src/news.php:12", "kind": "php.sql.query",
		"status": "static_confirmed", "runtime_status": "not_run",
		"evidence": []map[string]any{
			{"id": "ev:source", "kind": "source", "file": "src/news.php", "start_line": 10},
			{"id": "ev:sink", "kind": "sink", "file": "src/news.php", "start_line": 12},
		},
	})
	entries := entriesJSON(t,
		map[string]any{"path": "/news", "http_methods": []string{"GET"}, "kind": "route_declaration", "language": "php", "file": "src/news.php", "path_status": "declared", "source": "declaration"},
		map[string]any{"path": "", "http_methods": []string{}, "kind": "application_entry", "language": "php", "file": "public/index.php"},
	)
	runtime := runtimeJSON(t, runtimeEntry("r1", "GET", "/news"))
	report, err := Correlate(
		Input{Path: "findings.json", Data: findings},
		Input{Path: "runtime.json", Data: runtime},
		Input{Path: "entries.json", Data: entries},
	)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if len(report.Results) != 1 || report.Results[0].Match != MatchCorrelated {
		t.Fatalf("derived correlation: %+v", report.Results)
	}
	endpoint := report.Results[0].Endpoint
	if endpoint == nil || endpoint.Path != "/news" || endpoint.Language != "php" || endpoint.Kind != "route_declaration" || endpoint.Source != "declaration" {
		t.Fatalf("derived endpoint: %+v", endpoint)
	}
	if report.Coverage.FindingsEndpointDerived != 1 {
		t.Fatalf("derived coverage: %+v", report.Coverage)
	}
}

func TestCorrelateAmbiguousFileRoutesStayUncorrelated(t *testing.T) {
	findings := findingsJSON(t, map[string]any{
		"id": "code:php.x:src/routes.php:5", "kind": "php.sql.query",
		"status": "static_confirmed", "runtime_status": "not_run",
		"evidence": []map[string]any{{"id": "ev:sink", "kind": "sink", "file": "src/routes.php", "start_line": 5}},
	})
	entries := entriesJSON(t,
		map[string]any{"path": "/a", "http_methods": []string{"GET"}, "kind": "route_declaration", "language": "php", "file": "src/routes.php"},
		map[string]any{"path": "/b", "http_methods": []string{"GET"}, "kind": "route_declaration", "language": "php", "file": "src/routes.php"},
	)
	runtime := runtimeJSON(t, runtimeEntry("r1", "GET", "/a"))
	report, err := Correlate(
		Input{Path: "findings.json", Data: findings},
		Input{Path: "runtime.json", Data: runtime},
		Input{Path: "entries.json", Data: entries},
	)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if len(report.Results) != 1 || report.Results[0].Match != MatchNotCorrelated || report.Results[0].Reason != "multiple_static_routes_for_finding_file" {
		t.Fatalf("ambiguous derived route: %+v", report.Results)
	}
}

func TestCorrelateMatchesRoutesInThreeStates(t *testing.T) {
	findings := findingsJSON(t,
		findingEntry("unique", "/orders", []string{"GET"},
			map[string]any{"id": "ev:route", "kind": "route"},
			map[string]any{"id": "ev:sink", "kind": "sink"}),
		findingEntry("multi", "/admin", []string{"GET"}),
		findingEntry("missing", "/absent", []string{"GET"}),
		findingEntry("dependency", "", nil),
	)
	runtime := runtimeJSON(t,
		runtimeEntry("r1", "GET", "/orders"),
		runtimeEntry("r2", "GET", "/admin"),
		runtimeEntry("r3", "GET", "/admin"),
		runtimeEntry("r4", "POST", "/orphan"),
	)
	report, err := Correlate(
		Input{Path: "findings.json", Data: findings},
		Input{Path: "runtime.json", Data: runtime},
	)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if report.RuntimeStatus != "observed" || report.AnalysisKind != AnalysisKind {
		t.Fatalf("unexpected identity: %+v", report)
	}
	byID := map[string]Correlation{}
	for _, item := range report.Results {
		byID[item.FindingID] = item
	}
	if byID["unique"].Match != MatchCorrelated || len(byID["unique"].Runtime) != 1 {
		t.Fatalf("unique match: %+v", byID["unique"])
	}
	if len(byID["unique"].FindingEvidenceID) != 1 || byID["unique"].FindingEvidenceID[0] != "ev:route" {
		t.Fatalf("route evidence not carried: %+v", byID["unique"].FindingEvidenceID)
	}
	if byID["multi"].Match != MatchAmbiguous || len(byID["multi"].Runtime) != 2 {
		t.Fatalf("ambiguous match: %+v", byID["multi"])
	}
	if byID["missing"].Match != MatchNotCorrelated || byID["missing"].Reason != "no_runtime_result_with_matching_route_and_method" {
		t.Fatalf("missing match: %+v", byID["missing"])
	}
	if byID["dependency"].Match != MatchNotCorrelated || byID["dependency"].Reason != "finding_has_no_endpoint" {
		t.Fatalf("dependency match: %+v", byID["dependency"])
	}
	if report.Coverage.Correlated != 1 || report.Coverage.Ambiguous != 1 || report.Coverage.NotCorrelated != 2 {
		t.Fatalf("coverage: %+v", report.Coverage)
	}
	if report.Coverage.RuntimeResultsMatched != 3 || report.Coverage.RuntimeResultsUnmatched != 1 {
		t.Fatalf("runtime coverage: %+v", report.Coverage)
	}
	if len(report.Unmatched) != 1 || report.Unmatched[0].ID != "r4" {
		t.Fatalf("unmatched runtime: %+v", report.Unmatched)
	}
	if byID["dependency"].Runtime == nil {
		t.Fatalf("runtime results must be an empty array, not null")
	}
}

func TestCorrelateMethodUnrestrictedIsWildcard(t *testing.T) {
	findings := findingsJSON(t, findingEntry("any", "/admin", nil))
	runtime := runtimeJSON(t, runtimeEntry("r1", "get", "/admin"))
	report, err := Correlate(
		Input{Path: "f.json", Data: findings},
		Input{Path: "r.json", Data: runtime},
	)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if report.Results[0].Match != MatchCorrelated || report.Results[0].Runtime[0].Method != "GET" {
		t.Fatalf("wildcard match: %+v", report.Results[0])
	}
	foundWildcard := false
	for _, limitation := range report.Limitations {
		if strings.HasPrefix(limitation, "method_unrestricted_matches_any_observed_method") {
			foundWildcard = true
		}
	}
	if !foundWildcard {
		t.Fatalf("wildcard limitation missing: %+v", report.Limitations)
	}
}

func TestCorrelateRejectsUnobservedRuntime(t *testing.T) {
	doc := map[string]any{
		"schema_version": 1, "analysis_kind": RuntimeAnalysisKind,
		"runtime_status": "inconclusive", "results": []any{},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := Correlate(
		Input{Path: "f.json", Data: findingsJSON(t)},
		Input{Path: "r.json", Data: data},
	); err == nil {
		t.Fatalf("unobserved runtime report accepted")
	}
}

func TestCorrelateRejectsDuplicateFindingIDs(t *testing.T) {
	findings := findingsJSON(t,
		findingEntry("same", "/a", []string{"GET"}),
		findingEntry("same", "/b", []string{"GET"}),
	)
	if _, err := Correlate(
		Input{Path: "f.json", Data: findings},
		Input{Path: "r.json", Data: runtimeJSON(t, runtimeEntry("r1", "GET", "/a"))},
	); err == nil {
		t.Fatalf("duplicate finding ids accepted")
	}
}

func TestCorrelateIsDeterministic(t *testing.T) {
	findings := findingsJSON(t,
		findingEntry("b", "/b", []string{"GET"}),
		findingEntry("a", "/a", []string{"GET"}),
	)
	runtime := runtimeJSON(t,
		runtimeEntry("r2", "GET", "/b"),
		runtimeEntry("r1", "GET", "/a"),
	)
	first, err := Correlate(Input{Path: "f.json", Data: findings}, Input{Path: "r.json", Data: runtime})
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	second, err := Correlate(Input{Path: "f.json", Data: findings}, Input{Path: "r.json", Data: runtime})
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	firstBytes, _ := json.Marshal(first)
	secondBytes, _ := json.Marshal(second)
	if string(firstBytes) != string(secondBytes) {
		t.Fatalf("correlation output is not deterministic")
	}
	if first.Results[0].FindingID != "a" || first.Results[1].FindingID != "b" {
		t.Fatalf("results not sorted: %+v", first.Results)
	}
}
