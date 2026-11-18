package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/codescan"
)

const analysisFixturePOM = `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>demo</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency>
  </dependencies>
</project>`

const analysisFixtureController = `package demo;
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

func TestAnalysisToolsReturnObservedCitations(t *testing.T) {
	snapshot, _, _ := testSnapshot(t, map[string][]byte{
		"pom.xml":                     []byte(analysisFixturePOM),
		"src/main/java/demo/App.java": []byte(analysisFixtureController),
	})
	registry := New(snapshot)

	var dependencies analysisResponse
	if err := json.Unmarshal(execute(t, registry, "inspect_dependencies", map[string]any{}), &dependencies); err != nil {
		t.Fatal(err)
	}
	if dependencies.Total != 1 || dependencies.AdvisoryConfigured || dependencies.Items == nil {
		t.Fatalf("dependency result: %+v", dependencies)
	}
	if dependencies.Citations != nil {
		t.Fatalf("metadata-only dependency tool exposed citations: %+v", dependencies.Citations)
	}

	var advisories analysisResponse
	if err := json.Unmarshal(execute(t, registry, "match_advisories", map[string]any{}), &advisories); err != nil {
		t.Fatal(err)
	}
	if advisories.AdvisoryConfigured || advisories.Total != 0 {
		t.Fatalf("unconfigured advisory result: %+v", advisories)
	}

	var endpoints analysisResponse
	if err := json.Unmarshal(execute(t, registry, "query_endpoints", map[string]any{"limit": 5}), &endpoints); err != nil {
		t.Fatal(err)
	}
	if endpoints.Total != 1 || len(endpoints.Citations) == 0 {
		t.Fatalf("endpoint result: %+v", endpoints)
	}
	for _, citation := range endpoints.Citations {
		if err := registry.ValidateEvidence(citation); err != nil {
			t.Fatalf("endpoint citation not observed: %v", err)
		}
	}

	raw := execute(t, registry, "trace_dataflow", map[string]any{"category": "sql"})
	if len(raw) > 24<<10 {
		t.Fatalf("analysis result exceeds loop budget: %d bytes", len(raw))
	}
	var flows analysisResponse
	if err := json.Unmarshal(raw, &flows); err != nil {
		t.Fatal(err)
	}
	if flows.Total != 1 || len(flows.Citations) == 0 {
		t.Fatalf("dataflow result: %+v", flows)
	}
	extracted, err := ExtractEvidence("trace_dataflow", raw)
	if err != nil || len(extracted) == 0 {
		t.Fatalf("analysis evidence extraction: %v %+v", err, extracted)
	}
	for _, citation := range extracted {
		if err := registry.ValidateEvidence(citation); err != nil {
			t.Fatalf("dataflow citation not observed: %v", err)
		}
	}

	var findingsPage analysisResponse
	if err := json.Unmarshal(execute(t, registry, "list_findings", map[string]any{"status": "static_confirmed"}), &findingsPage); err != nil {
		t.Fatal(err)
	}
	if findingsPage.Total != 1 || len(findingsPage.Citations) == 0 {
		t.Fatalf("findings result: %+v", findingsPage)
	}

	var emptyPage analysisResponse
	if err := json.Unmarshal(execute(t, registry, "list_findings", map[string]any{"offset": 10}), &emptyPage); err != nil {
		t.Fatal(err)
	}
	if emptyPage.Total != 2 || emptyPage.Citations != nil {
		t.Fatalf("offset result: %+v", emptyPage)
	}
}

func TestAnalysisToolsRejectInvalidFilters(t *testing.T) {
	snapshot, _, _ := testSnapshot(t, map[string][]byte{"a.txt": []byte("plain\n")})
	registry := New(snapshot)
	for _, call := range []struct {
		name string
		args any
	}{
		{"inspect_dependencies", map[string]any{"limit": 26}},
		{"match_advisories", map[string]any{"offset": -1}},
		{"query_endpoints", map[string]any{"q": string(make([]byte, 257))}},
		{"trace_dataflow", map[string]any{"category": "rce"}},
		{"list_findings", map[string]any{"status": "confirmed"}},
	} {
		encoded, _ := json.Marshal(call.args)
		if _, err := registry.Execute(t.Context(), call.name, encoded); !errors.Is(err, ErrArguments) {
			t.Fatalf("%s accepted invalid filters: %v", call.name, err)
		}
	}
}

func TestAnalysisToolsUseConfiguredAdvisoryCatalog(t *testing.T) {
	snapshot, _, _ := testSnapshot(t, map[string][]byte{
		"pom.xml":                     []byte(analysisFixturePOM),
		"src/main/java/demo/App.java": []byte(analysisFixtureController),
	})
	advisory, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "java-maven", "advisories", "CVE-2022-42889.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "advisory.json")
	if err = os.WriteFile(path, advisory, 0o600); err != nil {
		t.Fatal(err)
	}
	registry := NewWithAnalysis(snapshot, AnalysisOptions{AdvisoryPath: path})
	var match analysisResponse
	if err = json.Unmarshal(execute(t, registry, "match_advisories", map[string]any{}), &match); err != nil {
		t.Fatal(err)
	}
	if !match.AdvisoryConfigured || match.Total != 1 {
		t.Fatalf("configured advisory result: %+v", match)
	}
}

// Regression: the Agent's analysis tools must see the console's cached
// multi-language findings, otherwise a PHP project reads as "no findings" to
// the model even though the findings page shows them.
func TestAnalysisToolsMergeCodeFindings(t *testing.T) {
	snapshot, _, _ := testSnapshot(t, map[string][]byte{
		"pom.xml":                     []byte(analysisFixturePOM),
		"src/main/java/demo/App.java": []byte(analysisFixtureController),
	})
	codeReport := codescan.Report{
		Partial: false,
		Findings: []codescan.Finding{{
			ID: "php.xss.output:public/ip.php:27:echo:270", Language: "php",
			RuleID: "php.xss.output", Category: "xss", CWE: "CWE-79",
			Severity: "medium", Status: "static_confirmed",
			Source: &codescan.Ref{Kind: "source", Symbol: "$_SERVER", File: "public/ip.php", SHA256: "0", Line: 27},
			Sink:   &codescan.Ref{Kind: "sink", Symbol: "echo", File: "public/ip.php", SHA256: "0", Line: 275},
			Evidence: []codescan.Ref{
				{Kind: "source", Symbol: "$_SERVER", File: "public/ip.php", SHA256: "0", Line: 27},
				{Kind: "sink", Symbol: "echo", File: "public/ip.php", SHA256: "0", Line: 275},
			},
		}},
	}
	registry := NewWithAnalysis(snapshot, AnalysisOptions{CodeReport: &codeReport})

	var findings analysisResponse
	if err := json.Unmarshal(execute(t, registry, "list_findings", map[string]any{"limit": 10}), &findings); err != nil {
		t.Fatal(err)
	}
	merged := false
	for _, item := range findings.Items.([]any) {
		raw, _ := json.Marshal(item)
		var view struct {
			ID       string `json:"id"`
			Location string `json:"location"`
			Status   string `json:"status"`
		}
		if err := json.Unmarshal(raw, &view); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(view.ID, "code:") {
			merged = true
			if view.Status != "static_confirmed" || !strings.Contains(view.Location, "public/ip.php:275") {
				t.Fatalf("code finding lacks location/status: %+v", view)
			}
		}
	}
	if !merged {
		t.Fatalf("code finding was not merged: %+v", findings.Items)
	}
	if findings.Counts["findings_total"] != 3 { // 1 dependency + 1 dataflow + 1 code
		t.Fatalf("counts did not include the code finding: %+v", findings.Counts)
	}

	// The dataflow-only tool must stay Java-scoped: merged code findings do not
	// masquerade as bounded dataflow evidence.
	var dataflow analysisResponse
	if err := json.Unmarshal(execute(t, registry, "trace_dataflow", map[string]any{"limit": 10}), &dataflow); err != nil {
		t.Fatal(err)
	}
	for _, item := range dataflow.Items.([]any) {
		raw, _ := json.Marshal(item)
		var view struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &view); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(view.ID, "code:") {
			t.Fatalf("code finding leaked into trace_dataflow: %s", view.ID)
		}
	}
}

func codeReportFixture() codescan.Report {
	return codescan.Report{
		Partial: false,
		Findings: []codescan.Finding{
			{
				ID: "php.sql.query:src/db.php:10:query:12", Language: "php",
				RuleID: "php.sql.query", Category: "sql", CWE: "CWE-89",
				Severity: "high", Status: "static_confirmed",
				Source: &codescan.Ref{Kind: "source", Symbol: "$_GET", File: "src/db.php", SHA256: "0", Line: 10},
				Sink:   &codescan.Ref{Kind: "sink", Symbol: "mysql_query", File: "src/db.php", SHA256: "0", Line: 12},
				Evidence: []codescan.Ref{
					{Kind: "source", Symbol: "$_GET", File: "src/db.php", SHA256: "0", Line: 10},
					{Kind: "sink", Symbol: "mysql_query", File: "src/db.php", SHA256: "0", Line: 12},
				},
			},
			{
				ID: "python.command.subprocess:src/tools.py:20:system:22", Language: "python",
				RuleID: "python.command.subprocess", Category: "command", CWE: "CWE-78",
				Severity: "high", Status: "static_confirmed",
				Source: &codescan.Ref{Kind: "source", Symbol: "request.args", File: "src/tools.py", SHA256: "0", Line: 20},
				Sink:   &codescan.Ref{Kind: "sink", Symbol: "os.system", File: "src/tools.py", SHA256: "0", Line: 22},
				Evidence: []codescan.Ref{
					{Kind: "source", Symbol: "request.args", File: "src/tools.py", SHA256: "0", Line: 20},
					{Kind: "sink", Symbol: "os.system", File: "src/tools.py", SHA256: "0", Line: 22},
				},
			},
		},
	}
}

func mergedRegistry(t *testing.T) *Registry {
	t.Helper()
	snapshot, _, _ := testSnapshot(t, map[string][]byte{
		"pom.xml":                     []byte(analysisFixturePOM),
		"src/main/java/demo/App.java": []byte(analysisFixtureController),
	})
	codeReport := codeReportFixture()
	return NewWithAnalysis(snapshot, AnalysisOptions{CodeReport: &codeReport})
}

func symbolReportFixture() codescan.Report {
	return codescan.Report{
		SchemaVersion: 1,
		ToolVersion:   codescan.ToolVersion,
		AnalysisKind:  codescan.AnalysisKind,
		Symbols: []codescan.Symbol{
			{Language: "php", Kind: "function", Name: "login", QualifiedName: "login", File: "src/auth.php", Line: 10},
			{Language: "php", Kind: "method", Name: "doLogin", QualifiedName: "Auth.doLogin", Container: "Auth", File: "src/Auth.php", Line: 22},
			{Language: "python", Kind: "function", Name: "login_view", QualifiedName: "login_view", File: "src/views.py", Line: 8},
		},
		Languages: []codescan.LanguageSummary{{Language: "php", FilesScanned: 2, Symbols: 2}, {Language: "python", FilesScanned: 1, Symbols: 1}},
		Partial:   false,
	}
}

// Agent symbol browsing must return declarations only, never calls or inferred
// types, and must stay unavailable when the console has not bound a code report.
func TestQuerySymbolsFiltersAndBounds(t *testing.T) {
	snapshot, _, _ := testSnapshot(t, map[string][]byte{"src/auth.php": []byte("<?php function login() {}")})
	report := symbolReportFixture()
	registry := NewWithAnalysis(snapshot, AnalysisOptions{CodeReport: &report})

	var all symbolQueryResponse
	if err := json.Unmarshal(execute(t, registry, "query_symbols", map[string]any{}), &all); err != nil {
		t.Fatal(err)
	}
	if !all.Available || all.Total != 3 || len(all.Items) != 3 {
		t.Fatalf("symbol page: %+v", all)
	}

	var php symbolQueryResponse
	if err := json.Unmarshal(execute(t, registry, "query_symbols", map[string]any{"language": "php", "kind": "method"}), &php); err != nil {
		t.Fatal(err)
	}
	if php.Total != 1 || php.Items[0].Name != "doLogin" || php.Items[0].Container != "Auth" {
		t.Fatalf("filtered symbols: %+v", php.Items)
	}

	var page symbolQueryResponse
	if err := json.Unmarshal(execute(t, registry, "query_symbols", map[string]any{"limit": 1, "offset": 1}), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || len(page.Items) != 1 || page.Items[0].Name != "doLogin" {
		t.Fatalf("paged symbols: %+v", page)
	}

	var computed symbolQueryResponse
	if err := json.Unmarshal(execute(t, New(snapshot), "query_symbols", map[string]any{}), &computed); err != nil {
		t.Fatal(err)
	}
	if !computed.Available || computed.Total < 1 || len(computed.Items) == 0 {
		t.Fatalf("lazy symbol query: %+v", computed)
	}

	if _, err := registry.Execute(context.Background(), "query_symbols", json.RawMessage(`{"limit":26}`)); !errors.Is(err, ErrArguments) {
		t.Fatalf("oversized limit was accepted: %v", err)
	}
}

// Regression: category=sql must reach code-audit findings by their rule
// category, not only the Java unified-model kind mapping.
func TestListFindingsCategoryReachesCodeFindings(t *testing.T) {
	registry := mergedRegistry(t)
	var page analysisResponse
	if err := json.Unmarshal(execute(t, registry, "list_findings", map[string]any{"category": "sql"}), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 { // 1 Java dataflow sql_injection + 1 php.sql.query
		t.Fatalf("category=sql missed code finding: total=%d items=%+v", page.Total, page.Items)
	}
	sawCode := false
	for _, item := range page.Items.([]any) {
		raw, _ := json.Marshal(item)
		var view struct {
			ID       string `json:"id"`
			Language string `json:"language"`
		}
		if err := json.Unmarshal(raw, &view); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(view.ID, "code:") {
			sawCode = true
			if view.Language != "php" {
				t.Fatalf("code finding language mismatch: %+v", view)
			}
		}
	}
	if !sawCode {
		t.Fatalf("code finding missing from category=sql page: %+v", page.Items)
	}
}

func TestListFindingsLanguageAndLocationFilters(t *testing.T) {
	registry := mergedRegistry(t)
	var phpPage analysisResponse
	if err := json.Unmarshal(execute(t, registry, "list_findings", map[string]any{"language": "php"}), &phpPage); err != nil {
		t.Fatal(err)
	}
	if phpPage.Total != 1 || phpPage.Counts["language_php"] != 1 || phpPage.Counts["language_java"] != 2 {
		t.Fatalf("language filter or counts wrong: total=%d counts=%+v", phpPage.Total, phpPage.Counts)
	}
	var byFile analysisResponse
	if err := json.Unmarshal(execute(t, registry, "list_findings", map[string]any{"q": "tools.py"}), &byFile); err != nil {
		t.Fatal(err)
	}
	if byFile.Total != 1 {
		t.Fatalf("location/name filter missed finding: total=%d", byFile.Total)
	}
	var unsupported analysisResponse
	if err := json.Unmarshal(execute(t, registry, "list_findings", map[string]any{"language": "cobol"}), &unsupported); err != nil {
		t.Fatal(err)
	}
	if unsupported.Total != 0 {
		t.Fatalf("unknown language must match nothing: %+v", unsupported)
	}
}

func TestListFindingsLimit25(t *testing.T) {
	snapshot, _, _ := testSnapshot(t, map[string][]byte{
		"pom.xml":                     []byte(analysisFixturePOM),
		"src/main/java/demo/App.java": []byte(analysisFixtureController),
	})
	report := codeReportFixture()
	for i := 0; i < 30; i++ {
		report.Findings = append(report.Findings, codescan.Finding{
			ID: fmt.Sprintf("php.xss.output:src/ip%d.php:7:echo:7", i), Language: "php",
			RuleID: "php.xss.output", Category: "xss", CWE: "CWE-79",
			Severity: "medium", Status: "static_confirmed",
			Source: &codescan.Ref{Kind: "source", Symbol: "$_GET", File: fmt.Sprintf("src/ip%d.php", i), SHA256: "0", Line: 7},
			Sink:   &codescan.Ref{Kind: "sink", Symbol: "echo", File: fmt.Sprintf("src/ip%d.php", i), SHA256: "0", Line: 7},
			Evidence: []codescan.Ref{
				{Kind: "sink", Symbol: "echo", File: fmt.Sprintf("src/ip%d.php", i), SHA256: "0", Line: 7},
			},
		})
	}
	registry := NewWithAnalysis(snapshot, AnalysisOptions{CodeReport: &report})
	var page analysisResponse
	if err := json.Unmarshal(execute(t, registry, "list_findings", map[string]any{"limit": 25}), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 34 || page.Limit != 25 || len(page.Items.([]any)) != 25 { // 30 xss + 2 fixture code findings + 1 dataflow + 1 dependency
		t.Fatalf("limit 25 not honored: total=%d limit=%d items=%d", page.Total, page.Limit, len(page.Items.([]any)))
	}
	encoded, _ := json.Marshal(map[string]any{"limit": 26})
	if _, err := registry.Execute(t.Context(), "list_findings", encoded); !errors.Is(err, ErrArguments) {
		t.Fatalf("limit above 25 must be rejected: %v", err)
	}
}

func TestListRulesExposesBuiltinRuleSet(t *testing.T) {
	registry := mergedRegistry(t)
	var page analysisResponse
	if err := json.Unmarshal(execute(t, registry, "list_rules", map[string]any{}), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total < 50 || page.Counts["rules_builtin_total"] != page.Total {
		t.Fatalf("builtin rule list incomplete: total=%d counts=%+v", page.Total, page.Counts)
	}
	items := page.Items.([]any)
	first, _ := json.Marshal(items[0])
	var rule struct {
		ID        string   `json:"id"`
		Languages []string `json:"languages"`
		Category  string   `json:"category"`
		CWE       string   `json:"cwe"`
		Sinks     int      `json:"sinks"`
	}
	if err := json.Unmarshal(first, &rule); err != nil {
		t.Fatal(err)
	}
	if rule.ID == "" || len(rule.Languages) == 0 || rule.CWE == "" || rule.Sinks == 0 {
		t.Fatalf("rule summary missing fields: %s", first)
	}
	var phpRules analysisResponse
	if err := json.Unmarshal(execute(t, registry, "list_rules", map[string]any{"language": "php"}), &phpRules); err != nil {
		t.Fatal(err)
	}
	if phpRules.Total == 0 || phpRules.Total >= page.Total {
		t.Fatalf("language filter for rules wrong: %d of %d", phpRules.Total, page.Total)
	}
	var redirectRules analysisResponse
	if err := json.Unmarshal(execute(t, registry, "list_rules", map[string]any{"category": "redirect"}), &redirectRules); err != nil {
		t.Fatal(err)
	}
	if redirectRules.Total < 6 {
		t.Fatalf("redirect rules missing across languages: %d", redirectRules.Total)
	}
}
