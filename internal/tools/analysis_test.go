package tools

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
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
	if emptyPage.Total != 1 || emptyPage.Citations != nil {
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
		{"inspect_dependencies", map[string]any{"limit": 21}},
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
