package sarif

import (
	"encoding/json"
	"testing"

	"trident/internal/findings"
)

func TestBuildProducesStableSARIFAndKeepsRuntimeStatus(t *testing.T) {
	report := findings.Report{
		ToolVersion:  "test",
		SnapshotHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		AnalysisKind: "finding_evidence",
		Findings: []findings.Finding{
			{
				ID: "CWE-89:/x:q", Kind: "sql_injection", Category: "SQL injection", CWE: "CWE-89",
				Severity: "high", Status: "static_confirmed", RuntimeStatus: "not_run", Title: "tainted SQL",
				Evidence:       []findings.Evidence{{File: "src/A.java", SHA256: "x", StartLine: 10, EndLine: 12, Kind: "sink"}},
				SourceAnalyses: []string{"dataflow"},
			},
			{
				ID: "CWE-22:/y:p", Kind: "path_traversal", Category: "Path traversal", CWE: "CWE-22",
				Severity: "unknown", Status: "inconclusive", RuntimeStatus: "not_run", Title: "unresolved path",
				Evidence: []findings.Evidence{{File: "src/B.java", StartLine: 4, EndLine: 4, Kind: "boundary"}},
			},
			{
				ID: "CWE-89:/z:q", Kind: "sql_injection", Category: "SQL injection", CWE: "CWE-89",
				Severity: "none", Status: "refuted", RuntimeStatus: "not_run", Title: "parameterized",
				Evidence: []findings.Evidence{{File: "src/C.java", StartLine: 7, EndLine: 7, Kind: "protection"}},
			},
		},
	}
	document, err := Build(report, "")
	if err != nil {
		t.Fatal(err)
	}
	if document.Version != "2.1.0" || len(document.Runs) != 1 || len(document.Runs[0].Results) != 3 {
		t.Fatalf("document shape: %+v", document)
	}
	if len(document.Runs[0].Tool.Driver.Rules) != 2 {
		t.Fatalf("rules: %+v", document.Runs[0].Tool.Driver.Rules)
	}
	levels := map[string]string{}
	for _, result := range document.Runs[0].Results {
		levels[result.RuleID+":"+result.Properties["status"].(string)] = result.Level
		if result.Properties["runtime_status"] != "not_run" {
			t.Fatalf("runtime status upgraded: %+v", result)
		}
	}
	if levels["trident/sql_injection:static_confirmed"] != "warning" || levels["trident/path_traversal:inconclusive"] != "note" || levels["trident/sql_injection:refuted"] != "none" {
		t.Fatalf("levels: %+v", levels)
	}
	first, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	secondDocument, err := Build(report, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(secondDocument)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("SARIF output is not deterministic")
	}
}
