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

func TestBuildGitHubCodeScanningMapping(t *testing.T) {
	report := findings.Report{
		ToolVersion:  "test",
		SnapshotHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		AnalysisKind: "finding_evidence",
		Findings: []findings.Finding{
			{
				ID: "CWE-89:/x:q", Kind: "sql_injection", Category: "SQL injection", CWE: "CWE-89",
				Severity: "high", Status: "static_confirmed", RuntimeStatus: "not_run", Title: "tainted SQL",
				Evidence:       []findings.Evidence{{File: "src/A.java", StartLine: 10, EndLine: 12, Kind: "sink"}},
				SourceAnalyses: []string{"dataflow"},
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
	rules := document.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 {
		t.Fatalf("rules: %+v", rules)
	}
	rule := rules[0]
	if rule.Properties["security-severity"] != SecuritySeverityConfirmed {
		t.Fatalf("confirmed security-severity: %v", rule.Properties["security-severity"])
	}
	if rule.Properties["precision"] != "high" || rule.Properties["problem.precision"] != "high" {
		t.Fatalf("confirmed precision: %+v", rule.Properties)
	}
	tags, ok := rule.Properties["tags"].([]string)
	if !ok || len(tags) != 2 || tags[0] != "security" || tags[1] != "CWE-89" {
		t.Fatalf("rule tags: %#v", rule.Properties["tags"])
	}

	confirmed := document.Runs[0].Results[0]
	if confirmed.Properties["status"] != "static_confirmed" {
		t.Fatalf("unexpected first result: %+v", confirmed)
	}
	// The shared rule inherits the representative (confirmed) status; verify
	// the per-result level mapping stays intact and the fingerprint is a
	// deterministic hash.
	if confirmed.Level != "warning" {
		t.Fatalf("confirmed level: %s", confirmed.Level)
	}
	fingerprint := confirmed.PartialFingerprints["primaryLocationLineHash"]
	if len(fingerprint) != 32 {
		t.Fatalf("fingerprint length: %q", fingerprint)
	}
	repeat, err := Build(report, "")
	if err != nil {
		t.Fatal(err)
	}
	if repeat.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"] != fingerprint {
		t.Fatal("fingerprint must be deterministic across builds")
	}

	// Same rule id at a different primary location must fingerprint differently
	// so code scanning can merge alerts per location.
	shifted := report
	shifted.Findings = append([]findings.Finding{}, report.Findings...)
	shifted.Findings[0].Evidence = []findings.Evidence{{File: "src/A.java", StartLine: 11, EndLine: 12, Kind: "sink"}}
	shiftedDocument, err := Build(shifted, "")
	if err != nil {
		t.Fatal(err)
	}
	if shiftedDocument.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"] == fingerprint {
		t.Fatal("different primary lines must produce different fingerprints")
	}
}

func TestSecuritySeverityAndCWEClassification(t *testing.T) {
	if securitySeverityFor("static_confirmed") != "7.5" || securitySeverityFor("inconclusive") != "3.0" || securitySeverityFor("refuted") != "0.0" {
		t.Fatal("security severity mapping must stay below unconfirmed evidence")
	}
	if precisionFor("static_confirmed") != "high" || precisionFor("inconclusive") != "low" || precisionFor("refuted") != "low" {
		t.Fatal("precision must be high only for confirmed dataflow")
	}
	if number, ok := cweNumber("cwe-79 "); !ok || number != 79 {
		t.Fatalf("cwe parsing: %d %v", number, ok)
	}
	if _, ok := cweNumber("CWE-"); ok {
		t.Fatal("empty CWE number must be rejected")
	}
	if _, ok := cweNumber("unknown"); ok {
		t.Fatal("non-CWE values must be rejected")
	}
	finding := findings.Finding{CWE: "CWE-79"}
	tags := ruleTags(finding)
	if len(tags) != 2 || tags[1] != "CWE-79" {
		t.Fatalf("tags: %v", tags)
	}
	tags = ruleTags(findings.Finding{CWE: "not-a-cwe"})
	if len(tags) != 1 || tags[0] != "security" {
		t.Fatalf("unparseable CWE must keep the security tag only: %v", tags)
	}
}
