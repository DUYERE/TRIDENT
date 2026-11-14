package sbom

import (
	"encoding/json"
	"regexp"
	"testing"

	"trident/internal/reach"
	"trident/internal/sca"
)

const testHash = "f6c6c4fa54c6775d24b7a6eee0a774b8d2374e0e2de8e3ec8328d5d2a2f2af00"

func testReport() sca.Report {
	return sca.Report{
		Partial: true,
		Dependencies: []sca.Dependency{
			{Module: "app", GroupID: "org.apache.commons", ArtifactID: "commons-text", Version: "1.9", DeclarationPOM: "app/pom.xml", VersionStatus: "resolved"},
			{Module: "worker", GroupID: "org.apache.commons", ArtifactID: "commons-text", Version: "1.9", DeclarationPOM: "worker/pom.xml", VersionStatus: "resolved"},
			{Module: "app", GroupID: "demo", ArtifactID: "missing", DeclarationPOM: "app/pom.xml", VersionStatus: "unresolved"},
		},
		AdvisoryMatches: []sca.AdvisoryMatch{
			{AdvisoryID: "CVE-2024-0001", Module: "app", Dependency: "org.apache.commons:commons-text", DeclaredVersion: "1.9", FindingStatus: "candidate"},
			{AdvisoryID: "CVE-2024-0002", Module: "app", Dependency: "org.apache.commons:commons-text", DeclaredVersion: "1.9", FindingStatus: "none"},
		},
		Limitations: []string{"maven_not_executed: declarations only", "runtime_status_not_run"},
	}
}

func TestBuildIsDeterministicAndDeclarationOnly(t *testing.T) {
	first, err := Build(testReport(), Options{SnapshotHash: testHash, ToolVersion: "test-tool"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(testReport(), Options{SnapshotHash: testHash, ToolVersion: "test-tool"})
	if err != nil {
		t.Fatal(err)
	}
	left, _ := json.Marshal(first)
	right, _ := json.Marshal(second)
	if string(left) != string(right) {
		t.Fatal("SBOM is not deterministic")
	}
	if first.BOMFormat != "CycloneDX" || first.SpecVersion != "1.5" || first.Version != 1 {
		t.Fatalf("identity: %+v", first)
	}
	if matched, _ := regexp.MatchString(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, first.SerialNumber); !matched {
		t.Fatalf("serial: %s", first.SerialNumber)
	}
	if len(first.Components) != 2 {
		t.Fatalf("components: %+v", first.Components)
	}
	if first.Components[0].BOMRef != "pkg:maven/org.apache.commons/commons-text@1.9" && first.Components[1].BOMRef != "pkg:maven/org.apache.commons/commons-text@1.9" {
		t.Fatalf("purl component missing: %+v", first.Components)
	}
	if len(first.Vulnerabilities) != 1 || first.Vulnerabilities[0].Analysis.State != "in_triage" {
		t.Fatalf("vulnerabilities: %+v", first.Vulnerabilities)
	}
	properties := map[string]string{}
	for _, property := range first.Metadata.Properties {
		properties[property.Name] = property.Value
	}
	if properties["trident:runtime_status"] != "not_run" || properties["trident:partial"] != "true" ||
		properties["trident:dependency_reachability"] != "unverified" {
		t.Fatalf("metadata properties: %+v", properties)
	}
}

func TestBuildRejectsInvalidHash(t *testing.T) {
	for _, hash := range []string{"", "short", string(make([]byte, 64))} {
		if _, err := Build(sca.Report{}, Options{SnapshotHash: hash}); err == nil {
			t.Fatalf("invalid hash accepted: %q", hash)
		}
	}
}

func TestBuildVEXAnalysisFromReachability(t *testing.T) {
	report := testReport()
	reachability := map[string]reach.Reachability{
		// Exact match for the candidate match (module app, commons-text 1.9).
		"app\x00org.apache.commons:commons-text\x001.9": {
			Module: "app", Dependency: "org.apache.commons:commons-text", Version: "1.9",
			Reachability: "unreachable", Reason: "no_path_from_entrypoint_in_bounded_call_graph",
			RuntimeStatus: "static_analysis_only",
		},
	}
	document, err := Build(report, Options{SnapshotHash: testHash, ToolVersion: "test-tool", Reachability: reachability})
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities: %+v", document.Vulnerabilities)
	}
	analysis := document.Vulnerabilities[0].Analysis
	if analysis.State != "not_affected" || analysis.Justification != "code_not_reachable" {
		t.Fatalf("unreachable analysis: %+v", analysis)
	}
	if reach.MaxPathDepth != 8 || !regexp.MustCompile(`depth 8 hops`).MatchString(analysis.Detail) {
		t.Fatalf("detail must state the bounded-graph boundary: %s", analysis.Detail)
	}
	properties := map[string]string{}
	for _, property := range document.Vulnerabilities[0].Properties {
		properties[property.Name] = property.Value
	}
	if properties["trident:reachability"] != "unreachable" || properties["trident:reachability_claim"] != "no_path_from_entrypoint_in_bounded_call_graph" {
		t.Fatalf("vulnerability properties: %+v", properties)
	}
	metadata := map[string]string{}
	for _, property := range document.Metadata.Properties {
		metadata[property.Name] = property.Value
	}
	if metadata["trident:dependency_reachability"] != "bounded_entry_call_graph" || metadata["trident:vex_basis"] != "bounded_entry_call_graph" {
		t.Fatalf("metadata must record the VEX basis: %+v", metadata)
	}

	// A reachable path must stay in_triage: static evidence never upgrades to
	// "exploitable".
	reachability["app\x00org.apache.commons:commons-text\x001.9"] = reach.Reachability{
		Module: "app", Dependency: "org.apache.commons:commons-text", Version: "1.9",
		Reachability: "reachable", Reason: "entry_to_import_path",
		RuntimeStatus: "static_analysis_only",
	}
	reachableDoc, err := Build(report, Options{SnapshotHash: testHash, ToolVersion: "test-tool", Reachability: reachability})
	if err != nil {
		t.Fatal(err)
	}
	if reachableDoc.Vulnerabilities[0].Analysis.State != "in_triage" || reachableDoc.Vulnerabilities[0].Analysis.Justification != "" {
		t.Fatalf("reachable analysis: %+v", reachableDoc.Vulnerabilities[0].Analysis)
	}

	// Unknown reasons stay in triage with the reason recorded.
	reachability["app\x00org.apache.commons:commons-text\x001.9"] = reach.Reachability{
		Module: "app", Dependency: "org.apache.commons:commons-text", Version: "1.9",
		Reachability: "unknown", Reason: "reflection_not_resolved", RuntimeStatus: "static_analysis_only",
	}
	unknownDoc, err := Build(report, Options{SnapshotHash: testHash, ToolVersion: "test-tool", Reachability: reachability})
	if err != nil {
		t.Fatal(err)
	}
	unknown := unknownDoc.Vulnerabilities[0].Analysis
	if unknown.State != "in_triage" || !regexp.MustCompile(`reflection_not_resolved`).MatchString(unknown.Detail) {
		t.Fatalf("unknown analysis: %+v", unknown)
	}

	// Without any reachability input the document stays identical to the
	// declaration-only baseline (in_triage, unverified metadata).
	baseline, err := Build(report, Options{SnapshotHash: testHash, ToolVersion: "test-tool"})
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Vulnerabilities[0].Analysis.State != "in_triage" || baseline.Vulnerabilities[0].Analysis.Justification != "" {
		t.Fatalf("baseline analysis: %+v", baseline.Vulnerabilities[0].Analysis)
	}
	metadata = map[string]string{}
	for _, property := range baseline.Metadata.Properties {
		metadata[property.Name] = property.Value
	}
	if metadata["trident:dependency_reachability"] != "unverified" {
		t.Fatalf("baseline metadata: %+v", metadata)
	}

	// Every VEX payload must remain byte-deterministic for identical inputs.
	left, _ := json.Marshal(unknownDoc)
	again, err := Build(report, Options{SnapshotHash: testHash, ToolVersion: "test-tool", Reachability: reachability})
	if err != nil {
		t.Fatal(err)
	}
	right, _ := json.Marshal(again)
	if string(left) != string(right) {
		t.Fatal("VEX SBOM is not deterministic")
	}
}
