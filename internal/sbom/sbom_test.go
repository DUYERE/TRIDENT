package sbom

import (
	"encoding/json"
	"regexp"
	"testing"

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
