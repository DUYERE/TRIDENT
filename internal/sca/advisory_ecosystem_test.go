package sca

import "testing"

func TestAdvisoryMatchesComposerDependency(t *testing.T) {
	advisory := &advisoryCatalog{AdvisoryID: "CVE-TEST-COMPOSER", Ecosystem: "Composer"}
	advisory.Package.GroupID = "squizlabs"
	advisory.Package.ArtifactID = "php_codesniffer"
	advisory.VersionCases = append(advisory.VersionCases, struct {
		Version           string `json:"version"`
		VersionRange      string `json:"version_range,omitempty"`
		VersionMatched    bool   `json:"version_matched"`
		SupplyChainStatus string `json:"supply_chain_status"`
		FindingStatus     string `json:"finding_status"`
		AssessmentScope   string `json:"assessment_scope"`
		RuntimeStatus     string `json:"runtime_status"`
	}{Version: "2.0.0", VersionMatched: true, AssessmentScope: "declared version only"})

	dependencies := []Dependency{{
		Module: "extend/PHPExcel", Ecosystem: "composer", Name: "squizlabs/php_codesniffer",
		GroupID: "squizlabs", ArtifactID: "php_codesniffer", Version: "2.0.0", VersionStatus: "resolved",
		DeclarationPOM: "composer.json",
	}}
	matches := matchAdvisories(dependencies, []*advisoryCatalog{advisory})
	if len(matches) != 1 || matches[0].FindingStatus != "candidate" || matches[0].Dependency != "squizlabs/php_codesniffer" {
		t.Fatalf("composer advisory match failed: %+v", matches)
	}
}

func TestAdvisoryRejectsCrossEcosystemNameCollision(t *testing.T) {
	advisory := &advisoryCatalog{AdvisoryID: "CVE-TEST-CROSS", Ecosystem: "npm"}
	advisory.Package.ArtifactID = "left-pad"
	dependencies := []Dependency{{
		Module: "app", Ecosystem: "composer", Name: "left-pad", Version: "1.0.0", VersionStatus: "resolved",
	}}
	if matches := matchAdvisories(dependencies, []*advisoryCatalog{advisory}); len(matches) != 0 {
		t.Fatalf("cross-ecosystem collision matched: %+v", matches)
	}
}
