package findings

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/project"
)

// fixtureSnapshot copies the repository fixture onto the local temp filesystem
// before importing. Bind mounts (for example the Linux race container) use
// filesystems that the secure snapshot importer intentionally rejects.
func fixtureSnapshot(t *testing.T) (*project.Snapshot, string) {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "tests", "fixtures", "java-maven"))
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "source")
	copyTree(t, source, copied)
	destination := filepath.Join(t.TempDir(), "snapshot")
	imported, err := project.Import(context.Background(), copied, destination)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := project.Open(context.Background(), destination, imported.Hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	return snapshot, filepath.Join(copied, "advisories", "CVE-2022-42889.json")
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(source, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected fixture entry %s", relative)
		}
		data, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func find(report Report, kind, path string) *Finding {
	for i := range report.Findings {
		finding := &report.Findings[i]
		if finding.Kind != kind {
			continue
		}
		if path == "" || (finding.Endpoint != nil && finding.Endpoint.Path == path) {
			return finding
		}
	}
	return nil
}

func hypothesis(finding *Finding, suffix string) *Hypothesis {
	for i := range finding.Hypotheses {
		if strings.HasSuffix(finding.Hypotheses[i].ID, suffix) {
			return &finding.Hypotheses[i]
		}
	}
	return nil
}

func TestAnalyzeLinksFixtureEvidenceAndKeepsRuntimeSeparate(t *testing.T) {
	snapshot, advisoryPath := fixtureSnapshot(t)
	report, err := Analyze(context.Background(), snapshot, Options{AdvisoryPath: advisoryPath})
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != SchemaVersion || report.AnalysisKind != "unified_finding_evidence_v1" || report.SnapshotHash != snapshot.Hash() {
		t.Fatalf("identity: %+v", report)
	}
	if report.Partial || len(report.Findings) != 4 {
		t.Fatalf("unexpected findings: partial=%v count=%d %+v", report.Partial, len(report.Findings), report.Findings)
	}
	if report.Coverage.FindingsStaticConfirmed != 1 || report.Coverage.FindingsRefuted != 1 || report.Coverage.FindingsInconclusive != 2 {
		t.Fatalf("status coverage: %+v", report.Coverage)
	}
	if report.Coverage.HypothesesSupported != 3 || report.Coverage.HypothesesUnsupported != 1 || report.Coverage.HypothesesUnverified != 6 {
		t.Fatalf("hypothesis coverage: %+v", report.Coverage)
	}
	if report.Coverage.ScaCandidates != 1 || report.Coverage.ScaNotAffected != 1 || report.Coverage.ScaUnknown != 0 {
		t.Fatalf("SCA coverage: %+v", report.Coverage)
	}
	if report.Coverage.EndpointsInventoried != 3 || report.Coverage.DataflowFindings != 3 || report.Coverage.DependencyReachability != "unverified" {
		t.Fatalf("context coverage: %+v", report.Coverage)
	}
	for _, finding := range report.Findings {
		if finding.RuntimeStatus != "not_run" {
			t.Fatalf("runtime status upgraded: %+v", finding)
		}
		runtime := hypothesis(&finding, ":runtime_exploitation")
		if runtime == nil || runtime.Status != "unverified" || len(runtime.RequiredEvidence) == 0 {
			t.Fatalf("runtime hypothesis missing: %+v", finding.Hypotheses)
		}
	}

	unsafe := find(report, "sql_injection", "/synthetic/customers/unsafe")
	if unsafe == nil || unsafe.Status != "static_confirmed" || unsafe.Severity != "high" {
		t.Fatalf("unsafe finding: %+v", unsafe)
	}
	flowHypothesis := hypothesis(unsafe, ":source_to_sink")
	if flowHypothesis == nil || flowHypothesis.Status != "supported" || len(flowHypothesis.EvidenceIDs) == 0 {
		t.Fatalf("safe flow hypothesis: %+v", flowHypothesis)
	}
	anchors := map[string]bool{}
	for _, evidence := range unsafe.Evidence {
		if evidence.SHA256 != "" && len(evidence.SHA256) != 64 {
			t.Fatalf("bad evidence digest: %+v", evidence)
		}
		if evidence.Anchor != "" {
			anchors[evidence.Anchor] = true
		}
	}
	if !anchors["fixture:unsafe-http-source"] || !anchors["fixture:sql-concatenation"] {
		t.Fatalf("fixture anchors missing: %v", anchors)
	}

	parameterized := find(report, "sql_injection", "/synthetic/customers/parameterized")
	if parameterized == nil || parameterized.Status != "refuted" {
		t.Fatalf("parameterized finding: %+v", parameterized)
	}
	if got := hypothesis(parameterized, ":source_to_sink"); got == nil || got.Status != "unsupported" {
		t.Fatalf("refuted flow hypothesis: %+v", got)
	}
	if got := hypothesis(parameterized, ":value_binding"); got == nil || got.Status != "supported" {
		t.Fatalf("value binding hypothesis: %+v", got)
	}

	dynamic := find(report, "sql_injection", "/synthetic/customers/dynamic")
	if dynamic == nil || dynamic.Status != "inconclusive" {
		t.Fatalf("dynamic finding: %+v", dynamic)
	}
	if got := hypothesis(dynamic, ":source_to_sink"); got == nil || got.Status != "unverified" || !strings.Contains(got.Reason, "dynamic_invocation") {
		t.Fatalf("dynamic hypothesis: %+v", got)
	}

	dependency := find(report, "vulnerable_dependency", "")
	if dependency == nil {
		t.Fatal("missing advisory candidate")
	}
	if dependency.Status != "inconclusive" || dependency.Severity != "unknown" || dependency.CWE != "CWE-1395" || dependency.RuntimeStatus != "not_run" {
		t.Fatalf("advisory finding status: %+v", dependency)
	}
	if dependency.Component == nil || dependency.Component.DeclaredVersion != "1.9" || dependency.Component.AdvisoryID != "CVE-2022-42889" || dependency.Component.DeclarationPOM == "" {
		t.Fatalf("advisory component: %+v", dependency.Component)
	}
	if got := hypothesis(dependency, ":declared_version_matches_advisory"); got == nil || got.Status != "supported" {
		t.Fatalf("version hypothesis: %+v", got)
	}
	if got := hypothesis(dependency, ":dependency_reachable_from_http_entrypoint"); got == nil || got.Status != "unverified" || len(got.EvidenceIDs) != 0 {
		t.Fatalf("reachability hypothesis: %+v", got)
	}
	poms := 0
	for _, evidence := range dependency.Evidence {
		if evidence.Kind == "pom" {
			poms++
			if len(evidence.SHA256) != 64 {
				t.Fatalf("pom evidence digest: %+v", evidence)
			}
		}
	}
	if poms == 0 {
		t.Fatalf("no POM evidence: %+v", dependency.Evidence)
	}

	if !hasPrefix(report.Limitations, "static_runtime_separation:") || !hasPrefix(report.Limitations, "correlation_not_exploitation:") {
		t.Fatalf("missing separation limitations: %v", report.Limitations)
	}
}

func TestAnalyzeWithoutAdvisoriesKeepsEndpointAndDataflowEvidence(t *testing.T) {
	snapshot, _ := fixtureSnapshot(t)
	report, err := Analyze(context.Background(), snapshot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 3 || report.Coverage.ScaCandidates != 0 || report.Coverage.ScaDependencies != 6 {
		t.Fatalf("unexpected no-advisory report: %+v", report.Coverage)
	}
	if !hasPrefix(report.Limitations, "advisory_catalog_not_provided") {
		t.Fatalf("missing advisory limitation: %v", report.Limitations)
	}
	for i := range report.Findings {
		if report.Findings[i].Kind != "sql_injection" {
			t.Fatalf("unexpected finding kind: %+v", report.Findings[i])
		}
	}
}

func TestAnalyzeRequiresPinnedSnapshot(t *testing.T) {
	if _, err := Analyze(context.Background(), nil, Options{}); err == nil {
		t.Fatal("nil snapshot accepted")
	}
	snapshot, err := project.Open(context.Background(), t.TempDir(), strings.Repeat("0", 64))
	if err != nil {
		t.Skipf("empty directory is not a snapshot: %v", err)
	}
	defer snapshot.Close()
	if _, err = Analyze(context.Background(), snapshot, Options{}); err == nil {
		t.Fatal("snapshot without hash accepted")
	}
}

func hasPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}
