package sca

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func snapshotFromFiles(t *testing.T, files map[string]string) *project.Snapshot {
	t.Helper()
	source := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		target := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	destination := filepath.Join(t.TempDir(), "snapshot")
	imported, err := project.Import(context.Background(), source, destination)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := project.Open(context.Background(), destination, imported.Hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Close() })
	return snapshot
}

func dependency(report Report, module, artifactID string) Dependency {
	for _, dependency := range report.Dependencies {
		if dependency.Module == module && dependency.ArtifactID == artifactID {
			return dependency
		}
	}
	return Dependency{}
}

func match(report Report, module string) AdvisoryMatch {
	for _, match := range report.AdvisoryMatches {
		if match.Module == module {
			return match
		}
	}
	return AdvisoryMatch{}
}

func TestInspectFixtureDeclarationsAndExactAdvisoryCases(t *testing.T) {
	snapshot, advisoryPath := fixtureSnapshot(t)
	report, err := Inspect(context.Background(), snapshot, Options{AdvisoryPath: advisoryPath})
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Project.POMCount != 3 || report.Project.ModuleCount != 2 || report.Project.BuildSystem != "Maven" {
		t.Fatalf("unexpected project coverage: %+v", report.Project)
	}
	if len(report.Project.RootPOMs) != 1 || report.Project.RootPOMs[0] != "pom.xml" {
		t.Fatalf("unexpected roots: %v", report.Project.RootPOMs)
	}
	if report.Coverage.DependenciesDeclared != 6 || report.Coverage.DependenciesResolved != 6 || report.Coverage.DependenciesUnresolved != 0 {
		t.Fatalf("unexpected dependency coverage: %+v", report.Coverage)
	}
	candidate := dependency(report, "jdbc-app", "commons-text")
	if candidate.Version != "1.9" || candidate.ManagementPOM != "pom.xml" || candidate.Property != "commons-text.version" || candidate.PropertyPOM != "pom.xml" || candidate.Scope != "compile" || !candidate.Direct || candidate.VersionStatus != "resolved" {
		t.Fatalf("candidate declaration: %+v", candidate)
	}
	control := dependency(report, "advisory-control", "commons-text")
	if control.Version != "1.10.0" || control.PropertyPOM != "advisory-control/pom.xml" || control.ManagementPOM != "pom.xml" {
		t.Fatalf("control declaration: %+v", control)
	}
	for _, dependency := range report.Dependencies {
		if dependency.Module == "." {
			t.Fatalf("dependencyManagement was reported as an imported dependency: %+v", dependency)
		}
	}
	if len(report.AdvisoryMatches) != 2 {
		t.Fatalf("unexpected matches: %+v", report.AdvisoryMatches)
	}
	matched := match(report, "jdbc-app")
	if matched.VersionStatus != "version_matched" || matched.SupplyChainStatus != "version_matched" || matched.FindingStatus != "candidate" || matched.DeclaredVersion != "1.9" || matched.RuntimeStatus != "not_run" || matched.InputReachability != "unknown" {
		t.Fatalf("candidate match: %+v", matched)
	}
	notAffected := match(report, "advisory-control")
	if notAffected.VersionStatus != "not_affected" || notAffected.SupplyChainStatus != "not_affected" || notAffected.FindingStatus != "none" || !strings.Contains(notAffected.AssessmentScope, "CVE-2022-42889") {
		t.Fatalf("control match: %+v", notAffected)
	}
	if report.Coverage.MavenExecuted || report.Coverage.TransitiveTree != "not_available" || report.Coverage.ArtifactHashes != "unavailable" {
		t.Fatalf("execution coverage overclaimed: %+v", report.Coverage)
	}
	if len(report.Advisories) != 1 || report.Advisories[0].AllCVEsChecked {
		t.Fatalf("advisory coverage: %+v", report.Advisories)
	}
}

func TestInspectUnresolvedPropertyAndUnknownVersionCase(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"pom.xml": `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>${missing.version}</version></dependency>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>9.9.9</version></dependency>
  </dependencies>
</project>`,
	})
	advisoryPath := filepath.Join(t.TempDir(), "advisory.json")
	content, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "java-maven", "advisories", "CVE-2022-42889.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(advisoryPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(context.Background(), snapshot, Options{AdvisoryPath: advisoryPath})
	if err != nil {
		t.Fatal(err)
	}
	if report.Coverage.DependenciesUnresolved != 1 || report.Coverage.DependenciesResolved != 1 {
		t.Fatalf("coverage: %+v", report.Coverage)
	}
	var unresolved, unknown bool
	for _, dependency := range report.Dependencies {
		if dependency.VersionReason == "unresolved_property:missing.version" {
			unresolved = true
		}
	}
	for _, match := range report.AdvisoryMatches {
		if match.Reason == "unresolved_version" {
			unresolved = true
		}
		if match.Reason == "no_exact_version_case" && match.FindingStatus == "unknown" {
			unknown = true
		}
	}
	if !unresolved || !unknown {
		t.Fatalf("unresolved/unknown coverage lost: %+v %+v", report.Dependencies, report.AdvisoryMatches)
	}
}

func TestInspectRejectsDTDAndMarksPartial(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"pom.xml": `<?xml version="1.0"?>
<!DOCTYPE project [<!ENTITY version "1.0">]>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>app</artifactId><version>&version;</version>
  <dependencies>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency>
  </dependencies>
</project>`,
	})
	report, err := Inspect(context.Background(), snapshot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial || report.Coverage.POMsRejected != 1 || report.Coverage.POMsScanned != 0 || len(report.Dependencies) != 0 {
		t.Fatalf("DTD POM was not rejected: %+v", report)
	}
	found := false
	for _, limitation := range report.Limitations {
		if strings.HasPrefix(limitation, "rejected_pom:pom.xml:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("rejection not reported: %v", report.Limitations)
	}
}

func TestInspectParentCycleTerminates(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"a/pom.xml": `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>example</groupId><artifactId>b</artifactId><version>1</version><relativePath>../b/pom.xml</relativePath></parent>
  <groupId>example</groupId><artifactId>a</artifactId><version>1</version></project>`,
		"b/pom.xml": `<project><modelVersion>4.0.0</modelVersion>
  <parent><groupId>example</groupId><artifactId>a</artifactId><version>1</version><relativePath>../a/pom.xml</relativePath></parent>
  <groupId>example</groupId><artifactId>b</artifactId><version>1</version></project>`,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	report, err := Inspect(ctx, snapshot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial || report.Coverage.POMsScanned != 2 {
		t.Fatalf("cycle coverage: %+v", report)
	}
	found := false
	for _, limitation := range report.Limitations {
		if strings.Contains(limitation, "parent_cycle:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("cycle not reported: %v", report.Limitations)
	}
}

func TestInspectManagementAloneAndDuplicateDeclaration(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"pom.xml": `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>parent</artifactId><version>1</version><packaging>pom</packaging>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId></dependency>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId></dependency>
  </dependencies>
</project>`,
	})
	report, err := Inspect(context.Background(), snapshot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Dependencies) != 2 || report.Dependencies[0].Version != "1.9" || report.Dependencies[1].Version != "1.9" {
		t.Fatalf("management lookup: %+v", report.Dependencies)
	}
	if report.Dependencies[0].Duplicate || !report.Dependencies[1].Duplicate {
		t.Fatalf("duplicate marker: %+v", report.Dependencies)
	}
}

func TestAdvisoryRangeAliasesAndOutsideRange(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"pom.xml": `<project><modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9.5</version></dependency>
  </dependencies>
</project>`,
	})
	advisoryPath := filepath.Join(t.TempDir(), "range.json")
	advisory := `{"schema_version":"1.0.0","fixture_id":"range","kind":"curated_advisory_fixture","advisory_id":"CVE-RANGE","aliases":["GHSA-xxxx"],"aliases_complete":true,"published_date":"2026-01-01","retrieved_date":"2026-01-01","ecosystem":"Maven","package":{"group_id":"org.apache.commons","artifact_id":"commons-text"},"sources":[],"matching_scope":{"source_id":"","policy":"range","fixed_default_configuration_release":""},"version_cases":[{"version_range":">=1.9,<1.10","version_matched":true,"supply_chain_status":"version_matched","finding_status":"candidate","assessment_scope":"declared range","runtime_status":"not_run"}],"exploitability_prerequisites":[],"forbidden_inferences":[],"coverage":{"advisories":[],"all_cves_checked":false,"artifact_hashes_available":false,"effective_dependency_tree_available":false,"runtime_exploit_test_available":false}}`
	if err := os.WriteFile(advisoryPath, []byte(advisory), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(context.Background(), snapshot, Options{AdvisoryPath: advisoryPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AdvisoryMatches) != 1 {
		t.Fatalf("range match missing: %+v", report.AdvisoryMatches)
	}
	match := report.AdvisoryMatches[0]
	if match.FindingStatus != "candidate" || match.MatchedBy != "range" || len(match.Aliases) != 1 || match.Aliases[0] != "GHSA-xxxx" {
		t.Fatalf("unexpected range match: %+v", match)
	}
	if report.Advisories[0].RangeCaseCount != 1 || !report.Advisories[0].AliasesComplete {
		t.Fatalf("advisory info: %+v", report.Advisories[0])
	}

	outside := snapshotFromFiles(t, map[string]string{
		"pom.xml": `<project><modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.10.0</version></dependency>
  </dependencies>
</project>`,
	})
	report, err = Inspect(context.Background(), outside, Options{AdvisoryPath: advisoryPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AdvisoryMatches) != 1 || report.AdvisoryMatches[0].VersionStatus != "not_affected" || report.AdvisoryMatches[0].MatchedBy != "range_excluded" {
		t.Fatalf("outside-range result: %+v", report.AdvisoryMatches)
	}
}

func TestGradleDeclarationsAndModules(t *testing.T) {
	snapshot := snapshotFromFiles(t, map[string]string{
		"settings.gradle": `rootProject.name = 'demo'`,
		"build.gradle": `group = 'com.example'
version = '1.0.0'
dependencies {
  implementation "org.apache.commons:commons-text:1.9"
  implementation group: 'com.google.guava', name: 'guava', version: '33.0.0-jre'
  testImplementation 'junit:junit:4.12'
  implementation platform('org.springframework.boot:spring-boot-dependencies:3.2.0')
  implementation libs.commons.lang
  implementation project(':app')
}`,
		"app/build.gradle.kts": `dependencies {
  implementation("org.apache.commons:commons-text:1.10.0")
  implementation("com.example:dynamic:1.+")
}`,
	})
	report, err := Inspect(context.Background(), snapshot, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Project.BuildSystem != "Gradle" || report.Project.GradleFileCount != 2 || report.Coverage.GradleFilesScanned != 2 {
		t.Fatalf("gradle project: %+v %+v", report.Project, report.Coverage)
	}
	if report.Coverage.DependenciesDeclared != 5 || report.Coverage.DependenciesResolved != 4 || report.Coverage.DependenciesUnresolved != 1 {
		t.Fatalf("gradle dependency coverage: %+v %+v", report.Coverage, report.Dependencies)
	}
	if report.Project.ModuleCount != 2 || len(report.Project.RootGradleFiles) != 1 || report.Project.RootGradleFiles[0] != "build.gradle" {
		t.Fatalf("gradle modules: %+v", report.Project)
	}
	var text, guava, dynamic Dependency
	for _, dependency := range report.Dependencies {
		switch dependency.ArtifactID {
		case "commons-text":
			if dependency.DeclarationPOM == "build.gradle" {
				text = dependency
			}
		case "guava":
			guava = dependency
		case "dynamic":
			dynamic = dependency
		}
	}
	if text.GroupID != "org.apache.commons" || text.Version != "1.9" || text.DeclarationPOM != "build.gradle" {
		t.Fatalf("string notation: %+v", text)
	}
	if guava.GroupID != "com.google.guava" || guava.Version != "33.0.0-jre" {
		t.Fatalf("map notation: %+v", guava)
	}
	if dynamic.VersionStatus != "unresolved" || dynamic.VersionReason != "gradle_dynamic_or_missing_version" {
		t.Fatalf("dynamic version: %+v", dynamic)
	}
	tree := Tree(report)
	if len(tree.Roots) != 1 || tree.Roots[0].POM != "build.gradle" {
		t.Fatalf("gradle tree roots: %+v", tree.Roots)
	}
	var appChild bool
	for _, child := range tree.Roots[0].Children {
		if child.POM == "app/build.gradle.kts" {
			appChild = true
		}
	}
	if !appChild || tree.Coverage.ExternalLeaves == 0 {
		t.Fatalf("gradle tree children: %+v", tree.Roots[0].Children)
	}
}

func TestModuleDeclarationTree(t *testing.T) {
	snapshot, advisoryPath := fixtureSnapshot(t)
	report, err := Inspect(context.Background(), snapshot, Options{AdvisoryPath: advisoryPath})
	if err != nil {
		t.Fatal(err)
	}
	tree := Tree(report)
	if len(tree.Roots) != 1 || tree.Roots[0].POM != "pom.xml" {
		t.Fatalf("tree roots: %+v", tree.Roots)
	}
	if tree.Coverage.Modules != 2 || tree.Coverage.ExternalLeaves == 0 || tree.Coverage.Cycles != 0 {
		t.Fatalf("tree coverage: %+v", tree.Coverage)
	}
	var modules int
	var walk func(TreeNode)
	walk = func(node TreeNode) {
		if !node.External {
			modules++
		}
		for _, child := range node.Children {
			walk(child)
		}
	}
	walk(tree.Roots[0])
	if modules != 3 {
		t.Fatalf("module nodes: %d", modules)
	}
}

func TestLoadAdvisoriesRejectsUnsafeOrUnknownFormats(t *testing.T) {
	valid := `{"schema_version":"1.0.0","fixture_id":"x","kind":"curated_advisory_fixture","advisory_id":"CVE-X","aliases":[],"aliases_complete":false,"published_date":"2026-01-01","retrieved_date":"2026-01-01","ecosystem":"Maven","package":{"group_id":"g","artifact_id":"a"},"sources":[],"matching_scope":{"source_id":"","policy":"exact","fixed_default_configuration_release":""},"version_cases":[{"version":"1","version_matched":true,"supply_chain_status":"version_matched","finding_status":"candidate","assessment_scope":"","runtime_status":"not_run"}],"exploitability_prerequisites":[],"forbidden_inferences":[],"coverage":{"advisories":[],"all_cves_checked":false,"artifact_hashes_available":false,"effective_dependency_tree_available":false,"runtime_exploit_test_available":false}}`
	dir := t.TempDir()
	for name, content := range map[string]string{
		"valid.json":     valid,
		"unknown.json":   strings.Replace(valid, `"fixture_id":"x"`, `"fixture_id":"x","unexpected":true`, 1),
		"ecosystem.json": strings.Replace(valid, `"ecosystem":"Maven"`, `"ecosystem":"npm"`, 1),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadAdvisories(filepath.Join(dir, "valid.json")); err != nil {
		t.Fatalf("valid advisory rejected: %v", err)
	}
	for _, name := range []string{"unknown.json", "ecosystem.json"} {
		if _, err := loadAdvisories(filepath.Join(dir, name)); !errors.Is(err, ErrAdvisory) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(filepath.Join(dir, "valid.json"), link); err == nil {
		if _, err := loadAdvisories(link); !errors.Is(err, ErrAdvisory) {
			t.Fatalf("symlink advisory accepted: %v", err)
		}
	}
	if _, err := loadAdvisories(filepath.Join(dir, "missing.json")); !errors.Is(err, ErrAdvisory) {
		t.Fatalf("missing advisory: %v", err)
	}
}

func TestAdvisoryDirectoryMergesAndFailsClosed(t *testing.T) {
	source := filepath.Join("..", "..", "tests", "fixtures", "java-maven", "advisories", "CVE-2022-42889.json")
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, "a.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	catalogs, err := loadAdvisoryDir(dir)
	if err != nil || len(catalogs) != 1 || catalogs[0].AdvisoryID != "CVE-2022-42889" {
		t.Fatalf("directory load failed: %v catalogs=%d", err, len(catalogs))
	}

	// A second catalog carrying the same advisory id must not silently win.
	if err = os.WriteFile(filepath.Join(dir, "b.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadAdvisoryDir(dir); !errors.Is(err, ErrAdvisory) {
		t.Fatalf("duplicate advisory must fail closed, got %v", err)
	}
	if _, err = loadAdvisoryDir(filepath.Join(dir, "missing")); !errors.Is(err, ErrAdvisory) {
		t.Fatalf("missing directory must fail closed, got %v", err)
	}
}
