package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/sca"
)

func TestSCACLIWithoutDatabase(t *testing.T) {
	t.Setenv("TRIDENT_DATABASE_URL", "")
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	pom := `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency>
  </dependencies>
</project>`
	if err := os.WriteFile(filepath.Join(source, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatal(err)
	}
	advisoryPath := filepath.Join(parent, "CVE-2022-42889.json")
	advisory, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "java-maven", "advisories", "CVE-2022-42889.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(advisoryPath, advisory, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "snapshot")
	var imported bytes.Buffer
	if err = runProject(context.Background(), []string{"import", "--source", source, "--snapshot", destination}, &imported); err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		SnapshotHash string `json:"snapshot_hash"`
	}
	if err = json.Unmarshal(imported.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = runSCA(context.Background(), []string{"inspect", "--snapshot", destination, "--snapshot-hash", receipt.SnapshotHash, "--advisories", advisoryPath}, &out); err != nil {
		t.Fatal(err)
	}
	var report sca.Report
	if err = json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Project.POMCount != 1 || report.Project.ModuleCount != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if len(report.Dependencies) != 1 || report.Dependencies[0].Version != "1.9" {
		t.Fatalf("dependency output: %+v", report.Dependencies)
	}
	if len(report.AdvisoryMatches) != 1 || report.AdvisoryMatches[0].VersionStatus != "version_matched" || report.AdvisoryMatches[0].FindingStatus != "candidate" {
		t.Fatalf("advisory output: %+v", report.AdvisoryMatches)
	}
	if report.Coverage.MavenExecuted || report.Coverage.RuntimeStatus != "not_run" {
		t.Fatalf("execution overclaimed: %+v", report.Coverage)
	}
	if strings.Contains(out.String(), "SYNTHETIC") {
		t.Fatal("unexpected content in report")
	}
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"inspect"},
		{"inspect", "--snapshot", destination},
		{"inspect", "--snapshot", destination, "--snapshot-hash", receipt.SnapshotHash, "extra"},
	} {
		out.Reset()
		if err = runSCA(context.Background(), args, &out); err == nil || out.Len() != 0 {
			t.Fatalf("invalid sca args accepted: %q", args)
		}
	}
}

// [01] SCA dispatch must happen before the database gate, like project tools.
func TestSCAMainDispatchWithoutDatabase(t *testing.T) {
	for _, dsn := range []string{"", "not-a-database-url"} {
		t.Setenv("TRIDENT_DATABASE_URL", dsn)
		previous := os.Args
		os.Args = []string{"trident", "sca", "unknown"}
		defer func() { os.Args = previous }()
		if err := run(); err == nil || !strings.Contains(err.Error(), "unknown sca command") {
			t.Fatalf("sca command passed through database gate: %v", err)
		}
	}
}
