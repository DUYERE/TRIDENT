package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/findings"
)

func TestFindingsCLIWithoutDatabase(t *testing.T) {
	t.Setenv("TRIDENT_DATABASE_URL", "")
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	javaDir := filepath.Join(source, "src", "main", "java", "demo")
	if err := os.MkdirAll(javaDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pom := `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>demo</groupId><artifactId>app</artifactId><version>1</version>
  <dependencies>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency>
  </dependencies>
</project>`
	controller := `package demo;
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
	if err := os.WriteFile(filepath.Join(source, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(javaDir, "App.java"), []byte(controller), 0o600); err != nil {
		t.Fatal(err)
	}
	advisory, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "java-maven", "advisories", "CVE-2022-42889.json"))
	if err != nil {
		t.Fatal(err)
	}
	advisoryPath := filepath.Join(parent, "advisory.json")
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
	args := []string{"findings", "--snapshot", destination, "--snapshot-hash", receipt.SnapshotHash, "--advisories", advisoryPath}
	var out bytes.Buffer
	if err = runAudit(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	var report findings.Report
	if err = json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 2 || report.Coverage.FindingsStaticConfirmed != 1 || report.Coverage.ScaCandidates != 1 {
		t.Fatalf("finding coverage: %+v", report)
	}
	var sqlFinding, dependency bool
	for _, finding := range report.Findings {
		if finding.RuntimeStatus != "not_run" {
			t.Fatalf("runtime status: %+v", finding)
		}
		switch finding.Kind {
		case "sql_injection":
			sqlFinding = finding.Status == "static_confirmed" && finding.Endpoint != nil && finding.Endpoint.Path == "/users"
		case "vulnerable_dependency":
			dependency = finding.Status == "inconclusive" && finding.Component != nil && finding.Component.DeclaredVersion == "1.9"
		}
	}
	if !sqlFinding || !dependency {
		t.Fatalf("linked findings missing: %+v", report.Findings)
	}
	if !hasLimitation(report.Limitations, "static_runtime_separation:") {
		t.Fatalf("missing separation limitation: %v", report.Limitations)
	}

	for _, invalid := range [][]string{
		{},
		{"--snapshot", destination},
		{"--snapshot", destination, "--snapshot-hash", receipt.SnapshotHash, "extra"},
		{"--snapshot", destination, "--snapshot-hash", receipt.SnapshotHash, "--advisories", filepath.Join(parent, "missing.json")},
	} {
		out.Reset()
		if err = runFindings(context.Background(), invalid, &out); err == nil || out.Len() != 0 {
			t.Fatalf("invalid findings args accepted: %q", invalid)
		}
	}
}

// [01] Findings dispatch must happen before the database gate.
func TestFindingsMainDispatchWithoutDatabase(t *testing.T) {
	for _, dsn := range []string{"", "not-a-database-url"} {
		t.Setenv("TRIDENT_DATABASE_URL", dsn)
		previous := os.Args
		os.Args = []string{"trident", "audit", "findings"}
		defer func() { os.Args = previous }()
		if err := run(); err == nil || !strings.Contains(err.Error(), "audit findings requires") {
			t.Fatalf("findings command passed through database gate: %v", err)
		}
	}
}

func hasLimitation(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}
