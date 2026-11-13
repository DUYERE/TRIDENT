package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/audit"
)

func TestAuditCLIWithoutDatabase(t *testing.T) {
	t.Setenv("TRIDENT_DATABASE_URL", "")
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	javaDir := filepath.Join(source, "src", "main", "java", "demo")
	if err := os.MkdirAll(javaDir, 0o700); err != nil {
		t.Fatal(err)
	}
	controller := `package demo;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api")
public class App {
    @GetMapping("/users")
    public String users(@RequestParam("name") String name) { return name; }
}
`
	if err := os.WriteFile(filepath.Join(javaDir, "App.java"), []byte(controller), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "snapshot")
	var imported bytes.Buffer
	if err := runProject(context.Background(), []string{"import", "--source", source, "--snapshot", destination}, &imported); err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		SnapshotHash string `json:"snapshot_hash"`
	}
	if err := json.Unmarshal(imported.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runAudit(context.Background(), []string{"endpoints", "--snapshot", destination, "--snapshot-hash", receipt.SnapshotHash}, &out); err != nil {
		t.Fatal(err)
	}
	var report audit.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Partial || report.Coverage.ControllersFound != 1 || report.Coverage.EndpointsFound != 1 || len(report.Endpoints) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	endpoint := report.Endpoints[0]
	if endpoint.Path != "/api/users" || endpoint.HTTPMethods[0] != "GET" || endpoint.Method != "users" || len(endpoint.Parameters) != 1 || endpoint.Parameters[0].BindingName != "name" {
		t.Fatalf("endpoint: %+v", endpoint)
	}
	if report.Coverage.JavaAST != "not_available" || report.Coverage.TaintAnalysis != "not_run" || report.Coverage.RuntimeStatus != "not_run" {
		t.Fatalf("overclaimed coverage: %+v", report.Coverage)
	}
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"endpoints"},
		{"endpoints", "--snapshot", destination},
		{"endpoints", "--snapshot", destination, "--snapshot-hash", receipt.SnapshotHash, "extra"},
	} {
		out.Reset()
		if err := runAudit(context.Background(), args, &out); err == nil || out.Len() != 0 {
			t.Fatalf("invalid audit args accepted: %q", args)
		}
	}
}

// [01] Audit dispatch must happen before the database gate.
func TestAuditMainDispatchWithoutDatabase(t *testing.T) {
	for _, dsn := range []string{"", "not-a-database-url"} {
		t.Setenv("TRIDENT_DATABASE_URL", dsn)
		previous := os.Args
		os.Args = []string{"trident", "audit", "unknown"}
		defer func() { os.Args = previous }()
		if err := run(); err == nil || !strings.Contains(err.Error(), "unknown audit command") {
			t.Fatalf("audit command passed through database gate: %v", err)
		}
	}
}
