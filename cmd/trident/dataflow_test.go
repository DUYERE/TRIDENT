package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trident/internal/dataflow"
)

func TestDataflowCLIWithoutDatabase(t *testing.T) {
	t.Setenv("TRIDENT_DATABASE_URL", "")
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	javaDir := filepath.Join(source, "src", "main", "java", "demo")
	if err := os.MkdirAll(javaDir, 0o700); err != nil {
		t.Fatal(err)
	}
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
	if err := runAudit(context.Background(), []string{"dataflow", "--snapshot", destination, "--snapshot-hash", receipt.SnapshotHash}, &out); err != nil {
		t.Fatal(err)
	}
	var report dataflow.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Status != "static_confirmed" || report.Findings[0].Sink == nil {
		t.Fatalf("finding: %+v", report.Findings)
	}
	if report.Findings[0].Endpoint.Path != "/users" || report.Findings[0].Sources[0].Parameter != "name" || report.Coverage.FindingsConfirmed != 1 {
		t.Fatalf("finding binding: %+v", report.Findings[0])
	}
	for _, args := range [][]string{
		nil,
		{"--snapshot", destination},
		{"--snapshot", destination, "--snapshot-hash", receipt.SnapshotHash, "extra"},
	} {
		out.Reset()
		if err := runDataflow(context.Background(), args, &out); err == nil || out.Len() != 0 {
			t.Fatalf("invalid dataflow args accepted: %q", args)
		}
	}
}

// [01] Dataflow dispatch must happen before the database gate.
func TestDataflowMainDispatchWithoutDatabase(t *testing.T) {
	for _, dsn := range []string{"", "not-a-database-url"} {
		t.Setenv("TRIDENT_DATABASE_URL", dsn)
		previous := os.Args
		os.Args = []string{"trident", "audit", "dataflow"}
		defer func() { os.Args = previous }()
		if err := run(); err == nil || !strings.Contains(err.Error(), "audit dataflow requires") {
			t.Fatalf("dataflow command passed through database gate: %v", err)
		}
	}
}
