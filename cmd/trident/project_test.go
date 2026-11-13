package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectCLIWithoutDatabase(t *testing.T) {
	t.Setenv("TRIDENT_DATABASE_URL", "")
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("class Example {\n  // synthetic search marker\n}\n")
	for name, data := range map[string][]byte{"Example.java": content, "pom.xml": []byte("<project/>\n"), ".env": []byte("SYNTHETIC_SECRET=not-a-real-key")} {
		if err := os.WriteFile(filepath.Join(source, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	destination := filepath.Join(parent, "snapshot")
	var out bytes.Buffer
	if err := runProject(context.Background(), []string{"import", "--source", source, "--snapshot", destination}, &out); err != nil {
		t.Fatal(err)
	}
	var imported struct {
		SchemaVersion int    `json:"schema_version"`
		SnapshotHash  string `json:"snapshot_hash"`
	}
	if err := json.Unmarshal(out.Bytes(), &imported); err != nil {
		t.Fatal(err)
	}
	if imported.SchemaVersion != 1 || len(imported.SnapshotHash) != 64 {
		t.Fatalf("invalid import receipt: %s", out.Bytes())
	}
	for _, command := range []struct {
		name string
		args []string
		want string
	}{
		{"inspect", nil, "pom.xml"},
		{"list", []string{"--limit", "1"}, "Example.java"},
		{"read", []string{"--path", "Example.java", "--limit", "2"}, "synthetic search marker"},
		{"search", []string{"--query", "search marker"}, "Example.java"},
	} {
		t.Run(command.name, func(t *testing.T) {
			out.Reset()
			args := append([]string{command.name, "--snapshot", destination, "--snapshot-hash", imported.SnapshotHash}, command.args...)
			if err := runProject(context.Background(), args, &out); err != nil {
				t.Fatal(err)
			}
			if !json.Valid(out.Bytes()) || !strings.Contains(out.String(), imported.SnapshotHash) || !strings.Contains(out.String(), command.want) {
				t.Fatalf("unexpected output: %s", out.Bytes())
			}
			if strings.Contains(out.String(), "SYNTHETIC_SECRET") {
				t.Fatal("excluded file content leaked")
			}
		})
	}
	for _, name := range []string{"Example.java", "pom.xml", ".env"} {
		if _, err := os.Stat(filepath.Join(source, name)); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := os.ReadFile(filepath.Join(source, "Example.java")); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("source changed: %v", err)
	}
	out.Reset()
	if err := runProject(context.Background(), []string{"import", "--source", source, "--snapshot", destination}, &out); err == nil || out.Len() != 0 {
		t.Fatal("existing destination accepted or success output emitted on failure")
	}
}

// [01] CLI 分流必须在数据库门禁之前；即使配置了无效 DSN，也不能连接它。
func TestProjectMainDispatchWithoutDatabase(t *testing.T) {
	for _, dsn := range []string{"", "not-a-database-url"} {
		t.Run(dsn, func(t *testing.T) {
			t.Setenv("TRIDENT_DATABASE_URL", dsn)
			previous := os.Args
			os.Args = []string{"trident", "project", "unknown"}
			defer func() { os.Args = previous }()
			if err := run(); err == nil || !strings.Contains(err.Error(), "unknown project command") {
				t.Fatalf("project command passed through database gate: %v", err)
			}
		})
	}
}

func TestProjectCLIInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"shell"},
		{"import"},
		{"import", "--source", "not-read", "--snapshot", "not-created", "extra"},
		{"inspect", "--snapshot", "not-opened"},
		{"list", "--snapshot", "not-opened", "--snapshot-hash", strings.Repeat("a", 64), "--limit", "201"},
		{"read", "--snapshot", "not-opened", "--snapshot-hash", strings.Repeat("a", 64), "--path", "file", "--cursor", "x", "--start-line", "1"},
		{"search", "--snapshot", "not-opened", "--snapshot-hash", strings.Repeat("a", 64)},
		{"inspect", "--snapshot", "not-opened", "--source", "unexpected"},
	} {
		var out bytes.Buffer
		if err := runProject(context.Background(), args, &out); err == nil || out.Len() != 0 {
			t.Fatalf("invalid args accepted: %q", args)
		}
	}
}
