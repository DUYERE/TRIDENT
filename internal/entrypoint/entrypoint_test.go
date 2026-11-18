package entrypoint

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"trident/internal/project"
)

func TestInspectDetectsPHPRequestScriptsWithoutFramework(t *testing.T) {
	source := t.TempDir()
	files := map[string]string{
		"public/index.php": `<?php
$app = require __DIR__ . '/../bootstrap.php';
$app->run();
`,
		"public/request.php": `<?php
$body = file_get_contents('php://input');
`,
		"root-action.php": `<?php
$q = $_GET['q'];
`,
		"modules/Reports/archive.php": `<?php
if (isset($_POST['id'])) {
    $id = $_POST['id'];
}
`,
		"modules/Reports/view.php": `<?php
echo "read only";
`,
		"src/Internal.php": `<?php
$value = $_GET['internal'];
`,
		"app/Controller.php": `<?php
$value = $_GET['controller'];
`,
		"vendor/example/action.php": `<?php
$value = $_GET['dependency'];
`,
		"thinkphp/library/think/Request.php": `<?php
$value = $_GET['framework'];
`,
		"public/static/vendor/action.php": `<?php
$value = $_GET['static'];
`,
	}
	for name, content := range files {
		full := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
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

	report, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial {
		t.Fatalf("unexpected partial report: %+v", report)
	}
	byPath := map[string]Entry{}
	for _, entry := range report.Entries {
		byPath[entry.Path] = entry
	}
	for _, path := range []string{"public/request.php", "root-action.php", "modules/Reports/archive.php"} {
		entry, ok := byPath[path]
		if !ok {
			t.Fatalf("missing request script %s; got %+v", path, report.Entries)
		}
		if entry.Language != "php" || entry.Kind != "request_script" || entry.Reason != "php_request_superglobal_observed" {
			t.Fatalf("%s: %+v", path, entry)
		}
		if entry.Line < 2 || entry.SHA256 == "" {
			t.Fatalf("%s: incomplete evidence: %+v", path, entry)
		}
	}
	if entry := byPath["public/index.php"]; entry.Kind != "application_entry" {
		t.Fatalf("known entry changed kind: %+v", entry)
	}
	for _, path := range []string{
		"modules/Reports/view.php", "src/Internal.php", "app/Controller.php", "vendor/example/action.php",
		"thinkphp/library/think/Request.php", "public/static/vendor/action.php",
	} {
		if _, ok := byPath[path]; ok {
			t.Fatalf("excluded or request-free file reported: %s", path)
		}
	}
	counts := map[string]int{}
	for _, entry := range report.Entries {
		counts[entry.Path]++
	}
	if counts["public/index.php"] != 1 {
		t.Fatalf("known entry duplicated: %+v", report.Entries)
	}
	for _, limitation := range []string{
		"php_request_script_candidate_not_route",
		"php_request_script_not_deployed",
		"php_request_script_content_bounded_1mib",
	} {
		if !containsString(report.Limitations, limitation) {
			t.Fatalf("missing limitation %s: %+v", limitation, report.Limitations)
		}
	}
}

func TestInspectBoundsPHPRequestScripts(t *testing.T) {
	source := t.TempDir()
	for i := 0; i < MaxEntries+2; i++ {
		name := filepath.Join("scripts", "handler-"+strconv.Itoa(i)+".php")
		full := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		content := "<?php\n$value = $_GET['q'];\n"
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
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

	report, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Partial || len(report.Entries) != MaxEntries {
		t.Fatalf("bound failed: partial=%v entries=%d", report.Partial, len(report.Entries))
	}
	if !containsString(report.Limitations, "entrypoint_inventory_truncated") {
		t.Fatalf("truncation limitation missing: %+v", report.Limitations)
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func TestInspectDetectsApplicationEntries(t *testing.T) {
	source := t.TempDir()
	files := map[string]string{
		"public/index.php": `<?php
require __DIR__ . '/../thinkphp/start.php';
$app = new think\App();
$app->run();
`,
		"public/router.php": `<?php
if (is_file($_SERVER['DOCUMENT_ROOT'] . $_SERVER['PATH_INFO'])) {
    return false;
}
require __DIR__ . '/index.php';
`,
		"src/Program.cs": `var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.Run();
`,
		"manage.py": `#!/usr/bin/env python
import django
from django.core.management import execute_from_command_line
execute_from_command_line()
`,
		"server.js": `const express = require("express");
const app = express();
app.listen(3000);
`,
		"main.go": `package main

import "net/http"

func main() {
    http.ListenAndServe(":8080", nil)
}
`,
		"vendor/example/index.php": `<?php
// This is a dependency example and must not be reported.
`,
		"tests/index.php": `<?php
// Fixture index must not be reported.
`,
	}
	for name, content := range files {
		full := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
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

	report, err := Inspect(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if report.Partial {
		t.Fatalf("unexpected partial report: %+v", report)
	}
	got := map[string]Entry{}
	for _, entry := range report.Entries {
		got[entry.Path] = entry
	}
	want := map[string]struct {
		language  string
		framework string
	}{
		"public/index.php":  {language: "php", framework: "ThinkPHP"},
		"public/router.php": {language: "php", framework: "PHP built-in server router"},
		"src/Program.cs":    {language: "csharp", framework: "ASP.NET Core"},
		"manage.py":         {language: "python", framework: "Django"},
		"server.js":         {language: "javascript", framework: "Express"},
		"main.go":           {language: "go", framework: "net/http"},
	}
	for name, expected := range want {
		entry, ok := got[name]
		if !ok {
			t.Fatalf("missing entry %s; got %+v", name, report.Entries)
		}
		if entry.Language != expected.language || entry.Framework != expected.framework {
			t.Fatalf("%s: got language=%q framework=%q, want %q/%q", name, entry.Language, entry.Framework, expected.language, expected.framework)
		}
		if entry.Line < 1 || entry.SHA256 == "" {
			t.Fatalf("%s: incomplete evidence: %+v", name, entry)
		}
	}
	for _, excluded := range []string{"vendor/example/index.php", "tests/index.php"} {
		if _, ok := got[excluded]; ok {
			t.Fatalf("excluded entry was reported: %s", excluded)
		}
	}
}
