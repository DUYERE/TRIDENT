package r3

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNodeCheckLanguageProfile(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.js"), []byte("const value = 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := runLanguageValidation(context.Background(), dir, "node-check", Sandbox{Kind: SandboxProcess})
	if len(results) != 1 || results[0].Status != "ok" {
		t.Fatalf("node-check failed: %+v", results)
	}
}

func TestPythonCompileLanguageProfile(t *testing.T) {
	if _, err := exec.LookPath("python"); err != nil {
		t.Skip("python not installed")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.py"), []byte("value = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := runLanguageValidation(context.Background(), dir, "python-compile", Sandbox{Kind: SandboxProcess})
	if len(results) != 1 || results[0].Status != "ok" {
		t.Fatalf("python-compile failed: %+v", results)
	}
}

func TestMissingPHPToolchainReportsToolchainUnavailable(t *testing.T) {
	t.Setenv("PATH", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.php"), []byte("<?php echo 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := runLanguageValidation(context.Background(), dir, "php-lint", Sandbox{Kind: SandboxProcess})
	if len(results) != 1 || results[0].Status != "toolchain_unavailable" {
		t.Fatalf("missing php must be toolchain_unavailable: %+v", results)
	}
}

func TestProbeToolchainsReportsHostAvailability(t *testing.T) {
	t.Setenv("PATH", "")
	for _, item := range ProbeToolchains() {
		if item.Available || item.Status != "toolchain_unavailable" || item.Reason == "" {
			t.Fatalf("probe without PATH must report unavailable: %+v", item)
		}
	}
}
