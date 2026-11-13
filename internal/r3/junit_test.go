package r3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTestSummary(t *testing.T) {
	ok := parseTestSummary("Time: 0.01\n\nOK (2 tests)\n")
	if ok == nil || ok.Tests != 2 || ok.Failures != 0 || ok.Errors != 0 {
		t.Fatalf("OK summary: %+v", ok)
	}
	failed := parseTestSummary("Tests run: 3,  Failures: 1,  Errors: 0,  Skipped: 2\n")
	if failed == nil || failed.Tests != 3 || failed.Failures != 1 || failed.Skipped != 2 {
		t.Fatalf("failure summary: %+v", failed)
	}
	if parseTestSummary("no summary here") != nil {
		t.Fatal("unrecognized output produced a summary")
	}
}

func TestParseJUnitXMLDirAndJacoco(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "TEST-A.xml"), []byte(`<testsuite name="A" tests="2" failures="1" errors="0" skipped="1"></testsuite>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "TEST-B.xml"), []byte(`<testsuites><testsuite name="B" tests="3" failures="0" errors="0" skipped="0"></testsuite></testsuites>`), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := parseJUnitXMLDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Suites != 2 || summary.Tests != 5 || summary.Failures != 1 || summary.Skipped != 1 || len(summary.Files) != 2 {
		t.Fatalf("xml summary: %+v", summary)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.xml"), []byte(`<not-a-suite/>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseJUnitXMLDir(dir); err == nil {
		t.Fatal("invalid JUnit XML accepted")
	}

	jacoco := filepath.Join(t.TempDir(), "jacoco.xml")
	if err := os.WriteFile(jacoco, []byte(`<report name="x"><counter type="LINE" missed="2" covered="8"/><counter type="BRANCH" missed="1" covered="3"/><counter type="METHOD" missed="0" covered="4"/></report>`), 0o600); err != nil {
		t.Fatal(err)
	}
	coverage, err := parseJacocoXML(jacoco)
	if err != nil {
		t.Fatal(err)
	}
	if coverage.LineCovered != 8 || coverage.LineTotal != 10 || coverage.LinePercent != 80 || coverage.BranchTotal != 4 || coverage.MethodTotal != 4 {
		t.Fatalf("coverage: %+v", coverage)
	}
}

func TestJUnitClassAndContainerClasspathValidation(t *testing.T) {
	classes, err := junitTestClasses("a.B,c.D a.B", nil)
	if err != nil || len(classes) != 2 || classes[0] != "a.B" || classes[1] != "c.D" {
		t.Fatalf("classes: %v %v", classes, err)
	}
	if _, err := junitTestClasses("not a class!", nil); err == nil {
		t.Fatal("invalid class accepted")
	}
	entries := []string{t.TempDir(), t.TempDir()}
	mounts, classpath, err := junitContainerClasspath(entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 2 || !strings.Contains(classpath, "/trident-cp/0:/trident-cp/1") {
		t.Fatalf("mounts/classpath: %+v %s", mounts, classpath)
	}
	for _, mount := range mounts {
		if !mount.ReadOnly || !strings.HasPrefix(mount.Container, "/trident-cp/") {
			t.Fatalf("unsafe mount: %+v", mount)
		}
	}
}
