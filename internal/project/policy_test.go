package project

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// 01: Keep portable names stricter than either native OS accepts by itself.
func TestPolicyPortablePathValidation(t *testing.T) {
	for _, name := range []string{"src/main.go", "notes/file_name-1.txt", "中文/源码.go", "COM10.txt", "console.txt"} {
		if err := validateRelative(name); err != nil {
			t.Errorf("valid %q: %v", name, err)
		}
	}
	for _, name := range []string{"", ".", "..", "../x", "/x", `C:\x`, `a\b`, "a:b", "a//b", "a/./b", "a/../b", "a.", "a ", "a\n", "NUL.txt", "CON", "COM1.log", "LPT9", "COM¹.txt", "LPT².log", "a?", "a|b", "a\x00b", strings.Repeat("x", 256), strings.Repeat("d/", 33) + "x"} {
		if err := validateRelative(name); err == nil {
			t.Errorf("invalid accepted %q", name)
		}
	}
}
func TestPolicyDefaultSensitiveExclusions(t *testing.T) {
	for _, name := range []string{".git", ".ssh", ".aws", ".kube", "secrets", "credentials", "node_modules", "vendor", "target"} {
		if exclusionReason(name, true) == "" {
			t.Errorf("sensitive directory not excluded: %s", name)
		}
	}
	for _, name := range []string{".env", ".ENV.production", "id_rsa", "id_ed25519.pub", "private.key", "certificate.pem", "credentials.json", "secrets.yml", "application_default_credentials.json", "dump.sql", "data.db", "archive.zip"} {
		if exclusionReason(name, false) == "" {
			t.Errorf("sensitive file not excluded: %s", name)
		}
	}
	for _, name := range []string{"main.go", "pom.xml", "package.json", "go.mod", "src/notes.txt"} {
		if exclusionReason(name, false) != "" {
			t.Errorf("source excluded: %s", name)
		}
	}
}

// A3: only urlconfig-named SQLite snapshots are exempt from the sensitive-file
// exclusion; other databases stay excluded.
func TestPolicyURLConfigSQLiteIsImportable(t *testing.T) {
	for _, name := range []string{"database/urlconfig.db", "data/URLConfig.sqlite", "db/urlconfig.sqlite3"} {
		if exclusionReason(name, false) != "" {
			t.Errorf("urlconfig database excluded: %s", name)
		}
	}
	for _, name := range []string{"database/users.db", "data/app.sqlite", "dump.sql"} {
		if exclusionReason(name, false) == "" {
			t.Errorf("unrelated database not excluded: %s", name)
		}
	}
}

// 02: Model a full entry budget without creating 20,000 filesystem entries.
// Only the exact snapshot-root marker is metadata exempt from that budget.
func TestPolicySnapshotMarkerEntryBudgetBoundary(t *testing.T) {
	limits := DefaultLimits()
	for _, tc := range []struct {
		name         string
		marker       string
		snapshot     bool
		withFile     bool
		initialCount int
		wantCount    int
		wantErr      error
	}{
		{"root_marker_at_limit", ManifestFileName, true, false, limits.MaxEntries, limits.MaxEntries, nil},
		{"root_marker_and_last_entry", ManifestFileName, true, true, limits.MaxEntries - 1, limits.MaxEntries, nil},
		{"root_marker_does_not_relax_limit", ManifestFileName, true, true, limits.MaxEntries, limits.MaxEntries + 1, ErrLimit},
		{"source_marker_rejected", ManifestFileName, false, false, 0, 0, ErrUnsafePath},
		{"case_alias_marker_rejected", strings.ToUpper(ManifestFileName), true, false, 0, 0, ErrUnsafePath},
		{"nested_marker_rejected", "nested/" + ManifestFileName, true, false, 0, 1, ErrUnsafePath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			snapshotWrite(t, dir, tc.marker, []byte("{}"))
			if tc.withFile {
				snapshotWrite(t, dir, "file.go", nil)
			}
			root, _, err := openAbsoluteDirectory(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.close()
			scan := newScanner(context.Background(), root)
			scan.snapshot = tc.snapshot
			scan.count = tc.initialCount
			scan.expected = map[string]FileEntry{"file.go": {Path: "file.go", Size: 0, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}
			err = scan.walk(root, nil, "", 0)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("entry budget rejected valid snapshot: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
			if scan.count != tc.wantCount {
				t.Fatalf("entry count=%d, want %d", scan.count, tc.wantCount)
			}
		})
	}
}

func TestPolicyBudgetBoundaryChecks(t *testing.T) {
	source, _ := snapshotFixture(t)
	root, _, err := openAbsoluteDirectory(source)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	file, stamp, err := openRelative(root, "src/main.go")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	limits := DefaultLimits()
	for _, mode := range []string{"files", "bytes", "negative", "oversize", "entries", "exclusions"} {
		t.Run(mode, func(t *testing.T) {
			scan := newScanner(context.Background(), root)
			before := stamp
			switch mode {
			case "files":
				scan.manifest.Entries = make([]FileEntry, limits.MaxFiles)
			case "bytes":
				scan.manifest.TotalBytes = limits.MaxTotalBytes
			case "negative":
				before.Size = -1
			case "oversize":
				before.Size = limits.MaxFileBytes + 1
			case "entries":
				scan.count = limits.MaxEntries
			case "exclusions":
				scan.manifest.Excluded = make([]Exclusion, limits.MaxExcluded)
				snapshotWrite(t, source, ".env", nil)
			}
			var err error
			if mode == "entries" || mode == "exclusions" {
				err = scan.walk(root, nil, "", 0)
			} else {
				err = scan.scanFile(file, before, nil, "main.go", "src/main.go")
			}
			if !errors.Is(err, ErrLimit) {
				t.Fatalf("expected budget rejection: %v", err)
			}
		})
	}
}
