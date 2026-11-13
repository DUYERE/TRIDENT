package project

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// 01: Fixtures contain inert source text only; tests never execute project code.
func snapshotFixture(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	source := filepath.Join(base, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	snapshotWrite(t, source, "src/main.go", []byte("package fixture\n// inert source\n"))
	if err := os.Mkdir(filepath.Join(source, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	return source, filepath.Join(base, "snapshot")
}
func snapshotWrite(t *testing.T, root, relative string, data []byte) {
	t.Helper()
	name := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func snapshotImport(t *testing.T, source, dest string) ImportResult {
	t.Helper()
	result, err := Import(context.Background(), source, dest)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func requireNoSnapshot(t *testing.T, dest string) {
	t.Helper()
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("incomplete destination remains: %v", err)
	}
}

func TestSnapshotImportOpenReadAndDefensiveManifest(t *testing.T) {
	source, dest := snapshotFixture(t)
	snapshotWrite(t, source, ".env.production", []byte("DO_NOT_COPY=secret"))
	snapshotWrite(t, source, "credentials/access.txt", []byte("DO_NOT_COPY"))
	snapshotWrite(t, source, "vendor/dep.go", []byte("package dep"))
	result := snapshotImport(t, source, dest)
	if result.Path != dest || !validHash(result.Hash) || result.Manifest.TotalFiles != 1 || !result.Manifest.Partial || len(result.Manifest.Excluded) != 3 {
		t.Fatalf("unexpected result: %+v", result)
	}
	raw, err := os.ReadFile(filepath.Join(dest, ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != result.Hash {
		t.Fatal("manifest hash does not authenticate bytes")
	}
	snapshot, err := Open(context.Background(), dest, result.Hash)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	got, err := snapshot.ReadFile(context.Background(), "src/main.go")
	if err != nil || !bytes.Contains(got, []byte("package fixture")) {
		t.Fatalf("read: %q %v", got, err)
	}
	manifest := snapshot.Manifest()
	manifest.Entries[0].Path = "mutated"
	manifest.Excluded[0].Reason = "mutated"
	manifest.Directories[0] = "mutated"
	manifest.Warnings[0] = "mutated"
	if !reflect.DeepEqual(snapshot.Manifest(), result.Manifest) || snapshot.Hash() != result.Hash {
		t.Fatal("Manifest exposes internal mutable slices")
	}
	if _, err = snapshot.ReadFile(context.Background(), ".env.production"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("excluded read: %v", err)
	}
	if err = snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if err = snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = snapshot.ReadFile(context.Background(), "src/main.go"); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed read: %v", err)
	}
}

func TestSnapshotRequiresTrustedHashAndRejectsTampering(t *testing.T) {
	for _, mode := range []string{"missing_hash", "wrong_hash", "manifest", "content", "missing_file", "extra_file", "extra_directory", "hardlink"} {
		t.Run(mode, func(t *testing.T) {
			source, dest := snapshotFixture(t)
			result := snapshotImport(t, source, dest)
			expected := result.Hash
			switch mode {
			case "missing_hash":
				expected = ""
			case "wrong_hash":
				expected = strings.Repeat("0", 64)
			case "manifest":
				snapshotWrite(t, dest, ManifestFileName, []byte("{}"))
			case "content":
				snapshotWrite(t, dest, "src/main.go", []byte("tampered\n"))
			case "missing_file":
				if err := os.Remove(filepath.Join(dest, "src/main.go")); err != nil {
					t.Fatal(err)
				}
			case "extra_file":
				snapshotWrite(t, dest, "unexpected.txt", []byte("extra"))
			case "extra_directory":
				if err := os.Mkdir(filepath.Join(dest, "unexpected"), 0700); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(dest, "src/main.go"), filepath.Join(filepath.Dir(dest), "outside-link")); err != nil {
					t.Skipf("hardlinks unavailable: %v", err)
				}
			}
			if opened, err := Open(context.Background(), dest, expected); err == nil {
				opened.Close()
				t.Fatal("tampered snapshot accepted")
			}
		})
	}
}

func TestSnapshotExistingNestedAndAliasDestinations(t *testing.T) {
	for _, mode := range []string{"existing", "same", "nested", "ancestor", "symlink_source", "symlink_parent"} {
		t.Run(mode, func(t *testing.T) {
			source, dest := snapshotFixture(t)
			switch mode {
			case "existing":
				if err := os.Mkdir(dest, 0700); err != nil {
					t.Fatal(err)
				}
				snapshotWrite(t, dest, "keep.txt", []byte("untouched"))
			case "same":
				dest = source
			case "nested":
				dest = filepath.Join(source, "output")
			case "ancestor":
				dest = filepath.Dir(source)
			case "symlink_source":
				alias := filepath.Join(filepath.Dir(source), "source-alias")
				if err := os.Symlink(source, alias); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				source = alias
			case "symlink_parent":
				alias := filepath.Join(filepath.Dir(source), "parent-alias")
				if err := os.Symlink(filepath.Dir(source), alias); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				dest = filepath.Join(alias, "snapshot")
			}
			if _, err := Import(context.Background(), source, dest); err == nil {
				t.Fatal("unsafe destination/source accepted")
			}
			if mode == "existing" {
				value, err := os.ReadFile(filepath.Join(dest, "keep.txt"))
				if err != nil || string(value) != "untouched" {
					t.Fatal("existing destination was modified")
				}
			}
		})
	}
}

func TestSnapshotRejectsLinksIncludingExcludedNames(t *testing.T) {
	for _, mode := range []string{"file_symlink", "directory_symlink", "excluded_symlink", "hardlink", "excluded_hardlink"} {
		t.Run(mode, func(t *testing.T) {
			source, dest := snapshotFixture(t)
			outside := filepath.Join(filepath.Dir(source), "outside.txt")
			if err := os.WriteFile(outside, []byte("external secret"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch mode {
			case "file_symlink":
				err = os.Symlink(outside, filepath.Join(source, "link.txt"))
			case "directory_symlink":
				err = os.Symlink(filepath.Dir(source), filepath.Join(source, "escape"))
			case "excluded_symlink":
				err = os.Symlink(outside, filepath.Join(source, ".env"))
			case "hardlink":
				err = os.Link(outside, filepath.Join(source, "linked.txt"))
			case "excluded_hardlink":
				err = os.Link(outside, filepath.Join(source, ".env"))
			}
			if err != nil {
				t.Skipf("link unavailable: %v", err)
			}
			if _, err = Import(context.Background(), source, dest); err == nil {
				t.Fatal("link accepted")
			}
			requireNoSnapshot(t, dest)
		})
	}
}

func TestSnapshotPolicyAndBudgetsFailClosed(t *testing.T) {
	for _, mode := range []string{"reserved_manifest", "oversize", "total_bytes", "exclusions", "depth"} {
		t.Run(mode, func(t *testing.T) {
			source, dest := snapshotFixture(t)
			limits := DefaultLimits()
			switch mode {
			case "reserved_manifest":
				snapshotWrite(t, source, ManifestFileName, []byte("reserved"))
			case "oversize":
				file, err := os.Create(filepath.Join(source, "large.txt"))
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate(limits.MaxFileBytes + 1)
				file.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "total_bytes":
				for i := 0; i < 9; i++ {
					file, err := os.Create(filepath.Join(source, fmt.Sprintf("large-%02d.txt", i)))
					if err != nil {
						t.Fatal(err)
					}
					err = file.Truncate(limits.MaxFileBytes)
					file.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
			case "exclusions":
				for i := 0; i <= limits.MaxExcluded; i++ {
					snapshotWrite(t, source, fmt.Sprintf("secret-%04d.key", i), nil)
				}
			case "depth":
				snapshotWrite(t, source, strings.Repeat("d/", limits.MaxDepth)+"file.go", nil)
			}
			if _, err := Import(context.Background(), source, dest); err == nil {
				t.Fatal("budget/reserved violation accepted")
			}
			requireNoSnapshot(t, dest)
		})
	}
}

// 02: A controlled Context callback mutates/cancels at an actual I/O boundary,
// avoiding flaky timing races or production test hooks.
type snapshotActionContext struct {
	context.Context
	action func()
}

func (c *snapshotActionContext) Err() error {
	if c.action != nil {
		c.action()
	}
	return c.Context.Err()
}

func TestSnapshotCancellationAndSourceChangeCleanup(t *testing.T) {
	for _, mode := range []string{"cancel_before", "cancel_during", "content_change", "membership_change"} {
		t.Run(mode, func(t *testing.T) {
			source, dest := snapshotFixture(t)
			snapshotWrite(t, source, "a.txt", bytes.Repeat([]byte("a"), 1<<16))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel_before" {
				cancel()
			}
			actionCtx := &snapshotActionContext{Context: ctx}
			acted := false
			actionCtx.action = func() {
				if acted || mode == "cancel_before" {
					return
				}
				// The copied file has been closed by the time its directory is rechecked;
				// on Windows this is necessary because source opens deny write sharing.
				if st, err := os.Stat(filepath.Join(dest, "a.txt")); err != nil || st.Size() != 1<<16 {
					return
				}
				switch mode {
				case "cancel_during":
					acted = true
					cancel()
				case "content_change":
					// Retry if Windows still has this source file pinned.
					if err := os.WriteFile(filepath.Join(source, "a.txt"), bytes.Repeat([]byte("b"), 1<<16), 0600); err == nil {
						acted = true
					}
				case "membership_change":
					if err := os.WriteFile(filepath.Join(source, "new.txt"), []byte("new"), 0600); err == nil {
						acted = true
					}
				}
			}
			_, err := Import(actionCtx, source, dest)
			if err == nil {
				t.Fatalf("%s was accepted (action=%v)", mode, acted)
			}
			if strings.HasPrefix(mode, "cancel") && !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation: %v", err)
			}
			if !strings.HasPrefix(mode, "cancel") && !errors.Is(err, ErrSourceChanged) {
				t.Fatalf("expected source change: %v", err)
			}
			requireNoSnapshot(t, dest)
		})
	}
}

func TestSnapshotReadRevalidatesAndRejectsUnsafeNames(t *testing.T) {
	source, dest := snapshotFixture(t)
	result := snapshotImport(t, source, dest)
	snapshot, err := Open(context.Background(), dest, result.Hash)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	for _, name := range []string{"../outside", "/absolute", `src\main.go`, "src/main.go:ads", "src/../main.go", "src//main.go", "CON", "COM¹.txt", "file.", "file ", "src/\x00bad"} {
		if _, err = snapshot.ReadFile(context.Background(), name); err == nil {
			t.Fatalf("unsafe path accepted: %q", name)
		}
	}
	snapshotWrite(t, dest, "src/main.go", []byte("modified after Open"))
	if data, err := snapshot.ReadFile(context.Background(), "src/main.go"); err == nil || data != nil {
		t.Fatalf("unverified bytes returned: %q %v", data, err)
	}
}

func TestSnapshotRejectsUntrustedManifestEvenWithMatchingHash(t *testing.T) {
	for _, mode := range []string{"limits", "path", "duplicate", "noncanonical", "unknown", "sensitive", "negative", "bad_directory"} {
		t.Run(mode, func(t *testing.T) {
			source, dest := snapshotFixture(t)
			result := snapshotImport(t, source, dest)
			manifest := result.Manifest
			switch mode {
			case "limits":
				manifest.Limits.MaxFileBytes++
			case "path":
				manifest.Entries[0].Path = "../escape"
			case "duplicate":
				manifest.Entries = append(manifest.Entries, manifest.Entries[0])
				manifest.TotalFiles++
			case "sensitive":
				manifest.Entries[0].Path = ".env"
			case "negative":
				manifest.Entries[0].Size = -1
			case "bad_directory":
				manifest.Directories = append(manifest.Directories, "../bad")
			}
			raw, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "noncanonical" {
				raw = append(raw, '\n')
			}
			if mode == "unknown" {
				raw = append(raw[:len(raw)-1], []byte(",\"unknown\":true}")...)
			}
			snapshotWrite(t, dest, ManifestFileName, raw)
			sum := sha256.Sum256(raw)
			if snapshot, err := Open(context.Background(), dest, hex.EncodeToString(sum[:])); err == nil {
				snapshot.Close()
				t.Fatal("untrusted invalid manifest accepted")
			}
		})
	}
}

func TestSnapshotConcurrentReadsAndClose(t *testing.T) {
	source, dest := snapshotFixture(t)
	result := snapshotImport(t, source, dest)
	snapshot, err := Open(context.Background(), dest, result.Hash)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 10; j++ {
				_, err := snapshot.ReadFile(context.Background(), "src/main.go")
				if err != nil && !errors.Is(err, os.ErrClosed) {
					t.Errorf("concurrent read: %v", err)
				}
				_ = snapshot.Manifest()
				_ = snapshot.Hash()
			}
		}()
	}
	time.Sleep(time.Millisecond)
	if err = snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	group.Wait()
}
