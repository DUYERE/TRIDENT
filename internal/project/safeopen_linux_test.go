//go:build linux

package project

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// 01: FIFO opens must not block and unix sockets/devices are never source files.
func TestSafeopenLinuxSpecialFiles(t *testing.T) {
	for _, name := range []string{"pipe", ".env"} {
		t.Run(name, func(t *testing.T) {
			source, dest := snapshotFixture(t)
			if err := unix.Mkfifo(filepath.Join(source, name), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Import(context.Background(), source, dest); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("FIFO accepted: %v", err)
			}
			requireNoSnapshot(t, dest)
		})
	}
}
func TestSafeopenLinuxUnsupportedMountAndWritableParent(t *testing.T) {
	if root, _, err := openAbsoluteDirectory("/proc"); err == nil {
		root.close()
		t.Fatal("proc filesystem accepted")
	}
	source, dest := snapshotFixture(t)
	parent := filepath.Dir(dest)
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0700)
	if _, err := Import(context.Background(), source, dest); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("world writable parent accepted: %v", err)
	}
	requireNoSnapshot(t, dest)
}

// 02: A real mount namespace test runs only when CAP_SYS_ADMIN is available.
// No fallback mocks away RESOLVE_NO_XDEV; unprivileged runs explicitly skip.
func TestSafeopenLinuxRejectsNestedMount(t *testing.T) {
	source, dest := snapshotFixture(t)
	outside := t.TempDir()
	mountpoint := filepath.Join(source, "mounted")
	if err := os.Mkdir(mountpoint, 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(outside, mountpoint, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("bind mount requires CAP_SYS_ADMIN: %v", err)
	}
	defer unix.Unmount(mountpoint, unix.MNT_DETACH)
	if _, err := Import(context.Background(), source, dest); err == nil {
		t.Fatal("nested bind mount accepted")
	}
	requireNoSnapshot(t, dest)
}
func TestSafeopenLinuxRootBindAliasNestedDestination(t *testing.T) {
	source, _ := snapshotFixture(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Mkdir(alias, 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(source, alias, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("bind mount requires CAP_SYS_ADMIN: %v", err)
	}
	defer unix.Unmount(alias, unix.MNT_DETACH)
	dest := filepath.Join(alias, "snapshot")
	if _, err := Import(context.Background(), source, dest); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("bind alias nested destination accepted: %v", err)
	}
	requireNoSnapshot(t, dest)
}

func TestSafeopenLinuxMountRelationshipPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                                                 string
		sourceDevice, parentDevice, sourceMount, parentMount uint64
		reject                                               bool
	}{
		{"same_mount", 1, 1, 10, 10, false}, {"alias_mount", 1, 1, 10, 11, true}, {"unknown_source", 1, 1, 0, 10, true}, {"unknown_parent", 1, 1, 10, 0, true}, {"different_filesystem", 1, 2, 10, 20, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMountRelationship(tc.sourceDevice, tc.parentDevice, tc.sourceMount, tc.parentMount)
			if tc.reject && !errors.Is(err, ErrUnsupportedPlatform) {
				t.Fatalf("unsafe mounts accepted: %v", err)
			}
			if !tc.reject && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSafeopenLinuxReadRejectsSymlinkReplacement(t *testing.T) {
	source, dest := snapshotFixture(t)
	result := snapshotImport(t, source, dest)
	snapshot, err := Open(context.Background(), dest, result.Hash)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	file := filepath.Join(dest, "src/main.go")
	if err = os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(source, "src/main.go"), file); err != nil {
		t.Fatal(err)
	}
	if data, err := snapshot.ReadFile(context.Background(), "src/main.go"); err == nil || data != nil {
		t.Fatalf("symlink replacement read: %q %v", data, err)
	}
}
