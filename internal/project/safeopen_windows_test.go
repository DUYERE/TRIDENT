//go:build windows

package project

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 01: Construct an inert NTFS junction by FSCTL rather than invoking a shell.
func makeTestJunction(t *testing.T, name, target string) {
	t.Helper()
	if err := os.Mkdir(name, 0700); err != nil {
		t.Fatal(err)
	}
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(ptr, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Skipf("junction setup unavailable: %v", err)
	}
	defer windows.CloseHandle(handle)
	substitute, err := windows.UTF16FromString(`\??\` + target)
	if err != nil {
		t.Fatal(err)
	}
	printName, err := windows.UTF16FromString(target)
	if err != nil {
		t.Fatal(err)
	}
	type junctionHeader struct {
		Tag                                                              uint32
		Length, Reserved, SubOffset, SubLength, PrintOffset, PrintLength uint16
	}
	names := append(substitute, printName...)
	header := junctionHeader{Tag: windows.IO_REPARSE_TAG_MOUNT_POINT, Length: uint16(8 + 2*len(names)), SubLength: uint16(2 * (len(substitute) - 1)), PrintOffset: uint16(2 * len(substitute)), PrintLength: uint16(2 * (len(printName) - 1))}
	buffer := make([]byte, 16+len(names)*2)
	*(*junctionHeader)(unsafe.Pointer(&buffer[0])) = header
	copy(unsafe.Slice((*uint16)(unsafe.Pointer(&buffer[16])), len(names)), names)
	var returned uint32
	if err = windows.DeviceIoControl(handle, windows.FSCTL_SET_REPARSE_POINT, &buffer[0], uint32(len(buffer)), nil, 0, &returned, nil); err != nil {
		t.Skipf("junction setup unavailable: %v", err)
	}
}
func TestSafeopenWindowsRejectsJunctions(t *testing.T) {
	for _, mode := range []string{"source", "entry", "excluded", "parent"} {
		t.Run(mode, func(t *testing.T) {
			source, dest := snapshotFixture(t)
			outside := t.TempDir()
			switch mode {
			case "source":
				alias := filepath.Join(filepath.Dir(source), "alias")
				makeTestJunction(t, alias, source)
				source = alias
			case "entry":
				makeTestJunction(t, filepath.Join(source, "escape"), outside)
			case "excluded":
				makeTestJunction(t, filepath.Join(source, "credentials"), outside)
			case "parent":
				alias := filepath.Join(filepath.Dir(source), "alias")
				makeTestJunction(t, alias, outside)
				dest = filepath.Join(alias, "snapshot")
			}
			if _, err := Import(context.Background(), source, dest); err == nil {
				t.Fatal("junction accepted")
			}
			if mode == "entry" || mode == "excluded" {
				requireNoSnapshot(t, dest)
			}
		})
	}
}
func TestSafeopenWindowsSourceSharingAndNamespacePolicy(t *testing.T) {
	source, _ := snapshotFixture(t)
	root, _, err := openAbsoluteDirectory(source)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	file, _, err := openRelative(root, "src/main.go")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = os.WriteFile(filepath.Join(source, "src/main.go"), []byte("mutation"), 0600); err == nil {
		t.Fatal("source file allowed write while pinned")
	}
	if err = os.Rename(source, source+"-renamed"); err == nil {
		t.Fatal("pinned root allowed rename")
	}
	for _, name := range []string{`\\server\share\folder`, `\\?\C:\Windows`, `\\.\C:\Windows`} {
		if dir, _, err := openAbsoluteDirectory(name); err == nil {
			dir.close()
			t.Fatalf("unsupported namespace accepted %q", name)
		}
	}
	if _, err = Import(context.Background(), source, source); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("same source accepted %v", err)
	}
}
