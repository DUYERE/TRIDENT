//go:build windows

package project

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 01: NtCreateFile resolves exactly one name relative to a pinned directory.
// OBJ_DONT_REPARSE rejects intermediate reparse traversal; OPEN_REPARSE_POINT
// exposes any final reparse object, which fileState rejects before any read.
func ntOpen(parent windows.Handle, name string, directory, create, write, remove bool) (*os.File, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: objectName, Attributes: windows.OBJ_DONT_REPARSE | windows.OBJ_CASE_INSENSITIVE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	access := uint32(windows.FILE_GENERIC_READ)
	if write {
		access |= windows.FILE_GENERIC_WRITE
	}
	if remove {
		access |= windows.DELETE
	}
	options := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
	}
	if create && !directory {
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	disposition := uint32(windows.FILE_OPEN)
	if create {
		disposition = windows.FILE_CREATE
	}
	// Excluding SHARE_WRITE/SHARE_DELETE prevents same-file mutation and renames
	// while source files and destination/root directories are pinned.
	var handle windows.Handle
	err = windows.NtCreateFile(&handle, access, &oa, &windows.IO_STATUS_BLOCK{}, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ, disposition, options, 0, 0)
	if err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
			return nil, ErrDestinationExists
		}
		return nil, wrapUnsafe("NtCreateFile", err)
	}
	file := os.NewFile(uintptr(handle), name)
	if _, err = fileState(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

type basicInfo struct {
	Creation, Access, Write, Change int64
	Attributes                      uint32
	Padding                         uint32
}

func fileState(file *os.File) (fileStamp, error) {
	handle := windows.Handle(file.Fd())
	kind, err := windows.GetFileType(handle)
	if err != nil {
		return fileStamp{}, err
	}
	if kind != windows.FILE_TYPE_DISK {
		return fileStamp{}, fmt.Errorf("%w: not disk file", ErrUnsafePath)
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fileStamp{}, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return fileStamp{}, fmt.Errorf("%w: reparse/device object", ErrUnsafePath)
	}
	directory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if !directory && info.NumberOfLinks != 1 {
		return fileStamp{}, fmt.Errorf("%w: hard linked file", ErrUnsafePath)
	}
	var basic basicInfo
	if err = windows.GetFileInformationByHandleEx(handle, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return fileStamp{}, err
	}
	return fileStamp{Identity: fileIdentity{uint64(info.VolumeSerialNumber), uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)}, Size: int64(uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)), Modified: basic.Write, Changed: basic.Change, Links: uint64(info.NumberOfLinks), Directory: directory}, nil
}

func allowedFilesystem(handle windows.Handle) error {
	var serial, maxComponent, flags uint32
	var fsname [64]uint16
	if err := windows.GetVolumeInformationByHandle(handle, nil, 0, &serial, &maxComponent, &flags, &fsname[0], uint32(len(fsname))); err != nil {
		return fmt.Errorf("%w: volume information: %v", ErrUnsupportedPlatform, err)
	}
	if windows.UTF16ToString(fsname[:]) != "NTFS" {
		return fmt.Errorf("%w: only local NTFS is supported", ErrUnsupportedPlatform)
	}
	// Verify the resolved handle's volume, rather than trusting a mapped drive.
	var final [32768]uint16
	n, err := windows.GetFinalPathNameByHandle(handle, &final[0], uint32(len(final)), 1) // VOLUME_NAME_GUID
	if err != nil || n == 0 || n >= uint32(len(final)) {
		return fmt.Errorf("%w: final volume path", ErrUnsupportedPlatform)
	}
	value := windows.UTF16ToString(final[:n])
	if !strings.HasPrefix(value, `\\?\Volume{`) {
		return fmt.Errorf("%w: nonlocal volume", ErrUnsupportedPlatform)
	}
	end := strings.Index(value, `}\`)
	if end < 0 {
		return ErrUnsupportedPlatform
	}
	volume, err := windows.UTF16PtrFromString(value[:end+2])
	if err != nil {
		return err
	}
	if windows.GetDriveType(volume) != windows.DRIVE_FIXED {
		return fmt.Errorf("%w: volume is not fixed local disk", ErrUnsupportedPlatform)
	}
	return nil
}

func openAbsoluteDirectory(name string) (*safeDir, []fileIdentity, error) {
	abs, err := absoluteDirectoryName(name)
	if err != nil {
		return nil, nil, err
	}
	// UNC, device, volume-relative and extended namespace inputs are unsupported.
	volume := filepath.VolumeName(abs)
	if len(volume) != 2 || volume[1] != ':' || len(abs) < 3 || abs[2] != '\\' {
		return nil, nil, fmt.Errorf("%w: only local drive paths", ErrUnsupportedPlatform)
	}
	rootName := `\??\` + volume + `\`
	file, err := ntOpen(0, rootName, true, false, false, false)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()
	stamp, err := fileState(file)
	if err != nil {
		return nil, nil, err
	}
	ids := []fileIdentity{stamp.Identity}
	for _, part := range strings.Split(abs[3:], `\`) {
		if part == "" {
			continue
		}
		if err = validateComponent(part); err != nil {
			return nil, nil, err
		}
		next, e := ntOpen(windows.Handle(file.Fd()), part, true, false, false, false)
		if e != nil {
			return nil, nil, e
		}
		_ = file.Close()
		file = next
		stamp, err = fileState(file)
		if err != nil {
			return nil, nil, err
		}
		ids = append(ids, stamp.Identity)
	}
	if err = allowedFilesystem(windows.Handle(file.Fd())); err != nil {
		return nil, nil, err
	}
	dir := &safeDir{file: file, identity: stamp.Identity, absolute: abs}
	file = nil
	return dir, ids, nil
}

func openChild(parent *safeDir, name string) (*os.File, fileStamp, error) {
	if err := validateComponent(name); err != nil {
		return nil, fileStamp{}, err
	}
	file, err := ntOpen(windows.Handle(parent.file.Fd()), name, false, false, false, false)
	if err != nil {
		return nil, fileStamp{}, err
	}
	stamp, err := fileState(file)
	if err != nil {
		_ = file.Close()
		return nil, fileStamp{}, err
	}
	return file, stamp, nil
}

func openRelative(root *safeDir, relative string) (*os.File, fileStamp, error) {
	if err := validateRelative(relative); err != nil {
		return nil, fileStamp{}, err
	}
	// A single NT lookup avoids ancestor-handle lifetime gaps. OBJ_DONT_REPARSE
	// applies to every intermediate component, not just the final component.
	file, err := ntOpen(windows.Handle(root.file.Fd()), strings.ReplaceAll(relative, "/", `\`), false, false, false, false)
	if err != nil {
		return nil, fileStamp{}, err
	}
	stamp, err := fileState(file)
	if err != nil {
		_ = file.Close()
		return nil, fileStamp{}, err
	}
	return file, stamp, nil
}

func reopenDirectory(dir *safeDir) (*safeDir, error) {
	file, err := ntOpen(windows.Handle(dir.file.Fd()), "", true, false, false, false)
	if err != nil {
		return nil, err
	}
	return &safeDir{file: file, identity: dir.identity}, nil
}

func validateRootRelationship(source, parent *safeDir) error { return nil }

// Pinned directory handles deny delete sharing. ACL administration by another
// principal, the same user, or an administrator is outside this process boundary.
func validateDestinationParent(parent *safeDir) error { return nil }

func createDirectory(parent *safeDir, name string) (*safeDir, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	file, err := ntOpen(windows.Handle(parent.file.Fd()), name, true, true, false, false)
	if err != nil {
		return nil, err
	}
	stamp, err := fileState(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &safeDir{file: file, identity: stamp.Identity}, nil
}

func createFile(parent *safeDir, name string) (*os.File, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	return ntOpen(windows.Handle(parent.file.Fd()), name, false, true, true, false)
}

// 02: Delete the opened object, never a pathname that can be replaced mid-check.
func removeChild(parent *safeDir, name string, expected fileIdentity, directory bool) error {
	file, err := ntOpen(windows.Handle(parent.file.Fd()), name, directory, false, false, true)
	if err != nil {
		return err
	}
	defer file.Close()
	stamp, err := fileState(file)
	if err != nil {
		return err
	}
	if stamp.Identity != expected || stamp.Directory != directory {
		return ErrIntegrity
	}
	deleteFlag := byte(1)
	return windows.SetFileInformationByHandle(windows.Handle(file.Fd()), windows.FileDispositionInfo, &deleteFlag, 1)
}
