//go:build linux

package project

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// 01: Linux requires openat2. There is deliberately no openat/pathname fallback.
const resolveInside = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV

func secureOpenAt(parent int, name string, flags int, mode uint32, inside bool) (int, error) {
	resolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)
	if inside {
		resolve = resolveInside
	}
	fd, err := unix.Openat2(parent, name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW), Mode: uint64(mode), Resolve: resolve})
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) {
		return -1, fmt.Errorf("%w: openat2 unavailable: %v", ErrUnsupportedPlatform, err)
	}
	return fd, err
}

func allowedFilesystem(fd int) error {
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		return err
	}
	switch uint64(st.Type) {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC:
		return nil
	default:
		return fmt.Errorf("%w: Linux filesystem %#x", ErrUnsupportedPlatform, st.Type)
	}
}

func fileState(file *os.File) (fileStamp, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return fileStamp{}, err
	}
	kind := st.Mode & unix.S_IFMT
	if kind != unix.S_IFREG && kind != unix.S_IFDIR {
		return fileStamp{}, fmt.Errorf("%w: not a regular file/directory", ErrUnsafePath)
	}
	if kind == unix.S_IFREG && st.Nlink != 1 {
		return fileStamp{}, fmt.Errorf("%w: hard linked file", ErrUnsafePath)
	}
	return fileStamp{Identity: fileIdentity{uint64(st.Dev), st.Ino}, Size: st.Size, Modified: st.Mtim.Nano(), Changed: st.Ctim.Nano(), Links: uint64(st.Nlink), Directory: kind == unix.S_IFDIR}, nil
}

func openAbsoluteDirectory(name string) (*safeDir, []fileIdentity, error) {
	abs, err := absoluteDirectoryName(name)
	if err != nil {
		return nil, nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	defer func() {
		if current != nil {
			_ = current.Close()
		}
	}()
	stamp, err := fileState(current)
	if err != nil {
		return nil, nil, err
	}
	ancestors := []fileIdentity{stamp.Identity}
	for _, part := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
		if part == "" {
			continue
		}
		if err = validateComponent(part); err != nil {
			return nil, nil, err
		}
		next, e := secureOpenAt(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY, 0, false)
		if e != nil {
			return nil, nil, wrapUnsafe("open root", e)
		}
		_ = current.Close()
		current = os.NewFile(uintptr(next), part)
		stamp, err = fileState(current)
		if err != nil {
			return nil, nil, err
		}
		ancestors = append(ancestors, stamp.Identity)
	}
	if err = allowedFilesystem(int(current.Fd())); err != nil {
		return nil, nil, err
	}
	dir := &safeDir{file: current, identity: stamp.Identity, absolute: filepath.Clean(abs)}
	current = nil
	return dir, ancestors, nil
}

// 02: Every lookup stays under a pinned directory and rejects nested mounts.
func openChild(parent *safeDir, name string) (*os.File, fileStamp, error) {
	if err := validateComponent(name); err != nil {
		return nil, fileStamp{}, err
	}
	fd, err := secureOpenAt(int(parent.file.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0, true)
	if err != nil {
		return nil, fileStamp{}, wrapUnsafe("open child", err)
	}
	file := os.NewFile(uintptr(fd), name)
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
	fd, err := secureOpenAt(int(root.file.Fd()), relative, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0, true)
	if err != nil {
		return nil, fileStamp{}, wrapUnsafe("open relative", err)
	}
	file := os.NewFile(uintptr(fd), relative)
	stamp, err := fileState(file)
	if err != nil {
		_ = file.Close()
		return nil, fileStamp{}, err
	}
	return file, stamp, nil
}

func reopenDirectory(dir *safeDir) (*safeDir, error) {
	fd, err := secureOpenAt(int(dir.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY, 0, true)
	if err != nil {
		return nil, err
	}
	return &safeDir{file: os.NewFile(uintptr(fd), "."), identity: dir.identity}, nil
}

// Distinct mounts of the same superblock can alias an excluded subtree. Linux
// cannot prove their physical ancestry with openat2 alone; reject that topology.
func validateRootRelationship(source, parent *safeDir) error {
	if source.identity.Device != parent.identity.Device {
		return nil
	}
	var a, b unix.Statx_t
	for _, pair := range []struct {
		dir  *safeDir
		stat *unix.Statx_t
	}{{source, &a}, {parent, &b}} {
		if err := unix.Statx(int(pair.dir.file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, pair.stat); err != nil {
			return fmt.Errorf("%w: statx mount identity: %v", ErrUnsupportedPlatform, err)
		}
		if pair.stat.Mask&unix.STATX_MNT_ID == 0 {
			return fmt.Errorf("%w: kernel mount identity unavailable", ErrUnsupportedPlatform)
		}
	}
	return checkMountRelationship(source.identity.Device, parent.identity.Device, a.Mnt_id, b.Mnt_id)
}

func checkMountRelationship(sourceDevice, parentDevice, sourceMount, parentMount uint64) error {
	if sourceDevice == parentDevice && (sourceMount == 0 || parentMount == 0 || sourceMount != parentMount) {
		return fmt.Errorf("%w: same-filesystem roots on different/unknown mounts may alias", ErrUnsupportedPlatform)
	}
	return nil
}

// The importer cannot isolate an attacker with the same UID or CAP_SYS_ADMIN.
// Refuse directories other users can rename entries in (except owned sticky
// temporary directories). No pathname cleanup can solve same-UID rename races.
func validateDestinationParent(parent *safeDir) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(parent.file.Fd()), &st); err != nil {
		return err
	}
	owned := st.Uid == uint32(unix.Geteuid())
	sticky := st.Mode&unix.S_ISVTX != 0 && (owned || st.Uid == 0)
	if (!owned && !sticky) || (st.Mode&0022 != 0 && !sticky) {
		return fmt.Errorf("%w: destination parent is not protected from other users", ErrUnsafePath)
	}
	return nil
}

func createDirectory(parent *safeDir, name string) (*safeDir, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	if err := unix.Mkdirat(int(parent.file.Fd()), name, 0700); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil, ErrDestinationExists
		}
		return nil, err
	}
	file, stamp, err := openChild(parent, name)
	if err != nil {
		return nil, err
	}
	if !stamp.Directory {
		_ = file.Close()
		return nil, ErrUnsafePath
	}
	return &safeDir{file: file, identity: stamp.Identity}, nil
}

func createFile(parent *safeDir, name string) (*os.File, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	fd, err := secureOpenAt(int(parent.file.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NONBLOCK, 0600, true)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	stamp, err := fileState(file)
	if err != nil || stamp.Directory {
		_ = file.Close()
		if err == nil {
			err = ErrUnsafePath
		}
		return nil, err
	}
	return file, nil
}

func removeChild(parent *safeDir, name string, expected fileIdentity, directory bool) error {
	file, stamp, err := openChild(parent, name)
	if err != nil {
		return err
	}
	_ = file.Close()
	if stamp.Identity != expected || stamp.Directory != directory {
		return ErrIntegrity
	}
	flags := 0
	if directory {
		flags = unix.AT_REMOVEDIR
	}
	return unix.Unlinkat(int(parent.file.Fd()), name, flags)
}
