package project

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// 01: File identities and change stamps come only from an already-open handle.
type fileIdentity struct{ Device, File uint64 }
type fileStamp struct {
	Identity          fileIdentity
	Size              int64
	Modified, Changed int64
	Links             uint64
	Directory         bool
}

type safeDir struct {
	file     *os.File
	identity fileIdentity
	absolute string
}

func (d *safeDir) close() error { return d.file.Close() }

func contextOK(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("nil context")
	}
	return ctx.Err()
}

func absoluteDirectoryName(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: empty directory", ErrUnsafePath)
	}
	return filepath.Abs(name)
}

// 02: Read/copy is always bounded and cancellable; never ReadFile a host path.
func copyBounded(ctx context.Context, dst io.Writer, src io.Reader, max int64) (int64, error) {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		if err := contextOK(ctx); err != nil {
			return total, err
		}
		n, err := src.Read(buf)
		if n > 0 {
			if int64(n) > max-total {
				return total, fmt.Errorf("%w: file bytes", ErrLimit)
			}
			written, writeErr := dst.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return total, contextOK(ctx)
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
}

func wrapUnsafe(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s: %w", ErrUnsafePath, op, err)
}

func sameStamp(a, b fileStamp) bool { return a == b }

func containsIdentity(ids []fileIdentity, id fileIdentity) bool {
	for _, candidate := range ids {
		if candidate == id {
			return true
		}
	}
	return false
}

// 03: Cleanup uses pinned directories and never traverses links. Linux unlinkat
// still requires a name: same-UID/administrator rename attacks are not isolated.
// Cleanup is bounded; errors are reported instead of following hostile entries.
func cleanupDestination(ctx context.Context, parent *safeDir, name string, root *safeDir) error {
	if root == nil {
		return nil
	}
	if err := removeChildren(ctx, root, 0); err != nil {
		return err
	}
	_ = root.close()
	return removeChild(parent, name, root.identity, true)
}

func removeChildren(ctx context.Context, dir *safeDir, depth int) error {
	if depth > DefaultLimits().MaxDepth {
		return ErrLimit
	}
	// Reopen the directory so enumeration starts at offset zero after earlier walks.
	reader, err := reopenDirectory(dir)
	if err != nil {
		return err
	}
	defer reader.close()
	count := 0
	for {
		if err := contextOK(ctx); err != nil {
			return err
		}
		entries, err := reader.file.ReadDir(64)
		for _, entry := range entries {
			count++
			if count > DefaultLimits().MaxEntries {
				return ErrLimit
			}
			if e := validateComponent(entry.Name()); e != nil {
				return e
			}
			file, stamp, e := openChild(dir, entry.Name())
			if e != nil {
				return e
			}
			if stamp.Directory {
				child := &safeDir{file: file, identity: stamp.Identity}
				e = removeChildren(ctx, child, depth+1)
				_ = child.close()
				if e == nil {
					e = removeChild(dir, entry.Name(), stamp.Identity, true)
				}
			} else {
				_ = file.Close()
				e = removeChild(dir, entry.Name(), stamp.Identity, false)
			}
			if e != nil {
				return e
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
