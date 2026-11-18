package webui

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// writeFileAtomic replaces path with data through a temp file created with an
// unpredictable name in the same directory, then renames it into place.
//
// The name matters: os.CreateTemp opens with O_CREATE|O_EXCL, so a local
// attacker who pre-creates a link at a guessed temp path cannot make this
// write follow it. Rename replaces whatever is at path (including a symlink)
// instead of writing through it.
func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".trident-write-*")
	if err != nil {
		return fmt.Errorf("workspace is not writable: %w", err)
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if err = temp.Chmod(perm); err != nil {
		_ = temp.Close()
		return fmt.Errorf("workspace is not writable: %w", err)
	}
	if _, err = temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("workspace is not writable: %w", err)
	}
	if err = temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("workspace is not writable: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("workspace is not writable: %w", err)
	}
	return os.Rename(name, path)
}
