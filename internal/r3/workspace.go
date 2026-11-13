package r3

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"trident/internal/project"
)

type WorkspaceInfo struct {
	Path  string `json:"path"`
	Files int    `json:"files"`
	Bytes int64  `json:"bytes"`
}

// CreateWorkspace copies a pinned snapshot into a new caller-owned writable
// directory. The destination must not exist and must not be inside the snapshot
// directory. Every file is read through the hash-verifying snapshot reader.
func CreateWorkspace(ctx context.Context, snapshot *project.Snapshot, snapshotDir, destination string) (WorkspaceInfo, error) {
	result := WorkspaceInfo{}
	if snapshot == nil || snapshot.Hash() == "" {
		return result, fmt.Errorf("a pinned snapshot is required")
	}
	snapshotAbs, err := filepath.Abs(snapshotDir)
	if err != nil {
		return result, err
	}
	destinationAbs, err := filepath.Abs(destination)
	if err != nil {
		return result, err
	}
	if destinationAbs == snapshotAbs {
		return result, fmt.Errorf("workspace must not be the snapshot directory")
	}
	if rel, relErr := filepath.Rel(snapshotAbs, destinationAbs); relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
		return result, fmt.Errorf("workspace must not be inside the snapshot directory")
	}
	parent := filepath.Dir(destinationAbs)
	if info, statErr := os.Stat(parent); statErr != nil || !info.IsDir() {
		return result, fmt.Errorf("workspace parent must be an existing directory")
	}
	if err = os.Mkdir(destinationAbs, 0o700); err != nil {
		return result, fmt.Errorf("workspace must be a new directory: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(destinationAbs)
		}
	}()
	for _, entry := range snapshot.Manifest().Entries {
		if strings.EqualFold(entry.Path, project.ManifestFileName) {
			continue
		}
		if err = ctx.Err(); err != nil {
			return result, err
		}
		content, readErr := snapshot.ReadFile(ctx, entry.Path)
		if readErr != nil {
			return result, readErr
		}
		if int64(len(content)) != entry.Size {
			return result, fmt.Errorf("snapshot file size mismatch for %q", entry.Path)
		}
		target, pathErr := safeWorkspacePath(destinationAbs, entry.Path)
		if pathErr != nil {
			return result, pathErr
		}
		if err = os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return result, err
		}
		file, createErr := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			return result, createErr
		}
		_, writeErr := file.Write(content)
		closeErr := file.Close()
		if writeErr != nil {
			return result, writeErr
		}
		if closeErr != nil {
			return result, closeErr
		}
		result.Files++
		result.Bytes += int64(len(content))
	}
	result.Path = destinationAbs
	success = true
	return result, nil
}
