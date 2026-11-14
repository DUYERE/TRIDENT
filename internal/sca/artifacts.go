package sca

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Artifact lookup is a read-only evidence step: it hashes jars/poms that already
// exist in a caller-supplied local repository or Gradle cache and compares them
// with an optional caller-supplied hash catalog. It never downloads artifacts,
// verifies signatures or claims that a local repository is trustworthy.
const (
	MaxArtifactCatalogBytes   = 128 << 10
	MaxArtifactCatalogEntries = 4096
	MaxArtifactBytes          = 1 << 30
	MaxGradleArtifactFiles    = 64
)

var ErrArtifactCatalog = errors.New("invalid artifact hash catalog")

// Artifact records one observed or expected file for a resolved GAV. Status:
// observed (hashed locally), mismatch (local hash differs from the catalog),
// catalog_only (hash known only from the caller catalog) or missing.
type Artifact struct {
	GroupID       string `json:"group_id"`
	ArtifactID    string `json:"artifact_id"`
	Version       string `json:"version"`
	Kind          string `json:"kind"`
	Classifier    string `json:"classifier,omitempty"`
	Status        string `json:"status"`
	Source        string `json:"source"`
	Repository    string `json:"repository,omitempty"`
	Path          string `json:"path,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	Bytes         int64  `json:"bytes,omitempty"`
	CatalogSHA256 string `json:"catalog_sha256,omitempty"`
	CatalogMatch  string `json:"catalog_match,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

type ArtifactOptions struct {
	// MavenRepo is an explicit absolute local Maven repository (for example
	// ~/.m2/repository). It is never inferred from the snapshot.
	MavenRepo string
	// GradleUserHome is an explicit absolute Gradle user home containing
	// caches/modules-2/files-2.1.
	GradleUserHome string
	// HashCatalogPath is an explicit local JSON hash catalog.
	HashCatalogPath string
}

type artifactKey struct {
	group      string
	artifact   string
	version    string
	kind       string
	classifier string
}

type catalogDocument struct {
	SchemaVersion int               `json:"schema_version"`
	Artifacts     []catalogArtifact `json:"artifacts"`
}

type catalogArtifact struct {
	GroupID    string `json:"group_id"`
	ArtifactID string `json:"artifact_id"`
	Version    string `json:"version"`
	Kind       string `json:"kind"`
	Classifier string `json:"classifier,omitempty"`
	SHA256     string `json:"sha256"`
}

// collectArtifacts resolves local artifact hashes for every resolved
// dependency. The returned status is one of observed, partial or unavailable.
func collectArtifacts(ctx context.Context, dependencies []Dependency, opts ArtifactOptions) ([]Artifact, string, []string, bool, error) {
	artifacts := []Artifact{}
	catalog, err := loadHashCatalog(opts.HashCatalogPath)
	if err != nil {
		return nil, "", nil, false, err
	}
	mavenRepo, err := validateRepository(opts.MavenRepo, "maven_repo")
	if err != nil {
		return nil, "", nil, false, err
	}
	gradleHome, err := validateRepository(opts.GradleUserHome, "gradle_user_home")
	if err != nil {
		return nil, "", nil, false, err
	}
	if mavenRepo == "" && gradleHome == "" && catalog == nil {
		return artifacts, "unavailable", []string{"artifact_hashes_unavailable"}, false, nil
	}

	seen := map[artifactKey]bool{}
	keys := make([]artifactKey, 0, len(dependencies))
	for _, dependency := range dependencies {
		if dependency.VersionStatus != "resolved" || dependency.Version == "" {
			continue
		}
		if dependency.GroupID == "" || dependency.ArtifactID == "" {
			continue
		}
		kinds := []string{"jar", "pom"}
		if dependency.Type == "pom" {
			kinds = []string{"pom"}
		}
		for _, kind := range kinds {
			key := artifactKey{
				group: dependency.GroupID, artifact: dependency.ArtifactID,
				version: dependency.Version, kind: kind,
				// Classifiers are not carried by the declaration report, so only
				// the unclassified artifact is expected here.
				classifier: "",
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.group != b.group {
			return a.group < b.group
		}
		if a.artifact != b.artifact {
			return a.artifact < b.artifact
		}
		if a.version != b.version {
			return a.version < b.version
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.classifier < b.classifier
	})

	limitations := []string{"artifact_hash_local_only", "artifact_signature_not_verified"}
	partial := false
	observed, catalogOnly := 0, 0
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, "", nil, false, err
		}
		record := Artifact{
			GroupID: key.group, ArtifactID: key.artifact, Version: key.version,
			Kind: key.kind, Classifier: key.classifier,
		}
		localPath, localSHA, localBytes, localErr := locateArtifact(ctx, mavenRepo, gradleHome, key)
		entry, hasCatalog := catalog[key]
		if localErr != nil {
			record.Status = "unavailable"
			record.Source = "unavailable"
			record.Reason = localErr.Error()
		}
		if localSHA != "" {
			record.Status = "observed"
			record.Source = "local_repository"
			record.Repository, record.Path = localPath.repository, localPath.relative
			record.SHA256, record.Bytes = localSHA, localBytes
			if hasCatalog {
				record.CatalogSHA256 = entry
				record.CatalogMatch = "matched"
				if !strings.EqualFold(entry, localSHA) {
					record.Status = "mismatch"
					record.CatalogMatch = "mismatch"
					limitations = append(limitations, "artifact_hash_mismatch:"+artifactLabel(key))
				}
			}
			if record.Status == "observed" {
				observed++
			}
		} else if hasCatalog {
			record.Status = "catalog_only"
			record.Source = "caller_catalog"
			record.SHA256 = entry
			record.CatalogSHA256 = entry
			record.Reason = "local_artifact_missing"
			catalogOnly++
		} else if record.Status == "" {
			record.Status = "missing"
			record.Source = "unavailable"
			record.Reason = "not_found_in_local_repository"
			if mavenRepo == "" && gradleHome == "" {
				record.Reason = "no_local_repository_configured"
			}
		}
		if record.Status == "mismatch" {
			partial = true
		}
		artifacts = append(artifacts, record)
	}

	status := "unavailable"
	switch {
	case len(artifacts) == 0:
		status = "unavailable"
	case observed == len(artifacts):
		status = "observed"
	case observed > 0 || catalogOnly > 0:
		status = "partial"
	}
	if status == "unavailable" {
		limitations = append(limitations, "artifact_hashes_unavailable")
	}
	sort.Strings(limitations)
	return artifacts, status, dedupe(limitations), partial, nil
}

type locatedArtifact struct {
	repository string
	relative   string
}

// locateArtifact hashes the first matching jar/pom in the configured local
// repositories. A missing file is not an error; an unsafe or unreadable path is
// recorded as unavailable instead of being silently skipped.
func locateArtifact(ctx context.Context, mavenRepo, gradleHome string, key artifactKey) (locatedArtifact, string, int64, error) {
	var candidates []locatedArtifact
	if mavenRepo != "" {
		relative, ok := mavenRelativePath(key)
		if ok {
			candidates = append(candidates, locatedArtifact{repository: "maven_local", relative: relative})
		}
	}
	if gradleHome != "" {
		relative, ok, err := gradleArtifactPath(gradleHome, key)
		if err != nil {
			return locatedArtifact{}, "", 0, err
		}
		if ok {
			candidates = append(candidates, locatedArtifact{repository: "gradle_modules", relative: relative})
		}
	}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return locatedArtifact{}, "", 0, err
		}
		root := mavenRepo
		if candidate.repository == "gradle_modules" {
			root = gradleHome
		}
		full := filepath.Join(root, filepath.FromSlash(candidate.relative))
		if !withinRoot(root, full) {
			return locatedArtifact{}, "", 0, fmt.Errorf("artifact path escapes repository root")
		}
		sum, size, err := sha256File(full)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return locatedArtifact{}, "", 0, err
		}
		return candidate, sum, size, nil
	}
	return locatedArtifact{}, "", 0, nil
}

func mavenRelativePath(key artifactKey) (string, bool) {
	groupPath := strings.ReplaceAll(key.group, ".", "/")
	if !safeCoordinates(groupPath, key.artifact, key.version, key.classifier) {
		return "", false
	}
	name := key.artifact + "-" + key.version
	if key.classifier != "" {
		name += "-" + key.classifier
	}
	return groupPath + "/" + key.artifact + "/" + key.version + "/" + name + "." + key.kind, true
}

// gradleArtifactPath finds a file inside
// <home>/caches/modules-2/files-2.1/<group>/<artifact>/<version>/<sha1-dir>/.
func gradleArtifactPath(home string, key artifactKey) (string, bool, error) {
	groupPath := strings.ReplaceAll(key.group, ".", "/")
	if !safeCoordinates(groupPath, key.artifact, key.version, key.classifier) {
		return "", false, nil
	}
	base := filepath.Join(home, "caches", "modules-2", "files-2.1", filepath.FromSlash(groupPath), key.artifact, key.version)
	entries, err := os.ReadDir(base)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	name := key.artifact + "-" + key.version
	if key.classifier != "" {
		name += "-" + key.classifier
	}
	target := name + "." + key.kind
	inspected := 0
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		files, err := os.ReadDir(filepath.Join(base, entry.Name()))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", false, err
		}
		for _, file := range files {
			inspected++
			if inspected > MaxGradleArtifactFiles {
				return "", false, fmt.Errorf("%w: Gradle artifact file count", ErrLimit)
			}
			if file.IsDir() || file.Name() != target {
				continue
			}
			relative := strings.TrimPrefix(filepath.Join(base, entry.Name(), target), home)
			relative = strings.TrimPrefix(filepath.ToSlash(relative), "/")
			return relative, true, nil
		}
	}
	return "", false, nil
}

func safeCoordinates(groupPath, artifact, version, classifier string) bool {
	if groupPath == "" || artifact == "" || version == "" {
		return false
	}
	for _, part := range strings.Split(groupPath, "/") {
		if !safeArtifactPart(part) {
			return false
		}
	}
	if !safeArtifactPart(artifact) || !safeArtifactPart(version) {
		return false
	}
	return classifier == "" || safeArtifactPart(classifier)
}

func safeArtifactPart(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-', r == '+':
		default:
			return false
		}
	}
	return true
}

func withinRoot(root, full string) bool {
	relative, err := filepath.Rel(root, full)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateRepository(path, label string) (string, error) {
	if path == "" {
		return "", nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%s must be an absolute directory: %w", label, err)
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s must be an existing directory that is not a symlink", label)
	}
	return absolute, nil
}

func sha256File(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", 0, fmt.Errorf("artifact is not a regular file")
	}
	if info.Size() > MaxArtifactBytes {
		return "", 0, fmt.Errorf("%w: artifact exceeds %d bytes", ErrLimit, MaxArtifactBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, MaxArtifactBytes+1))
	if err != nil {
		return "", 0, err
	}
	if written > MaxArtifactBytes {
		return "", 0, fmt.Errorf("%w: artifact exceeds %d bytes", ErrLimit, MaxArtifactBytes)
	}
	return hex.EncodeToString(hash.Sum(nil)), written, nil
}

func loadHashCatalog(path string) (map[artifactKey]string, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > MaxArtifactCatalogBytes {
		return nil, fmt.Errorf("%w: hash catalog must be a bounded regular file", ErrArtifactCatalog)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document catalogDocument
	if err = decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrArtifactCatalog, err)
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing content", ErrArtifactCatalog)
	}
	if document.SchemaVersion != 1 || len(document.Artifacts) == 0 || len(document.Artifacts) > MaxArtifactCatalogEntries {
		return nil, fmt.Errorf("%w: unsupported schema or entry count", ErrArtifactCatalog)
	}
	catalog := make(map[artifactKey]string, len(document.Artifacts))
	for _, entry := range document.Artifacts {
		if entry.GroupID == "" || entry.ArtifactID == "" || entry.Version == "" {
			return nil, fmt.Errorf("%w: missing coordinates", ErrArtifactCatalog)
		}
		if entry.Kind != "jar" && entry.Kind != "pom" {
			return nil, fmt.Errorf("%w: kind must be jar or pom", ErrArtifactCatalog)
		}
		if len(entry.SHA256) != 64 {
			return nil, fmt.Errorf("%w: sha256 must be 64 hex characters", ErrArtifactCatalog)
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil {
			return nil, fmt.Errorf("%w: sha256 is not hexadecimal", ErrArtifactCatalog)
		}
		key := artifactKey{group: entry.GroupID, artifact: entry.ArtifactID, version: entry.Version, kind: entry.Kind, classifier: entry.Classifier}
		if _, exists := catalog[key]; exists {
			return nil, fmt.Errorf("%w: duplicate catalog entry", ErrArtifactCatalog)
		}
		catalog[key] = strings.ToLower(entry.SHA256)
	}
	return catalog, nil
}

func artifactLabel(key artifactKey) string {
	label := key.group + ":" + key.artifact + ":" + key.version + ":" + key.kind
	if key.classifier != "" {
		label += ":" + key.classifier
	}
	return label
}
