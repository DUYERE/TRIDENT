package project

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
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Exclusion struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}
type Manifest struct {
	Version       int         `json:"schema_version"`
	Source        string      `json:"source"`
	PolicyVersion string      `json:"policy_version"`
	ToolVersion   string      `json:"tool_version"`
	Commit        string      `json:"commit,omitempty"`
	Entries       []FileEntry `json:"entries"`
	Directories   []string    `json:"directories"`
	Excluded      []Exclusion `json:"excluded"`
	TotalFiles    int         `json:"total_files"`
	TotalBytes    int64       `json:"total_bytes"`
	Partial       bool        `json:"partial"`
	Limits        Limits      `json:"limits"`
	Warnings      []string    `json:"warnings"`
}
type ImportResult struct {
	Path     string   `json:"path"`
	Hash     string   `json:"hash"`
	Manifest Manifest `json:"manifest"`
}

type Snapshot struct {
	mu       sync.RWMutex
	root     *safeDir
	manifest Manifest
	hash     string
	entries  map[string]FileEntry
	closed   bool
}

type scanRecord struct {
	Stamp    fileStamp
	Hash     string
	Excluded string
}
type scanner struct {
	ctx       context.Context
	root      *safeDir
	forbidden fileIdentity
	records   map[string]scanRecord
	manifest  Manifest
	count     int
	snapshot  bool
	expected  map[string]FileEntry
}

// 01: Import exclusively creates a new destination. It never modifies an existing
// destination and publishes the manifest only after a second source verification.
func Import(ctx context.Context, sourceDir, destDir string) (result ImportResult, retErr error) {
	if err := contextOK(ctx); err != nil {
		return result, err
	}
	source, _, err := openAbsoluteDirectory(sourceDir)
	if err != nil {
		return result, err
	}
	defer source.close()
	destinationName, err := absoluteDirectoryName(destDir)
	if err != nil {
		return result, err
	}
	name := filepath.Base(destinationName)
	if err = validateComponent(name); err != nil {
		return result, err
	}
	parent, parentAncestors, err := openAbsoluteDirectory(filepath.Dir(destinationName))
	if err != nil {
		return result, err
	}
	defer parent.close()
	if containsIdentity(parentAncestors, source.identity) {
		return result, fmt.Errorf("%w: destination nested in source", ErrUnsafePath)
	}
	// New targets cannot contain an existing source. Explicit names/aliases still
	// must not select the source root itself or a root-like destination.
	if strings.EqualFold(source.absolute, destinationName) || name == filepath.VolumeName(destinationName) {
		return result, ErrUnsafePath
	}
	if err = validateRootRelationship(source, parent); err != nil {
		return result, err
	}
	if err = validateDestinationParent(parent); err != nil {
		return result, err
	}
	destination, err := createDirectory(parent, name)
	if err != nil {
		return result, err
	}
	success := false
	defer func() {
		if !success {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if e := cleanupDestination(cleanupCtx, parent, name, destination); e != nil {
				retErr = errors.Join(retErr, fmt.Errorf("incomplete destination cleanup: %w", e))
			}
		}
		_ = destination.close()
	}()
	// Preflight first: reject an unsafe/over-budget source before copying bytes.
	preflight := newScanner(ctx, source)
	preflight.forbidden = parent.identity
	if err = preflight.walk(source, nil, "", 0); err != nil {
		return result, err
	}
	first := newScanner(ctx, source)
	first.forbidden = parent.identity
	if err = first.walk(source, destination, "", 0); err != nil {
		return result, err
	}
	if !reflect.DeepEqual(preflight.records, first.records) {
		return result, ErrSourceChanged
	}
	second := newScanner(ctx, source)
	second.forbidden = parent.identity
	if err = second.walk(source, nil, "", 0); err != nil {
		return result, fmt.Errorf("%w: %w", ErrSourceChanged, err)
	}
	if !reflect.DeepEqual(first.records, second.records) {
		return result, ErrSourceChanged
	}
	manifest := first.manifest
	sort.Slice(manifest.Entries, func(i, j int) bool { return manifest.Entries[i].Path < manifest.Entries[j].Path })
	sort.Slice(manifest.Excluded, func(i, j int) bool { return manifest.Excluded[i].Path < manifest.Excluded[j].Path })
	sort.Strings(manifest.Directories)
	manifest.TotalFiles = len(manifest.Entries)
	manifest.Partial = len(manifest.Excluded) > 0
	if manifest.Partial {
		manifest.Warnings = append(manifest.Warnings, "default policy excluded files or directories; snapshot is partial")
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return result, err
	}
	if int64(len(encoded)) > DefaultLimits().MaxManifestBytes {
		return result, ErrLimit
	}
	digest := sha256.Sum256(encoded)
	hash := hex.EncodeToString(digest[:])
	// Verify all copied bytes before publishing the completion marker.
	if err = verifyTree(ctx, destination, manifest); err != nil {
		return result, err
	}
	if err = contextOK(ctx); err != nil {
		return result, err
	}
	file, err := createFile(destination, ManifestFileName)
	if err != nil {
		return result, err
	}
	_, err = copyBounded(ctx, file, bytes.NewReader(encoded), DefaultLimits().MaxManifestBytes)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return result, err
	}
	// Check the published name still denotes the exclusively created directory.
	check, _, err := openChild(parent, name)
	if err != nil {
		return result, err
	}
	checkStamp, err := fileState(check)
	_ = check.Close()
	if err != nil {
		return result, err
	}
	if checkStamp.Identity != destination.identity {
		return result, ErrIntegrity
	}
	success = true
	return ImportResult{Path: destinationName, Hash: hash, Manifest: cloneManifest(manifest)}, nil
}

func newScanner(ctx context.Context, root *safeDir) *scanner {
	return &scanner{ctx: ctx, root: root, records: make(map[string]scanRecord), manifest: Manifest{Version: 1, Source: root.absolute, PolicyVersion: PolicyVersion, ToolVersion: SnapshotToolVersion, Entries: []FileEntry{}, Directories: []string{}, Excluded: []Exclusion{}, Limits: DefaultLimits(), Warnings: []string{}}}
}

// 02: Directory enumeration is bounded; each entry is opened before any policy
// exclusion so links, hard links, reparse points and nested mounts cannot hide.
func (s *scanner) walk(dir, dest *safeDir, prefix string, depth int) error {
	if err := contextOK(s.ctx); err != nil {
		return err
	}
	if depth > DefaultLimits().MaxDepth {
		return ErrLimit
	}
	before, err := fileState(dir.file)
	if err != nil {
		return err
	}
	if !before.Directory {
		return ErrUnsafePath
	}
	if s.forbidden != (fileIdentity{}) && before.Identity == s.forbidden {
		return fmt.Errorf("%w: destination parent aliases source descendant", ErrUnsafePath)
	}
	reader, err := reopenDirectory(dir)
	if err != nil {
		return err
	}
	defer reader.close()
	seen := map[string]bool{}
	for {
		if err = contextOK(s.ctx); err != nil {
			return err
		}
		entries, readErr := reader.file.ReadDir(64)
		for _, entry := range entries {
			name := entry.Name()
			if err = validateComponent(name); err != nil {
				return err
			}
			lower := strings.ToLower(name)
			if seen[lower] {
				return fmt.Errorf("%w: case-alias collision", ErrUnsafePath)
			}
			seen[lower] = true
			relative := name
			if prefix != "" {
				relative = prefix + "/" + name
			}
			if err = validateRelative(relative); err != nil {
				return err
			}
			if strings.EqualFold(name, ManifestFileName) {
				if s.snapshot && prefix == "" && name == ManifestFileName {
					marker, stamp, e := openRelative(s.root, name)
					if e != nil {
						return e
					}
					_ = marker.Close()
					if stamp.Directory {
						return ErrIntegrity
					}
					continue
				}
				return fmt.Errorf("%w: reserved manifest name", ErrUnsafePath)
			}
			// The authenticated root marker is metadata added by Import, not a
			// source entry. Only that exact marker is exempt from the entry budget.
			s.count++
			if s.count > DefaultLimits().MaxEntries {
				return ErrLimit
			}
			file, stamp, e := openRelative(s.root, relative)
			if e != nil {
				return e
			}
			if stamp.Directory && s.forbidden != (fileIdentity{}) && stamp.Identity == s.forbidden {
				_ = file.Close()
				return ErrUnsafePath
			}
			reason := ""
			if !s.snapshot {
				reason = exclusionReason(relative, stamp.Directory)
			}
			if reason != "" {
				_ = file.Close()
				if len(s.manifest.Excluded) >= DefaultLimits().MaxExcluded {
					return ErrLimit
				}
				s.manifest.Excluded = append(s.manifest.Excluded, Exclusion{Path: relative, Reason: reason})
				s.records[relative] = scanRecord{Stamp: stamp, Excluded: reason}
				continue
			}
			if stamp.Directory {
				s.manifest.Directories = append(s.manifest.Directories, relative)
				child := &safeDir{file: file, identity: stamp.Identity}
				var out *safeDir
				if dest != nil {
					out, e = createDirectory(dest, name)
					if e != nil {
						_ = child.close()
						return e
					}
				}
				e = s.walk(child, out, relative, depth+1)
				if out != nil {
					_ = out.close()
				}
				_ = child.close()
				if e != nil {
					return e
				}
			} else {
				e = s.scanFile(file, stamp, dest, name, relative)
				_ = file.Close()
				if e != nil {
					return e
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	after, err := fileState(dir.file)
	if err != nil {
		return err
	}
	if !sameStamp(before, after) {
		return ErrSourceChanged
	}
	s.records[prefix] = scanRecord{Stamp: after}
	return nil
}

func (s *scanner) scanFile(file *os.File, before fileStamp, dest *safeDir, name, relative string) error {
	limits := DefaultLimits()
	if before.Size < 0 || before.Size > limits.MaxFileBytes || before.Size > limits.MaxTotalBytes-s.manifest.TotalBytes || len(s.manifest.Entries) >= limits.MaxFiles {
		return ErrLimit
	}
	if s.snapshot {
		expected, ok := s.expected[relative]
		if !ok || expected.Size != before.Size {
			return ErrIntegrity
		}
	}
	hasher := sha256.New()
	var writer io.Writer = hasher
	var output *os.File
	if dest != nil {
		var err error
		output, err = createFile(dest, name)
		if err != nil {
			return err
		}
		defer output.Close()
		writer = io.MultiWriter(output, hasher)
	}
	n, err := copyBounded(s.ctx, writer, file, limits.MaxFileBytes)
	if err != nil {
		return err
	}
	after, err := fileState(file)
	if err != nil {
		return err
	}
	if n != before.Size || !sameStamp(before, after) {
		return ErrSourceChanged
	}
	hash := hex.EncodeToString(hasher.Sum(nil))
	if s.snapshot && hash != s.expected[relative].SHA256 {
		return ErrIntegrity
	}
	if output != nil {
		if err = output.Sync(); err != nil {
			return err
		}
		if err = output.Close(); err != nil {
			return err
		}
	}
	s.manifest.Entries = append(s.manifest.Entries, FileEntry{Path: relative, Size: n, SHA256: hash})
	s.manifest.TotalBytes += n
	s.records[relative] = scanRecord{Stamp: after, Hash: hash}
	return nil
}

// 03: Open requires a separately trusted manifest hash; no TOFU mode exists.
func Open(ctx context.Context, dir, expectedHash string) (*Snapshot, error) {
	if err := contextOK(ctx); err != nil {
		return nil, err
	}
	if !validHash(expectedHash) {
		return nil, fmt.Errorf("%w: expected hash must be lowercase SHA256", ErrIntegrity)
	}
	root, _, err := openAbsoluteDirectory(dir)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = root.close()
		}
	}()
	file, before, err := openChild(root, ManifestFileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if before.Directory || before.Size < 0 || before.Size > DefaultLimits().MaxManifestBytes {
		return nil, ErrLimit
	}
	var buf bytes.Buffer
	if _, err = copyBounded(ctx, &buf, file, DefaultLimits().MaxManifestBytes); err != nil {
		return nil, err
	}
	after, err := fileState(file)
	if err != nil {
		return nil, err
	}
	if !sameStamp(before, after) {
		return nil, ErrIntegrity
	}
	digest := sha256.Sum256(buf.Bytes())
	if hex.EncodeToString(digest[:]) != expectedHash {
		return nil, ErrIntegrity
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("%w: manifest JSON", ErrIntegrity)
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, buf.Bytes()) {
		return nil, fmt.Errorf("%w: noncanonical manifest", ErrIntegrity)
	}
	if err = validateManifest(manifest); err != nil {
		return nil, err
	}
	if err = verifyTree(ctx, root, manifest); err != nil {
		return nil, err
	}
	// Reauthenticate the path-bound marker after the full-tree verification.
	marker, markerBefore, err := openChild(root, ManifestFileName)
	if err != nil {
		return nil, err
	}
	var markerBytes bytes.Buffer
	_, err = copyBounded(ctx, &markerBytes, marker, DefaultLimits().MaxManifestBytes)
	markerAfter, stampErr := fileState(marker)
	_ = marker.Close()
	if err != nil {
		return nil, err
	}
	if stampErr != nil {
		return nil, stampErr
	}
	if !sameStamp(before, markerBefore) || !sameStamp(markerBefore, markerAfter) || !bytes.Equal(buf.Bytes(), markerBytes.Bytes()) {
		return nil, ErrIntegrity
	}
	snapshot := &Snapshot{root: root, manifest: cloneManifest(manifest), hash: expectedHash, entries: make(map[string]FileEntry, len(manifest.Entries))}
	for _, entry := range manifest.Entries {
		snapshot.entries[entry.Path] = entry
	}
	success = true
	return snapshot, nil
}

func verifyTree(ctx context.Context, root *safeDir, manifest Manifest) error {
	scan := newScanner(ctx, root)
	scan.snapshot = true
	scan.expected = make(map[string]FileEntry, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		scan.expected[entry.Path] = entry
	}
	if err := scan.walk(root, nil, "", 0); err != nil {
		return fmt.Errorf("%w: %w", ErrIntegrity, err)
	}
	sort.Strings(scan.manifest.Directories)
	if !reflect.DeepEqual(scan.manifest.Directories, manifest.Directories) || len(scan.manifest.Entries) != manifest.TotalFiles || scan.manifest.TotalBytes != manifest.TotalBytes {
		return ErrIntegrity
	}
	return nil
}

func validateManifest(m Manifest) error {
	limits := DefaultLimits()
	if m.Version != 1 || m.PolicyVersion != PolicyVersion || m.ToolVersion != SnapshotToolVersion || m.Commit != "" || m.Limits != limits || m.Source == "" || len(m.Source) > 32768 || len(m.Entries) > limits.MaxFiles || len(m.Excluded) > limits.MaxExcluded || m.TotalFiles != len(m.Entries) || m.Partial != (len(m.Excluded) > 0) || len(m.Warnings) > 1 {
		return ErrIntegrity
	}
	if len(m.Directories)+len(m.Entries)+len(m.Excluded) > limits.MaxEntries {
		return ErrIntegrity
	}
	var total int64
	last := ""
	names := map[string]bool{}
	directories := map[string]bool{}
	for _, dir := range m.Directories {
		if validateRelative(dir) != nil || dir <= last || exclusionReason(dir, true) != "" || names[strings.ToLower(dir)] {
			return ErrIntegrity
		}
		parts := strings.Split(dir, "/")
		if len(parts) > 1 && !directories[strings.Join(parts[:len(parts)-1], "/")] {
			return ErrIntegrity
		}
		directories[dir] = true
		names[strings.ToLower(dir)] = true
		last = dir
	}
	last = ""
	for _, entry := range m.Entries {
		if validateRelative(entry.Path) != nil || entry.Path <= last || !validHash(entry.SHA256) || entry.Size < 0 || entry.Size > limits.MaxFileBytes || entry.Size > limits.MaxTotalBytes-total {
			return ErrIntegrity
		}
		if strings.EqualFold(entry.Path, ManifestFileName) || names[strings.ToLower(entry.Path)] {
			return ErrIntegrity
		}
		names[strings.ToLower(entry.Path)] = true
		last = entry.Path
		total += entry.Size
		if exclusionReason(entry.Path, false) != "" {
			return ErrIntegrity
		}
		parts := strings.Split(entry.Path, "/")
		if len(parts) > 1 && !directories[strings.Join(parts[:len(parts)-1], "/")] {
			return ErrIntegrity
		}
		for i := 1; i < len(parts); i++ {
			if exclusionReason(strings.Join(parts[:i], "/"), true) != "" {
				return ErrIntegrity
			}
		}
	}
	last = ""
	for _, entry := range m.Excluded {
		if validateRelative(entry.Path) != nil || entry.Path <= last || names[strings.ToLower(entry.Path)] {
			return ErrIntegrity
		}
		if entry.Reason != "sensitive_metadata" && entry.Reason != "generated_or_dependency_directory" && entry.Reason != "sensitive_file" && entry.Reason != "binary_or_archive" {
			return ErrIntegrity
		}
		last = entry.Path
	}
	if total != m.TotalBytes {
		return ErrIntegrity
	}
	for _, warning := range m.Warnings {
		if warning != "default policy excluded files or directories; snapshot is partial" {
			return ErrIntegrity
		}
	}
	return nil
}
func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func cloneManifest(m Manifest) Manifest {
	m.Entries = append([]FileEntry{}, m.Entries...)
	m.Directories = append([]string{}, m.Directories...)
	m.Excluded = append([]Exclusion{}, m.Excluded...)
	m.Warnings = append([]string{}, m.Warnings...)
	return m
}
func (s *Snapshot) Manifest() Manifest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneManifest(s.manifest)
}
func (s *Snapshot) Hash() string { s.mu.RLock(); defer s.mu.RUnlock(); return s.hash }
func (s *Snapshot) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.root.close()
}

// 04: Every read reopens under the original pinned root, checks file type/link
// count, and authenticates the full bytes before releasing any content.
func (s *Snapshot) ReadFile(ctx context.Context, relative string) ([]byte, error) {
	if err := contextOK(ctx); err != nil {
		return nil, err
	}
	if err := validateRelative(relative); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	expected, ok := s.entries[relative]
	if !ok {
		return nil, os.ErrNotExist
	}
	file, before, err := openRelative(s.root, relative)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if before.Directory || before.Size != expected.Size {
		return nil, ErrIntegrity
	}
	var buf bytes.Buffer
	if _, err = copyBounded(ctx, &buf, file, expected.Size); err != nil {
		return nil, err
	}
	after, err := fileState(file)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(buf.Bytes())
	if !sameStamp(before, after) || int64(buf.Len()) != expected.Size || hex.EncodeToString(sum[:]) != expected.SHA256 {
		return nil, ErrIntegrity
	}
	return buf.Bytes(), nil
}
