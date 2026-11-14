// Package cache stores derived analysis indexes keyed by tool version and input
// SHA-256. It never stores source text, credentials or secrets.
package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const (
	SchemaVersion = 1
	MaxEntryBytes = 8 << 20
)

// ErrCorrupt marks an entry that exists but cannot be trusted. Callers must
// treat it as a miss and rebuild instead of failing the analysis.
var ErrCorrupt = errors.New("cache entry corrupt")

var validPart = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type Store struct {
	dir string
}

type entry struct {
	SchemaVersion int             `json:"schema_version"`
	Kind          string          `json:"kind"`
	Key           string          `json:"key"`
	ToolVersion   string          `json:"tool_version"`
	Payload       json.RawMessage `json:"payload"`
}

// Open prepares a cache directory outside any snapshot. The caller is
// responsible for choosing a path that does not overlap its read-only inputs.
func Open(dir string) (*Store, error) {
	if dir == "" || len(dir) > 1024 {
		return nil, fmt.Errorf("cache directory must be a non-empty path")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if info, statErr := os.Stat(absolute); statErr == nil && !info.IsDir() {
		return nil, fmt.Errorf("cache path is not a directory")
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: absolute}, nil
}

func (s *Store) Dir() string {
	if s == nil {
		return ""
	}
	return s.dir
}

// Key derives a stable 64-hex key from ordered parts. Empty parts are still
// separated so that ("ab","c") and ("a","bc") cannot collide.
func Key(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (s *Store) path(kind, key string) (string, error) {
	if !validPart.MatchString(kind) {
		return "", fmt.Errorf("invalid cache kind")
	}
	if !validPart.MatchString(key) || len(key) < 16 {
		return "", fmt.Errorf("invalid cache key")
	}
	return filepath.Join(s.dir, kind, key[:2], key+".json"), nil
}

// Get decodes a trusted entry. A missing entry is (false, nil); an unreadable
// or malformed entry is (false, ErrCorrupt) so the caller rebuilds it.
func (s *Store) Get(kind, key, toolVersion string, target any) (bool, error) {
	path, err := s.path(kind, key)
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, nil
	}
	if len(data) == 0 || len(data) > MaxEntryBytes {
		return false, ErrCorrupt
	}
	var record entry
	if err := json.Unmarshal(data, &record); err != nil {
		return false, ErrCorrupt
	}
	if record.SchemaVersion != SchemaVersion || record.Kind != kind || record.Key != key || record.ToolVersion != toolVersion {
		return false, ErrCorrupt
	}
	if len(record.Payload) == 0 {
		return false, ErrCorrupt
	}
	if err := json.Unmarshal(record.Payload, target); err != nil {
		return false, ErrCorrupt
	}
	return true, nil
}

// Put writes an entry atomically with owner-only permissions.
func (s *Store) Put(kind, key, toolVersion string, value any) error {
	path, err := s.path(kind, key)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	record, err := json.Marshal(entry{
		SchemaVersion: SchemaVersion, Kind: kind, Key: key,
		ToolVersion: toolVersion, Payload: payload,
	})
	if err != nil {
		return err
	}
	if len(record) > MaxEntryBytes {
		return fmt.Errorf("cache entry exceeds %d bytes", MaxEntryBytes)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	if _, err = temp.Write(record); err == nil {
		err = temp.Close()
	} else {
		temp.Close()
	}
	if err != nil {
		os.Remove(tempName)
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		os.Remove(tempName)
		// Windows cannot replace an existing file with Rename.
		if removeErr := os.Remove(path); removeErr == nil {
			return os.Rename(tempName, path)
		}
		return err
	}
	return nil
}

// HasSource reports whether any cached file contains text that looks like Java
// source. It is used by acceptance tests to keep the cache source-free.
func HasSource(dir string, markers ...string) (bool, error) {
	if len(markers) == 0 {
		return false, nil
	}
	found := false
	err := filepath.WalkDir(dir, func(path string, item os.DirEntry, walkErr error) error {
		if walkErr != nil || item.IsDir() {
			return walkErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, marker := range markers {
			if bytes.Contains(data, []byte(marker)) {
				found = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	return found, err
}
