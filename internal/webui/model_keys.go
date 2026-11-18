package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// Locally stored model keys. The console used to read keys only from the
// process environment, which forced a restart before the first model could be
// used. Keys entered in the UI are written to this workspace file (0600) and
// never returned to the browser: responses expose only presence and source.
type modelKeysFile struct {
	SchemaVersion int               `json:"schema_version"`
	Keys          map[string]string `json:"keys"`
}

const (
	modelKeysSchemaVersion = 1
	maxStoredKeyLength     = 2048
	maxStoredKeys          = 64
)

func modelKeysPath(workspace string) string {
	return filepath.Join(workspace, "model_keys.json")
}

func loadModelKeys(workspace string) (map[string]string, error) {
	keys := map[string]string{}
	if workspace == "" {
		return keys, nil
	}
	data, err := os.ReadFile(modelKeysPath(workspace))
	if errors.Is(err, os.ErrNotExist) {
		return keys, nil
	}
	if err != nil {
		return keys, fmt.Errorf("model keys are unreadable: %w", err)
	}
	if len(data) > 1<<20 {
		return keys, errors.New("model keys file is too large")
	}
	var file modelKeysFile
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return keys, fmt.Errorf("model keys are invalid: %v", err)
	}
	if file.SchemaVersion != modelKeysSchemaVersion {
		return keys, fmt.Errorf("model keys schema %d is not supported", file.SchemaVersion)
	}
	for id, key := range file.Keys {
		if !profileIDPattern.MatchString(id) {
			continue
		}
		if key == "" || len(key) > maxStoredKeyLength || strings.ContainsFunc(key, unicode.IsControl) {
			continue
		}
		keys[id] = key
	}
	return keys, nil
}

func saveModelKeys(workspace string, keys map[string]string) error {
	if workspace == "" {
		return errors.New("pinned console cannot store model keys")
	}
	clean := make(map[string]string, len(keys))
	ids := make([]string, 0, len(keys))
	for id, key := range keys {
		if key == "" {
			continue
		}
		clean[id] = key
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ordered := make(map[string]string, len(ids))
	for _, id := range ids {
		ordered[id] = clean[id]
	}
	data, err := json.MarshalIndent(modelKeysFile{SchemaVersion: modelKeysSchemaVersion, Keys: ordered}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		return fmt.Errorf("console workspace is not writable: %w", err)
	}
	path := modelKeysPath(workspace)
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("model keys are not writable: %w", err)
	}
	return nil
}

// storedModelKey returns the locally saved key for one profile, if any.
func (c *Console) storedModelKey(id string) (string, bool) {
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	key, ok := c.modelKeys[id]
	return key, ok && key != ""
}

// profileKey resolves the effective key. A key saved from the UI wins over the
// environment variable because it is the more recent, explicit action; the
// environment stays as the fallback for existing deployments.
func (c *Console) profileKey(profile modelProfile) (string, string) {
	if key, ok := c.storedModelKey(profile.ID); ok {
		return key, "stored"
	}
	if value := os.Getenv(profile.KeyEnv); value != "" {
		return value, "env"
	}
	return "", "none"
}

func (c *Console) setModelKey(id, key string) error {
	// Hold the lock across the write so two quick saves cannot lose each other;
	// the file is small and writes are rare.
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	next := make(map[string]string, len(c.modelKeys)+1)
	for existingID, existingKey := range c.modelKeys {
		next[existingID] = existingKey
	}
	if key == "" {
		delete(next, id)
	} else {
		if len(next) >= maxStoredKeys {
			if _, replacing := next[id]; !replacing {
				return fmt.Errorf("本机最多保存 %d 个模型密钥", maxStoredKeys)
			}
		}
		next[id] = key
	}
	if err := saveModelKeys(c.workspace, next); err != nil {
		return err
	}
	c.modelKeys = next
	return nil
}

func (c *Console) removeModelKey(id string) {
	if _, ok := c.storedModelKey(id); !ok {
		return
	}
	_ = c.setModelKey(id, "")
}

// validateStoredKey bounds what the browser may write. Keys are opaque tokens,
// so only length and control characters are checked: rejecting characters could
// break providers with unusual key formats.
func validateStoredKey(key string) error {
	if key == "" {
		return errors.New("密钥不能为空；要清除已保存的密钥请用清除操作")
	}
	if len(key) > maxStoredKeyLength {
		return fmt.Errorf("密钥不能超过 %d 字节", maxStoredKeyLength)
	}
	if strings.ContainsFunc(key, unicode.IsControl) {
		return errors.New("密钥不能包含换行或控制字符")
	}
	return nil
}
