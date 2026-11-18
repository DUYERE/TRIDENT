package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestModelKeysRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	keys := map[string]string{"alpha": "sk-alpha", "beta": "sk-beta"}
	if err := saveModelKeys(dir, keys); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "model_keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Windows ignores POSIX mode bits (os.WriteFile reports 0666); the 0600
	// request is meaningful on Unix, where the console normally runs.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("model_keys.json must be 0600, got %o", info.Mode().Perm())
	}
	loaded, err := loadModelKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 || loaded["alpha"] != "sk-alpha" {
		t.Fatalf("round trip mismatch: %+v", loaded)
	}
	// Clearing one key must not leave an empty entry behind.
	if err := saveModelKeys(dir, map[string]string{"alpha": "sk-alpha"}); err != nil {
		t.Fatal(err)
	}
	loaded, _ = loadModelKeys(dir)
	if _, ok := loaded["beta"]; ok {
		t.Fatalf("removed key must disappear: %+v", loaded)
	}
}

func TestProfileKeyPrefersStoredOverEnvironment(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	console.modelKeys = map[string]string{}
	profile := modelProfile{ID: "alpha", KeyEnv: "TRIDENT_KEY_TEST"}

	t.Setenv("TRIDENT_KEY_TEST", "sk-env")
	if key, source := console.profileKey(profile); key != "sk-env" || source != "env" {
		t.Fatalf("environment fallback failed: %q %q", key, source)
	}
	if err := console.setModelKey("alpha", "sk-stored"); err != nil {
		t.Fatal(err)
	}
	if key, source := console.profileKey(profile); key != "sk-stored" || source != "stored" {
		t.Fatalf("stored key must win: %q %q", key, source)
	}
	if err := console.setModelKey("alpha", ""); err != nil {
		t.Fatal(err)
	}
	if key, source := console.profileKey(profile); key != "sk-env" || source != "env" {
		t.Fatalf("clearing stored key must fall back to env: %q %q", key, source)
	}
}

func TestStoredKeyValidation(t *testing.T) {
	if err := validateStoredKey("sk-ok"); err != nil {
		t.Fatalf("normal key rejected: %v", err)
	}
	if err := validateStoredKey("sk-bad\nline"); err == nil {
		t.Fatal("control characters must be rejected")
	}
	if err := validateStoredKey(""); err == nil {
		t.Fatal("empty key must be rejected by validateStoredKey")
	}
	if err := validateStoredKey(strings.Repeat("x", maxStoredKeyLength+1)); err == nil {
		t.Fatal("oversized key must be rejected")
	}
}

func TestModelKeyEndpointStoresAndHidesValue(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	console.modelKeys = map[string]string{}
	body := strings.NewReader(`{"id":"alpha","key":"sk-super-secret"}`)
	recorder := httptest.NewRecorder()
	console.handleModelKey(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/models/key", body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("save key failed: %d %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		KeyPresent bool   `json:"key_present"`
		KeySource  string `json:"key_source"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.KeyPresent || payload.KeySource != "stored" {
		t.Fatalf("unexpected key state: %+v", payload)
	}
	if strings.Contains(recorder.Body.String(), "sk-super-secret") {
		t.Fatal("response must never echo the key")
	}

	// The stored value survives through the file and is used by profile views.
	loaded, err := loadModelKeys(console.workspace)
	if err != nil || loaded["alpha"] != "sk-super-secret" {
		t.Fatalf("stored key not persisted: %+v %v", loaded, err)
	}

	// Clearing works and reports the remaining source.
	body = strings.NewReader(`{"id":"alpha","key":""}`)
	recorder = httptest.NewRecorder()
	console.handleModelKey(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/models/key", body))
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), `"stored"`) {
		t.Fatalf("clear failed: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestModelKeyEndpointRejectsControlCharacters(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	console.modelKeys = map[string]string{}
	body := strings.NewReader(`{"id":"alpha","key":"sk-bad\nline"}`)
	recorder := httptest.NewRecorder()
	console.handleModelKey(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/models/key", body))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("control characters must be rejected: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestDeletingProfileDropsStoredKey(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	console.modelKeys = map[string]string{"beta": "sk-beta"}
	// beta is referenced by the worker role in the fixture; detach it first.
	file := console.modelsSnapshot()
	file.Roles.Worker = followMain
	if err := saveModels(console.workspace, file); err != nil {
		t.Fatal(err)
	}
	console.applyModels(file)

	recorder := httptest.NewRecorder()
	console.handleModelProfileRemove(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/models/remove",
		strings.NewReader(`{"id":"beta"}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete failed: %d %s", recorder.Code, recorder.Body.String())
	}
	loaded, _ := loadModelKeys(console.workspace)
	if _, ok := loaded["beta"]; ok {
		t.Fatalf("stored key must be removed with its profile: %+v", loaded)
	}
}
