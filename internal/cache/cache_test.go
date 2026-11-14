package cache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type payload struct {
	Paths []string `json:"paths"`
}

func TestStoreRoundTripMissAndCorruption(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	key := Key("v1", "file-sha")
	var got payload
	hit, err := store.Get("endpoint-inventory", key, "v1", &got)
	if err != nil || hit {
		t.Fatalf("missing entry: hit=%v err=%v", hit, err)
	}
	if err := store.Put("endpoint-inventory", key, "v1", payload{Paths: []string{"/a", "/b"}}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if hit, err = store.Get("endpoint-inventory", key, "v1", &got); err != nil || !hit {
		t.Fatalf("round trip: hit=%v err=%v", hit, err)
	}
	if len(got.Paths) != 2 || got.Paths[1] != "/b" {
		t.Fatalf("payload mismatch: %+v", got)
	}
	if _, err := store.Get("endpoint-inventory", key, "v2", &got); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tool version mismatch accepted: %v", err)
	}
	path, _ := store.path("endpoint-inventory", key)
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("endpoint-inventory", key, "v1", &got); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt entry accepted: %v", err)
	}
}

func TestStoreRejectsUnsafeParts(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, kind := range []string{"../escape", "Upper", ""} {
		if _, err := store.path(kind, Key("x")); err == nil {
			t.Fatalf("unsafe kind accepted: %q", kind)
		}
	}
	if _, err := store.path("endpoint-inventory", "../short"); err == nil {
		t.Fatalf("unsafe key accepted")
	}
}

func TestStoreKeepsDerivedIndexesOnly(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Put("endpoint-inventory", Key("v1", "sha"), "v1", payload{Paths: []string{"/orders"}}); err != nil {
		t.Fatalf("put: %v", err)
	}
	found, err := HasSource(dir, "public class", "return query")
	if err != nil || found {
		t.Fatalf("source text found in cache: found=%v err=%v", found, err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "endpoint-inventory"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("cache layout missing: %v", err)
	}
}
