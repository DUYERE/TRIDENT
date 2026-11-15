package javaast

import (
	"context"
	"os"
	"testing"

	"trident/internal/project"
)

// TestProfileLocalSnapshot is an opt-in profiling harness for a local snapshot.
// It is skipped unless TRIDENT_PROFILE_SNAPSHOT and TRIDENT_PROFILE_HASH are
// set, so the normal test run never depends on machine-local data.
func TestProfileLocalSnapshot(t *testing.T) {
	dir := os.Getenv("TRIDENT_PROFILE_SNAPSHOT")
	hash := os.Getenv("TRIDENT_PROFILE_HASH")
	if dir == "" || hash == "" {
		t.Skip("set TRIDENT_PROFILE_SNAPSHOT and TRIDENT_PROFILE_HASH to profile a local snapshot")
	}
	snapshot, err := project.Open(context.Background(), dir, hash)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	model, err := Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("types=%d methods=%d calls=%d", model.Coverage.TypesIndexed, model.Coverage.MethodsIndexed, model.Coverage.CallsObserved)
}
