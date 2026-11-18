package webui

import (
	"testing"

	"trident/internal/codescan"
)

func TestCodeAuditCacheRoundTripAndRejectsStale(t *testing.T) {
	console := &Console{workspace: t.TempDir()}
	report := codescan.Report{
		SchemaVersion:  codescan.SchemaVersion,
		ToolVersion:    codescan.ToolVersion,
		SnapshotHash:   "snapshot-1",
		AnalysisKind:   codescan.AnalysisKind,
		RuleSetVersion: codescan.RuleSetVersion,
		Partial:        true,
		FilePartial:    true,
	}
	console.saveCodeCache(report)
	loaded, ok := console.loadCodeCache("snapshot-1")
	if !ok || loaded.SnapshotHash != report.SnapshotHash || !loaded.FilePartial {
		t.Fatalf("cache round trip failed: ok=%v loaded=%+v", ok, loaded)
	}
	if _, ok := console.loadCodeCache("snapshot-2"); ok {
		t.Fatal("cache accepted a different snapshot hash")
	}
	report.ToolVersion = "stale-tool"
	console.saveCodeCache(report)
	if _, ok := console.loadCodeCache("snapshot-1"); ok {
		t.Fatal("cache accepted a stale tool version")
	}
}

func TestCodeAuditCacheSkipsSnapshotOnlyConsole(t *testing.T) {
	console := &Console{}
	if path, ok := console.codeCachePath("snapshot-1"); ok || path != "" {
		t.Fatalf("snapshot-only console should not persist code cache")
	}
}
