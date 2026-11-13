package tools

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"trident/internal/project"
)

// [01] Only actual returned complete lines count; manifest hashes and knowledge
// that a file exists do not establish that source content reached the caller.
func TestEvidenceTracksOnlyReturnedReadRanges(t *testing.T) {
	s, imported, _ := testSnapshot(t, map[string][]byte{"a.txt": []byte("one\ntwo\nthree\nfour\nfive\n"), "b.txt": []byte("other\n")})
	r := New(s)
	entry := imported.Manifest.Entries[0]
	base := Evidence{SnapshotHash: imported.Hash, Path: "a.txt", SHA256: entry.SHA256, StartLine: 1, EndLine: 2}
	if err := r.ValidateEvidence(base); !errors.Is(err, ErrEvidence) {
		t.Fatal("unseen file was accepted")
	}
	for _, name := range []string{"inspect_project", "list_files"} {
		result := execute(t, r, name, map[string]any{})
		evidence, err := ExtractEvidence(name, result)
		if err != nil || len(evidence) != 0 {
			t.Fatalf("metadata supplies source evidence: %+v %v", evidence, err)
		}
	}
	if err := r.ValidateEvidence(base); !errors.Is(err, ErrEvidence) {
		t.Fatal("manifest-only operations authorized source evidence")
	}
	result := execute(t, r, "read_source", project.ReadOptions{Path: "a.txt", Limit: 2})
	evidence, err := ExtractEvidence("read_source", result)
	if err != nil || !reflect.DeepEqual(evidence, []Evidence{base}) {
		t.Fatalf("wrong read evidence: %+v %v", evidence, err)
	}
	if err := r.ValidateEvidence(base); err != nil {
		t.Fatal(err)
	}
	subrange := base
	subrange.StartLine = 2
	if err := r.ValidateEvidence(subrange); err != nil {
		t.Fatal("returned subrange was rejected")
	}
	for _, change := range []func(*Evidence){
		func(e *Evidence) { e.SnapshotHash = strings.Repeat("0", 64) },
		func(e *Evidence) { e.Path = "b.txt" },
		func(e *Evidence) { e.Path = "./a.txt" },
		func(e *Evidence) { e.SHA256 = strings.Repeat("0", 64) },
		func(e *Evidence) { e.StartLine = 0 },
		func(e *Evidence) { e.EndLine = 0 },
		func(e *Evidence) { e.EndLine = 3 },
	} {
		forged := base
		change(&forged)
		if err := r.ValidateEvidence(forged); !errors.Is(err, ErrEvidence) {
			t.Errorf("forged evidence accepted: %+v", forged)
		}
	}
	execute(t, r, "read_source", project.ReadOptions{Path: "a.txt", StartLine: 4, Limit: 1})
	gap := base
	gap.EndLine = 4
	if err := r.ValidateEvidence(gap); !errors.Is(err, ErrEvidence) {
		t.Fatal("unseen line 3 filled in from read range endpoints")
	}
	execute(t, r, "read_source", project.ReadOptions{Path: "a.txt", StartLine: 3, Limit: 1})
	if err := r.ValidateEvidence(gap); err != nil {
		t.Fatal("actual contiguous returned ranges did not merge")
	}
	gap.EndLine = 5
	if err := r.ValidateEvidence(gap); !errors.Is(err, ErrEvidence) {
		t.Fatal("read ahead outside returned pages accepted")
	}
	// Caller modifications of JSON cannot retroactively expand the ledger.
	var modified project.ReadResult
	if err := json.Unmarshal(result, &modified); err != nil {
		t.Fatal(err)
	}
	modified.StartLine, modified.EndLine = 5, 5
	modified.Lines = []project.SourceLine{{Number: 5, Text: "five", Bytes: 4}}
	fabricated, _ := json.Marshal(modified)
	forged, err := ExtractEvidence("read_source", fabricated)
	if err != nil || len(forged) != 1 {
		t.Fatalf("pure parser failed: %+v %v", forged, err)
	}
	if err := r.ValidateEvidence(forged[0]); !errors.Is(err, ErrEvidence) {
		t.Fatal("pure extraction granted provenance")
	}
	if err := New(s).ValidateEvidence(base); !errors.Is(err, ErrEvidence) {
		t.Fatal("separate registry inherited unseen evidence")
	}
	var nilRegistry *Registry
	if err := nilRegistry.ValidateEvidence(base); !errors.Is(err, ErrEvidence) {
		t.Fatal("nil registry accepted evidence")
	}
}

func TestEvidenceSearchCannotBridgeUnseenLines(t *testing.T) {
	s, _, _ := testSnapshot(t, map[string][]byte{"a.txt": []byte("needle\nunseen\nneedle\n"), "b.txt": []byte("needle\n")})
	r := New(s)
	result := execute(t, r, "search_source", project.SearchOptions{Query: "needle", Prefix: "a.txt", Limit: 1})
	first, err := ExtractEvidence("search_source", result)
	if err != nil || len(first) != 1 || first[0].StartLine != 1 || first[0].EndLine != 1 {
		t.Fatalf("invalid search evidence: %+v %v", first, err)
	}
	unreturned := first[0]
	unreturned.StartLine, unreturned.EndLine = 3, 3
	if err := r.ValidateEvidence(unreturned); !errors.Is(err, ErrEvidence) {
		t.Fatal("unreturned matching line accepted")
	}
	var page project.SearchResult
	if err := json.Unmarshal(result, &page); err != nil {
		t.Fatal(err)
	}
	lastResult := execute(t, r, "search_source", project.SearchOptions{Query: "needle", Prefix: "a.txt", Limit: 1, Cursor: page.NextCursor})
	last, err := ExtractEvidence("search_source", lastResult)
	if err != nil || len(last) != 1 || last[0].StartLine != 3 {
		t.Fatalf("wrong resumed search evidence: %+v %v", last, err)
	}
	if err := r.ValidateEvidence(last[0]); err != nil {
		t.Fatal(err)
	}
	bridge := first[0]
	bridge.EndLine = 3
	if err := r.ValidateEvidence(bridge); !errors.Is(err, ErrEvidence) {
		t.Fatal("isolated search lines bridged unreturned line")
	}
}

func TestEvidenceExcludesTruncatedAndBinaryLines(t *testing.T) {
	s, imported, _ := testSnapshot(t, map[string][]byte{
		"a.txt":      []byte("needle short\nneedle" + strings.Repeat("x", project.MaxToolLineBytes) + "\nneedle end\n"),
		"binary.dat": {0, 'a'}, "empty.txt": {},
	})
	r := New(s)
	for _, name := range []string{"read_source", "search_source"} {
		var args any = project.ReadOptions{Path: "a.txt"}
		if name == "search_source" {
			args = project.SearchOptions{Query: "needle"}
		}
		result := execute(t, r, name, args)
		evidence, err := ExtractEvidence(name, result)
		if err != nil || len(evidence) != 2 || evidence[0].StartLine != 1 || evidence[0].EndLine != 1 || evidence[1].StartLine != 3 || evidence[1].EndLine != 3 {
			t.Fatalf("clipped line cited: %+v %v", evidence, err)
		}
		for _, e := range evidence {
			if err := r.ValidateEvidence(e); err != nil {
				t.Fatal(err)
			}
		}
		clipped := evidence[0]
		clipped.StartLine, clipped.EndLine = 2, 2
		if err := r.ValidateEvidence(clipped); !errors.Is(err, ErrEvidence) {
			t.Fatal("truncated line authorized evidence")
		}
	}
	for _, file := range []string{"empty.txt", "binary.dat"} {
		result := execute(t, r, "read_source", project.ReadOptions{Path: file})
		evidence, err := ExtractEvidence("read_source", result)
		if err != nil || len(evidence) != 0 {
			t.Fatalf("empty/binary content supplies evidence: %+v %v", evidence, err)
		}
	}
	if r.SnapshotHash() != imported.Hash {
		t.Fatal("snapshot hash changed")
	}
}

func TestExtractEvidenceRejectsMalformedResults(t *testing.T) {
	for _, tool := range []string{"read_source", "search_source"} {
		for _, raw := range []string{"", "null", "[]", "{}", "{} {}", `{"unknown":true}`, strings.Repeat(" ", project.MaxToolResponseBytes+1)} {
			if _, err := ExtractEvidence(tool, json.RawMessage(raw)); !errors.Is(err, ErrEvidence) {
				t.Errorf("accepted malformed %s result (%d bytes): %v", tool, len(raw), err)
			}
		}
	}
	if _, err := ExtractEvidence("write_file", json.RawMessage(`{}`)); !errors.Is(err, ErrUnknownTool) {
		t.Fatal("unknown evidence tool accepted")
	}
	s, _, _ := testSnapshot(t, map[string][]byte{"a.txt": []byte("one\ntwo\n")})
	original, err := s.Read(context.Background(), project.ReadOptions{Path: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*project.ReadResult){
		func(r *project.ReadResult) { r.Verification = "manifest_only" },
		func(r *project.ReadResult) { r.SnapshotHash = strings.Repeat("A", 64) },
		func(r *project.ReadResult) { r.Path = "../a.txt" },
		func(r *project.ReadResult) { r.SHA256 = "invalid" },
		func(r *project.ReadResult) { r.EndLine++ },
		func(r *project.ReadResult) { r.Binary = true },
		func(r *project.ReadResult) { r.Lines[0].Number++ },
	} {
		copy := original
		copy.Lines = append([]project.SourceLine{}, original.Lines...)
		mutate(&copy)
		encoded, _ := json.Marshal(copy)
		if _, err := ExtractEvidence("read_source", encoded); !errors.Is(err, ErrEvidence) {
			t.Errorf("accepted inconsistent read metadata: %s %v", encoded, err)
		}
	}
}
