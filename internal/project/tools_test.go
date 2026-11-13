package project

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// [01] Fixtures exercise the real import/open boundary. No model, database,
// subprocess target, external network, or writes to the original tree are used.
func toolTestSnapshot(t *testing.T, files map[string][]byte) (*Snapshot, ImportResult, string) {
	t.Helper()
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "snapshot")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		file := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := Import(context.Background(), source, destination)
	if errors.Is(err, ErrUnsupportedPlatform) {
		t.Skipf("secure filesystem unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := Open(context.Background(), result.Path, result.Hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := snapshot.Close(); err != nil {
			t.Error(err)
		}
	})
	return snapshot, result, source
}

func toolTestJSONBound(t *testing.T, value any) {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(b)+1 > MaxToolResponseBytes { // Include CLI Encoder's trailing newline.
		t.Fatalf("response exceeds limit: %d > %d", len(b)+1, MaxToolResponseBytes)
	}
}

func toolTestReason(reasons []string, expected string) bool {
	for _, reason := range reasons {
		if reason == expected {
			return true
		}
	}
	return false
}

func TestToolsInspectSortedBoundedPathClues(t *testing.T) {
	s, imported, _ := toolTestSnapshot(t, map[string][]byte{
		"src/z.go": []byte("package z\n"), "src/a.go": []byte("package a\n"),
		"pom.xml": []byte("<project/>"), "package.json": []byte("{}"),
		"README.md": []byte("readme"), ".env": []byte("DO_NOT_DISPLAY=secret"),
	})
	r, err := s.Inspect(context.Background(), InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.SnapshotHash != imported.Hash || r.TotalFiles != 5 || r.TotalBytes != imported.Manifest.TotalBytes {
		t.Fatalf("incorrect inspection metadata: %+v", r)
	}
	if r.Verification != "manifest_only" || r.ExcludedCount != 1 || len(r.Exclusions) != 1 || !r.Partial || !toolTestReason(r.Reasons, "snapshot_exclusions") {
		t.Fatalf("excluded files must be explicit: %+v", r)
	}
	if len(r.BuildFiles) != 2 || r.BuildFiles[0].Path != "package.json" || r.BuildFiles[1].Path != "pom.xml" {
		t.Fatalf("incorrect build path clues: %+v", r.BuildFiles)
	}
	if !sort.SliceIsSorted(r.Extensions, func(i, j int) bool { return r.Extensions[i].Name < r.Extensions[j].Name }) ||
		!sort.SliceIsSorted(r.Directories, func(i, j int) bool { return r.Directories[i].Name < r.Directories[j].Name }) {
		t.Fatal("inspection summaries are not sorted")
	}
	again, err := s.Inspect(context.Background(), InspectOptions{})
	if err != nil || !reflect.DeepEqual(r, again) {
		t.Fatalf("inspection unstable: %v", err)
	}
	toolTestJSONBound(t, r)
}

func TestToolsListStablePagingAndPrefixBoundary(t *testing.T) {
	s, _, _ := toolTestSnapshot(t, map[string][]byte{
		"src/z.go": []byte("z"), "src/a.go": []byte("a"), "src2/leak.go": []byte("x"),
		"root.txt": []byte("root"),
	})
	ctx := context.Background()
	first, err := s.List(ctx, ListOptions{Prefix: "src", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != 2 || len(first.Entries) != 1 || first.Entries[0].Path != "src/a.go" || !first.Partial || first.NextCursor == "" {
		t.Fatalf("bad first list page: %+v", first)
	}
	last, err := s.List(ctx, ListOptions{Prefix: "src/", Limit: 1, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(last.Entries) != 1 || last.Entries[0].Path != "src/z.go" || last.NextCursor != "" || last.Partial {
		t.Fatalf("bad final list page: %+v", last)
	}
	exact, err := s.List(ctx, ListOptions{Prefix: "root.txt"})
	if err != nil || len(exact.Entries) != 1 || exact.Entries[0].Path != "root.txt" {
		t.Fatalf("exact file prefix not respected: %+v, %v", exact, err)
	}
	all, err := s.List(ctx, ListOptions{})
	if err != nil || len(all.Entries) != 4 || all.Limits.Limit != DefaultToolLimit {
		t.Fatalf("default list: %+v, %v", all, err)
	}
	none, err := s.List(ctx, ListOptions{Prefix: "not-present"})
	if err != nil || none.Entries == nil || len(none.Entries) != 0 || none.Partial {
		t.Fatalf("empty list must be complete: %+v, %v", none, err)
	}
	toolTestJSONBound(t, first)
	toolTestJSONBound(t, last)
}

// [02] A cursor is neither transferable between options/tools/snapshots nor
// trusted as an authorization token. Recomputed digests cannot bypass bounds.
func TestToolsCursorBindingAndValidation(t *testing.T) {
	files := map[string][]byte{"a.txt": []byte("needle\nneedle\n"), "b.txt": []byte("needle\n")}
	s, imported, _ := toolTestSnapshot(t, files)
	ctx := context.Background()
	listed, err := s.List(ctx, ListOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []ListOptions{
		{Limit: 2, Cursor: listed.NextCursor},
		{Limit: 1, Prefix: "a.txt", Cursor: listed.NextCursor},
		{Limit: 1, Cursor: "not a cursor"},
		{Limit: 1, Cursor: strings.Repeat("a", 2049)},
	} {
		if _, err := s.List(ctx, opts); !errors.Is(err, ErrToolCursor) {
			t.Errorf("accepted wrong list cursor %+v: %v", opts, err)
		}
	}
	searched, err := s.Search(ctx, SearchOptions{Query: "needle", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []SearchOptions{
		{Query: "other", Limit: 1, Cursor: searched.NextCursor},
		{Query: "needle", Prefix: "b.txt", Limit: 1, Cursor: searched.NextCursor},
		{Query: "needle", Limit: 2, Cursor: searched.NextCursor},
		{Query: "needle", Limit: 1, Cursor: listed.NextCursor},
	} {
		if _, err := s.Search(ctx, opts); !errors.Is(err, ErrToolCursor) {
			t.Errorf("accepted wrong search cursor %+v: %v", opts, err)
		}
	}
	read, err := s.Read(ctx, ReadOptions{Path: "a.txt", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(ctx, ReadOptions{Path: "b.txt", Limit: 1, Cursor: read.NextCursor}); !errors.Is(err, ErrToolCursor) {
		t.Fatalf("read cursor accepted another path: %v", err)
	}
	if _, err := s.Read(ctx, ReadOptions{Path: "a.txt", StartLine: 1, Limit: 1, Cursor: read.NextCursor}); !errors.Is(err, ErrToolOptions) {
		t.Fatalf("start_line combined with cursor: %v", err)
	}
	// Independent Open/process-style handles must accept the same continuation.
	reopened, err := Open(ctx, imported.Path, imported.Hash)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.List(ctx, ListOptions{Limit: 1, Cursor: listed.NextCursor}); err != nil {
		t.Fatalf("cursor did not survive reopen: %v", err)
	}
	other, _, _ := toolTestSnapshot(t, map[string][]byte{"a.txt": []byte("different\n"), "b.txt": []byte("needle\n")})
	if _, err := other.List(ctx, ListOptions{Limit: 1, Cursor: listed.NextCursor}); !errors.Is(err, ErrToolCursor) {
		t.Fatalf("cursor accepted another snapshot: %v", err)
	}
	binding := s.toolBinding("list", "", "", "", 1)
	for _, at := range []toolPosition{{File: -1}, {File: 10000}, {File: 1, Line: 1}, {File: 1, Origin: 1}} {
		meta := ToolMetadata{}
		meta.continueAt(binding, at)
		if _, err := s.List(ctx, ListOptions{Limit: 1, Cursor: meta.NextCursor}); !errors.Is(err, ErrToolCursor) {
			t.Errorf("forged out-of-range continuation accepted: %+v, %v", at, err)
		}
	}
	bad := toolCursor{Version: 1, Binding: binding, At: toolPosition{File: 1}, Digest: strings.Repeat("0", 64)}
	b, _ := json.Marshal(bad)
	if _, err := s.List(ctx, ListOptions{Limit: 1, Cursor: base64.RawURLEncoding.EncodeToString(b)}); !errors.Is(err, ErrToolCursor) {
		t.Fatalf("incorrect cursor checksum accepted: %v", err)
	}
}

func TestToolsReadLineNumbersUTF8AndMetadata(t *testing.T) {
	s, imported, source := toolTestSnapshot(t, map[string][]byte{
		"source.txt": []byte("一号\r\nsecond\n\nlast"), "empty.txt": {},
		"newline.txt": []byte("\n"), "binary.dat": {'a', 0, 'b'}, "invalid.dat": {0xff, 'a'},
	})
	ctx := context.Background()
	// Reads are always from the snapshot; the original may subsequently change.
	if err := os.WriteFile(filepath.Join(source, "source.txt"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := s.Read(ctx, ReadOptions{Path: "source.txt", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if first.SnapshotHash != imported.Hash || first.Verification != "content_sha256" || first.Binary || !first.UTF8 || first.TotalLines != 4 || first.StartLine != 1 || first.EndLine != 2 || first.Size != int64(len("一号\r\nsecond\n\nlast")) || len(first.SHA256) != 64 {
		t.Fatalf("incorrect read metadata: %+v", first)
	}
	if !reflect.DeepEqual(first.Lines, []SourceLine{{Number: 1, Text: "一号", Bytes: 6}, {Number: 2, Text: "second", Bytes: 6}}) {
		t.Fatalf("incorrect CRLF/UTF8 lines: %+v", first.Lines)
	}
	last, err := s.Read(ctx, ReadOptions{Path: "source.txt", Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if last.StartLine != 3 || last.EndLine != 4 || last.NextCursor != "" || last.Partial ||
		!reflect.DeepEqual(last.Lines, []SourceLine{{Number: 3, Text: "", Bytes: 0}, {Number: 4, Text: "last", Bytes: 4}}) {
		t.Fatalf("incorrect final read page: %+v", last)
	}
	start, err := s.Read(ctx, ReadOptions{Path: "source.txt", StartLine: 3, Limit: 1})
	if err != nil || start.StartLine != 3 || start.Lines[0].Text != "" {
		t.Fatalf("start line not honored: %+v, %v", start, err)
	}
	empty, err := s.Read(ctx, ReadOptions{Path: "empty.txt"})
	if err != nil || empty.Binary || !empty.UTF8 || empty.TotalLines != 0 || len(empty.Lines) != 0 || empty.Partial {
		t.Fatalf("incorrect empty file: %+v, %v", empty, err)
	}
	newline, err := s.Read(ctx, ReadOptions{Path: "newline.txt"})
	if err != nil || newline.TotalLines != 1 || len(newline.Lines) != 1 || newline.Lines[0].Text != "" {
		t.Fatalf("trailing newline generated phantom line: %+v, %v", newline, err)
	}
	for _, name := range []string{"binary.dat", "invalid.dat"} {
		r, err := s.Read(ctx, ReadOptions{Path: name})
		if err != nil || !r.Binary || len(r.Lines) != 0 || !r.Partial || !toolTestReason(r.Reasons, "binary_file") || r.NextCursor != "" {
			t.Errorf("binary file leaked or misclassified: %+v, %v", r, err)
		}
		if name == "binary.dat" && !r.UTF8 {
			t.Error("valid UTF8 containing NUL must keep utf8=true, binary=true")
		}
		if name == "invalid.dat" && r.UTF8 {
			t.Error("invalid UTF8 incorrectly marked valid")
		}
	}
	toolTestJSONBound(t, first)
}

func TestToolsReadAndSearchResponseBudgets(t *testing.T) {
	// JSON escaping makes the encoded response much larger than the raw text.
	line := "needle" + strings.Repeat("\t\"<", MaxToolLineBytes)
	content := strings.Repeat(line+"\n", 30)
	s, _, _ := toolTestSnapshot(t, map[string][]byte{"long.txt": []byte(content), "unicode.txt": []byte(strings.Repeat("界", MaxToolLineBytes) + "\n")})
	ctx := context.Background()
	opts := ReadOptions{Path: "long.txt", Limit: MaxToolLimit}
	var numbers []int
	for page := 0; page < 40; page++ {
		r, err := s.Read(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		toolTestJSONBound(t, r)
		if !r.Partial || !toolTestReason(r.Reasons, "line_bytes") {
			t.Fatalf("long-line loss not reported: %+v", r.ToolMetadata)
		}
		for _, line := range r.Lines {
			if !line.Truncated || line.Bytes <= len(line.Text) || len(line.Text) > MaxToolLineBytes {
				t.Fatalf("incorrect line truncation: %+v", line)
			}
			numbers = append(numbers, line.Number)
		}
		if r.NextCursor == "" {
			break
		}
		if r.NextCursor == opts.Cursor {
			t.Fatal("read cursor did not advance")
		}
		opts.Cursor = r.NextCursor
	}
	if len(numbers) != 30 {
		t.Fatalf("read pagination lost long lines: %v", numbers)
	}
	for i, number := range numbers {
		if number != i+1 {
			t.Fatalf("duplicate/missing read line: %v", numbers)
		}
	}
	unicode, err := s.Read(ctx, ReadOptions{Path: "unicode.txt"})
	if err != nil || !utf8.ValidString(unicode.Lines[0].Text) || !unicode.Lines[0].Truncated {
		t.Fatalf("UTF8 split at clipping boundary: %+v, %v", unicode, err)
	}
	search := SearchOptions{Query: "needle", Limit: MaxToolLimit}
	var matches []SearchMatch
	for page := 0; page < 40; page++ {
		r, err := s.Search(ctx, search)
		if err != nil {
			t.Fatal(err)
		}
		toolTestJSONBound(t, r)
		matches = append(matches, r.Matches...)
		if r.NextCursor == "" {
			break
		}
		if r.NextCursor == search.Cursor {
			t.Fatal("search cursor did not advance")
		}
		search.Cursor = r.NextCursor
	}
	if len(matches) != 30 {
		t.Fatalf("search lost long-line matches: %d", len(matches))
	}
	for i, match := range matches {
		if match.Line != i+1 || !match.Truncated || match.LineBytes != len(line) {
			t.Fatalf("incorrect long-line search match: %+v", match)
		}
	}
}

func TestToolsSearchLiteralStablePagination(t *testing.T) {
	s, _, _ := toolTestSnapshot(t, map[string][]byte{
		"src/b.txt":    []byte("no\nneedle needle\nneedle\n"),
		"src/a.txt":    []byte("界needle\nNEEDLE\n.*\n"),
		"src/c.dat":    {0, 'n', 'e', 'e', 'd', 'l', 'e'},
		"src2/out.txt": []byte("needle\n"),
	})
	ctx := context.Background()
	opts := SearchOptions{Query: "needle", Prefix: "src", Limit: 1}
	var matches []SearchMatch
	for pages := 0; pages < 10; pages++ {
		r, err := s.Search(ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		if r.ScannedFiles < 1 || r.ScannedFiles > MaxSearchFiles || r.ScannedBytes > MaxSearchBytes {
			t.Fatalf("invalid per-page search counters: %+v", r)
		}
		matches = append(matches, r.Matches...)
		toolTestJSONBound(t, r)
		if r.NextCursor == "" {
			if !r.Partial || r.SkippedBinary != 1 || !toolTestReason(r.Reasons, "binary_files_skipped") {
				t.Fatalf("binary skip absent: %+v", r)
			}
			break
		}
		if opts.Cursor == r.NextCursor {
			t.Fatal("search repeated cursor")
		}
		opts.Cursor = r.NextCursor
	}
	if len(matches) != 3 || matches[0].Path != "src/a.txt" || matches[0].Line != 1 || matches[0].Column != 2 ||
		matches[1].Path != "src/b.txt" || matches[1].Line != 2 || matches[2].Line != 3 || len(matches[0].SHA256) != 64 {
		t.Fatalf("incorrect ordered literal matches: %+v", matches)
	}
	literal, err := s.Search(ctx, SearchOptions{Query: ".*"})
	if err != nil || len(literal.Matches) != 1 || literal.Matches[0].Line != 3 {
		t.Fatalf("query unexpectedly parsed as regex: %+v, %v", literal, err)
	}
}

// [03] No-match pages still carry a forward continuation when file/byte budgets
// stop the search; counters never pretend that skipped prefixes were scanned.
func TestToolsSearchFileBudgetMakesProgress(t *testing.T) {
	files := make(map[string][]byte)
	for i := 0; i < MaxSearchFiles+3; i++ {
		files[fmt.Sprintf("files/%04d.txt", i)] = []byte("not a match\n")
	}
	s, _, _ := toolTestSnapshot(t, files)
	first, err := s.Search(context.Background(), SearchOptions{Query: "absent"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ScannedFiles != MaxSearchFiles || len(first.Matches) != 0 || first.NextCursor == "" || !toolTestReason(first.Reasons, "search_file_budget") {
		t.Fatalf("file budget did not stop search: %+v", first)
	}
	last, err := s.Search(context.Background(), SearchOptions{Query: "absent", Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if last.ScannedFiles != 3 || last.NextCursor != "" || last.Partial || len(last.Matches) != 0 {
		t.Fatalf("search restarted instead of resuming: %+v", last)
	}
}

func TestToolsSearchByteBudgetMakesProgress(t *testing.T) {
	// Each file fits the import policy, but their combined size exceeds one page.
	data := bytes.Repeat([]byte{'x'}, int(MaxSearchBytes/2)+1)
	s, _, _ := toolTestSnapshot(t, map[string][]byte{"a.txt": data, "b.txt": data})
	first, err := s.Search(context.Background(), SearchOptions{Query: "absent"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ScannedFiles != 1 || first.ScannedBytes != int64(len(data)) || first.NextCursor == "" || !toolTestReason(first.Reasons, "search_byte_budget") {
		t.Fatalf("byte budget absent: %+v", first)
	}
	last, err := s.Search(context.Background(), SearchOptions{Query: "absent", Cursor: first.NextCursor})
	if err != nil || last.ScannedFiles != 1 || last.ScannedBytes != int64(len(data)) || last.NextCursor != "" || last.Partial {
		t.Fatalf("byte budget cannot advance: %+v, %v", last, err)
	}
}

func TestToolsOptionsTraversalAndCancellation(t *testing.T) {
	s, _, _ := toolTestSnapshot(t, map[string][]byte{"a.txt": []byte("a\n")})
	ctx := context.Background()
	for _, n := range []int{-1, MaxToolLimit + 1} {
		if _, err := s.List(ctx, ListOptions{Limit: n}); !errors.Is(err, ErrToolOptions) {
			t.Errorf("list accepted limit %d: %v", n, err)
		}
		if _, err := s.Read(ctx, ReadOptions{Path: "a.txt", Limit: n}); !errors.Is(err, ErrToolOptions) {
			t.Errorf("read accepted limit %d: %v", n, err)
		}
		if _, err := s.Search(ctx, SearchOptions{Query: "a", Limit: n}); !errors.Is(err, ErrToolOptions) {
			t.Errorf("search accepted limit %d: %v", n, err)
		}
	}
	for _, p := range []string{"../a.txt", "/a.txt", "a/../a.txt", "a//b", "./a.txt", "C:/a.txt", "a\\b", "a.txt:stream", "a\x00b"} {
		if _, err := s.Read(ctx, ReadOptions{Path: p}); err == nil {
			t.Errorf("read accepted unsafe path %q", p)
		}
		if _, err := s.List(ctx, ListOptions{Prefix: p}); err == nil {
			t.Errorf("list accepted unsafe prefix %q", p)
		}
		if _, err := s.Search(ctx, SearchOptions{Prefix: p, Query: "a"}); err == nil {
			t.Errorf("search accepted unsafe prefix %q", p)
		}
	}
	for _, query := range []string{"", strings.Repeat("x", MaxSearchQueryBytes+1), "a\nb", "a\rb", "a\x00b", string([]byte{0xff})} {
		if _, err := s.Search(ctx, SearchOptions{Query: query}); !errors.Is(err, ErrToolOptions) {
			t.Errorf("accepted invalid query %q: %v", query, err)
		}
	}
	if _, err := s.Read(ctx, ReadOptions{Path: "missing.txt"}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file not distinguished: %v", err)
	}
	if _, err := s.Read(ctx, ReadOptions{Path: "a.txt", StartLine: 2}); err == nil {
		t.Fatal("accepted line position past EOF")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	checks := []func() error{
		func() error { _, err := s.Inspect(cancelled, InspectOptions{}); return err },
		func() error { _, err := s.List(cancelled, ListOptions{}); return err },
		func() error { _, err := s.Read(cancelled, ReadOptions{Path: "a.txt"}); return err },
		func() error { _, err := s.Search(cancelled, SearchOptions{Query: "a"}); return err },
	}
	for i, check := range checks {
		if err := check(); !errors.Is(err, context.Canceled) {
			t.Errorf("tool %d ignored cancellation: %v", i, err)
		}
	}
}

func TestToolsNilContextAndClosedSnapshot(t *testing.T) {
	s, _, _ := toolTestSnapshot(t, map[string][]byte{"a.txt": []byte("a\n")})
	invoke := func(snapshot *Snapshot, ctx context.Context) []error {
		_, inspectErr := snapshot.Inspect(ctx, InspectOptions{})
		_, listErr := snapshot.List(ctx, ListOptions{})
		_, readErr := snapshot.Read(ctx, ReadOptions{Path: "a.txt"})
		_, searchErr := snapshot.Search(ctx, SearchOptions{Query: "a"})
		return []error{inspectErr, listErr, readErr, searchErr}
	}
	for i, err := range invoke(s, nil) {
		if err == nil {
			t.Errorf("tool %d accepted nil context", i)
		}
	}
	for i, err := range invoke(nil, context.Background()) {
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("tool %d accepted nil snapshot: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for i, err := range invoke(s, context.Background()) {
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("tool %d accepted closed snapshot: %v", i, err)
		}
	}
}

func TestToolsInspectCollectionLimitsExplicit(t *testing.T) {
	files := make(map[string][]byte)
	for i := 0; i < MaxToolLimit+1; i++ {
		files[fmt.Sprintf("module%03d/pom.xml", i)] = []byte("<project/>")
		files[fmt.Sprintf("module%03d/.env", i)] = []byte("EXCLUDED=secret")
	}
	s, _, _ := toolTestSnapshot(t, files)
	r, err := s.Inspect(context.Background(), InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.TotalFiles != MaxToolLimit+1 || r.ExcludedCount != MaxToolLimit+1 || !r.ExclusionsTruncated ||
		len(r.Exclusions) != MaxToolLimit || len(r.BuildFiles) != MaxToolLimit || len(r.Directories) != MaxToolLimit ||
		!r.Partial || !toolTestReason(r.Reasons, "inspection_limit") || !toolTestReason(r.Reasons, "snapshot_exclusions") {
		t.Fatalf("inspection limits silently lost data: %+v", r)
	}
	toolTestJSONBound(t, r)
}

// [04] Same-size changes after Open must fail the per-read SHA256 boundary.
// Metadata-only operations intentionally do not claim live content verification.
func TestToolsPerFileIntegrityOnReadAndSearch(t *testing.T) {
	s, imported, _ := toolTestSnapshot(t, map[string][]byte{"a.txt": []byte("needle\n"), "b.txt": []byte("needle\n")})
	file := filepath.Join(imported.Path, "a.txt")
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("tamper\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(context.Background(), ReadOptions{Path: "a.txt"}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("read did not detect same-size tampering: %v", err)
	}
	if _, err := s.Search(context.Background(), SearchOptions{Query: "needle"}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("search swallowed file integrity failure: %v", err)
	}
	listed, err := s.List(context.Background(), ListOptions{})
	if err != nil || listed.Verification != "manifest_only" {
		t.Fatalf("metadata falsely claims content verification: %+v, %v", listed, err)
	}
}

func TestToolsCursorStrictJSONAndSearchOffsets(t *testing.T) {
	s, _, _ := toolTestSnapshot(t, map[string][]byte{"a.txt": []byte("needle\nneedle\n")})
	ctx := context.Background()
	binding := s.toolBinding("search", "", "", "needle", DefaultToolLimit)
	for _, at := range []toolPosition{{Line: -1}, {File: 1}, {Line: 2}, {Line: 1000000000}, {Origin: 1}} {
		meta := ToolMetadata{}
		meta.continueAt(binding, at)
		if _, err := s.Search(ctx, SearchOptions{Query: "needle", Cursor: meta.NextCursor}); !errors.Is(err, ErrToolCursor) {
			t.Errorf("search accepted invalid offset %+v: %v", at, err)
		}
	}
	meta := ToolMetadata{}
	meta.continueAt(binding, toolPosition{Line: 1})
	decoded, _ := base64.RawURLEncoding.DecodeString(meta.NextCursor)
	for _, data := range [][]byte{append(append([]byte{}, decoded...), []byte(" {}")...),
		[]byte(strings.Replace(string(decoded), `"version":1`, `"unexpected":true,"version":1`, 1))} {
		if _, err := s.Search(ctx, SearchOptions{Query: "needle", Cursor: base64.RawURLEncoding.EncodeToString(data)}); !errors.Is(err, ErrToolCursor) {
			t.Errorf("accepted ambiguous/unknown cursor JSON %s: %v", data, err)
		}
	}
	// A deliberately skipped prefix is allowed, but the counter is only this read.
	r, err := s.Search(ctx, SearchOptions{Query: "needle", Cursor: meta.NextCursor})
	if err != nil || r.ScannedFiles != 1 || len(r.Matches) != 1 || r.Matches[0].Line != 2 {
		t.Fatalf("validated continuation did not respect its bounded offset: %+v, %v", r, err)
	}
}
