package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"trident/internal/project"
)

// [01] Real temporary snapshots only: tests never call models, databases,
// executables or network services, and never import the working project tree.
func testSnapshot(t *testing.T, files map[string][]byte) (*project.Snapshot, project.ImportResult, string) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "source")
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
	imported, err := project.Import(context.Background(), source, filepath.Join(root, "snapshot"))
	if errors.Is(err, project.ErrUnsupportedPlatform) {
		t.Skipf("secure filesystem unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := project.Open(context.Background(), imported.Path, imported.Hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := snapshot.Close(); err != nil {
			t.Error(err)
		}
	})
	return snapshot, imported, source
}

func execute(t *testing.T, r *Registry, name string, args any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.Execute(context.Background(), name, encoded)
	if err != nil {
		t.Fatalf("%s failed: %v", name, err)
	}
	if !json.Valid(result) || len(result) > project.MaxToolResponseBytes {
		t.Fatalf("invalid or oversized result (%d bytes)", len(result))
	}
	return result
}

func TestDefinitionsFixedReadOnlyAndIndependent(t *testing.T) {
	r := New(nil)
	definitions := r.Definitions()
	want := []string{
		"inspect_project", "list_files", "read_source", "search_source",
		"inspect_dependencies", "match_advisories", "query_endpoints", "trace_dataflow", "list_findings",
	}
	if len(definitions) != len(want) {
		t.Fatalf("unexpected tools: %+v", definitions)
	}
	for i, definition := range definitions {
		if definition.Name != want[i] || definition.Description == "" {
			t.Fatalf("incorrect definition: %+v", definition)
		}
		var schema struct {
			Type                 string                     `json:"type"`
			Properties           map[string]json.RawMessage `json:"properties"`
			Required             []string                   `json:"required"`
			AdditionalProperties bool                       `json:"additionalProperties"`
		}
		if err := json.Unmarshal(definition.Schema, &schema); err != nil {
			t.Fatal(err)
		}
		if schema.Type != "object" || schema.Properties == nil || schema.Required == nil || schema.AdditionalProperties {
			t.Fatalf("non-strict schema: %s", definition.Schema)
		}
		if len(schema.Properties) != len(specifications[i].fields) {
			t.Fatal("schema and decoder disagree")
		}
		for key, spec := range specifications[i].fields {
			if _, ok := schema.Properties[key]; !ok {
				t.Fatalf("missing schema option %q", key)
			}
			found := false
			for _, required := range schema.Required {
				found = found || required == key
			}
			if found != spec.required {
				t.Fatalf("incorrect required option %q", key)
			}
		}
		definitions[i].Schema[0] = '!'
		definitions[i].Name = "write_file"
	}
	for i, definition := range r.Definitions() {
		if definition.Name != want[i] || !json.Valid(definition.Schema) {
			t.Fatal("caller mutated registry definitions")
		}
	}
	if r.SnapshotHash() != "" {
		t.Fatal("nil snapshot has a hash")
	}
}

func TestExecutePreservesProjectResultsAndOptions(t *testing.T) {
	s, imported, source := testSnapshot(t, map[string][]byte{
		"src/a.txt": []byte("界needle\r\nsecond\nneedle\n"), "src/b.txt": []byte("needle\n"),
		"src2/out.txt": []byte("needle\n"), "go.mod": []byte("module fixture\n"), ".env": []byte("SECRET=hidden"),
	})
	r := New(s)
	if r.SnapshotHash() != imported.Hash {
		t.Fatal("registry did not pin snapshot hash")
	}
	if err := os.WriteFile(filepath.Join(source, "src", "a.txt"), []byte("changed original"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	inspect, err := s.Inspect(ctx, project.InspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := s.List(ctx, project.ListOptions{Prefix: "src/", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	read, err := s.Read(ctx, project.ReadOptions{Path: "src/a.txt", StartLine: 2, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	search, err := s.Search(ctx, project.SearchOptions{Query: "needle", Prefix: "src", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args any
		want any
	}{
		{"inspect_project", project.InspectOptions{}, inspect},
		{"list_files", project.ListOptions{Prefix: "src/", Limit: 1}, listed},
		{"read_source", project.ReadOptions{Path: "src/a.txt", StartLine: 2, Limit: 1}, read},
		{"search_source", project.SearchOptions{Query: "needle", Prefix: "src", Limit: 1}, search},
	} {
		got := execute(t, r, tc.name, tc.args)
		want, err := json.Marshal(tc.want)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s changed project output: %s != %s (%v)", tc.name, got, want, err)
		}
		if !bytes.Contains(got, []byte(`"partial":true`)) || !bytes.Contains(got, []byte(imported.Hash)) {
			t.Fatal("lost partial/hash metadata")
		}
	}
	// [02] Each cursor is forwarded unchanged with its original bound options.
	for _, tc := range []struct {
		name string
		args any
		want any
	}{
		{"list_files", project.ListOptions{Prefix: "src/", Limit: 1, Cursor: listed.NextCursor}, nil},
		{"read_source", project.ReadOptions{Path: "src/a.txt", Limit: 1, Cursor: read.NextCursor}, nil},
		{"search_source", project.SearchOptions{Query: "needle", Prefix: "src", Limit: 1, Cursor: search.NextCursor}, nil},
	} {
		execute(t, r, tc.name, tc.args)
	}
}

func TestArgumentsRejectAmbiguousAndUnboundedJSON(t *testing.T) {
	r := New(nil) // Invalid input must fail before any snapshot access.
	common := []string{"", " ", "null", "[]", "true", `"{}"`, "1", "{} {}", "{} null", "{}garbage", "{", `{"root":"C:/"}`, `{"path_root":"/"}`, `{"unknown":null}`}
	for _, definition := range r.Definitions() {
		for _, raw := range common {
			if result, err := r.Execute(context.Background(), definition.Name, json.RawMessage(raw)); !errors.Is(err, ErrArguments) || result != nil {
				t.Errorf("%s accepted %q: %s, %v", definition.Name, raw, result, err)
			}
		}
	}
	for _, spec := range specifications {
		for key, field := range spec.fields {
			base := map[string]any{}
			if _, ok := spec.fields["path"]; ok {
				base["path"] = "a.txt"
			}
			if _, ok := spec.fields["query"]; ok {
				base["query"] = "needle"
			}
			for _, bad := range []string{"null", "true", "[]", "{}", "1.5", "1e2", "-1e0", "9223372036854775808", `"1"`, "1"} {
				if (field.kind == stringArgument && bad == `"1"`) || (field.kind == integerArgument && bad == "1") {
					continue
				}
				var fields []string
				for name, value := range base {
					if name != key {
						encoded, _ := json.Marshal(value)
						fields = append(fields, fmt.Sprintf("%q:%s", name, encoded))
					}
				}
				fields = append(fields, fmt.Sprintf("%q:%s", key, bad))
				raw := "{" + strings.Join(fields, ",") + "}"
				if _, err := r.Execute(context.Background(), spec.name, json.RawMessage(raw)); !errors.Is(err, ErrArguments) {
					t.Errorf("%s accepted mistyped %s=%s: %v", spec.name, key, bad, err)
				}
			}
		}
	}
	for _, tc := range []struct{ name, raw string }{
		{"list_files", `{"limit":1,"limit":2}`},
		{"list_files", `{"prefix":"src","pre\u0066ix":"other"}`},
		{"read_source", `{"path":"a.txt","path":"b.txt"}`},
		{"read_source", `{}`},
		{"search_source", `{}`},
		{"search_source", `{"query":"a","query":"b"}`},
		{"list_files", `{"prefix":` + strings.Repeat("[", 6000) + "0" + strings.Repeat("]", 6000) + "}"},
		{"list_files", `{"prefix":"` + strings.Repeat("x", MaxArgumentsBytes) + `"}`},
		{"list_files", "{\"prefix\":\"" + string([]byte{0xff}) + "\"}"},
	} {
		if _, err := r.Execute(context.Background(), tc.name, json.RawMessage(tc.raw)); !errors.Is(err, ErrArguments) {
			t.Errorf("accepted ambiguous/unbounded %s arguments (%d bytes): %v", tc.name, len(tc.raw), err)
		}
	}
	for _, name := range []string{"", "write_file", "exec", "fetch", "READ_SOURCE", "read_source "} {
		if result, err := r.Execute(context.Background(), name, nil); !errors.Is(err, ErrUnknownTool) || result != nil {
			t.Errorf("unknown tool %q not rejected: %v", name, err)
		}
	}
}

func TestProjectOptionSafetyAndOperationalErrorsRemainDistinct(t *testing.T) {
	s, imported, _ := testSnapshot(t, map[string][]byte{"a.txt": []byte("needle\nneedle\n")})
	r := New(s)
	for _, tc := range []struct{ name, raw string }{
		{"list_files", `{"limit":-1}`}, {"list_files", `{"limit":201}`},
		{"list_files", `{"prefix":"../escape"}`}, {"read_source", `{"path":"/absolute"}`},
		{"read_source", `{"path":"C:/host"}`}, {"read_source", `{"path":"a.txt:ads"}`},
		{"read_source", `{"path":""}`}, {"read_source", `{"path":"a.txt","start_line":-1}`},
		{"read_source", `{"path":"a.txt","start_line":1,"cursor":"invalid"}`},
		{"list_files", `{"cursor":"invalid"}`}, {"list_files", `{"cursor":"` + strings.Repeat("a", 2049) + `"}`},
		{"search_source", `{"query":""}`}, {"search_source", `{"query":"a\nb"}`},
		{"search_source", `{"query":"\u0000"}`}, {"search_source", `{"query":"` + strings.Repeat("界", 86) + `"}`},
		{"search_source", `{"query":"needle","prefix":"a\\b"}`},
	} {
		result, err := r.Execute(context.Background(), tc.name, json.RawMessage(tc.raw))
		if !errors.Is(err, ErrArguments) || result != nil {
			t.Errorf("invalid options accepted: %s %s: %v", tc.name, tc.raw, err)
		}
	}
	for _, name := range []string{"read_source", "search_source"} {
		args := json.RawMessage(`{"path":"a.txt"}`)
		if name == "search_source" {
			args = json.RawMessage(`{"query":"needle"}`)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if result, err := r.Execute(ctx, name, args); !errors.Is(err, context.Canceled) || errors.Is(err, ErrArguments) || result != nil {
			t.Fatalf("cancellation misclassified: %v", err)
		}
	}
	if _, err := r.Execute(nil, "inspect_project", json.RawMessage(`{}`)); err == nil {
		t.Fatal("accepted nil context")
	}
	if result, err := r.Execute(context.Background(), "read_source", json.RawMessage(`{"path":"missing.txt"}`)); !errors.Is(err, ErrArguments) || errors.Is(err, os.ErrNotExist) || result != nil {
		t.Fatalf("path absent from manifest must be a tool argument error: %v", err)
	}
	file := filepath.Join(imported.Path, "a.txt")
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("tamper\ntamper\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, raw string }{{"read_source", `{"path":"a.txt"}`}, {"search_source", `{"query":"needle"}`}} {
		if result, err := r.Execute(context.Background(), tc.name, json.RawMessage(tc.raw)); !errors.Is(err, project.ErrIntegrity) || errors.Is(err, ErrArguments) || result != nil {
			t.Errorf("integrity failure swallowed/misclassified: %v", err)
		}
	}
	execute(t, r, "list_files", project.ListOptions{}) // Still manifest-only.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, registry := range []*Registry{r, New(nil), nil, {}} {
		if result, err := registry.Execute(context.Background(), "inspect_project", json.RawMessage(`{}`)); !errors.Is(err, os.ErrClosed) || errors.Is(err, ErrArguments) || result != nil {
			t.Errorf("closed/nil snapshot misclassified: %v", err)
		}
	}
}

// [04] A live unsafe file is not a model argument error, even if its path was
// originally valid. No output or citation may escape a failed safe read.
func TestLiveFilesystemSafetyFailureIsNotArguments(t *testing.T) {
	s, imported, _ := testSnapshot(t, map[string][]byte{"a.txt": []byte("needle\n")})
	r := New(s)
	if err := os.Link(filepath.Join(imported.Path, "a.txt"), filepath.Join(imported.Path, "alias.txt")); err != nil {
		t.Skipf("temporary filesystem does not support hard links: %v", err)
	}
	for _, tc := range []struct{ name, raw string }{{"read_source", `{"path":"a.txt"}`}, {"search_source", `{"query":"needle"}`}} {
		result, err := r.Execute(context.Background(), tc.name, json.RawMessage(tc.raw))
		if !errors.Is(err, project.ErrUnsafePath) || errors.Is(err, ErrArguments) || result != nil {
			t.Errorf("live hard-link safety failure misclassified: %s: %v", tc.name, err)
		}
	}
	entry := imported.Manifest.Entries[0]
	if err := r.ValidateEvidence(Evidence{SnapshotHash: imported.Hash, Path: entry.Path, SHA256: entry.SHA256, StartLine: 1, EndLine: 1}); !errors.Is(err, ErrEvidence) {
		t.Fatal("failed safe read supplied evidence")
	}
}

func TestCursorBindingAndDefaultOptionsThroughRegistry(t *testing.T) {
	s, _, _ := testSnapshot(t, map[string][]byte{"a.txt": []byte("needle\nneedle\n"), "b.txt": []byte("needle\n")})
	r := New(s)
	first := execute(t, r, "list_files", project.ListOptions{Limit: 1})
	var listed project.ListResult
	if err := json.Unmarshal(first, &listed); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []project.ListOptions{
		{Limit: 2, Cursor: listed.NextCursor},
		{Limit: 1, Prefix: "a.txt", Cursor: listed.NextCursor},
	} {
		args, _ := json.Marshal(opts)
		if _, err := r.Execute(context.Background(), "list_files", args); !errors.Is(err, ErrArguments) || !errors.Is(err, project.ErrToolCursor) {
			t.Fatalf("cursor rebinding not rejected: %+v %v", opts, err)
		}
	}
	other, _, _ := testSnapshot(t, map[string][]byte{"a.txt": []byte("different\n"), "b.txt": []byte("needle\n")})
	args, _ := json.Marshal(project.ListOptions{Limit: 1, Cursor: listed.NextCursor})
	if _, err := New(other).Execute(context.Background(), "list_files", args); !errors.Is(err, ErrArguments) {
		t.Fatalf("cursor accepted by different snapshot: %v", err)
	}
	for _, raw := range []string{`{}`, `{"prefix":"","limit":0,"cursor":""}`} {
		result, err := r.Execute(context.Background(), "list_files", json.RawMessage(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(result, &listed); err != nil || listed.Limits.Limit != project.DefaultToolLimit || len(listed.Entries) != 2 {
			t.Fatalf("default/zero option mapping changed: %+v %v", listed, err)
		}
	}
}

func TestEmptyBinaryAndClippedOutputPreserved(t *testing.T) {
	s, _, _ := testSnapshot(t, map[string][]byte{
		"empty.txt": {}, "binary.dat": {'a', 0, 'b'},
		"long.txt": []byte("needle" + strings.Repeat("x", project.MaxToolLineBytes) + "\nshort\n"),
	})
	r := New(s)
	for _, file := range []string{"empty.txt", "binary.dat", "long.txt"} {
		got := execute(t, r, "read_source", project.ReadOptions{Path: file})
		want, err := s.Read(context.Background(), project.ReadOptions{Path: file})
		if err != nil {
			t.Fatal(err)
		}
		var decoded project.ReadResult
		if err := json.Unmarshal(got, &decoded); err != nil || !reflect.DeepEqual(decoded, want) {
			t.Fatalf("lost binary/clipped/empty metadata: %v", err)
		}
	}
	execute(t, r, "search_source", project.SearchOptions{Query: "needle"})
}

func TestConcurrentExecutionAndEvidence(t *testing.T) {
	s, _, _ := testSnapshot(t, map[string][]byte{"a.txt": []byte("needle\nneedle\nneedle\n")})
	r := New(s)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := r.Execute(context.Background(), "read_source", json.RawMessage(`{"path":"a.txt","limit":2}`))
			if err != nil {
				t.Error(err)
				return
			}
			evidence, err := ExtractEvidence("read_source", result)
			if err != nil || len(evidence) != 1 {
				t.Errorf("bad concurrent extraction: %v", err)
				return
			}
			if err := r.ValidateEvidence(evidence[0]); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(r.observed) != 1 {
		t.Fatal("evidence keys did not deduplicate")
	}
	for _, ranges := range r.observed {
		if !reflect.DeepEqual(ranges, []lineRange{{1, 2}}) {
			t.Fatalf("repeated calls grow ledger: %+v", ranges)
		}
	}
}

// [03] Fuzzing stays entirely at the argument boundary; no snapshot or host I/O.
func FuzzExecuteArguments(f *testing.F) {
	for _, seed := range []string{`{}`, `null`, `{"limit":1,"limit":2}`, `{"prefix":[]}`, `{"prefix":"src"}`} {
		f.Add(seed)
	}
	r := New(nil)
	f.Fuzz(func(t *testing.T, raw string) {
		result, err := r.Execute(context.Background(), "list_files", json.RawMessage(raw))
		if result != nil || (!errors.Is(err, ErrArguments) && !errors.Is(err, os.ErrClosed)) {
			t.Fatalf("unexpected result/error: %s %v", result, err)
		}
	})
}
