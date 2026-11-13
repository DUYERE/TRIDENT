// Package tools exposes only bounded, read-only operations on a pinned snapshot.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"trident/internal/model"
	"trident/internal/project"
)

var (
	ErrArguments   = errors.New("invalid tool arguments")
	ErrUnknownTool = errors.New("unknown tool")
	ErrEvidence    = errors.New("evidence was not returned by this registry")
)

type toolSpec struct {
	name        string
	description string
	schema      string
	fields      map[string]argumentSpec
}

// [01] Definitions and dispatch share one fixed allowlist. There are no host
// roots, executables, network destinations or caller-supplied tool registrations.
var specifications = []toolSpec{
	{
		name:        "inspect_project",
		description: "Inspect bounded snapshot manifest path clues and exclusions. Metadata only; partial results do not prove full audit coverage.",
		schema:      `{"type":"object","properties":{},"required":[],"additionalProperties":false}`,
		fields:      map[string]argumentSpec{},
	},
	{
		name:        "list_files",
		description: "List sorted snapshot-relative files with hashes. Optional prefix selects a file or directory; repeat the same options with next_cursor to continue. Metadata only.",
		schema:      `{"type":"object","properties":{"prefix":{"type":"string","description":"Snapshot-relative file or directory prefix; empty selects all files."},"limit":{"type":"integer","minimum":0,"maximum":200,"description":"Page size; omitted or zero uses 50."},"cursor":{"type":"string","maxLength":2048,"description":"Opaque next_cursor from a previous page with the same options."}},"required":[],"additionalProperties":false}`,
		fields:      map[string]argumentSpec{"prefix": {kind: stringArgument}, "limit": {kind: integerArgument}, "cursor": {kind: stringArgument}},
	},
	{
		name:        "read_source",
		description: "Read bounded, numbered UTF-8 source lines from a snapshot-relative file after full-file SHA256 verification. Binary files and clipped lines are explicit partial results. start_line and cursor cannot be combined.",
		schema:      `{"type":"object","properties":{"path":{"type":"string","minLength":1,"description":"Snapshot-relative file path; never an absolute or host path."},"start_line":{"type":"integer","minimum":0,"description":"One-based first line; omitted or zero starts at line 1. Nonzero cannot be combined with cursor."},"limit":{"type":"integer","minimum":0,"maximum":200,"description":"Page size; omitted or zero uses 50."},"cursor":{"type":"string","maxLength":2048,"description":"Opaque next_cursor from a previous page with the same path and limit."}},"required":["path"],"additionalProperties":false}`,
		fields:      map[string]argumentSpec{"path": {kind: stringArgument, required: true}, "start_line": {kind: integerArgument}, "limit": {kind: integerArgument}, "cursor": {kind: stringArgument}},
	},
	{
		name:        "search_source",
		description: "Search snapshot source using a case-sensitive, single-line UTF-8 literal, not regex. Returns verified file hashes and numbered matching lines. Partial, skipped and clipped results do not prove absence; use next_cursor with identical options to continue.",
		schema:      `{"type":"object","properties":{"query":{"type":"string","minLength":1,"maxLength":256,"description":"Nonempty single-line literal, at most 256 UTF-8 bytes; no NUL, CR or LF."},"prefix":{"type":"string","description":"Snapshot-relative file or directory prefix; empty selects all files."},"limit":{"type":"integer","minimum":0,"maximum":200,"description":"Page size; omitted or zero uses 50."},"cursor":{"type":"string","maxLength":2048,"description":"Opaque next_cursor from a previous page with the same query, prefix and limit."}},"required":["query"],"additionalProperties":false}`,
		fields:      map[string]argumentSpec{"query": {kind: stringArgument, required: true}, "prefix": {kind: stringArgument}, "limit": {kind: integerArgument}, "cursor": {kind: stringArgument}},
	},
	{
		name:        "inspect_dependencies",
		description: "Inspect declaration-level Maven dependencies and modules on the pinned snapshot. This is not an effective dependency tree, classpath, SBOM or reachability result. Paginate with offset; citations are lines actually read from this snapshot.",
		schema:      `{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":10,"description":"Page size; omitted uses 10."},"offset":{"type":"integer","minimum":0,"maximum":100000,"description":"Zero-based result offset."}},"required":[],"additionalProperties":false}`,
		fields:      map[string]argumentSpec{"limit": {kind: integerArgument}, "offset": {kind: integerArgument}},
	},
	{
		name:        "match_advisories",
		description: "Match declared Maven versions against the Run's explicit local advisory catalog using exact version cases only. No range, alias, transitive, reachability or runtime inference. Returns configured=false when no catalog is bound.",
		schema:      `{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":10,"description":"Page size; omitted uses 10."},"offset":{"type":"integer","minimum":0,"maximum":100000,"description":"Zero-based result offset."}},"required":[],"additionalProperties":false}`,
		fields:      map[string]argumentSpec{"limit": {kind: integerArgument}, "offset": {kind: integerArgument}},
	},
	{
		name:        "query_endpoints",
		description: "List annotation-level Spring MVC endpoints with parameter bindings and path status. Routes are not deployed routes. Each returned endpoint includes citations read from this snapshot; use read_source for surrounding context.",
		schema:      `{"type":"object","properties":{"q":{"type":"string","maxLength":256,"description":"Case-insensitive filter over path, symbol, file and HTTP methods."},"limit":{"type":"integer","minimum":1,"maximum":10,"description":"Page size; omitted uses 10."},"offset":{"type":"integer","minimum":0,"maximum":100000,"description":"Zero-based result offset."}},"required":[],"additionalProperties":false}`,
		fields:      map[string]argumentSpec{"q": {kind: stringArgument}, "limit": {kind: integerArgument}, "offset": {kind: integerArgument}},
	},
	{
		name:        "trace_dataflow",
		description: "Return bounded static source-to-sink findings (SQL and eight other injection categories) with status static_confirmed, inconclusive or refuted. Runtime status is always not_run. Citations are actual snapshot lines; absence of a finding is not a safety proof.",
		schema:      `{"type":"object","properties":{"category":{"type":"string","maxLength":32,"description":"sql, command, ssrf, path, template, xss, deserialization, xxe, ldap or all."},"status":{"type":"string","maxLength":32,"description":"static_confirmed, inconclusive, refuted or all."},"q":{"type":"string","maxLength":256,"description":"Case-insensitive filter over finding, endpoint, file and parameter fields."},"limit":{"type":"integer","minimum":1,"maximum":10,"description":"Page size; omitted uses 10."},"offset":{"type":"integer","minimum":0,"maximum":100000,"description":"Zero-based result offset."}},"required":[],"additionalProperties":false}`,
		fields:      map[string]argumentSpec{"category": {kind: stringArgument}, "status": {kind: stringArgument}, "q": {kind: stringArgument}, "limit": {kind: integerArgument}, "offset": {kind: integerArgument}},
	},
	{
		name:        "list_findings",
		description: "List unified Finding/Hypothesis evidence, including dependency-advisory candidates and dataflow findings. Static status is separate from runtime_status=not_run. Citations are actual snapshot lines; use read_source before citing additional context.",
		schema:      `{"type":"object","properties":{"category":{"type":"string","maxLength":32,"description":"sql, command, ssrf, path, template, xss, deserialization, xxe, ldap, dependency or all."},"status":{"type":"string","maxLength":32,"description":"static_confirmed, inconclusive, refuted or all."},"q":{"type":"string","maxLength":256,"description":"Case-insensitive filter over finding, endpoint, component and file fields."},"limit":{"type":"integer","minimum":1,"maximum":10,"description":"Page size; omitted uses 10."},"offset":{"type":"integer","minimum":0,"maximum":100000,"description":"Zero-based result offset."}},"required":[],"additionalProperties":false}`,
		fields:      map[string]argumentSpec{"category": {kind: stringArgument}, "status": {kind: stringArgument}, "q": {kind: stringArgument}, "limit": {kind: integerArgument}, "offset": {kind: integerArgument}},
	},
}

// Registry borrows its snapshot: the caller owns Close. A registry must not be
// copied after use. Its evidence ledger is safe for concurrent tool executions.
type Registry struct {
	snapshot        *project.Snapshot
	analysisOptions AnalysisOptions
	mu              sync.RWMutex
	observed        map[evidenceFile][]lineRange
	analysisMu      sync.Mutex
	analysis        *analysisCache
}

func New(snapshot *project.Snapshot) *Registry {
	return NewWithAnalysis(snapshot, AnalysisOptions{})
}

// NewWithAnalysis pins the snapshot and local advisory configuration. The
// caller owns the snapshot and must not mutate it while the registry is used.
func NewWithAnalysis(snapshot *project.Snapshot, opts AnalysisOptions) *Registry {
	return &Registry{snapshot: snapshot, analysisOptions: opts, observed: make(map[evidenceFile][]lineRange)}
}

func (r *Registry) SnapshotHash() string {
	if r == nil || r.snapshot == nil {
		return ""
	}
	return r.snapshot.Hash()
}

// [02] Return fresh schema bytes so callers cannot mutate future definitions.
func (r *Registry) Definitions() []model.Tool {
	definitions := make([]model.Tool, 0, len(specifications))
	for _, spec := range specifications {
		definitions = append(definitions, model.Tool{Name: spec.name, Description: spec.description, Schema: json.RawMessage(spec.schema)})
	}
	return definitions
}

func (r *Registry) Execute(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error) {
	var spec *toolSpec
	for i := range specifications {
		if specifications[i].name == name {
			spec = &specifications[i]
			break
		}
	}
	if spec == nil {
		return nil, ErrUnknownTool
	}
	values, err := decodeArguments(args, spec.fields)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, fmt.Errorf("nil tool context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || r.snapshot == nil {
		return nil, os.ErrClosed
	}
	var result any
	switch name {
	case "inspect_project":
		result, err = r.snapshot.Inspect(ctx, project.InspectOptions{})
	case "list_files":
		result, err = r.snapshot.List(ctx, project.ListOptions{
			Prefix: stringValue(values, "prefix"), Limit: integerValue(values, "limit"), Cursor: stringValue(values, "cursor"),
		})
	case "read_source":
		// [04] The pinned manifest distinguishes a guessed/nonexistent tool path
		// from a listed file disappearing on disk. Match exact portable paths;
		// never normalize aliases or downgrade errors from the actual safe read.
		filePath := stringValue(values, "path")
		listed := false
		for _, entry := range r.snapshot.Manifest().Entries {
			if entry.Path == filePath {
				listed = true
				break
			}
		}
		if !listed {
			return nil, fmt.Errorf("%w: path must name a file in the snapshot manifest", ErrArguments)
		}
		result, err = r.snapshot.Read(ctx, project.ReadOptions{
			Path: filePath, StartLine: integerValue(values, "start_line"),
			Limit: integerValue(values, "limit"), Cursor: stringValue(values, "cursor"),
		})
	case "search_source":
		result, err = r.snapshot.Search(ctx, project.SearchOptions{
			Query: stringValue(values, "query"), Prefix: stringValue(values, "prefix"),
			Limit: integerValue(values, "limit"), Cursor: stringValue(values, "cursor"),
		})
	case "inspect_dependencies":
		result, err = r.inspectDependencies(ctx, values)
	case "match_advisories":
		result, err = r.matchAdvisories(ctx, values)
	case "query_endpoints":
		result, err = r.queryEndpoints(ctx, values)
	case "trace_dataflow":
		result, err = r.traceDataflow(ctx, values)
	case "list_findings":
		result, err = r.listFindings(ctx, values)
	}
	if err != nil {
		// [03] Only project option/cursor errors are caller mistakes. In particular,
		// never relabel live filesystem safety, integrity or cancellation failures.
		if errors.Is(err, project.ErrToolOptions) || errors.Is(err, project.ErrToolCursor) {
			return nil, fmt.Errorf("%w: %w", ErrArguments, err)
		}
		return nil, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if len(encoded) > project.MaxToolResponseBytes {
		return nil, fmt.Errorf("%w: tool response exceeds byte budget", project.ErrLimit)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Only successful, serialized read/search output enters the evidence ledger.
	if name == "read_source" || name == "search_source" {
		evidence, err := ExtractEvidence(name, encoded)
		if err != nil {
			return nil, err
		}
		r.remember(evidence)
	}
	return encoded, nil
}
