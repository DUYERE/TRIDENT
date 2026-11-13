// Package audit extracts bounded, annotation-level Spring MVC endpoint
// inventory from a pinned source snapshot. It is a lexical structural pass,
// not a Java AST, call graph or taint analysis, and it never executes Java.
package audit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"trident/internal/project"
)

const (
	SchemaVersion      = 1
	ToolVersion        = "0.2.0-p0.2+r2-endpoint-inventory-v3"
	MaxJavaFileBytes   = 2 << 20
	MaxJavaFiles       = 2000
	MaxJavaTokens      = 500_000
	MaxControllers     = 2000
	MaxEndpoints       = 20_000
	MaxParameters      = 256
	MaxAnnotationDepth = 32
)

var (
	ErrLimit       = errors.New("audit analysis limit")
	ErrUnsupported = errors.New("unsupported Java source")
)

type Report struct {
	SchemaVersion int          `json:"schema_version"`
	ToolVersion   string       `json:"tool_version"`
	SnapshotHash  string       `json:"snapshot_hash"`
	AnalysisKind  string       `json:"analysis_kind"`
	Partial       bool         `json:"partial"`
	Controllers   []Controller `json:"controllers"`
	Endpoints     []Endpoint   `json:"endpoints"`
	Coverage      Coverage     `json:"coverage"`
	Limitations   []string     `json:"limitations"`
}

type Controller struct {
	File           string   `json:"file"`
	Package        string   `json:"package"`
	Class          string   `json:"class"`
	Symbol         string   `json:"symbol"`
	SHA256         string   `json:"sha256"`
	Annotations    []string `json:"annotations"`
	BasePaths      []string `json:"base_paths"`
	BasePathStatus string   `json:"base_path_status"`
	StartLine      int      `json:"start_line"`
	EndLine        int      `json:"end_line"`
}

type Endpoint struct {
	Path           string      `json:"path"`
	BasePath       string      `json:"base_path"`
	RelativePath   string      `json:"relative_path"`
	HTTPMethods    []string    `json:"http_methods"`
	MethodStatus   string      `json:"method_status"`
	Produces       []string    `json:"produces"`
	ProducesStatus string      `json:"produces_status"`
	ResponseBody   bool        `json:"response_body"`
	File           string      `json:"file"`
	Package        string      `json:"package"`
	Class          string      `json:"class"`
	Method         string      `json:"method"`
	Symbol         string      `json:"symbol"`
	SHA256         string      `json:"sha256"`
	Annotation     string      `json:"annotation"`
	StartLine      int         `json:"start_line"`
	EndLine        int         `json:"end_line"`
	MethodLine     int         `json:"method_line"`
	Parameters     []Parameter `json:"parameters"`
	PathStatus     string      `json:"path_status"`
	PathReason     string      `json:"path_reason,omitempty"`
	Anchor         string      `json:"anchor,omitempty"`
	AnchorLine     int         `json:"anchor_line,omitempty"`
	Duplicate      bool        `json:"duplicate,omitempty"`
}

type Parameter struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Bindings    []string `json:"bindings"`
	BindingName string   `json:"binding_name,omitempty"`
	Required    string   `json:"required"`
	Line        int      `json:"line"`
}

type Coverage struct {
	JavaFilesScanned     int    `json:"java_files_scanned"`
	JavaFilesRejected    int    `json:"java_files_rejected"`
	ControllersFound     int    `json:"controllers_found"`
	EndpointsFound       int    `json:"endpoints_found"`
	UnresolvedPaths      int    `json:"unresolved_paths"`
	DuplicateRoutes      int    `json:"duplicate_routes"`
	NestedClassesSkipped int    `json:"nested_classes_skipped"`
	JavaAST              string `json:"java_ast"`
	TaintAnalysis        string `json:"taint_analysis"`
	RuntimeStatus        string `json:"runtime_status"`
}

// Inspect parses every snapshot .java file and reports only recognized Spring
// MVC controller mappings. Snapshot integrity errors abort; individual
// unsupported files are reported as partial coverage.
func Inspect(ctx context.Context, snapshot *project.Snapshot) (Report, error) {
	if snapshot == nil || snapshot.Hash() == "" {
		return Report{}, fmt.Errorf("%w: pinned snapshot required", ErrLimit)
	}
	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   ToolVersion,
		SnapshotHash:  snapshot.Hash(),
		AnalysisKind:  "http_annotation_inventory",
		Controllers:   []Controller{},
		Endpoints:     []Endpoint{},
		Coverage:      Coverage{JavaAST: "not_available", TaintAnalysis: "not_run", RuntimeStatus: "not_run"},
		Limitations: []string{
			"lexical_annotation_inventory_not_ast: no JavaParser, type resolution, meta-annotations, interface inheritance or framework configuration analysis",
			"http_framework_annotations_only: Spring MVC, JAX-RS (@Path/@GET family) and @WebServlet doGet/doPost-style methods are recognized; web.xml, Servlet 3 registration APIs, WebFlux and custom routers are not",
			"annotation_name_only_no_import_resolution: a custom annotation sharing a known short name could be misidentified",
			"no_source_sink_or_taint: parameters are inventoried only; no call graph, sanitizer or dataflow analysis",
			"path_joining_approximation: simple base+method concatenation; no PathPattern, placeholder, regex or configured context-path semantics",
			"constant_folding_unsupported: non-literal annotation values are unresolved, never guessed",
			"servlet_parameters_unbound: HttpServletRequest.getParameter extraction is not modeled, so servlet entries carry no request source",
			"runtime_status_not_run: a route declaration does not prove deployment, reachability or exploitability",
		},
	}

	var javaFiles []string
	for _, entry := range snapshot.Manifest().Entries {
		if strings.HasSuffix(entry.Path, ".java") {
			javaFiles = append(javaFiles, entry.Path)
		}
	}
	sort.Strings(javaFiles)
	if len(javaFiles) > MaxJavaFiles {
		return Report{}, fmt.Errorf("%w: Java file count exceeds %d", ErrLimit, MaxJavaFiles)
	}
	if len(javaFiles) == 0 {
		report.Limitations = append(report.Limitations, "no_java_source_found")
		sort.Strings(report.Limitations)
		return report, nil
	}

	for _, file := range javaFiles {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		data, err := snapshot.ReadFile(ctx, file)
		if err != nil {
			return Report{}, err
		}
		entry := manifestEntry(snapshot, file)
		parsed, err := parseJavaFile(file, entry.SHA256, data)
		if err != nil {
			report.Partial = true
			report.Coverage.JavaFilesRejected++
			report.Limitations = append(report.Limitations, "rejected_java:"+file+":"+javaErrorReason(err))
			continue
		}
		report.Coverage.JavaFilesScanned++
		report.Controllers = append(report.Controllers, parsed.Controllers...)
		report.Endpoints = append(report.Endpoints, parsed.Endpoints...)
		report.Coverage.NestedClassesSkipped += parsed.NestedClasses
		report.Limitations = append(report.Limitations, parsed.Problems...)
	}
	report.Coverage.ControllersFound = len(report.Controllers)
	report.Coverage.EndpointsFound = len(report.Endpoints)

	if len(report.Controllers) == 0 {
		report.Limitations = append(report.Limitations, "no_spring_mvc_controller_found")
	}
	for i := range report.Endpoints {
		if report.Endpoints[i].PathStatus != "resolved" {
			report.Coverage.UnresolvedPaths++
			report.Partial = true
		}
	}
	if report.Coverage.NestedClassesSkipped > 0 {
		report.Partial = true
	}
	markDuplicateRoutes(&report)
	sort.Slice(report.Controllers, func(i, j int) bool {
		if report.Controllers[i].File != report.Controllers[j].File {
			return report.Controllers[i].File < report.Controllers[j].File
		}
		return report.Controllers[i].Symbol < report.Controllers[j].Symbol
	})
	sort.Slice(report.Endpoints, func(i, j int) bool {
		a, b := report.Endpoints[i], report.Endpoints[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return strings.Join(a.HTTPMethods, ",") < strings.Join(b.HTTPMethods, ",")
	})
	sort.Strings(report.Limitations)
	report.Limitations = dedupe(report.Limitations)
	return report, nil
}

func manifestEntry(snapshot *project.Snapshot, file string) project.FileEntry {
	for _, entry := range snapshot.Manifest().Entries {
		if entry.Path == file {
			return entry
		}
	}
	return project.FileEntry{}
}

func markDuplicateRoutes(report *Report) {
	seen := make(map[string]bool)
	for i := range report.Endpoints {
		endpoint := &report.Endpoints[i]
		if endpoint.PathStatus != "resolved" {
			continue
		}
		methods := endpoint.HTTPMethods
		if len(methods) == 0 {
			methods = []string{"*"}
		}
		for _, method := range methods {
			key := method + " " + endpoint.Path
			if seen[key] {
				endpoint.Duplicate = true
				report.Coverage.DuplicateRoutes++
				report.Limitations = append(report.Limitations, "duplicate_route:"+method+" "+endpoint.Path)
				continue
			}
			seen[key] = true
		}
	}
}

func javaErrorReason(err error) string {
	switch {
	case errors.Is(err, ErrLimit):
		return "limit"
	case errors.Is(err, ErrUnsupported):
		return "unsupported_or_malformed"
	default:
		return "unreadable"
	}
}

func dedupe(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
