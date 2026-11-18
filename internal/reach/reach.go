// Package reach builds a bounded class-level call graph over a pinned snapshot
// and looks for evidence that a declared dependency is used from an inventoried
// HTTP entrypoint. It resolves imports and same-package type references only; it
// does not parse bytecode, follow reflection, or prove runtime class loading.
package reach

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"trident/internal/audit"
	"trident/internal/project"
	"trident/internal/sca"
)

const (
	SchemaVersion      = 1
	ToolVersion        = "0.2.0-p0.2+r2-bounded-entry-call-graph-v2"
	MaxJavaFiles       = 2000
	MaxJavaBytes       = 2 << 20
	MaxPackageMapBytes = 64 << 10
	MaxMappingEntries  = 256
	MaxPrefixes        = 64
	MaxImportMatches   = 20
	MaxTypesPerFile    = 512
	MaxGraphEdges      = 20_000
	MaxGraphNodes      = 4_000
	MaxPathDepth       = 8
	MaxPathsPerDep     = 5
	MaxReflectiveHits  = 8
	MaxHits            = 20_000
)

var (
	classPattern      = regexp.MustCompile(`\b(?:class|interface|enum|record)\s+([A-Za-z_$][A-Za-z0-9_$]*)`)
	identifierPattern = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*`)
	reflectiveTarget  = regexp.MustCompile(`(?:Class\s*\.\s*forName|\.\s*loadClass)\s*\(\s*"([^"]{1,256})"`)
	reflectiveMarker  = regexp.MustCompile(`Class\s*\.\s*forName|\.\s*loadClass|\.\s*getDeclared?(?:Method|Constructor)|Proxy\s*\.\s*newProxyInstance`)
)

type Options struct {
	// PackageMapPath maps group:artifact to package prefixes. Without it every
	// dependency stays unknown: source imports cannot be attributed otherwise.
	PackageMapPath string
}

type Report struct {
	SchemaVersion int            `json:"schema_version"`
	ToolVersion   string         `json:"tool_version"`
	SnapshotHash  string         `json:"snapshot_hash"`
	AnalysisKind  string         `json:"analysis_kind"`
	Partial       bool           `json:"partial"`
	Entrypoints   []Entrypoint   `json:"entrypoints"`
	Dependencies  []Reachability `json:"dependencies"`
	Coverage      Coverage       `json:"coverage"`
	Limitations   []string       `json:"limitations"`
	RuntimeStatus string         `json:"runtime_status"`
}

type Entrypoint struct {
	Path        string   `json:"path"`
	HTTPMethods []string `json:"http_methods"`
	Symbol      string   `json:"symbol"`
	File        string   `json:"file"`
	SHA256      string   `json:"sha256"`
	Line        int      `json:"line"`
}

type Reachability struct {
	Path           string      `json:"path"`
	Module         string      `json:"module"`
	Dependency     string      `json:"dependency"`
	Language       string      `json:"language,omitempty"`
	Ecosystem      string      `json:"ecosystem,omitempty"`
	Version        string      `json:"version,omitempty"`
	VersionStatus  string      `json:"version_status"`
	Reachability   string      `json:"reachability"`
	Reason         string      `json:"reason,omitempty"`
	MappedPrefixes []string    `json:"mapped_prefixes,omitempty"`
	MatchedImports []ImportRef `json:"matched_imports,omitempty"`
	Paths          []Path      `json:"paths,omitempty"`
	RuntimeStatus  string      `json:"runtime_status"`
}

type ImportRef struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Import string `json:"import"`
}

// Path records one bounded entry-to-import path. Every step carries the file
// digest and line that justify it, so a reader can re-check the evidence.
type Path struct {
	Entry  Entrypoint `json:"entry"`
	Steps  []Step     `json:"steps"`
	Import ImportRef  `json:"import"`
}

type Step struct {
	Class    string `json:"class,omitempty"`
	File     string `json:"file"`
	SHA256   string `json:"sha256"`
	Line     int    `json:"line"`
	Relation string `json:"relation"`
}

type Coverage struct {
	JavaFilesScanned      int    `json:"java_files_scanned"`
	JavaFilesRejected     int    `json:"java_files_rejected"`
	ImportsParsed         int    `json:"imports_parsed"`
	Entrypoints           int    `json:"entrypoints"`
	ClassesIndexed        int    `json:"classes_indexed"`
	GraphEdges            int    `json:"graph_edges"`
	Dependencies          int    `json:"dependencies"`
	Reachable             int    `json:"reachable"`
	Unreachable           int    `json:"unreachable"`
	Unknown               int    `json:"unknown"`
	LanguageFilesScanned  int    `json:"language_files_scanned"`
	LanguageFilesRejected int    `json:"language_files_rejected"`
	LanguageImports       int    `json:"language_imports"`
	LanguageReachable     int    `json:"language_reachable"`
	LanguageUnreachable   int    `json:"language_unreachable"`
	LanguageUnknown       int    `json:"language_unknown"`
	RuntimeStatus         string `json:"runtime_status"`
}

type packageMap struct {
	SchemaVersion int                 `json:"schema_version"`
	Dependencies  map[string][]string `json:"dependencies"`
}

type sourceFile struct {
	path              string
	sha256            string
	pkg               string
	class             string
	line              int
	imports           []importRecord
	types             map[string]bool
	reflective        bool
	reflectiveTargets []string
}

type importRecord struct {
	file string
	line int
	name string
}

type edge struct {
	file     string
	relation string
}

type graph struct {
	files     map[string]*sourceFile
	byFQCN    map[string]string
	byPackage map[string][]string
	edges     map[string][]edge
	edgeTotal int
	limited   bool
}

type pathHit struct {
	module string
	entry  Entrypoint
	steps  []Step
	imp    ImportRef
}

type traversal struct {
	hits            []pathHit
	reachable       map[string]bool
	reflectiveFiles map[string]bool
	fileModules     map[string]string
	limitExceeded   bool
	entryUnresolved bool
	entriesPerMod   map[string]int
}

func Inspect(ctx context.Context, snapshot *project.Snapshot, opts Options) (Report, error) {
	if snapshot == nil || snapshot.Hash() == "" {
		return Report{}, fmt.Errorf("pinned snapshot required")
	}
	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   ToolVersion,
		SnapshotHash:  snapshot.Hash(),
		AnalysisKind:  "bounded_entry_call_graph_v1",
		Entrypoints:   []Entrypoint{},
		Dependencies:  []Reachability{},
		Coverage:      Coverage{RuntimeStatus: "not_run"},
		RuntimeStatus: "not_run",
		Limitations: []string{
			"reachability_bounded_call_graph: imports, same-package type references and bounded breadth-first traversal only; no bytecode, framework wiring, AOP, async dispatch or dynamic proxy resolution",
			"reflection_not_resolved: reflective class loading is reported as unknown instead of being followed",
			"classpath_not_resolved: declared versions are not verified against an effective dependency tree",
			"runtime_status_not_run: no deployed target or runtime exploit test is executed",
		},
	}
	mapping, err := loadPackageMap(opts.PackageMapPath)
	if err != nil {
		return Report{}, err
	}
	if mapping == nil {
		report.Limitations = append(report.Limitations, "package_map_not_configured: all dependencies stay unknown")
	}

	scaReport, err := sca.Inspect(ctx, snapshot, sca.Options{})
	if err != nil {
		return Report{}, err
	}
	report.Partial = report.Partial || scaReport.Partial
	auditReport, err := audit.Inspect(ctx, snapshot)
	if err != nil {
		return Report{}, err
	}
	report.Partial = report.Partial || auditReport.Partial

	hashes := map[string]string{}
	for _, entry := range snapshot.Manifest().Entries {
		hashes[entry.Path] = entry.SHA256
	}
	files, scanned, rejected, parseLimitations := scanSources(ctx, snapshot, hashes)
	report.Coverage.JavaFilesScanned = scanned
	report.Coverage.JavaFilesRejected = rejected
	for _, file := range files {
		report.Coverage.ImportsParsed += len(file.imports)
	}
	report.Partial = report.Partial || rejected > 0
	report.Limitations = append(report.Limitations, parseLimitations...)

	moduleDirs := moduleDirectories(scaReport)
	classes := buildGraph(files)
	report.Coverage.ClassesIndexed = len(classes.byFQCN)
	for _, edges := range classes.edges {
		report.Coverage.GraphEdges += len(edges)
	}
	if classes.limited {
		report.Partial = true
		report.Limitations = append(report.Limitations, "reachability_graph_limit")
	}
	entrypoints := entrypointsFrom(auditReport)
	report.Entrypoints = entrypoints
	report.Coverage.Entrypoints = len(entrypoints)

	result := traverseEntries(classes, entrypoints, moduleDirs)
	report.Partial = report.Partial || result.limitExceeded
	if result.limitExceeded {
		report.Limitations = append(report.Limitations, "reachability_traversal_limit")
	}
	if result.entryUnresolved {
		report.Limitations = append(report.Limitations, "entrypoint_class_unresolved")
	}
	if len(entrypoints) == 0 {
		report.Limitations = append(report.Limitations, "no_entrypoints_found")
	}

	for _, dependency := range scaReport.Dependencies {
		if dependency.Ecosystem != "" {
			continue
		}
		item := Reachability{
			Module: dependency.Module, Dependency: dependency.GroupID + ":" + dependency.ArtifactID,
			Version: dependency.Version, VersionStatus: dependency.VersionStatus, RuntimeStatus: "not_run",
		}
		prefixes := mapping[item.Dependency]
		if len(prefixes) == 0 {
			item.Reachability = "unknown"
			item.Reason = "package_mapping_missing"
			report.Coverage.Unknown++
			report.Dependencies = append(report.Dependencies, item)
			continue
		}
		item.MappedPrefixes = append([]string{}, prefixes...)
		paths := pathsForModule(result.hits, dependency.Module, prefixes)
		if len(paths) > 0 {
			item.Reachability = "reachable"
			item.Reason = "entry_import_path"
			item.Paths = paths
			item.MatchedImports = uniqueImports(paths)
			report.Coverage.Reachable++
			report.Dependencies = append(report.Dependencies, item)
			continue
		}
		entryCount := result.entriesPerMod[dependency.Module]
		switch {
		case result.limitExceeded:
			item.Reachability = "unknown"
			item.Reason = "call_graph_limit"
		case entryCount == 0:
			item.Reachability = "unknown"
			item.Reason = "no_entrypoints_in_module"
		case reflectionForModule(result.reflectiveFiles, classes, result.fileModules, dependency.Module, prefixes):
			item.Reachability = "unknown"
			item.Reason = "reflection_not_resolved"
		case dependency.VersionStatus != "resolved":
			item.Reachability = "unknown"
			item.Reason = "version_unresolved"
		default:
			item.Reachability = "unreachable"
			item.Reason = "no_path_from_module_entrypoints"
		}
		switch item.Reachability {
		case "reachable":
			report.Coverage.Reachable++
		case "unreachable":
			report.Coverage.Unreachable++
		default:
			report.Coverage.Unknown++
		}
		report.Dependencies = append(report.Dependencies, item)
	}
	languageItems, languageCoverage, languageLimitations, languagePartial := analyzeLanguageReach(ctx, snapshot, scaReport.Dependencies)
	report.Dependencies = append(report.Dependencies, languageItems...)
	report.Coverage.LanguageFilesScanned = languageCoverage.LanguageFilesScanned
	report.Coverage.LanguageFilesRejected = languageCoverage.LanguageFilesRejected
	report.Coverage.LanguageImports = languageCoverage.LanguageImports
	report.Coverage.LanguageReachable = languageCoverage.LanguageReachable
	report.Coverage.LanguageUnreachable = languageCoverage.LanguageUnreachable
	report.Coverage.LanguageUnknown = languageCoverage.LanguageUnknown
	report.Coverage.Reachable += languageCoverage.LanguageReachable
	report.Coverage.Unreachable += languageCoverage.LanguageUnreachable
	report.Coverage.Unknown += languageCoverage.LanguageUnknown
	report.Partial = report.Partial || languagePartial
	report.Limitations = append(report.Limitations, languageLimitations...)
	report.Coverage.Dependencies = len(report.Dependencies)
	sort.Slice(report.Dependencies, func(i, j int) bool {
		a, b := report.Dependencies[i], report.Dependencies[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.Dependency != b.Dependency {
			return a.Dependency < b.Dependency
		}
		return a.Version < b.Version
	})
	sort.Strings(report.Limitations)
	report.Limitations = dedupe(report.Limitations)
	return report, nil
}

func loadPackageMap(path string) (map[string][]string, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > MaxPackageMapBytes {
		return nil, fmt.Errorf("package map must be a bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var mapping packageMap
	if err = decoder.Decode(&mapping); err != nil {
		return nil, fmt.Errorf("invalid package map JSON: %w", err)
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing package map content")
	}
	if mapping.SchemaVersion != 1 || len(mapping.Dependencies) > MaxMappingEntries {
		return nil, fmt.Errorf("unsupported package map schema or size")
	}
	for key, prefixes := range mapping.Dependencies {
		if !strings.Contains(key, ":") || len(prefixes) > MaxPrefixes {
			return nil, fmt.Errorf("invalid package map entry")
		}
		for _, prefix := range prefixes {
			if prefix == "" || len(prefix) > 256 || strings.Contains(prefix, "..") || strings.ContainsAny(prefix, "/\\") {
				return nil, fmt.Errorf("invalid package prefix")
			}
		}
	}
	return mapping.Dependencies, nil
}

// scanSources parses package, imports, class name, capitalized type identifiers
// and reflection markers. Source text is not retained after each file.
func scanSources(ctx context.Context, snapshot *project.Snapshot, hashes map[string]string) ([]*sourceFile, int, int, []string) {
	var files []string
	for _, entry := range snapshot.Manifest().Entries {
		if path.Ext(entry.Path) == ".java" {
			files = append(files, entry.Path)
		}
	}
	sort.Strings(files)
	if len(files) > MaxJavaFiles {
		return nil, 0, len(files), []string{"java_file_limit_exceeded"}
	}
	sources := make([]*sourceFile, 0, len(files))
	scanned, rejected := 0, 0
	var limitations []string
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			break
		}
		data, err := snapshot.ReadFile(ctx, file)
		if err != nil {
			return nil, 0, 0, []string{"snapshot_read_failed"}
		}
		if len(data) == 0 || len(data) > MaxJavaBytes || !utf8.Valid(data) {
			rejected++
			limitations = append(limitations, "rejected_java:"+file)
			continue
		}
		scanned++
		sources = append(sources, parseSource(file, string(data), hashes[file]))
	}
	return sources, scanned, rejected, dedupe(limitations)
}

func parseSource(file, source, digest string) *sourceFile {
	parsed := &sourceFile{path: file, sha256: digest, types: map[string]bool{}}
	lines := strings.Split(source, "\n")
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}
		if parsed.pkg == "" && strings.HasPrefix(trimmed, "package ") {
			parsed.pkg = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(trimmed, "package ")), ";")
		}
		if parsed.class == "" {
			if match := classPattern.FindStringSubmatch(trimmed); match != nil {
				parsed.class = match[1]
				parsed.line = index + 1
			}
		}
		if strings.HasPrefix(trimmed, "import ") {
			parsed.imports = append(parsed.imports, parseImportLine(file, index+1, trimmed)...)
		}
		if target := reflectiveTarget.FindStringSubmatch(trimmed); target != nil {
			parsed.reflective = true
			if len(parsed.reflectiveTargets) < MaxReflectiveHits {
				parsed.reflectiveTargets = append(parsed.reflectiveTargets, target[1])
			}
			continue
		}
		if reflectiveMarker.MatchString(trimmed) {
			parsed.reflective = true
		}
		if len(parsed.types) < MaxTypesPerFile {
			for _, token := range identifierPattern.FindAllString(trimmed, -1) {
				if token[0] >= 'A' && token[0] <= 'Z' {
					parsed.types[token] = true
					if len(parsed.types) >= MaxTypesPerFile {
						break
					}
				}
			}
		}
	}
	return parsed
}

func parseImportLine(file string, line int, trimmed string) []importRecord {
	value := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(trimmed, "import ")), ";")
	value = strings.TrimPrefix(value, "static ")
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "*") {
		return nil
	}
	return []importRecord{{file: file, line: line, name: value}}
}

func buildGraph(sources []*sourceFile) *graph {
	g := &graph{
		files:     make(map[string]*sourceFile, len(sources)),
		byFQCN:    make(map[string]string, len(sources)),
		byPackage: make(map[string][]string),
		edges:     make(map[string][]edge, len(sources)),
	}
	for _, file := range sources {
		if file.class == "" {
			continue
		}
		g.files[file.path] = file
		fqcn := file.class
		if file.pkg != "" {
			fqcn = file.pkg + "." + file.class
		}
		if _, exists := g.byFQCN[fqcn]; !exists {
			g.byFQCN[fqcn] = file.path
		}
		g.byPackage[file.pkg] = append(g.byPackage[file.pkg], file.path)
	}
	for _, file := range g.files {
		seen := map[string]bool{}
		add := func(target, relation string) {
			if target == "" || target == file.path || seen[target] {
				return
			}
			if g.edgeTotal >= MaxGraphEdges {
				g.limited = true
				return
			}
			seen[target] = true
			g.edgeTotal++
			g.edges[file.path] = append(g.edges[file.path], edge{file: target, relation: relation})
		}
		for _, item := range file.imports {
			add(g.byFQCN[item.name], "import")
		}
		for _, other := range g.byPackage[file.pkg] {
			if other == file.path {
				continue
			}
			peer := g.files[other]
			if peer != nil && file.types[peer.class] {
				add(other, "same_package")
			}
		}
	}
	for file := range g.edges {
		sort.Slice(g.edges[file], func(i, j int) bool {
			if g.edges[file][i].file != g.edges[file][j].file {
				return g.edges[file][i].file < g.edges[file][j].file
			}
			return g.edges[file][i].relation < g.edges[file][j].relation
		})
	}
	return g
}

func entrypointsFrom(report audit.Report) []Entrypoint {
	entries := make([]Entrypoint, 0, len(report.Endpoints))
	for _, endpoint := range report.Endpoints {
		entries = append(entries, Entrypoint{
			Path: endpoint.Path, HTTPMethods: append([]string{}, endpoint.HTTPMethods...),
			Symbol: endpoint.Symbol, File: endpoint.File, SHA256: endpoint.SHA256, Line: endpoint.StartLine,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].File != entries[j].File {
			return entries[i].File < entries[j].File
		}
		if entries[i].Line != entries[j].Line {
			return entries[i].Line < entries[j].Line
		}
		return entries[i].Symbol < entries[j].Symbol
	})
	if len(entries) > MaxGraphNodes {
		entries = entries[:MaxGraphNodes]
	}
	return entries
}

func moduleDirectories(report sca.Report) []string {
	dirs := make([]string, 0, len(report.Modules))
	for _, module := range report.Modules {
		if module.Directory == "" {
			continue
		}
		dirs = append(dirs, module.Directory)
	}
	sort.Slice(dirs, func(i, j int) bool {
		if len(dirs[i]) != len(dirs[j]) {
			return len(dirs[i]) > len(dirs[j])
		}
		return dirs[i] < dirs[j]
	})
	return dirs
}

func moduleOf(file string, dirs []string) string {
	for _, dir := range dirs {
		if dir == "." || file == dir || strings.HasPrefix(file, dir+"/") {
			return dir
		}
	}
	return "."
}

func traverseEntries(g *graph, entries []Entrypoint, dirs []string) *traversal {
	result := &traversal{
		reachable:       map[string]bool{},
		reflectiveFiles: map[string]bool{},
		fileModules:     map[string]string{},
		entriesPerMod:   map[string]int{},
	}
	for _, entry := range entries {
		module := moduleOf(entry.File, dirs)
		result.entriesPerMod[module]++
		if g.files[entry.File] == nil {
			result.entryUnresolved = true
			continue
		}
		bfs(g, entry, module, result)
	}
	return result
}

func bfs(g *graph, entry Entrypoint, module string, result *traversal) {
	start := g.files[entry.File]
	if start == nil {
		return
	}
	predecessor := map[string]string{}
	relation := map[string]string{}
	depth := map[string]int{entry.File: 0}
	queue := []string{entry.File}
	visited := map[string]bool{entry.File: true}
	expanded := 0
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if expanded >= MaxGraphNodes {
			result.limitExceeded = true
			break
		}
		expanded++
		result.reachable[current] = true
		result.fileModules[current] = module
		file := g.files[current]
		if file == nil {
			continue
		}
		if file.reflective {
			result.reflectiveFiles[current] = true
		}
		for _, item := range file.imports {
			if len(result.hits) >= MaxHits {
				result.limitExceeded = true
				break
			}
			result.hits = append(result.hits, pathHit{
				module: module,
				entry:  entry,
				steps:  stepsFor(g, entry.File, current, predecessor, relation),
				imp:    ImportRef{File: item.file, Line: item.line, Import: item.name},
			})
		}
		if depth[current] >= MaxPathDepth {
			continue
		}
		for _, next := range g.edges[current] {
			if visited[next.file] {
				continue
			}
			visited[next.file] = true
			predecessor[next.file] = current
			relation[next.file] = next.relation
			depth[next.file] = depth[current] + 1
			queue = append(queue, next.file)
		}
	}
}

func stepsFor(g *graph, start, current string, predecessor map[string]string, relation map[string]string) []Step {
	chain := []string{current}
	for node := current; node != start; {
		parent, ok := predecessor[node]
		if !ok {
			break
		}
		chain = append([]string{parent}, chain...)
		node = parent
	}
	steps := make([]Step, 0, len(chain))
	for index, file := range chain {
		source := g.files[file]
		if source == nil {
			continue
		}
		step := Step{Class: source.class, File: source.path, SHA256: source.sha256, Line: source.line, Relation: relation[file]}
		if index == 0 {
			step.Relation = "entry"
		}
		steps = append(steps, step)
	}
	return steps
}

func pathsForModule(hits []pathHit, module string, prefixes []string) []Path {
	paths := []Path{}
	for _, hit := range hits {
		if hit.module != module || !matchesPrefix(hit.imp.Import, prefixes) {
			continue
		}
		paths = append(paths, Path{Entry: hit.entry, Steps: hit.steps, Import: hit.imp})
		if len(paths) >= MaxPathsPerDep {
			break
		}
	}
	return paths
}

func uniqueImports(paths []Path) []ImportRef {
	imports := make([]ImportRef, 0, len(paths))
	seen := map[string]bool{}
	for _, item := range paths {
		key := item.Import.File + "\x00" + item.Import.Import
		if seen[key] {
			continue
		}
		seen[key] = true
		imports = append(imports, item.Import)
		if len(imports) >= MaxImportMatches {
			break
		}
	}
	return imports
}

func reflectionForModule(files map[string]bool, g *graph, fileModules map[string]string, module string, prefixes []string) bool {
	for file := range files {
		if fileModules[file] != module {
			continue
		}
		source := g.files[file]
		if source == nil {
			continue
		}
		for _, target := range source.reflectiveTargets {
			if matchesPrefix(target, prefixes) {
				return true
			}
		}
	}
	return false
}

func matchesPrefix(name string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if name == prefix || strings.HasPrefix(name, prefix+".") {
			return true
		}
	}
	return false
}

func dedupe(values []string) []string {
	result := values[:0]
	sort.Strings(values)
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
