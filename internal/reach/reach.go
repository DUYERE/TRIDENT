// Package reach builds a bounded import graph over a pinned snapshot and
// compares it with declared dependencies using a caller-supplied package map.
// Import presence is not call reachability and does not prove classpath load.
package reach

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"trident/internal/project"
	"trident/internal/sca"
)

const (
	SchemaVersion      = 1
	ToolVersion        = "0.2.0-p0.2+r2-import-reachability-v1"
	MaxJavaFiles       = 2000
	MaxJavaBytes       = 2 << 20
	MaxPackageMapBytes = 64 << 10
	MaxMappingEntries  = 256
	MaxPrefixes        = 64
	MaxImportMatches   = 20
)

type Options struct {
	PackageMapPath string
}

type Report struct {
	SchemaVersion int            `json:"schema_version"`
	ToolVersion   string         `json:"tool_version"`
	SnapshotHash  string         `json:"snapshot_hash"`
	AnalysisKind  string         `json:"analysis_kind"`
	Partial       bool           `json:"partial"`
	Dependencies  []Reachability `json:"dependencies"`
	Coverage      Coverage       `json:"coverage"`
	Limitations   []string       `json:"limitations"`
	RuntimeStatus string         `json:"runtime_status"`
}

type Reachability struct {
	Module         string      `json:"module"`
	Dependency     string      `json:"dependency"`
	Version        string      `json:"version,omitempty"`
	VersionStatus  string      `json:"version_status"`
	Classification string      `json:"classification"`
	Reason         string      `json:"reason,omitempty"`
	MappedPrefixes []string    `json:"mapped_prefixes,omitempty"`
	MatchedImports []ImportRef `json:"matched_imports,omitempty"`
	RuntimeStatus  string      `json:"runtime_status"`
}

type ImportRef struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Import string `json:"import"`
}

type Coverage struct {
	JavaFilesScanned  int    `json:"java_files_scanned"`
	JavaFilesRejected int    `json:"java_files_rejected"`
	ImportsParsed     int    `json:"imports_parsed"`
	Dependencies      int    `json:"dependencies"`
	ImportReachable   int    `json:"import_reachable"`
	ImportNotObserved int    `json:"import_not_observed"`
	Unverified        int    `json:"unverified"`
	RuntimeStatus     string `json:"runtime_status"`
}

type packageMap struct {
	SchemaVersion int                 `json:"schema_version"`
	Dependencies  map[string][]string `json:"dependencies"`
}

func Inspect(ctx context.Context, snapshot *project.Snapshot, opts Options) (Report, error) {
	if snapshot == nil || snapshot.Hash() == "" {
		return Report{}, fmt.Errorf("pinned snapshot required")
	}
	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   ToolVersion,
		SnapshotHash:  snapshot.Hash(),
		AnalysisKind:  "import_graph_reachability",
		Dependencies:  []Reachability{},
		Coverage:      Coverage{RuntimeStatus: "not_run"},
		RuntimeStatus: "not_run",
		Limitations: []string{
			"import_presence_is_not_call_reachability: an imported package does not prove a vulnerable class or method is loaded or invoked",
			"package_map_is_caller_configuration: dependencies without an explicit mapping stay unverified",
			"classpath_not_resolved: declared versions are not verified against an effective dependency tree",
			"runtime_status_not_run: no deployed target or runtime exploit test is executed",
		},
	}
	mapping, err := loadPackageMap(opts.PackageMapPath)
	if err != nil {
		return Report{}, err
	}
	if mapping == nil {
		report.Limitations = append(report.Limitations, "package_map_not_configured: all dependencies stay unverified")
	}
	imports, scanned, rejected, parseLimitations := parseImports(ctx, snapshot)
	report.Coverage.JavaFilesScanned = scanned
	report.Coverage.JavaFilesRejected = rejected
	report.Coverage.ImportsParsed = len(imports)
	report.Partial = rejected > 0 || len(parseLimitations) > 0
	report.Limitations = append(report.Limitations, parseLimitations...)

	scaReport, err := sca.Inspect(ctx, snapshot, sca.Options{})
	if err != nil {
		return Report{}, err
	}
	report.Partial = report.Partial || scaReport.Partial
	for _, dependency := range scaReport.Dependencies {
		item := Reachability{
			Module: dependency.Module, Dependency: dependency.GroupID + ":" + dependency.ArtifactID,
			Version: dependency.Version, VersionStatus: dependency.VersionStatus, RuntimeStatus: "not_run",
		}
		if mapping == nil {
			item.Classification = "unverified"
			item.Reason = "package_mapping_missing"
			report.Coverage.Unverified++
			report.Dependencies = append(report.Dependencies, item)
			continue
		}
		prefixes := mapping[item.Dependency]
		if len(prefixes) == 0 {
			item.Classification = "unverified"
			item.Reason = "package_mapping_missing"
			report.Coverage.Unverified++
			report.Dependencies = append(report.Dependencies, item)
			continue
		}
		item.MappedPrefixes = append([]string{}, prefixes...)
		matches := matchImports(imports, prefixes)
		if len(matches) == 0 {
			item.Classification = "import_not_observed"
			item.Reason = "no_matching_import"
			report.Coverage.ImportNotObserved++
		} else {
			item.Classification = "import_reachable"
			item.Reason = "import_prefix_matched"
			item.MatchedImports = matches
			report.Coverage.ImportReachable++
		}
		report.Dependencies = append(report.Dependencies, item)
	}
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

type importRecord struct {
	file string
	line int
	name string
}

func parseImports(ctx context.Context, snapshot *project.Snapshot) ([]importRecord, int, int, []string) {
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
	var imports []importRecord
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
		imports = append(imports, parseImportLines(file, string(data))...)
	}
	return imports, scanned, rejected, dedupe(limitations)
}

func parseImportLines(file, source string) []importRecord {
	var records []importRecord
	for index, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "import ") {
			continue
		}
		trimmed = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(trimmed, "import ")), ";")
		trimmed = strings.TrimPrefix(trimmed, "static ")
		trimmed = strings.TrimSpace(trimmed)
		if trimmed == "" || strings.Contains(trimmed, "*") {
			continue
		}
		records = append(records, importRecord{file: file, line: index + 1, name: trimmed})
	}
	return records
}

func matchImports(imports []importRecord, prefixes []string) []ImportRef {
	var matches []ImportRef
	for _, item := range imports {
		for _, prefix := range prefixes {
			if item.name == prefix || strings.HasPrefix(item.name, prefix+".") {
				matches = append(matches, ImportRef{File: item.file, Line: item.line, Import: item.name})
				break
			}
		}
		if len(matches) >= MaxImportMatches {
			break
		}
	}
	return matches
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
