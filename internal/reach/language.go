package reach

import (
	"context"
	"path"
	"regexp"
	"sort"
	"strings"

	"trident/internal/project"
	"trident/internal/sca"
)

const (
	MaxLanguageReachFiles = 3000
	MaxLanguageReachBytes = 2 << 20
)

type languageImport struct {
	file string
	line int
	raw  string
}

type languageImportPattern struct {
	language string
	re       *regexp.Regexp
	group    int
}

var languageImportPatterns = []languageImportPattern{
	{language: "php", re: regexp.MustCompile(`(?m)^\s*use\s+([A-Za-z0-9_\\]+)`), group: 1},
	{language: "php", re: regexp.MustCompile(`(?i)(?:require|include)(?:_once)?\s*\(?\s*["']([^"']+)["']`), group: 1},
	{language: "csharp", re: regexp.MustCompile(`(?m)^\s*using\s+([A-Za-z0-9_.]+)\s*;`), group: 1},
	{language: "python", re: regexp.MustCompile(`(?m)^\s*from\s+([A-Za-z0-9_.]+)\s+import`), group: 1},
	{language: "python", re: regexp.MustCompile(`(?m)^\s*import\s+([A-Za-z0-9_.]+)`), group: 1},
	{language: "javascript", re: regexp.MustCompile(`(?i)(?:require\s*\(\s*["']([^"']+)["']|from\s+["']([^"']+)["']|import\s*\(\s*["']([^"']+)["'])`), group: 1},
	{language: "typescript", re: regexp.MustCompile(`(?i)(?:require\s*\(\s*["']([^"']+)["']|from\s+["']([^"']+)["']|import\s*\(\s*["']([^"']+)["'])`), group: 1},
	{language: "go", re: regexp.MustCompile(`(?m)^\s*(?:import\s+)?["]([^"]+)["]`), group: 1},
}

var languageEntryPatterns = []languageImportPattern{
	{language: "php", re: regexp.MustCompile(`(?i)(Route::|->rule\(|public\s+function\s+\w+\s*\()`), group: 0},
	{language: "csharp", re: regexp.MustCompile(`(?i)(\[(?:HttpGet|HttpPost|Route)|Map(?:Get|Post)|ApiController)`), group: 0},
	{language: "python", re: regexp.MustCompile(`(?i)(@(?:app|router)\.(get|post|route)|urlpatterns|path\s*\()`), group: 0},
	{language: "javascript", re: regexp.MustCompile(`(?i)(router\.(get|post|put|delete)|app\.(get|post|put|delete)|@(Get|Post|Controller))`), group: 0},
	{language: "typescript", re: regexp.MustCompile(`(?i)(router\.(get|post|put|delete)|app\.(get|post|put|delete)|@(Get|Post|Controller))`), group: 0},
	{language: "go", re: regexp.MustCompile(`(?i)(HandleFunc|\.GET\s*\(|\.POST\s*\(|gin\.Context|echo\.Context)`), group: 0},
}

func analyzeLanguageReach(ctx context.Context, snapshot *project.Snapshot, dependencies []sca.Dependency) ([]Reachability, Coverage, []string, bool) {
	coverage := Coverage{}
	if snapshot == nil {
		return nil, coverage, nil, false
	}
	var languageDeps []sca.Dependency
	for _, dependency := range dependencies {
		if dependency.Ecosystem != "" && dependency.Name != "" {
			languageDeps = append(languageDeps, dependency)
		}
	}
	if len(languageDeps) == 0 {
		return nil, coverage, nil, false
	}
	var files []project.FileEntry
	for _, entry := range snapshot.Manifest().Entries {
		language := languageFromPath(entry.Path)
		if language == "" || language == "java" || excludedReachPath(entry.Path) {
			continue
		}
		files = append(files, entry)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	if len(files) > MaxLanguageReachFiles {
		coverage.LanguageFilesRejected += len(files) - MaxLanguageReachFiles
		files = files[:MaxLanguageReachFiles]
	}
	imports := make([]languageImport, 0, 512)
	entryFiles := map[string]bool{}
	for _, entry := range files {
		data, err := snapshot.ReadFile(ctx, entry.Path)
		if err != nil || len(data) == 0 || len(data) > MaxLanguageReachBytes {
			coverage.LanguageFilesRejected++
			continue
		}
		coverage.LanguageFilesScanned++
		content := string(data)
		language := languageFromPath(entry.Path)
		if languageHasEntry(language, content) {
			entryFiles[entry.Path] = true
		}
		for _, pattern := range languageImportPatterns {
			if pattern.language != language {
				continue
			}
			for _, match := range pattern.re.FindAllStringSubmatchIndex(content, 500) {
				group := -1
				for candidate := pattern.group; candidate*2+1 < len(match); candidate++ {
					if match[candidate*2] >= 0 {
						group = candidate
						break
					}
				}
				if group < 0 {
					continue
				}
				raw := content[match[group*2]:match[group*2+1]]
				line := 1 + strings.Count(content[:match[0]], "\n")
				imports = append(imports, languageImport{file: entry.Path, line: line, raw: raw})
				if len(imports) >= 20000 {
					break
				}
			}
		}
	}
	coverage.LanguageImports = len(imports)
	byLanguage := map[string]int{}
	for _, file := range files {
		byLanguage[languageFromPath(file.Path)]++
	}
	items := make([]Reachability, 0, len(languageDeps))
	partial := coverage.LanguageFilesRejected > 0
	for _, dependency := range languageDeps {
		item := Reachability{
			Module: dependency.Module, Dependency: dependency.Name, Language: languageForEcosystem(dependency.Ecosystem),
			Ecosystem: dependency.Ecosystem, Version: dependency.Version, VersionStatus: dependency.VersionStatus,
			RuntimeStatus: "not_run",
		}
		matched := matchLanguageImports(dependency, imports)
		if len(matched) == 0 {
			if byLanguage[item.Language] == 0 {
				item.Reachability = "unknown"
				item.Reason = "language_not_scanned"
				coverage.LanguageUnknown++
			} else {
				item.Reachability = "unreachable"
				item.Reason = "no_language_import_reference"
				coverage.LanguageUnreachable++
			}
			items = append(items, item)
			continue
		}
		item.MatchedImports = matched
		entryBound := false
		for _, ref := range matched {
			if entryFiles[ref.File] {
				entryBound = true
				break
			}
		}
		if entryBound {
			item.Reachability = "reachable"
			item.Reason = "language_entry_file_import"
			coverage.LanguageReachable++
		} else {
			item.Reachability = "unknown"
			item.Reason = "import_without_entrypoint_binding"
			coverage.LanguageUnknown++
		}
		item.Paths = languagePaths(matched)
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Module != items[j].Module {
			return items[i].Module < items[j].Module
		}
		return items[i].Dependency < items[j].Dependency
	})
	limitations := []string{
		"language_reachability_file_local: PHP/C#/Python/JS/Go imports are matched to declared packages by bounded string heuristics; route-to-controller binding, runtime includes and framework scanning are not resolved",
	}
	return items, coverage, limitations, partial
}

func languageFromPath(file string) string {
	switch strings.ToLower(path.Ext(file)) {
	case ".php":
		return "php"
	case ".cs":
		return "csharp"
	case ".py":
		return "python"
	case ".js", ".jsx":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".go":
		return "go"
	case ".java":
		return "java"
	default:
		return ""
	}
}

func languageForEcosystem(ecosystem string) string {
	switch ecosystem {
	case "composer":
		return "php"
	case "nuget":
		return "csharp"
	case "pip", "python":
		return "python"
	case "npm":
		return "javascript"
	case "go":
		return "go"
	default:
		return ecosystem
	}
}

func excludedReachPath(file string) bool {
	lower := "/" + strings.ToLower(strings.ReplaceAll(file, "\\", "/")) + "/"
	return strings.Contains(lower, "/node_modules/") || strings.Contains(lower, "/vendor/") ||
		strings.Contains(lower, "/dist/") || strings.Contains(lower, "/bin/") || strings.Contains(lower, "/obj/")
}

func languageHasEntry(language, content string) bool {
	for _, pattern := range languageEntryPatterns {
		if pattern.language == language && pattern.re.MatchString(content) {
			return true
		}
	}
	return false
}

func matchLanguageImports(dependency sca.Dependency, imports []languageImport) []ImportRef {
	var refs []ImportRef
	for _, candidate := range dependencyCandidates(dependency) {
		lowerCandidate := strings.ToLower(candidate)
		if lowerCandidate == "" {
			continue
		}
		for _, item := range imports {
			lowerImport := strings.ToLower(item.raw)
			if lowerImport == lowerCandidate || strings.HasPrefix(lowerImport, lowerCandidate+"/") || strings.HasPrefix(lowerImport, lowerCandidate+"\\") || strings.HasPrefix(lowerImport, lowerCandidate+".") {
				refs = append(refs, ImportRef{File: item.file, Line: item.line, Import: item.raw})
			}
		}
		if len(refs) >= MaxImportMatches {
			break
		}
	}
	return refs
}

func dependencyCandidates(dependency sca.Dependency) []string {
	name := dependency.Name
	if name == "" {
		name = dependency.ArtifactID
	}
	switch dependency.Ecosystem {
	case "npm":
		return []string{name}
	case "composer":
		parts := strings.Split(name, "/")
		var out []string
		if len(parts) > 0 {
			out = append(out, ucfirst(parts[0]))
			out = append(out, ucfirst(parts[0])+"\\")
		}
		if len(parts) > 1 {
			out = append(out, ucfirst(parts[0])+"\\"+ucfirst(parts[1]))
		}
		return out
	case "nuget":
		return []string{name, strings.Split(name, ".")[0]}
	case "pip", "python":
		return []string{name, strings.ReplaceAll(name, "-", "_")}
	case "go":
		return []string{name}
	default:
		return []string{name}
	}
}

func ucfirst(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func languagePaths(refs []ImportRef) []Path {
	paths := make([]Path, 0, len(refs))
	for _, ref := range refs {
		paths = append(paths, Path{
			Entry:  Entrypoint{File: ref.File, Symbol: "language_import", Line: ref.Line},
			Import: ref,
			Steps:  []Step{},
		})
	}
	return paths
}
