package sca

import (
	"bufio"
	"context"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"

	"trident/internal/project"
)

const (
	MaxManifestFiles        = 2048
	MaxManifestBytes        = 2 << 20
	MaxManifestDependencies = 20000
)

type ecosystemManifest struct {
	path      string
	ecosystem string
	kind      string
}

var (
	requirementsLine    = regexp.MustCompile(`^\s*([A-Za-z0-9_.@/-]+)(?:\[[^\]]*\])?\s*([<>=!~^].*)?$`)
	pyprojectDependency = regexp.MustCompile(`(?m)^\s*["']([A-Za-z0-9_.-]+)\s*([<>=!~^].*)["']\s*,?\s*$`)
	csprojPackageRef    = regexp.MustCompile(`(?is)<PackageReference\b[^>]*\bInclude\s*=\s*["']([^"']+)["'][^>]*\bVersion\s*=\s*["']([^"']+)["'][^>]*/?>`)
	packagesConfig      = regexp.MustCompile(`(?is)<package\b[^>]*\bid\s*=\s*["']([^"']+)["'][^>]*\bversion\s*=\s*["']([^"']+)["'][^>]*/?>`)
	goModRequireSingle  = regexp.MustCompile(`(?m)^\s*require\s+([^\s]+)\s+([^\s]+)`)
	goModRequireLine    = regexp.MustCompile(`^\s*([^\s]+)\s+(v[^\s]+)`)
)

func inspectEcosystems(ctx context.Context, snapshot *project.Snapshot) ([]Dependency, []Manifest, Coverage, []string, bool) {
	coverage := Coverage{}
	if snapshot == nil {
		return nil, nil, coverage, nil, false
	}
	var files []ecosystemManifest
	for _, entry := range snapshot.Manifest().Entries {
		if isEcosystemExcluded(entry.Path) {
			continue
		}
		kind, ecosystem := ecosystemFor(path.Base(strings.ToLower(entry.Path)))
		if kind == "" {
			continue
		}
		files = append(files, ecosystemManifest{path: entry.Path, ecosystem: ecosystem, kind: kind})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	if len(files) == 0 {
		return nil, nil, coverage, []string{"no_npm_composer_nuget_pip_go_manifest_found"}, false
	}
	if len(files) > MaxManifestFiles {
		coverage.ManifestFilesRejected += len(files) - MaxManifestFiles
		files = files[:MaxManifestFiles]
	}
	exact := map[string]string{}
	// Lock files are read first so a declared range can use an exact version
	// from the same pinned snapshot without pretending to resolve anything.
	for _, file := range files {
		if !isLockManifest(file.kind) {
			continue
		}
		data, err := snapshot.ReadFile(ctx, file.path)
		if err != nil || len(data) == 0 || len(data) > MaxManifestBytes {
			coverage.ManifestFilesRejected++
			continue
		}
		loadLockVersions(file, data, exact)
	}
	dependencies := []Dependency{}
	manifests := []Manifest{}
	partial := false
	for _, file := range files {
		if isLockManifest(file.kind) {
			manifests = append(manifests, Manifest{Path: file.path, Ecosystem: file.ecosystem, Kind: "lockfile", Status: "version_source"})
			continue
		}
		data, err := snapshot.ReadFile(ctx, file.path)
		if err != nil || len(data) == 0 || len(data) > MaxManifestBytes {
			coverage.ManifestFilesRejected++
			partial = true
			continue
		}
		deps, reason := parseEcosystemManifest(file, data, exact)
		if reason != "" {
			partial = true
		}
		coverage.ManifestFilesScanned++
		if len(dependencies)+len(deps) > MaxManifestDependencies {
			deps = deps[:MaxManifestDependencies-len(dependencies)]
			partial = true
		}
		dependencies = append(dependencies, deps...)
		manifests = append(manifests, Manifest{Path: file.path, Ecosystem: file.ecosystem, Kind: file.kind, Dependencies: len(deps), Status: "declared", Reason: reason})
	}
	coverage.ManifestDependencies = len(dependencies)
	dependencies = dedupeEcosystemDependencies(dependencies)
	limitations := []string{
		"ecosystem_resolution_not_executed: npm/composer/nuget/pip/go manifests and locked files are parsed locally; no package manager, registry or transitive graph is executed",
	}
	if coverage.ManifestFilesRejected > 0 {
		limitations = append(limitations, "ecosystem_manifest_rejected: empty, oversized or unreadable manifest files were skipped")
	}
	sort.Strings(limitations)
	return dependencies, manifests, coverage, limitations, partial
}

func isEcosystemExcluded(file string) bool {
	lower := "/" + strings.ToLower(strings.ReplaceAll(file, "\\", "/")) + "/"
	return strings.Contains(lower, "/node_modules/") || strings.Contains(lower, "/vendor/") ||
		strings.Contains(lower, "/.git/") || strings.Contains(lower, "/dist/") || strings.Contains(lower, "/bin/")
}

func ecosystemFor(base string) (kind, ecosystem string) {
	switch base {
	case "package.json":
		return "npm_manifest", "npm"
	case "package-lock.json", "npm-shrinkwrap.json":
		return "npm_lock", "npm"
	case "composer.json":
		return "composer_manifest", "composer"
	case "composer.lock":
		return "composer_lock", "composer"
	case "requirements.txt", "requirements-dev.txt", "requirements-prod.txt", "constraints.txt":
		return "pip_requirements", "pip"
	case "pyproject.toml", "pipfile":
		return "python_manifest", "pip"
	case "go.mod":
		return "go_mod", "go"
	case "packages.config":
		return "nuget_packages_config", "nuget"
	case "packages.lock.json":
		return "nuget_lock", "nuget"
	}
	if strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".fsproj") || strings.HasSuffix(base, ".vbproj") {
		return "nuget_project", "nuget"
	}
	return "", ""
}

func isLockManifest(kind string) bool {
	return kind == "npm_lock" || kind == "composer_lock" || kind == "nuget_lock"
}

func loadLockVersions(file ecosystemManifest, data []byte, exact map[string]string) {
	switch file.kind {
	case "npm_lock":
		var lock struct {
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
			Dependencies map[string]struct {
				Version string `json:"version"`
			} `json:"dependencies"`
		}
		if json.Unmarshal(data, &lock) != nil {
			return
		}
		for name, item := range lock.Packages {
			name = strings.TrimPrefix(name, "node_modules/")
			if index := strings.LastIndex(name, "node_modules/"); index >= 0 {
				name = name[index+len("node_modules/"):]
			}
			if name != "" && item.Version != "" {
				exact["npm\x00"+name] = item.Version
			}
		}
		for name, item := range lock.Dependencies {
			if name != "" && item.Version != "" {
				exact["npm\x00"+name] = item.Version
			}
		}
	case "composer_lock":
		var lock struct {
			Packages    []struct{ Name, Version string } `json:"packages"`
			PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
		}
		if json.Unmarshal(data, &lock) != nil {
			return
		}
		for _, item := range append(append([]struct{ Name, Version string }{}, lock.Packages...), lock.PackagesDev...) {
			if item.Name != "" && item.Version != "" {
				exact["composer\x00"+item.Name] = strings.TrimPrefix(item.Version, "v")
			}
		}
	case "nuget_lock":
		loadNuGetLock(data, exact)
	}
}

func loadNuGetLock(data []byte, exact map[string]string) {
	var lock map[string]any
	if json.Unmarshal(data, &lock) != nil {
		return
	}
	var walk func(any)
	walk = func(node any) {
		switch value := node.(type) {
		case map[string]any:
			for name, child := range value {
				if item, ok := child.(map[string]any); ok {
					if version, ok := item["resolved"].(string); ok && version != "" {
						exact["nuget\x00"+name] = version
					}
					if version, ok := item["version"].(string); ok && version != "" && isExactVersion(version) {
						exact["nuget\x00"+name] = version
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range value {
				walk(child)
			}
		}
	}
	walk(lock)
}

func parseEcosystemManifest(file ecosystemManifest, data []byte, exact map[string]string) ([]Dependency, string) {
	switch file.kind {
	case "npm_manifest":
		return parseNPM(file, data, exact)
	case "composer_manifest":
		return parseComposer(file, data, exact)
	case "pip_requirements":
		return parseRequirements(file, data)
	case "python_manifest":
		return parsePythonManifest(file, data)
	case "go_mod":
		return parseGoMod(file, data)
	case "nuget_project":
		return parseNuGetProject(file, data)
	case "nuget_packages_config":
		return parseNuGetPackagesConfig(file, data)
	}
	return nil, ""
}

func parseNPM(file ecosystemManifest, data []byte, exact map[string]string) ([]Dependency, string) {
	var manifest struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, "invalid_npm_package_json"
	}
	var deps []Dependency
	appendGroup := func(values map[string]string, scope string, optional bool) {
		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			declared := strings.TrimSpace(values[name])
			version, status, reason := lockResolve("npm", name, declared, exact)
			deps = append(deps, newEcosystemDependency(file, "npm", name, version, scope, "npm", optional, status, reason))
		}
	}
	appendGroup(manifest.Dependencies, "runtime", false)
	appendGroup(manifest.DevDependencies, "dev", false)
	appendGroup(manifest.OptionalDependencies, "optional", true)
	return deps, ""
}

func parseComposer(file ecosystemManifest, data []byte, exact map[string]string) ([]Dependency, string) {
	var manifest struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, "invalid_composer_json"
	}
	var deps []Dependency
	appendGroup := func(values map[string]string, scope string) {
		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if strings.EqualFold(name, "php") || strings.HasPrefix(strings.ToLower(name), "ext-") || strings.HasPrefix(strings.ToLower(name), "lib-") {
				continue
			}
			declared := strings.TrimSpace(values[name])
			version, status, reason := lockResolve("composer", name, declared, exact)
			deps = append(deps, newEcosystemDependency(file, "composer", name, version, scope, "composer", false, status, reason))
		}
	}
	appendGroup(manifest.Require, "runtime")
	appendGroup(manifest.RequireDev, "dev")
	return deps, ""
}

func parseRequirements(file ecosystemManifest, data []byte) ([]Dependency, string) {
	var deps []Dependency
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024), 64<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			continue
		}
		match := requirementsLine.FindStringSubmatch(line)
		if len(match) < 2 || match[1] == "" {
			continue
		}
		name := match[1]
		if index := strings.Index(name, "["); index >= 0 {
			name = name[:index]
		}
		declared := strings.TrimSpace(match[2])
		version, status, reason := declaredVersion(declared)
		deps = append(deps, newEcosystemDependency(file, "pip", name, version, "runtime", "python", false, status, reason))
	}
	return deps, ""
}

func parsePythonManifest(file ecosystemManifest, data []byte) ([]Dependency, string) {
	var deps []Dependency
	if strings.EqualFold(path.Base(file.path), "pyproject.toml") {
		for _, match := range pyprojectDependency.FindAllStringSubmatch(string(data), MaxManifestDependencies) {
			if len(match) < 2 || match[1] == "" {
				continue
			}
			version, status, reason := declaredVersion(strings.TrimSpace(match[2]))
			deps = append(deps, newEcosystemDependency(file, "pip", match[1], version, "runtime", "python", false, status, reason))
		}
		return deps, ""
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(strings.ToLower(line), "package") || strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			name := strings.Trim(strings.TrimSpace(parts[0]), "\"'")
			declared := ""
			if len(parts) == 2 {
				declared = strings.Trim(strings.TrimSpace(parts[1]), "\"'")
			}
			if name != "" {
				version, status, reason := declaredVersion(declared)
				deps = append(deps, newEcosystemDependency(file, "pip", name, version, "runtime", "python", false, status, reason))
			}
		}
	}
	return deps, ""
}

func parseGoMod(file ecosystemManifest, data []byte) ([]Dependency, string) {
	var deps []Dependency
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inRequire := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "require (") || line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "//") || line == "" {
			continue
		}
		var name, version string
		if inRequire {
			match := goModRequireLine.FindStringSubmatch(line)
			if len(match) < 3 {
				continue
			}
			name, version = match[1], match[2]
		} else if match := goModRequireSingle.FindStringSubmatch(line); len(match) >= 3 {
			name, version = match[1], match[2]
		} else {
			continue
		}
		if strings.HasPrefix(version, "v") {
			version = version[1:]
		}
		deps = append(deps, newEcosystemDependency(file, "go", name, version, "runtime", "go", false, "resolved", "go_mod_require"))
	}
	return deps, ""
}

func parseNuGetProject(file ecosystemManifest, data []byte) ([]Dependency, string) {
	var deps []Dependency
	for _, match := range csprojPackageRef.FindAllStringSubmatch(string(data), MaxManifestDependencies) {
		if len(match) < 3 {
			continue
		}
		version := strings.TrimSpace(match[2])
		status, reason := "resolved", "csproj_package_reference"
		if !isExactVersion(version) {
			status, reason = "range", "declared_range"
		}
		deps = append(deps, newEcosystemDependency(file, "nuget", match[1], version, "runtime", "nuget", false, status, reason))
	}
	return deps, ""
}

func parseNuGetPackagesConfig(file ecosystemManifest, data []byte) ([]Dependency, string) {
	var deps []Dependency
	for _, match := range packagesConfig.FindAllStringSubmatch(string(data), MaxManifestDependencies) {
		if len(match) < 3 {
			continue
		}
		deps = append(deps, newEcosystemDependency(file, "nuget", match[1], match[2], "runtime", "nuget", false, "resolved", "packages_config"))
	}
	return deps, ""
}

func newEcosystemDependency(file ecosystemManifest, ecosystem, name, version, scope, typ string, optional bool, status, reason string) Dependency {
	group, artifact := ecosystemGroupArtifact(ecosystem, name)
	if version == "" {
		status = "missing"
		if reason == "" {
			reason = "version_not_declared"
		}
	}
	return Dependency{
		Module: path.Dir(file.path), Ecosystem: ecosystem, Name: name,
		GroupID: group, ArtifactID: artifact, Version: version, Scope: scope, Type: typ,
		Optional: optional, Direct: true, DeclarationPOM: file.path, Manifest: file.path,
		VersionStatus: status, VersionReason: reason,
	}
}

func ecosystemGroupArtifact(ecosystem, name string) (string, string) {
	name = strings.TrimSpace(name)
	switch ecosystem {
	case "composer":
		if index := strings.Index(name, "/"); index > 0 {
			return name[:index], name[index+1:]
		}
	case "npm":
		if strings.HasPrefix(name, "@") {
			if index := strings.Index(name, "/"); index > 0 {
				return name[:index], name[index+1:]
			}
		}
	case "go":
		if index := strings.LastIndex(name, "/"); index > 0 {
			return name[:index], name[index+1:]
		}
	}
	return "", name
}

func lockResolve(ecosystem, name, declared string, exact map[string]string) (string, string, string) {
	if locked, ok := exact[ecosystem+"\x00"+name]; ok && locked != "" {
		return locked, "resolved", "lockfile_exact"
	}
	return declaredVersion(declared)
}

func declaredVersion(declared string) (string, string, string) {
	declared = strings.TrimSpace(declared)
	if declared == "" || declared == "*" || declared == "latest" {
		return "", "missing", "version_not_declared"
	}
	if strings.HasPrefix(declared, "==") {
		declared = strings.TrimSpace(strings.TrimPrefix(declared, "=="))
		if isExactVersion(declared) {
			return declared, "resolved", "exact_declared"
		}
	}
	if isExactVersion(declared) {
		return strings.TrimPrefix(declared, "v"), "resolved", "exact_declared"
	}
	return declared, "range", "declared_range"
}

func isExactVersion(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" || strings.ContainsAny(version, "^~*<>=|, ") {
		return false
	}
	return true
}

func dedupeEcosystemDependencies(deps []Dependency) []Dependency {
	seen := map[string]bool{}
	out := make([]Dependency, 0, len(deps))
	for _, dep := range deps {
		key := dep.Module + "\x00" + dep.Ecosystem + "\x00" + dep.Name + "\x00" + dep.Version + "\x00" + dep.Scope
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, dep)
	}
	return out
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
