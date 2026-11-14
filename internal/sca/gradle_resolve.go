package sca

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"trident/internal/project"
)

const (
	MaxGradleOutputBytes        = 16 << 20
	MaxGradleModuleOutputBytes  = 8 << 20
	MaxGradleModules            = 64
	MaxGradleVersionOutputBytes = 16 << 10
)

var gradleConfigurationName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)

type GradleInfo struct {
	Version          string   `json:"version,omitempty"`
	Executed         bool     `json:"executed"`
	DurationMS       int64    `json:"duration_ms"`
	Offline          bool     `json:"offline"`
	Configurations   []string `json:"configurations,omitempty"`
	ModulesAttempted int      `json:"modules_attempted"`
	ModulesParsed    int      `json:"modules_parsed"`
}

// ResolveGradleEffectiveTree runs Gradle's dependency report on a disposable
// copy of the pinned snapshot. Gradle build scripts are executable input, so
// every invocation requires explicit approval and stays inside the copy.
func ResolveGradleEffectiveTree(ctx context.Context, snapshot *project.Snapshot, opts ResolveOptions) (ResolveReport, error) {
	report := ResolveReport{
		SchemaVersion:  SchemaVersion,
		ToolVersion:    ResolveToolVersion,
		AnalysisKind:   "gradle_effective_dependency_tree",
		ResolutionMode: "offline",
		Status:         "failed",
		Modules:        []ResolvedModule{},
		Coverage:       ResolveCoverage{EffectiveTree: "not_available", ArtifactHashes: "not_available", RuntimeStatus: "not_run"},
		RuntimeStatus:  "not_run",
		Gradle:         GradleInfo{Offline: true},
		Limitations: []string{
			"artifact_hashes_unavailable: module coordinates are not artifact bytes",
			"gradle_build_scripts_untrusted: build.gradle/settings.gradle are executable code; run only on a disposable copy",
			"gradle_configuration_selection: runtimeClasspath is preferred, then compileClasspath; other configurations are not counted",
			"gradle_dependency_report_not_runtime: resolved configuration metadata does not prove class loading, reachability or exploitability",
			"gradle_project_dependencies_are_local: project(...) edges describe the build, not external artifacts",
		},
	}
	if snapshot == nil || snapshot.Hash() == "" {
		return report, fmt.Errorf("pinned snapshot required")
	}
	report.SnapshotHash = snapshot.Hash()
	if !opts.ApproveGradle {
		return report, fmt.Errorf("Gradle execution requires explicit approval")
	}
	if opts.AllowNetwork {
		report.ResolutionMode = "online"
		report.Gradle.Offline = false
	}
	if opts.Timeout <= 0 || opts.Timeout > MaxResolveTimeoutS*time.Second {
		opts.Timeout = DefaultResolveTimeoutS * time.Second
	}
	if opts.GradleUserHome != "" {
		info, err := os.Stat(opts.GradleUserHome)
		if err != nil || !info.IsDir() || !filepath.IsAbs(opts.GradleUserHome) {
			return report, fmt.Errorf("gradle user home must be an absolute existing directory")
		}
	}
	if opts.GradleInitScript != "" {
		info, err := os.Stat(opts.GradleInitScript)
		if err != nil || !info.Mode().IsRegular() || !filepath.IsAbs(opts.GradleInitScript) {
			return report, fmt.Errorf("gradle init script must be an absolute existing file")
		}
	}
	declared, err := Inspect(ctx, snapshot, Options{})
	if err != nil {
		return report, err
	}
	var buildModules []Module
	for _, module := range declared.Modules {
		base := path.Base(module.POM)
		if base == "build.gradle" || base == "build.gradle.kts" {
			buildModules = append(buildModules, module)
		}
	}
	if len(buildModules) == 0 {
		report.Error = "no Gradle build file found; use --tool maven for Maven builds"
		report.Limitations = append(report.Limitations, "no_gradle_build_file")
		sort.Strings(report.Limitations)
		return report, fmt.Errorf("%s", report.Error)
	}
	if len(buildModules) > MaxGradleModules {
		return report, fmt.Errorf("%w: Gradle module count exceeds %d", ErrLimit, MaxGradleModules)
	}
	root, err := copySnapshotForBuildTool(ctx, snapshot)
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(root)

	gradlePath, err := resolveGradleExecutable(opts.GradlePath)
	if err != nil {
		report.Error = err.Error()
		return report, err
	}
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	report.Gradle.Version = gradleVersion(runCtx, gradlePath, root)

	started := time.Now()
	report.Gradle.Executed = true
	report.Gradle.ModulesAttempted = len(buildModules)
	configurations := map[string]bool{}
	var failures []string
	totalOutput := 0
	parsedModules := 0
	truncated := false
	for _, module := range buildModules {
		if err := runCtx.Err(); err != nil {
			report.Error = "gradle dependency resolution timed out or was cancelled"
			report.Partial = true
			report.Gradle.DurationMS = time.Since(started).Milliseconds()
			return report, err
		}
		moduleDir := filepath.Join(root, filepath.FromSlash(module.Directory))
		if info, statErr := os.Stat(moduleDir); statErr != nil || !info.IsDir() {
			failures = append(failures, module.POM+": module directory is missing")
			report.Partial = true
			continue
		}
		output := boundedBuffer{limit: MaxGradleModuleOutputBytes}
		args := []string{"--no-daemon", "--console=plain", "-q"}
		if !opts.AllowNetwork {
			args = append(args, "--offline")
		}
		if opts.GradleUserHome != "" {
			args = append(args, "-g", opts.GradleUserHome)
		}
		if opts.GradleInitScript != "" {
			args = append(args, "-I", opts.GradleInitScript)
		}
		args = append(args, "-p", moduleDir, "dependencies")
		command := exec.CommandContext(runCtx, gradlePath, args...)
		command.Dir = root
		command.Env = gradleEnv()
		command.Stdout = &output
		command.Stderr = &output
		runErr := command.Run()
		totalOutput += output.Len()
		truncated = truncated || output.Truncated()
		if totalOutput > MaxGradleOutputBytes {
			report.Error = "gradle output exceeded the resolution bound"
			report.Partial = true
			report.Limitations = append(report.Limitations, "gradle_output_truncated")
			break
		}
		parsed := parseGradleDependencyReport(output.String())
		dependencies, selected, ok := parsed.selected()
		for _, configuration := range selected {
			configurations[configuration] = true
		}
		if runErr != nil {
			failures = append(failures, module.POM+": "+gradleError(output.String()))
			report.Partial = true
		} else if !ok {
			report.Limitations = append(report.Limitations, "gradle_no_configuration_report:"+module.POM)
		}
		if runErr == nil && ok {
			parsedModules++
		}
		coordinate := strings.TrimSpace(module.GroupID + ":" + module.ArtifactID + ":" + module.Version)
		report.Modules = append(report.Modules, ResolvedModule{
			BuildFile:    module.POM,
			Coordinate:   coordinate,
			GroupID:      module.GroupID,
			ArtifactID:   module.ArtifactID,
			Version:      module.Version,
			Dependencies: dependencies,
		})
	}
	report.Gradle.DurationMS = time.Since(started).Milliseconds()
	report.Gradle.ModulesParsed = parsedModules
	for configuration := range configurations {
		report.Gradle.Configurations = append(report.Gradle.Configurations, configuration)
	}
	sort.Strings(report.Gradle.Configurations)
	for index := range report.Modules {
		sort.Slice(report.Modules[index].Dependencies, func(i, j int) bool {
			a, b := report.Modules[index].Dependencies[i], report.Modules[index].Dependencies[j]
			if a.Depth != b.Depth {
				return a.Depth < b.Depth
			}
			if a.GroupID != b.GroupID {
				return a.GroupID < b.GroupID
			}
			if a.ArtifactID != b.ArtifactID {
				return a.ArtifactID < b.ArtifactID
			}
			return a.Version < b.Version
		})
	}
	sort.Slice(report.Modules, func(i, j int) bool {
		if report.Modules[i].BuildFile != report.Modules[j].BuildFile {
			return report.Modules[i].BuildFile < report.Modules[j].BuildFile
		}
		return report.Modules[i].Coordinate < report.Modules[j].Coordinate
	})
	for _, module := range report.Modules {
		for _, dependency := range module.Dependencies {
			report.Coverage.Dependencies++
			if dependency.Direct {
				report.Coverage.Direct++
			} else {
				report.Coverage.Transitive++
			}
			if dependency.Omitted {
				report.Coverage.Omitted++
			}
		}
	}
	report.Coverage.Modules = len(report.Modules)
	report.Coverage.EffectiveTree = "gradle_dependency_report_observed"
	if truncated {
		report.Partial = true
		report.Limitations = append(report.Limitations, "gradle_output_truncated")
	}
	if len(failures) > 0 {
		report.Error = boundText(strings.Join(failures, " | "), 2000)
	}
	if parsedModules == 0 {
		report.Status = "failed"
		if report.Error == "" {
			report.Error = "gradle produced no parseable dependency report"
		}
		report.Limitations = append(report.Limitations, "empty_or_unparseable_gradle_report")
		sort.Strings(report.Limitations)
		report.Limitations = dedupe(report.Limitations)
		return report, fmt.Errorf("%s", report.Error)
	}
	report.Status = "ok"
	if report.Partial {
		report.Status = "partial"
	}
	report.Partial = report.Partial || declared.Partial
	report.Limitations = append(report.Limitations, "gradle_invoked: dependency resolution is observed build metadata, not a deployment")
	sort.Strings(report.Limitations)
	report.Limitations = dedupe(report.Limitations)
	return report, nil
}

func resolveGradleExecutable(value string) (string, error) {
	if value == "" {
		found, err := exec.LookPath("gradle")
		if err != nil {
			return "", fmt.Errorf("gradle executable not found in PATH; pass --gradle with an absolute path")
		}
		return found, nil
	}
	if !filepath.IsAbs(value) {
		return "", fmt.Errorf("gradle executable path must be absolute")
	}
	info, err := os.Stat(value)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("gradle executable must be an existing regular file")
	}
	return value, nil
}

func gradleVersion(ctx context.Context, gradlePath, dir string) string {
	output := boundedBuffer{limit: MaxGradleVersionOutputBytes}
	command := exec.CommandContext(ctx, gradlePath, "--version", "--console=plain")
	command.Dir = dir
	command.Env = gradleEnv()
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return ""
	}
	for _, line := range strings.Split(output.String(), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Gradle ") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "Gradle "))
		}
	}
	return ""
}

func gradleEnv() []string {
	keys := []string{"PATH", "JAVA_HOME", "HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP", "LANG", "LC_ALL"}
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return env
}

type gradleDependencyReport struct {
	configurations   map[string][]EffectiveDependency
	order            []string
	noConfigurations bool
}

func parseGradleDependencyReport(output string) gradleDependencyReport {
	report := gradleDependencyReport{configurations: map[string][]EffectiveDependency{}}
	current := ""
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if configuration := gradleConfigurationHeader(line); configuration != "" {
			current = configuration
			if _, ok := report.configurations[current]; !ok {
				report.configurations[current] = []EffectiveDependency{}
				report.order = append(report.order, current)
			}
			continue
		}
		if trimmed == "No configurations" {
			report.noConfigurations = true
			current = ""
			continue
		}
		if trimmed == "No dependencies" || current == "" {
			continue
		}
		depth, payload, ok := gradleTreeLine(line)
		if !ok {
			continue
		}
		if dependency, ok := parseGradleDependency(payload, current, depth); ok {
			report.configurations[current] = append(report.configurations[current], dependency)
		}
	}
	return report
}

func gradleConfigurationHeader(line string) string {
	if line == "" {
		return ""
	}
	switch line[0] {
	case ' ', '|', '+', '\\', '-':
		return ""
	}
	index := strings.Index(line, " - ")
	if index <= 0 {
		return ""
	}
	name := strings.TrimSpace(line[:index])
	if !gradleConfigurationName.MatchString(name) {
		return ""
	}
	return name
}

func gradleTreeLine(line string) (int, string, bool) {
	depth, index := 0, 0
	for index+5 <= len(line) {
		group := line[index : index+5]
		if group == "|    " || group == "     " {
			depth++
			index += 5
			continue
		}
		break
	}
	rest := line[index:]
	switch {
	case strings.HasPrefix(rest, "+--- "):
		return depth + 1, rest[5:], true
	case strings.HasPrefix(rest, `\--- `):
		return depth + 1, rest[5:], true
	}
	return 0, "", false
}

func parseGradleDependency(payload, configuration string, depth int) (EffectiveDependency, bool) {
	payload = strings.TrimSpace(payload)
	omitted, failed := false, false
	var notes []string
	for {
		switch {
		case strings.HasSuffix(payload, " (*)"):
			omitted = true
			payload = strings.TrimSpace(strings.TrimSuffix(payload, " (*)"))
		case strings.HasSuffix(payload, " (c)"):
			notes = append(notes, "constraint")
			payload = strings.TrimSpace(strings.TrimSuffix(payload, " (c)"))
		case strings.HasSuffix(payload, " (n)"):
			notes = append(notes, "not_resolved")
			payload = strings.TrimSpace(strings.TrimSuffix(payload, " (n)"))
		case strings.HasSuffix(payload, " FAILED"):
			failed = true
			payload = strings.TrimSpace(strings.TrimSuffix(payload, " FAILED"))
		default:
			goto parsed
		}
	}
parsed:
	if strings.HasPrefix(payload, "project ") {
		name := strings.TrimSpace(strings.TrimPrefix(payload, "project "))
		if name == "" {
			return EffectiveDependency{}, false
		}
		notes = append([]string{"project_dependency"}, notes...)
		return EffectiveDependency{
			ArtifactID: name, Type: "project", Scope: configuration,
			Depth: depth, Direct: depth == 1, Note: strings.Join(notes, "; "),
		}, true
	}
	if index := strings.Index(payload, " -> "); index > 0 {
		requested := strings.TrimSpace(payload[:index])
		final := strings.TrimSpace(payload[index+4:])
		if colon := strings.LastIndex(requested, ":"); colon > 0 && final != "" {
			notes = append(notes, "requested "+requested[colon+1:])
			payload = strings.TrimSpace(requested[:colon+1] + final)
		}
	}
	parts := strings.Split(payload, ":")
	if len(parts) < 2 {
		return EffectiveDependency{}, false
	}
	groupID := strings.TrimSpace(parts[0])
	artifactID := strings.TrimSpace(parts[1])
	version := ""
	if len(parts) >= 3 {
		version = strings.TrimSpace(parts[2])
	}
	if groupID == "" || artifactID == "" {
		return EffectiveDependency{}, false
	}
	if version == "" {
		notes = append(notes, "versionless")
	}
	if failed {
		notes = append(notes, "FAILED")
	}
	dependency := EffectiveDependency{
		GroupID: groupID, ArtifactID: artifactID, Version: version,
		Type: "jar", Scope: configuration, Depth: depth, Direct: depth == 1,
		Omitted: omitted, Failed: failed, Note: strings.Join(notes, "; "),
	}
	if len(parts) > 3 {
		dependency.Classifier = strings.Join(parts[3:], ":")
	}
	return dependency, true
}

func (r gradleDependencyReport) selected() ([]EffectiveDependency, []string, bool) {
	for _, name := range []string{"runtimeClasspath", "compileClasspath"} {
		if dependencies, ok := r.configurations[name]; ok {
			return dependencies, []string{name}, true
		}
	}
	var runtimeConfigurations, compileConfigurations []string
	for _, name := range r.order {
		switch {
		case strings.HasSuffix(name, "RuntimeClasspath"):
			runtimeConfigurations = append(runtimeConfigurations, name)
		case strings.HasSuffix(name, "CompileClasspath"):
			compileConfigurations = append(compileConfigurations, name)
		}
	}
	if len(runtimeConfigurations) > 0 {
		return r.configurations[runtimeConfigurations[0]], runtimeConfigurations[:1], true
	}
	if len(compileConfigurations) > 0 {
		return r.configurations[compileConfigurations[0]], compileConfigurations[:1], true
	}
	if len(r.order) == 0 {
		return nil, nil, false
	}
	var dependencies []EffectiveDependency
	for _, name := range r.order {
		dependencies = append(dependencies, r.configurations[name]...)
	}
	return dependencies, append([]string{}, r.order...), true
}

func gradleError(output string) string {
	var lines []string
	for _, raw := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		matched := strings.Contains(trimmed, "FAILED") ||
			strings.Contains(trimmed, "Could not resolve") ||
			strings.Contains(trimmed, "Could not find") ||
			strings.Contains(trimmed, "Failed to resolve") ||
			strings.HasPrefix(trimmed, "> Could not")
		if !matched {
			continue
		}
		duplicate := false
		for _, line := range lines {
			if line == trimmed {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		lines = append(lines, trimmed)
		if len(lines) >= 5 {
			break
		}
	}
	if len(lines) == 0 {
		return "gradle failed without a parsed error line"
	}
	return boundText(strings.Join(lines, " | "), 2000)
}

func boundText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
