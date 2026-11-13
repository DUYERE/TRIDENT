package sca

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"trident/internal/project"
)

// Gradle support is a bounded declaration extractor, not a Gradle model. It
// reads common Groovy/Kotlin dependency notations and never executes Gradle,
// resolves plugins, version catalogs or transitive configurations.
const (
	MaxGradleFiles = 512
	MaxGradleBytes = 512 << 10
)

type gradleFile struct {
	Path        string
	Directory   string
	GroupID     string
	Version     string
	Name        string
	ProjectDeps []string
}

type gradleDependency struct {
	File          string
	Directory     string
	Configuration string
	GroupID       string
	ArtifactID    string
	Version       string
	VersionStatus string
	VersionReason string
}

var (
	gradleStringDependency = regexp.MustCompile(`(?m)\b(implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testCompile|annotationProcessor|kapt)\s*\(?\s*["']([^"'\r\n]+)["']`)
	gradleMapDependency    = regexp.MustCompile(`(?m)\b(implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testCompile|annotationProcessor|kapt)\s*\(?\s*group\s*:\s*["']([^"']+)["']\s*,\s*name\s*:\s*["']([^"']+)["'](?:\s*,\s*version\s*:\s*["']([^"']+)["'])?`)
	gradleGroupSetting     = regexp.MustCompile(`(?m)^\s*group\s*=\s*["']([^"']+)["']`)
	gradleVersionSetting   = regexp.MustCompile(`(?m)^\s*version\s*=\s*["']([^"']+)["']`)
	gradleRootName         = regexp.MustCompile(`(?m)^\s*rootProject\.name\s*=\s*["']([^"']+)["']`)
	gradlePlatform         = regexp.MustCompile(`(?m)\bplatform\s*\(`)
	gradleVersionCatalog   = regexp.MustCompile(`(?m)\blibs\.\w+`)
	gradleProjectDep       = regexp.MustCompile(`(?m)\bproject\s*\(\s*["']([^"']+)["']\s*\)`)
)

func inspectGradle(ctx context.Context, snapshot *project.Snapshot) ([]gradleFile, []gradleDependency, int, []string, error) {
	var files []string
	for _, entry := range snapshot.Manifest().Entries {
		base := path.Base(entry.Path)
		if base == "build.gradle" || base == "build.gradle.kts" {
			files = append(files, entry.Path)
		}
	}
	sort.Strings(files)
	if len(files) > MaxGradleFiles {
		return nil, nil, 0, nil, fmt.Errorf("%w: Gradle file count exceeds %d", ErrLimit, MaxGradleFiles)
	}
	settings := map[string]string{}
	for _, entry := range snapshot.Manifest().Entries {
		base := path.Base(entry.Path)
		if base == "settings.gradle" || base == "settings.gradle.kts" {
			data, err := snapshot.ReadFile(ctx, entry.Path)
			if err != nil {
				return nil, nil, 0, nil, err
			}
			if match := gradleRootName.FindSubmatch(data); match != nil {
				settings[path.Dir(entry.Path)] = strings.TrimSpace(string(match[1]))
			}
		}
	}
	var models []gradleFile
	var dependencies []gradleDependency
	var problems []string
	rejected := 0
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, nil, 0, nil, err
		}
		data, err := snapshot.ReadFile(ctx, file)
		if err != nil {
			return nil, nil, 0, nil, err
		}
		if len(data) == 0 || len(data) > MaxGradleBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			rejected++
			problems = append(problems, "rejected_gradle:"+file+":size_or_encoding")
			continue
		}
		cleaned := stripGradleComments(string(data))
		directory := path.Dir(file)
		name := settings[directory]
		if name == "" {
			if directory == "." {
				name = "root"
			} else {
				name = path.Base(directory)
			}
		}
		model := gradleFile{Path: file, Directory: directory, Name: name}
		if match := gradleGroupSetting.FindStringSubmatch(cleaned); match != nil {
			model.GroupID = strings.TrimSpace(match[1])
		}
		if match := gradleVersionSetting.FindStringSubmatch(cleaned); match != nil {
			model.Version = strings.TrimSpace(match[1])
		}
		for _, match := range gradleProjectDep.FindAllStringSubmatch(cleaned, -1) {
			name := strings.TrimPrefix(strings.TrimSpace(match[1]), ":")
			if name != "" {
				model.ProjectDeps = append(model.ProjectDeps, name)
			}
		}
		sort.Strings(model.ProjectDeps)
		model.ProjectDeps = dedupe(model.ProjectDeps)
		models = append(models, model)
		if gradlePlatform.MatchString(cleaned) {
			problems = append(problems, "gradle_platform_dependency_unresolved:"+file)
		}
		if gradleVersionCatalog.MatchString(cleaned) {
			problems = append(problems, "gradle_version_catalog_unresolved:"+file)
		}
		seen := map[string]bool{}
		add := func(configuration, group, artifact, version, reason string) {
			artifact = strings.TrimSpace(artifact)
			if artifact == "" {
				problems = append(problems, "invalid_gradle_dependency:"+file)
				return
			}
			key := configuration + "\x00" + group + "\x00" + artifact + "\x00" + version
			if seen[key] {
				return
			}
			seen[key] = true
			status := "resolved"
			if reason == "" && (version == "" || strings.ContainsAny(version, "$+[]()")) {
				reason = "gradle_dynamic_or_missing_version"
			}
			if reason != "" {
				status = "unresolved"
			}
			dependencies = append(dependencies, gradleDependency{
				File: file, Directory: directory, Configuration: configuration,
				GroupID: strings.TrimSpace(group), ArtifactID: artifact, Version: strings.TrimSpace(version),
				VersionStatus: status, VersionReason: reason,
			})
		}
		for _, match := range gradleStringDependency.FindAllStringSubmatch(cleaned, -1) {
			coordinates := strings.Split(strings.TrimSpace(match[2]), ":")
			switch len(coordinates) {
			case 2:
				add(match[1], "", coordinates[0], coordinates[1], "")
			case 3:
				add(match[1], coordinates[0], coordinates[1], coordinates[2], "")
			default:
				problems = append(problems, "invalid_gradle_coordinates:"+file)
			}
		}
		for _, match := range gradleMapDependency.FindAllStringSubmatch(cleaned, -1) {
			add(match[1], match[2], match[3], match[4], "")
		}
	}
	sort.Strings(problems)
	return models, dependencies, rejected, dedupe(problems), nil
}

func stripGradleComments(source string) string {
	var out strings.Builder
	inLine, inBlock := false, false
	var quote byte
	for i := 0; i < len(source); i++ {
		c := source[i]
		if inLine {
			if c == '\n' {
				inLine = false
				out.WriteByte(c)
			}
			continue
		}
		if inBlock {
			if c == '*' && i+1 < len(source) && source[i+1] == '/' {
				inBlock = false
				i++
			}
			continue
		}
		if quote != 0 {
			out.WriteByte(c)
			if c == '\\' && i+1 < len(source) {
				out.WriteByte(source[i+1])
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			out.WriteByte(c)
		case '/':
			if i+1 < len(source) && source[i+1] == '/' {
				inLine = true
				i++
				continue
			}
			if i+1 < len(source) && source[i+1] == '*' {
				inBlock = true
				i++
				continue
			}
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}
