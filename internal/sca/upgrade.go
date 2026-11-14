package sca

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"trident/internal/project"
)

const (
	UpgradeToolVersion    = "0.2.0-p0.2+r4-dependency-upgrade-v1"
	MaxUpgradeFileBytes   = 2 << 20
	MaxUpgradeDependency  = 4096
	MaxUpgradePatchLine   = 4000
	upgradePatchContext   = 3
	upgradeDependencyHint = "group:artifact"
)

var (
	upgradeVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	pomDependencyBlock    = regexp.MustCompile(`(?s)<dependency\b[^>]*>(.*?)</dependency>`)
	pomGroupTag           = regexp.MustCompile(`(?s)<groupId>\s*([^<]+?)\s*</groupId>`)
	pomArtifactTag        = regexp.MustCompile(`(?s)<artifactId>\s*([^<]+?)\s*</artifactId>`)
	pomVersionTag         = regexp.MustCompile(`(?s)<version>\s*([^<]*?)\s*</version>`)
	gradleQuotedValue     = regexp.MustCompile(`["']([^"'\r\n]+)["']`)
	gradleMapValue        = regexp.MustCompile(`(?s)\bgroup\s*:\s*['"]([^'"]+)['"]\s*,\s*name\s*:\s*['"]([^'"]+)['"]\s*,\s*version\s*:\s*['"]([^'"]+)['"]`)
)

type UpgradeOptions struct {
	Module     string
	Dependency string
	ToVersion  string
}

type UpgradeChange struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Kind   string `json:"kind"`
	Before string `json:"before"`
	After  string `json:"after"`
}

type UpgradePlan struct {
	SchemaVersion   int             `json:"schema_version"`
	ToolVersion     string          `json:"tool_version"`
	SnapshotHash    string          `json:"snapshot_hash"`
	AnalysisKind    string          `json:"analysis_kind"`
	Status          string          `json:"status"`
	Dependency      string          `json:"dependency"`
	GroupID         string          `json:"group_id"`
	ArtifactID      string          `json:"artifact_id"`
	Module          string          `json:"module"`
	FromVersion     string          `json:"from_version"`
	ToVersion       string          `json:"to_version"`
	DeclarationFile string          `json:"declaration_file"`
	Property        string          `json:"property,omitempty"`
	Change          UpgradeChange   `json:"change"`
	Patch           string          `json:"patch"`
	PatchSHA256     string          `json:"patch_sha256"`
	PatchBytes      int             `json:"patch_bytes"`
	Limitations     []string        `json:"limitations"`
	RuntimeStatus   string          `json:"runtime_status"`
	Error           string          `json:"error,omitempty"`
	Details         []UpgradeChange `json:"details,omitempty"`
}

// PlanUpgrade generates a minimal, single-declaration version bump. It never
// executes a build tool and never reads repository artifacts; verification is a
// separate explicit step.
func PlanUpgrade(ctx context.Context, snapshot *project.Snapshot, opts UpgradeOptions) (UpgradePlan, error) {
	plan := UpgradePlan{
		SchemaVersion: SchemaVersion,
		ToolVersion:   UpgradeToolVersion,
		AnalysisKind:  "bounded_dependency_upgrade_plan",
		Status:        "failed",
		Change:        UpgradeChange{},
		Limitations: []string{
			"caller_selected_target_version: no advisory-driven or automatic version choice",
			"no_artifact_hash_verification: the target version is not fetched or hashed here",
			"single_declaration_bump: transitive upgrades and compatibility are not modeled",
			"verification_required_for_claim: a prepared patch is not a validated upgrade",
			"build_tool_not_executed: planning only; use the returned patch with an approved validation profile",
		},
		RuntimeStatus: "not_run",
	}
	if snapshot == nil || snapshot.Hash() == "" {
		return plan, fmt.Errorf("pinned snapshot required")
	}
	plan.SnapshotHash = snapshot.Hash()
	groupID, artifactID, err := parseUpgradeDependency(opts.Dependency)
	if err != nil {
		return plan, err
	}
	plan.GroupID, plan.ArtifactID = groupID, artifactID
	plan.Dependency = strings.TrimSpace(opts.Dependency)
	plan.ToVersion = strings.TrimSpace(opts.ToVersion)
	if !upgradeVersionPattern.MatchString(plan.ToVersion) {
		return plan, fmt.Errorf("target version must be a bounded literal version")
	}
	module := normalizeUpgradeModule(opts.Module)
	plan.Module = module
	declared, err := Inspect(ctx, snapshot, Options{})
	if err != nil {
		return plan, err
	}
	if len(declared.Dependencies) > MaxUpgradeDependency {
		return plan, fmt.Errorf("%w: dependency count exceeds %d", ErrLimit, MaxUpgradeDependency)
	}
	declaration, err := selectUpgradeDependency(declared.Dependencies, module, groupID, artifactID)
	if err != nil {
		return plan, err
	}
	plan.Module = declaration.Module
	plan.FromVersion = declaration.Version
	plan.DeclarationFile = declaration.DeclarationPOM
	plan.Property = declaration.Property
	if plan.FromVersion == "" || declaration.VersionStatus != "resolved" {
		return plan, fmt.Errorf("declared version is unresolved; cannot derive a bounded upgrade")
	}
	if plan.FromVersion == plan.ToVersion {
		return plan, fmt.Errorf("target version equals the declared version")
	}
	file, change, err := planUpgradeChange(ctx, snapshot, declaration, plan.ToVersion)
	if err != nil {
		return plan, err
	}
	content, err := readUpgradeFile(ctx, snapshot, file)
	if err != nil {
		return plan, err
	}
	patch, err := buildUpgradePatch(file, content, change)
	if err != nil {
		return plan, err
	}
	plan.Change = change
	plan.Details = []UpgradeChange{change}
	plan.Patch = patch
	sum := sha256.Sum256([]byte(patch))
	plan.PatchSHA256 = hex.EncodeToString(sum[:])
	plan.PatchBytes = len(patch)
	plan.Status = "prepared"
	sort.Strings(plan.Limitations)
	plan.Limitations = dedupe(plan.Limitations)
	return plan, nil
}

func parseUpgradeDependency(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	parts := strings.Split(value, ":")
	switch len(parts) {
	case 1:
		if parts[0] == "" {
			return "", "", fmt.Errorf("dependency must be %s", upgradeDependencyHint)
		}
		return "", parts[0], nil
	case 2:
		if parts[1] == "" {
			return "", "", fmt.Errorf("dependency must be %s", upgradeDependencyHint)
		}
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
	default:
		return "", "", fmt.Errorf("dependency must be %s without version components", upgradeDependencyHint)
	}
}

func normalizeUpgradeModule(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" {
		return "."
	}
	base := path.Base(value)
	if base == "pom.xml" || base == "build.gradle" || base == "build.gradle.kts" {
		value = path.Dir(value)
	}
	value = path.Clean(value)
	if value == "" {
		return "."
	}
	return value
}

func selectUpgradeDependency(dependencies []Dependency, module, groupID, artifactID string) (Dependency, error) {
	var matches []Dependency
	seen := map[string]bool{}
	for _, dependency := range dependencies {
		if dependency.ArtifactID != artifactID {
			continue
		}
		if groupID != "" && dependency.GroupID != groupID {
			continue
		}
		if module != "" && dependency.Module != module {
			continue
		}
		if dependency.VersionStatus != "resolved" || dependency.Version == "" {
			continue
		}
		key := dependency.Module + "\x00" + dependency.DeclarationPOM + "\x00" + dependency.Version +
			"\x00" + dependency.Property + "\x00" + dependency.ManagementPOM
		if seen[key] {
			continue
		}
		seen[key] = true
		matches = append(matches, dependency)
	}
	if len(matches) == 0 {
		return Dependency{}, fmt.Errorf("no resolved declaration for %s in module %q", moduleDependencyLabel(groupID, artifactID), module)
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Module != matches[j].Module {
			return matches[i].Module < matches[j].Module
		}
		if matches[i].DeclarationPOM != matches[j].DeclarationPOM {
			return matches[i].DeclarationPOM < matches[j].DeclarationPOM
		}
		return matches[i].Version < matches[j].Version
	})
	if len(matches) > 1 {
		var locations []string
		for _, match := range matches {
			locations = append(locations, match.Module+" ("+match.DeclarationPOM+", "+match.Version+")")
		}
		return Dependency{}, fmt.Errorf("ambiguous dependency declaration; specify --module: %s", strings.Join(locations, "; "))
	}
	return matches[0], nil
}

func moduleDependencyLabel(groupID, artifactID string) string {
	if groupID == "" {
		return artifactID
	}
	return groupID + ":" + artifactID
}

func planUpgradeChange(ctx context.Context, snapshot *project.Snapshot, declaration Dependency, toVersion string) (string, UpgradeChange, error) {
	isGradle := func(file string) bool {
		base := path.Base(file)
		return base == "build.gradle" || base == "build.gradle.kts"
	}
	if isGradle(declaration.DeclarationPOM) {
		file := declaration.DeclarationPOM
		content, err := readUpgradeFile(ctx, snapshot, file)
		if err != nil {
			return "", UpgradeChange{}, err
		}
		change, err := findGradleUpgradeChange(content, declaration, toVersion)
		return file, change, err
	}
	if declaration.Property != "" {
		file := declaration.PropertyPOM
		if file == "" {
			file = declaration.DeclarationPOM
		}
		content, err := readUpgradeFile(ctx, snapshot, file)
		if err != nil {
			return "", UpgradeChange{}, err
		}
		change, err := findPOMPropertyChange(content, file, declaration.Property, declaration.Version, toVersion)
		return file, change, err
	}
	file := declaration.DeclarationPOM
	if declaration.ManagementPOM != "" {
		file = declaration.ManagementPOM
	}
	content, err := readUpgradeFile(ctx, snapshot, file)
	if err != nil {
		return "", UpgradeChange{}, err
	}
	change, err := findPOMDependencyChange(content, file, declaration.GroupID, declaration.ArtifactID, declaration.Version, toVersion)
	return file, change, err
}

func readUpgradeFile(ctx context.Context, snapshot *project.Snapshot, file string) (string, error) {
	data, err := snapshot.ReadFile(ctx, file)
	if err != nil {
		return "", err
	}
	if len(data) == 0 || len(data) > MaxUpgradeFileBytes {
		return "", fmt.Errorf("upgrade declaration file %q is empty or exceeds %d bytes", file, MaxUpgradeFileBytes)
	}
	if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		return "", fmt.Errorf("upgrade declaration file %q is not bounded UTF-8 text", file)
	}
	return string(data), nil
}

func findPOMPropertyChange(content, file, property, from, to string) (UpgradeChange, error) {
	quoted := regexp.QuoteMeta(property)
	pattern, err := regexp.Compile(`(?s)^(.*?<` + quoted + `\s*>)(.*?)(</` + quoted + `\s*>.*)$`)
	if err != nil {
		return UpgradeChange{}, err
	}
	lines := strings.Split(content, "\n")
	var found *UpgradeChange
	for index, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		match := pattern.FindStringSubmatchIndex(line)
		if match == nil || len(match) < 8 {
			continue
		}
		raw := line[match[4]:match[5]]
		if strings.TrimSpace(raw) != from {
			continue
		}
		if found != nil {
			return UpgradeChange{}, fmt.Errorf("property %q is defined more than once in %s", property, file)
		}
		replaced := line[:match[4]] + strings.Replace(raw, from, to, 1) + line[match[5]:]
		if len(replaced) > MaxUpgradePatchLine {
			return UpgradeChange{}, fmt.Errorf("upgraded line exceeds the patch line bound")
		}
		found = &UpgradeChange{
			File: file, Line: index + 1, Kind: "maven_property",
			Before: line, After: replaced,
		}
	}
	if found == nil {
		return UpgradeChange{}, fmt.Errorf("could not locate property %q with value %q in %s", property, from, file)
	}
	return *found, nil
}

func findPOMDependencyChange(content, file, groupID, artifactID, from, to string) (UpgradeChange, error) {
	matches := pomDependencyBlock.FindAllStringSubmatchIndex(content, MaxUpgradeDependency)
	var found *UpgradeChange
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		blockStart, blockEnd := match[2], match[3]
		block := content[blockStart:blockEnd]
		group := pomTagValue(pomGroupTag, block)
		artifact := pomTagValue(pomArtifactTag, block)
		if artifact != artifactID || (groupID != "" && group != groupID) {
			continue
		}
		versionMatch := pomVersionTag.FindStringSubmatchIndex(block)
		if versionMatch == nil || len(versionMatch) < 6 {
			continue
		}
		raw := block[versionMatch[4]:versionMatch[5]]
		if strings.TrimSpace(raw) != from {
			continue
		}
		if found != nil {
			return UpgradeChange{}, fmt.Errorf("dependency %s is declared more than once in %s", moduleDependencyLabel(groupID, artifactID), file)
		}
		valueStart := blockStart + versionMatch[4]
		valueEnd := blockStart + versionMatch[5]
		lineIndex, lineStart, lineEnd, err := upgradeLineAt(content, valueStart)
		if err != nil {
			return UpgradeChange{}, err
		}
		line := strings.TrimSuffix(content[lineStart:lineEnd], "\r")
		if valueStart < lineStart || valueEnd > lineStart+len(line) {
			return UpgradeChange{}, fmt.Errorf("multiline dependency versions are unsupported in %s", file)
		}
		replacedValue := strings.Replace(raw, from, to, 1)
		replacedLine := line[:valueStart-lineStart] + replacedValue + line[valueEnd-lineStart:]
		if len(replacedLine) > MaxUpgradePatchLine {
			return UpgradeChange{}, fmt.Errorf("upgraded line exceeds the patch line bound")
		}
		found = &UpgradeChange{
			File: file, Line: lineIndex + 1, Kind: "maven_dependency",
			Before: line, After: replacedLine,
		}
	}
	if found == nil {
		return UpgradeChange{}, fmt.Errorf("could not locate dependency %s version %q in %s", moduleDependencyLabel(groupID, artifactID), from, file)
	}
	return *found, nil
}

func findGradleUpgradeChange(content string, declaration Dependency, to string) (UpgradeChange, error) {
	coordinate := moduleDependencyLabel(declaration.GroupID, declaration.ArtifactID) + ":" + declaration.Version
	if declaration.GroupID == "" {
		coordinate = declaration.ArtifactID + ":" + declaration.Version
	}
	lines := strings.Split(content, "\n")
	var found *UpgradeChange
	for index, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		for _, match := range gradleQuotedValue.FindAllStringSubmatchIndex(line, -1) {
			if match == nil || len(match) < 4 {
				continue
			}
			value := line[match[2]:match[3]]
			if value != coordinate {
				continue
			}
			if found != nil {
				return UpgradeChange{}, fmt.Errorf("Gradle dependency %s is declared more than once in %s", coordinate, declaration.DeclarationPOM)
			}
			rawVersion := declaration.Version
			valueOffset := match[2] + len(value) - len(rawVersion)
			replaced := line[:valueOffset] + to + line[valueOffset+len(rawVersion):]
			if len(replaced) > MaxUpgradePatchLine {
				return UpgradeChange{}, fmt.Errorf("upgraded line exceeds the patch line bound")
			}
			found = &UpgradeChange{
				File: declaration.DeclarationPOM, Line: index + 1, Kind: "gradle_string",
				Before: line, After: replaced,
			}
		}
		match := gradleMapValue.FindStringSubmatchIndex(line)
		if match == nil || len(match) < 8 {
			continue
		}
		group := line[match[2]:match[3]]
		artifact := line[match[4]:match[5]]
		version := line[match[6]:match[7]]
		if artifact != declaration.ArtifactID || (declaration.GroupID != "" && group != declaration.GroupID) || version != declaration.Version {
			continue
		}
		if found != nil {
			return UpgradeChange{}, fmt.Errorf("Gradle dependency %s is declared more than once in %s", coordinate, declaration.DeclarationPOM)
		}
		replaced := line[:match[6]] + to + line[match[7]:]
		if len(replaced) > MaxUpgradePatchLine {
			return UpgradeChange{}, fmt.Errorf("upgraded line exceeds the patch line bound")
		}
		found = &UpgradeChange{
			File: declaration.DeclarationPOM, Line: index + 1, Kind: "gradle_map",
			Before: line, After: replaced,
		}
	}
	if found == nil {
		return UpgradeChange{}, fmt.Errorf("could not locate Gradle declaration for %s in %s; version catalogs and plugin-managed versions are unsupported", coordinate, declaration.DeclarationPOM)
	}
	return *found, nil
}

func pomTagValue(pattern *regexp.Regexp, block string) string {
	match := pattern.FindStringSubmatch(block)
	if match == nil {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func buildUpgradePatch(file, content string, change UpgradeChange) (string, error) {
	lines := strings.Split(content, "\n")
	lineCount := len(lines)
	if lineCount > 0 && lines[lineCount-1] == "" {
		lineCount--
	}
	index := change.Line - 1
	if index < 0 || index >= lineCount {
		return "", fmt.Errorf("upgrade line is outside the declaration file")
	}
	existing := strings.TrimSuffix(lines[index], "\r")
	if existing != change.Before {
		return "", fmt.Errorf("upgrade line changed while planning")
	}
	start := index - upgradePatchContext
	if start < 0 {
		start = 0
	}
	end := index + upgradePatchContext + 1
	if end > lineCount {
		end = lineCount
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "--- a/%s\n+++ b/%s\n", file, file)
	fmt.Fprintf(&builder, "@@ -%d,%d +%d,%d @@\n", start+1, end-start, start+1, end-start)
	for i := start; i < end; i++ {
		line := strings.TrimSuffix(lines[i], "\r")
		switch i {
		case index:
			builder.WriteString("-")
			builder.WriteString(change.Before)
			builder.WriteString("\n+")
			builder.WriteString(change.After)
			builder.WriteString("\n")
		default:
			builder.WriteString(" ")
			builder.WriteString(line)
			builder.WriteString("\n")
		}
	}
	return builder.String(), nil
}

func upgradeLineAt(content string, offset int) (index, start, end int, err error) {
	if offset < 0 || offset > len(content) {
		return 0, 0, 0, fmt.Errorf("upgrade value offset is outside the declaration file")
	}
	start = strings.LastIndexByte(content[:offset], '\n') + 1
	end = strings.IndexByte(content[offset:], '\n')
	if end < 0 {
		end = len(content)
	} else {
		end += offset
	}
	index = strings.Count(content[:start], "\n")
	return index, start, end, nil
}
