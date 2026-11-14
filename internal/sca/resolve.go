package sca

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"trident/internal/project"
)

const (
	ResolveToolVersion     = "0.2.0-p0.2+r2-maven-effective-tree-v1"
	MaxResolveFiles        = 20000
	MaxResolveBytes        = 256 << 20
	MaxMavenOutputBytes    = 8 << 20
	DefaultResolveTimeoutS = 120
	MaxResolveTimeoutS     = 600
)

type ResolveOptions struct {
	AllowNetwork bool
	ApproveMaven bool
	MavenRepo    string
	Timeout      time.Duration
}

type ResolveReport struct {
	SchemaVersion  int              `json:"schema_version"`
	ToolVersion    string           `json:"tool_version"`
	SnapshotHash   string           `json:"snapshot_hash"`
	AnalysisKind   string           `json:"analysis_kind"`
	ResolutionMode string           `json:"resolution_mode"`
	Status         string           `json:"status"`
	Partial        bool             `json:"partial"`
	Maven          MavenInfo        `json:"maven"`
	Modules        []ResolvedModule `json:"modules"`
	Coverage       ResolveCoverage  `json:"coverage"`
	Limitations    []string         `json:"limitations"`
	RuntimeStatus  string           `json:"runtime_status"`
	Error          string           `json:"error,omitempty"`
}

type MavenInfo struct {
	Version    string `json:"version,omitempty"`
	Executed   bool   `json:"executed"`
	DurationMS int64  `json:"duration_ms"`
	RepoLocal  string `json:"repo_local,omitempty"`
}

type ResolvedModule struct {
	POM          string                `json:"pom,omitempty"`
	Coordinate   string                `json:"coordinate"`
	GroupID      string                `json:"group_id"`
	ArtifactID   string                `json:"artifact_id"`
	Version      string                `json:"version"`
	Dependencies []EffectiveDependency `json:"dependencies"`
}

type EffectiveDependency struct {
	GroupID    string `json:"group_id"`
	ArtifactID string `json:"artifact_id"`
	Type       string `json:"type,omitempty"`
	Classifier string `json:"classifier,omitempty"`
	Version    string `json:"version"`
	Scope      string `json:"scope"`
	Depth      int    `json:"depth"`
	Direct     bool   `json:"direct"`
	Omitted    bool   `json:"omitted,omitempty"`
	Note       string `json:"note,omitempty"`
}

type ResolveCoverage struct {
	Modules           int    `json:"modules"`
	Dependencies      int    `json:"dependencies"`
	Direct            int    `json:"direct"`
	Transitive        int    `json:"transitive"`
	Omitted           int    `json:"omitted"`
	EffectiveTree     string `json:"effective_tree"`
	ArtifactHashes    string `json:"artifact_hashes"`
	ClasspathVerified bool   `json:"classpath_verified"`
	RuntimeStatus     string `json:"runtime_status"`
}

// ResolveEffectiveTree runs Maven's dependency:tree on a disposable copy of the
// pinned snapshot. It never writes the snapshot. Offline is the default; online
// resolution requires explicit approval and is still build resolution, not
// runtime exploitability.
func ResolveEffectiveTree(ctx context.Context, snapshot *project.Snapshot, opts ResolveOptions) (ResolveReport, error) {
	report := ResolveReport{
		SchemaVersion:  SchemaVersion,
		ToolVersion:    ResolveToolVersion,
		AnalysisKind:   "maven_effective_dependency_tree",
		ResolutionMode: "offline",
		Status:         "failed",
		Modules:        []ResolvedModule{},
		Coverage:       ResolveCoverage{EffectiveTree: "not_available", ArtifactHashes: "not_available", RuntimeStatus: "not_run"},
		RuntimeStatus:  "not_run",
		Limitations: []string{
			"maven_effective_tree_not_runtime: resolved classpath metadata does not prove class loading, reachability or exploitability",
			"maven_pom_is_untrusted_input: dependency:tree may resolve plugins/extensions; run in a disposable environment",
			"artifact_hashes_unavailable: Maven coordinates are not artifact bytes",
			"gradle_effective_tree_unavailable: only Maven root POMs are supported",
		},
	}
	if snapshot == nil || snapshot.Hash() == "" {
		return report, fmt.Errorf("pinned snapshot required")
	}
	report.SnapshotHash = snapshot.Hash()
	if !opts.ApproveMaven {
		return report, fmt.Errorf("Maven execution requires explicit approval")
	}
	if opts.AllowNetwork {
		report.ResolutionMode = "online"
	}
	if opts.Timeout <= 0 || opts.Timeout > MaxResolveTimeoutS*time.Second {
		opts.Timeout = DefaultResolveTimeoutS * time.Second
	}
	if opts.MavenRepo != "" {
		info, err := os.Stat(opts.MavenRepo)
		if err != nil || !info.IsDir() || !filepath.IsAbs(opts.MavenRepo) {
			return report, fmt.Errorf("maven repository must be an absolute existing directory")
		}
		report.Maven.RepoLocal = filepath.Base(opts.MavenRepo)
	}
	declared, err := Inspect(ctx, snapshot, Options{})
	if err != nil {
		return report, err
	}
	if len(declared.Project.RootPOMs) == 0 {
		report.Error = "no Maven root POM found; Gradle effective trees are not implemented"
		report.Limitations = append(report.Limitations, "no_maven_root_pom")
		return report, fmt.Errorf("%s", report.Error)
	}
	root, err := copySnapshotForMaven(ctx, snapshot)
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(root)

	mavenPath, err := exec.LookPath("mvn")
	if err != nil {
		report.Error = "mvn executable not found"
		return report, fmt.Errorf("%s", report.Error)
	}
	report.Maven.Executed = true
	var output boundedBuffer
	output.limit = MaxMavenOutputBytes
	started := time.Now()
	for _, rootPOM := range declared.Project.RootPOMs {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		args := []string{"-B", "-f", filepath.Join(root, filepath.FromSlash(rootPOM)), "dependency:tree", "-DoutputType=text"}
		if !opts.AllowNetwork {
			args = append([]string{"-o"}, args...)
		}
		if opts.MavenRepo != "" {
			args = append(args, "-Dmaven.repo.local="+opts.MavenRepo)
		}
		command := exec.CommandContext(ctx, mavenPath, args...)
		command.Dir = root
		command.Env = mavenEnv()
		command.Stdout = &output
		command.Stderr = &output
		if err := command.Run(); err != nil {
			report.Partial = true
			report.Error = lastMavenError(output.String())
			report.Maven.DurationMS = time.Since(started).Milliseconds()
			report.Limitations = append(report.Limitations, "maven_dependency_tree_failed")
			sort.Strings(report.Limitations)
			return report, fmt.Errorf("maven dependency:tree failed: %s", report.Error)
		}
	}
	report.Maven.DurationMS = time.Since(started).Milliseconds()
	modules := parseMavenTree(output.String())
	if len(modules) == 0 {
		report.Error = "maven produced no parseable dependency tree"
		report.Partial = true
		report.Limitations = append(report.Limitations, "empty_or_unparseable_maven_tree")
		sort.Strings(report.Limitations)
		return report, fmt.Errorf("%s", report.Error)
	}
	moduleByGAV := map[string]Module{}
	for _, module := range declared.Modules {
		moduleByGAV[module.GroupID+":"+module.ArtifactID] = module
	}
	for index := range modules {
		if module, ok := moduleByGAV[modules[index].GroupID+":"+modules[index].ArtifactID]; ok {
			modules[index].POM = module.POM
		}
		for _, dependency := range modules[index].Dependencies {
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
	report.Modules = modules
	report.Coverage.Modules = len(modules)
	report.Coverage.EffectiveTree = "maven_dependency_tree_observed"
	report.Status = "ok"
	report.Partial = declared.Partial
	report.Limitations = append(report.Limitations, "maven_invoked: dependency resolution is observed build metadata, not a deployment")
	sort.Strings(report.Limitations)
	report.Limitations = dedupe(report.Limitations)
	return report, nil
}

func copySnapshotForMaven(ctx context.Context, snapshot *project.Snapshot) (string, error) {
	root, err := os.MkdirTemp("", "trident-maven-tree-")
	if err != nil {
		return "", err
	}
	files, total := 0, int64(0)
	for _, entry := range snapshot.Manifest().Entries {
		if err := ctx.Err(); err != nil {
			os.RemoveAll(root)
			return "", err
		}
		if entry.Size < 0 {
			os.RemoveAll(root)
			return "", fmt.Errorf("invalid snapshot entry size")
		}
		files++
		total += entry.Size
		if files > MaxResolveFiles || total > MaxResolveBytes {
			os.RemoveAll(root)
			return "", fmt.Errorf("snapshot exceeds Maven resolution copy bounds")
		}
		data, err := snapshot.ReadFile(ctx, entry.Path)
		if err != nil {
			os.RemoveAll(root)
			return "", err
		}
		target := filepath.Join(root, filepath.FromSlash(entry.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			os.RemoveAll(root)
			return "", err
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			os.RemoveAll(root)
			return "", err
		}
	}
	return root, nil
}

func mavenEnv() []string {
	keys := []string{"PATH", "JAVA_HOME", "HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP", "LANG", "LC_ALL"}
	env := []string{"MAVEN_OPTS=", "MAVEN_ARGS="}
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func parseMavenTree(output string) []ResolvedModule {
	var modules []ResolvedModule
	current := -1
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[INFO] Building ") {
			continue
		}
		if strings.HasPrefix(trimmed, "[INFO] ---") || strings.HasPrefix(trimmed, "[INFO] BUILD") {
			continue
		}
		if strings.HasPrefix(trimmed, "[INFO] ") {
			payload := strings.TrimPrefix(trimmed, "[INFO] ")
			if coordinate, ok := parseRootCoordinate(payload); ok {
				modules = append(modules, ResolvedModule{
					Coordinate: coordinate.String(), GroupID: coordinate.GroupID,
					ArtifactID: coordinate.ArtifactID, Version: coordinate.Version,
					Dependencies: []EffectiveDependency{},
				})
				current = len(modules) - 1
				continue
			}
			if current >= 0 {
				if dependency, ok := parseTreeDependency(payload); ok {
					modules[current].Dependencies = append(modules[current].Dependencies, dependency)
				}
			}
		}
	}
	for index := range modules {
		sort.Slice(modules[index].Dependencies, func(i, j int) bool {
			a, b := modules[index].Dependencies[i], modules[index].Dependencies[j]
			if a.Depth != b.Depth {
				return a.Depth < b.Depth
			}
			if a.GroupID != b.GroupID {
				return a.GroupID < b.GroupID
			}
			return a.ArtifactID < b.ArtifactID
		})
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Coordinate < modules[j].Coordinate })
	return modules
}

type mavenCoordinate struct {
	GroupID    string
	ArtifactID string
	Type       string
	Classifier string
	Version    string
	Scope      string
}

func (c mavenCoordinate) String() string {
	return c.GroupID + ":" + c.ArtifactID + ":" + c.Type + ":" + c.Version
}

func parseRootCoordinate(payload string) (mavenCoordinate, bool) {
	payload = strings.TrimSpace(payload)
	if strings.HasPrefix(payload, "+-") || strings.HasPrefix(payload, `\-`) || strings.HasPrefix(payload, "|") || strings.Contains(payload, " ") {
		return mavenCoordinate{}, false
	}
	return splitCoordinate(payload, false)
}

func parseTreeDependency(payload string) (EffectiveDependency, bool) {
	// Strip tree drawing, preserving depth. Each level occupies three columns.
	depth := 0
	index := 0
	for index+3 <= len(payload) {
		group := payload[index : index+3]
		if group != "|  " && group != "   " {
			break
		}
		depth++
		index += 3
	}
	rest := payload[index:]
	if !strings.HasPrefix(rest, "+- ") && !strings.HasPrefix(rest, `\- `) {
		return EffectiveDependency{}, false
	}
	rest = rest[3:]
	note := ""
	if position := strings.Index(rest, " ("); position >= 0 {
		note = strings.TrimSuffix(strings.TrimSpace(rest[position:]), ")")
		note = strings.TrimPrefix(note, "(")
		rest = strings.TrimSpace(rest[:position])
	}
	coordinate, ok := splitCoordinate(rest, true)
	if !ok {
		return EffectiveDependency{}, false
	}
	return EffectiveDependency{
		GroupID: coordinate.GroupID, ArtifactID: coordinate.ArtifactID, Type: coordinate.Type,
		Classifier: coordinate.Classifier, Version: coordinate.Version, Scope: coordinate.Scope,
		Depth: depth + 1, Direct: depth == 0,
		Omitted: strings.Contains(note, "omitted"), Note: note,
	}, true
}

func splitCoordinate(value string, withScope bool) (mavenCoordinate, bool) {
	parts := strings.Split(value, ":")
	minimum := 4
	if withScope {
		minimum = 5
	}
	if len(parts) < minimum {
		return mavenCoordinate{}, false
	}
	coordinate := mavenCoordinate{GroupID: parts[0], ArtifactID: parts[1], Type: parts[2]}
	if withScope {
		coordinate.Scope = parts[len(parts)-1]
		coordinate.Version = parts[len(parts)-2]
		if len(parts) >= 6 {
			coordinate.Classifier = strings.Join(parts[3:len(parts)-2], ":")
		}
	} else {
		coordinate.Version = parts[len(parts)-1]
		if len(parts) >= 5 {
			coordinate.Classifier = strings.Join(parts[3:len(parts)-1], ":")
		}
	}
	if coordinate.GroupID == "" || coordinate.ArtifactID == "" || coordinate.Version == "" {
		return mavenCoordinate{}, false
	}
	return coordinate, true
}

func lastMavenError(output string) string {
	lines := strings.Split(output, "\n")
	var errors []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[ERROR]") {
			errors = append(errors, strings.TrimSpace(strings.TrimPrefix(trimmed, "[ERROR]")))
			if len(errors) >= 5 {
				break
			}
		}
	}
	joined := strings.Join(errors, " | ")
	if len(joined) > 2000 {
		joined = joined[:2000]
	}
	if joined == "" {
		return "maven failed without a parsed [ERROR] line"
	}
	return joined
}

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		return len(data), nil
	}
	if len(data) > remaining {
		_, _ = b.buffer.Write(data[:remaining])
		return len(data), nil
	}
	_, _ = b.buffer.Write(data)
	return len(data), nil
}

func (b *boundedBuffer) String() string { return b.buffer.String() }
