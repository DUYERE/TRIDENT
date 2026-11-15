// Package sca performs bounded, declaration-level Maven analysis on a pinned
// source snapshot. It never executes Maven, resolves artifacts or inspects the
// runtime classpath; every result states those limits explicitly.
package sca

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"trident/internal/project"
)

const (
	SchemaVersion = 1
	ToolVersion   = "0.2.0-p0.2+r2-sca-declarations-v3-artifact-hash"

	MaxPOMBytes             = 512 << 10
	MaxPOMCount             = 512
	MaxXMLTokens            = 200_000
	MaxXMLDepth             = 64
	MaxProperties           = 4096
	MaxPropertyValue        = 4096
	MaxPropertyDepth        = 16
	MaxDependenciesPerPOM   = 4096
	MaxAdvisoryBytes        = 1 << 20
	MaxAdvisoryFiles        = 512
	MaxAdvisoryVersionCases = 256
)

var (
	ErrLimit       = errors.New("SCA analysis limit")
	ErrUnsafePOM   = errors.New("unsafe or malformed Maven POM")
	ErrAdvisory    = errors.New("invalid advisory fixture")
	ErrUnavailable = errors.New("SCA analysis unavailable")
)

type Options struct {
	// AdvisoryPath is an explicit local advisory JSON file supplied by the
	// caller. Repository content is never treated as an advisory catalog.
	AdvisoryPath string
	// AdvisoryDir loads every *.json catalog directly inside one directory,
	// sorted by name. It is mutually exclusive with AdvisoryPath and exists so
	// callers do not have to concatenate catalogs by hand.
	AdvisoryDir string
	// MavenRepo and GradleUserHome are explicit local artifact repositories
	// used only to hash already-present jars/poms. Nothing is downloaded.
	MavenRepo      string
	GradleUserHome string
	// HashCatalogPath is an explicit local SHA-256 catalog. A mismatch is
	// reported as evidence, never as a vulnerability verdict.
	HashCatalogPath string
}

type Report struct {
	SchemaVersion   int             `json:"schema_version"`
	ToolVersion     string          `json:"tool_version"`
	SnapshotHash    string          `json:"snapshot_hash"`
	AnalysisKind    string          `json:"analysis_kind"`
	Partial         bool            `json:"partial"`
	Project         Project         `json:"project"`
	Modules         []Module        `json:"modules"`
	Dependencies    []Dependency    `json:"dependencies"`
	Artifacts       []Artifact      `json:"artifacts"`
	Advisories      []AdvisoryInfo  `json:"advisories"`
	AdvisoryMatches []AdvisoryMatch `json:"advisory_matches"`
	Coverage        Coverage        `json:"coverage"`
	Limitations     []string        `json:"limitations"`
}

type Project struct {
	BuildSystem     string   `json:"build_system"`
	RootPOMs        []string `json:"root_poms"`
	RootGradleFiles []string `json:"root_gradle_files,omitempty"`
	GradleFileCount int      `json:"gradle_file_count"`
	ModuleCount     int      `json:"module_count"`
	POMCount        int      `json:"pom_count"`
}

type Module struct {
	POM         string   `json:"pom"`
	Directory   string   `json:"directory"`
	GroupID     string   `json:"group_id"`
	ArtifactID  string   `json:"artifact_id"`
	Version     string   `json:"version"`
	Packaging   string   `json:"packaging"`
	Parent      string   `json:"parent,omitempty"`
	Aggregator  bool     `json:"aggregator"`
	ModuleDirs  []string `json:"module_directories,omitempty"`
	ProjectDeps []string `json:"project_dependencies,omitempty"`
	VersionNote string   `json:"version_note,omitempty"`
}

type Dependency struct {
	Module         string `json:"module"`
	GroupID        string `json:"group_id"`
	ArtifactID     string `json:"artifact_id"`
	Version        string `json:"version,omitempty"`
	Scope          string `json:"scope"`
	Type           string `json:"type"`
	Optional       bool   `json:"optional"`
	Direct         bool   `json:"direct"`
	DeclarationPOM string `json:"declaration_pom"`
	ManagementPOM  string `json:"management_pom,omitempty"`
	PropertyPOM    string `json:"property_pom,omitempty"`
	Property       string `json:"property,omitempty"`
	VersionStatus  string `json:"version_status"`
	VersionReason  string `json:"version_reason,omitempty"`
	Duplicate      bool   `json:"duplicate,omitempty"`
}

type AdvisoryInfo struct {
	AdvisoryID                       string   `json:"advisory_id"`
	Aliases                          []string `json:"aliases,omitempty"`
	AliasesComplete                  bool     `json:"aliases_complete"`
	Package                          string   `json:"package"`
	SourceID                         string   `json:"source_id,omitempty"`
	Policy                           string   `json:"policy,omitempty"`
	RetrievedDate                    string   `json:"retrieved_date,omitempty"`
	VersionCaseCount                 int      `json:"version_case_count"`
	RangeCaseCount                   int      `json:"range_case_count"`
	AllCVEsChecked                   bool     `json:"all_cves_checked"`
	ArtifactHashesAvailable          bool     `json:"artifact_hashes_available"`
	EffectiveDependencyTreeAvailable bool     `json:"effective_dependency_tree_available"`
	RuntimeExploitTestAvailable      bool     `json:"runtime_exploit_test_available"`
}

type AdvisoryMatch struct {
	AdvisoryID        string   `json:"advisory_id"`
	Aliases           []string `json:"aliases,omitempty"`
	Module            string   `json:"module"`
	Dependency        string   `json:"dependency"`
	DeclaredVersion   string   `json:"declared_version,omitempty"`
	VersionStatus     string   `json:"version_status"`
	SupplyChainStatus string   `json:"supply_chain_status"`
	FindingStatus     string   `json:"finding_status"`
	MatchedBy         string   `json:"matched_by,omitempty"`
	AssessmentScope   string   `json:"assessment_scope,omitempty"`
	Reason            string   `json:"reason,omitempty"`
	RuntimeStatus     string   `json:"runtime_status"`
	InputReachability string   `json:"input_reachability"`
}

type Coverage struct {
	POMsScanned            int    `json:"poms_scanned"`
	POMsRejected           int    `json:"poms_rejected"`
	GradleFilesScanned     int    `json:"gradle_files_scanned"`
	GradleFilesRejected    int    `json:"gradle_files_rejected"`
	AdvisoriesLoaded       int    `json:"advisories_loaded"`
	DependenciesDeclared   int    `json:"dependencies_declared"`
	DependenciesResolved   int    `json:"dependencies_resolved"`
	DependenciesUnresolved int    `json:"dependencies_unresolved"`
	TransitiveTree         string `json:"transitive_tree"`
	ArtifactHashes         string `json:"artifact_hashes"`
	MavenExecuted          bool   `json:"maven_executed"`
	RuntimeStatus          string `json:"runtime_status"`
}

// Inspect parses every snapshot POM, resolves only local declarations, and
// optionally matches exact versions against a caller-supplied advisory file.
// Snapshot integrity/read errors abort; individual malformed POMs are reported
// as partial coverage instead of being silently dropped.
func Inspect(ctx context.Context, snapshot *project.Snapshot, opts Options) (Report, error) {
	if snapshot == nil || snapshot.Hash() == "" {
		return Report{}, fmt.Errorf("%w: pinned snapshot required", ErrUnavailable)
	}
	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   ToolVersion,
		SnapshotHash:  snapshot.Hash(),
		AnalysisKind:  "declaration_inventory",
		Project:       Project{BuildSystem: "unknown", RootPOMs: []string{}, RootGradleFiles: []string{}, ModuleCount: 0},
		Modules:       []Module{},
		Dependencies:  []Dependency{},
		Artifacts:     []Artifact{},
		Advisories:    []AdvisoryInfo{},
		Coverage: Coverage{
			TransitiveTree: "not_available",
			ArtifactHashes: "not_available",
			MavenExecuted:  false,
			RuntimeStatus:  "not_run",
		},
		Limitations: []string{
			"build_tools_not_executed: declarations only; no effective dependency tree, profiles, BOM imports, conflict mediation or repository resolution",
			"transitive_dependencies_unavailable: only direct declarations are reported",
			"runtime_status_not_run: declared versions do not prove classpath, reachability or exploitability",
			"source_callsites_not_analyzed: no AST or taint analysis in this slice",
		},
	}

	var pomPaths, gradlePaths []string
	for _, entry := range snapshot.Manifest().Entries {
		base := path.Base(entry.Path)
		switch base {
		case "pom.xml":
			pomPaths = append(pomPaths, entry.Path)
		case "build.gradle", "build.gradle.kts":
			gradlePaths = append(gradlePaths, entry.Path)
		}
	}
	sort.Strings(pomPaths)
	sort.Strings(gradlePaths)
	report.Project.POMCount = len(pomPaths)
	report.Project.GradleFileCount = len(gradlePaths)
	if len(pomPaths) == 0 && len(gradlePaths) == 0 {
		report.Limitations = append(report.Limitations, "no_maven_pom_found", "no_gradle_build_file_found", "artifact_hashes_unavailable")
		sort.Strings(report.Limitations)
		report.Limitations = dedupe(report.Limitations)
		return report, nil
	}
	if len(pomPaths) > MaxPOMCount {
		return Report{}, fmt.Errorf("%w: POM count exceeds %d", ErrLimit, MaxPOMCount)
	}

	dependencies := []Dependency{}
	if len(pomPaths) > 0 {
		models := make(map[string]*pomModel, len(pomPaths))
		for _, pomPath := range pomPaths {
			if err := ctx.Err(); err != nil {
				return Report{}, err
			}
			data, err := snapshot.ReadFile(ctx, pomPath)
			if err != nil {
				return Report{}, err
			}
			model, err := parsePOM(pomPath, data)
			if err != nil {
				report.Partial = true
				report.Coverage.POMsRejected++
				report.Limitations = append(report.Limitations, "rejected_pom:"+pomPath+":"+pomErrorReason(err))
				continue
			}
			models[pomPath] = model
		}
		report.Coverage.POMsScanned = len(models)

		r := newResolution(models)
		for _, pomPath := range sortedKeys(models) {
			r.resolve(models[pomPath])
		}
		r.applyModuleEdges()
		if len(r.problems) > 0 {
			report.Partial = true
			report.Limitations = append(report.Limitations, r.problems...)
		}

		modules, rootPOMs, moduleCount := buildModules(models, r)
		report.Modules = modules
		report.Project.RootPOMs = rootPOMs
		report.Project.ModuleCount = moduleCount
		dependencies = append(dependencies, buildDependencies(models, r)...)
	}

	if len(gradlePaths) > 0 {
		gradleFiles, gradleDependencies, rejected, problems, err := inspectGradle(ctx, snapshot)
		if err != nil {
			return Report{}, err
		}
		report.Coverage.GradleFilesScanned = len(gradleFiles)
		report.Coverage.GradleFilesRejected = rejected
		report.Partial = report.Partial || rejected > 0 || len(problems) > 0
		report.Limitations = append(report.Limitations, problems...)
		report.Modules = append(report.Modules, gradleModules(gradleFiles)...)
		report.Project.ModuleCount += len(gradleFiles)
		for _, file := range gradleFiles {
			root := true
			for _, other := range gradleFiles {
				if other.Path != file.Path && gradleDirAncestor(file.Directory, other.Directory) {
					root = false
					break
				}
			}
			if root {
				report.Project.RootGradleFiles = append(report.Project.RootGradleFiles, file.Path)
			}
		}
		sort.Strings(report.Project.RootGradleFiles)
		for _, dependency := range gradleDependencies {
			dependencies = append(dependencies, Dependency{
				Module:         dependency.Directory,
				GroupID:        dependency.GroupID,
				ArtifactID:     dependency.ArtifactID,
				Version:        dependency.Version,
				Scope:          dependency.Configuration,
				Type:           "jar",
				Direct:         true,
				DeclarationPOM: dependency.File,
				VersionStatus:  dependency.VersionStatus,
				VersionReason:  dependency.VersionReason,
			})
		}
		sortDependencies(dependencies)
	}

	switch {
	case len(pomPaths) > 0 && len(gradlePaths) > 0:
		report.Project.BuildSystem = "Maven+Gradle"
		report.AnalysisKind = "maven_gradle_declaration_inventory"
	case len(pomPaths) > 0:
		report.Project.BuildSystem = "Maven"
		report.AnalysisKind = "maven_declaration_inventory"
	default:
		report.Project.BuildSystem = "Gradle"
		report.AnalysisKind = "gradle_declaration_inventory"
	}
	if len(gradlePaths) > 0 {
		report.Limitations = append(report.Limitations, "gradle_not_executed: common Groovy/Kotlin dependency notations only; no plugins, settings evaluation, version catalogs, BOM/platform resolution or transitive configurations")
	}
	report.Dependencies = dependencies
	report.Coverage.DependenciesDeclared = len(dependencies)
	for _, dep := range dependencies {
		if dep.VersionStatus == "resolved" {
			report.Coverage.DependenciesResolved++
		} else {
			report.Coverage.DependenciesUnresolved++
		}
	}
	artifacts, artifactStatus, artifactLimitations, artifactPartial, err := collectArtifacts(ctx, dependencies, ArtifactOptions{
		MavenRepo: opts.MavenRepo, GradleUserHome: opts.GradleUserHome, HashCatalogPath: opts.HashCatalogPath,
	})
	if err != nil {
		return Report{}, err
	}
	report.Artifacts = artifacts
	report.Coverage.ArtifactHashes = artifactStatus
	report.Partial = report.Partial || artifactPartial
	report.Limitations = append(report.Limitations, artifactLimitations...)

	if opts.AdvisoryPath != "" && opts.AdvisoryDir != "" {
		return Report{}, fmt.Errorf("%w: use either an advisory file or a directory", ErrAdvisory)
	}
	advisories, err := loadAdvisories(opts.AdvisoryPath)
	if err != nil {
		return Report{}, err
	}
	directoryAdvisories, err := loadAdvisoryDir(opts.AdvisoryDir)
	if err != nil {
		return Report{}, err
	}
	advisories = append(advisories, directoryAdvisories...)
	report.Coverage.AdvisoriesLoaded = len(advisories)
	report.Advisories = advisoryInfo(advisories)
	if len(advisories) == 0 {
		report.Limitations = append(report.Limitations, "advisory_matching_disabled: no explicit advisory catalog supplied")
	} else {
		report.Limitations = append(report.Limitations, "advisory_matching_declared_cases: exact versions and caller-declared ranges only; no transitive or runtime inference")
	}
	report.AdvisoryMatches = matchAdvisories(dependencies, advisories)

	sort.Strings(report.Limitations)
	report.Limitations = dedupe(report.Limitations)
	return report, nil
}

func gradleModules(files []gradleFile) []Module {
	modules := make([]Module, 0, len(files))
	for _, file := range files {
		parent := ""
		for _, other := range files {
			if other.Path == file.Path || !gradleDirAncestor(file.Directory, other.Directory) {
				continue
			}
			if parent == "" || len(other.Directory) > len(path.Dir(parent)) {
				parent = other.Path
			}
		}
		modules = append(modules, Module{
			POM:         file.Path,
			Directory:   file.Directory,
			GroupID:     file.GroupID,
			ArtifactID:  file.Name,
			Version:     file.Version,
			Packaging:   "jar",
			Parent:      parent,
			Aggregator:  false,
			ProjectDeps: file.ProjectDeps,
		})
	}
	return modules
}

func gradleDirAncestor(fileDir, candidate string) bool {
	if fileDir == candidate {
		return false
	}
	if candidate == "." {
		return fileDir != "."
	}
	return strings.HasPrefix(fileDir, candidate+"/")
}

func sortDependencies(dependencies []Dependency) {
	sort.Slice(dependencies, func(i, j int) bool {
		a, b := dependencies[i], dependencies[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.GroupID != b.GroupID {
			return a.GroupID < b.GroupID
		}
		if a.ArtifactID != b.ArtifactID {
			return a.ArtifactID < b.ArtifactID
		}
		if a.DeclarationPOM != b.DeclarationPOM {
			return a.DeclarationPOM < b.DeclarationPOM
		}
		return a.Version < b.Version
	})
}

// ---------------------------------------------------------------------------
// XML parsing

type xmlProject struct {
	XMLName              xml.Name      `xml:"project"`
	GroupID              string        `xml:"groupId"`
	ArtifactID           string        `xml:"artifactId"`
	Version              string        `xml:"version"`
	Packaging            string        `xml:"packaging"`
	Parent               *xmlParent    `xml:"parent"`
	Properties           xmlProperties `xml:"properties"`
	DependencyManagement struct {
		Dependencies []xmlDependency `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
	Dependencies []xmlDependency `xml:"dependencies>dependency"`
	Modules      []string        `xml:"modules>module"`
}

type xmlParent struct {
	GroupID      string `xml:"groupId"`
	ArtifactID   string `xml:"artifactId"`
	Version      string `xml:"version"`
	RelativePath string `xml:"relativePath"`
}

type xmlDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
	Classifier string `xml:"classifier"`
	Optional   string `xml:"optional"`
}

type xmlProperties map[string]string

func (p *xmlProperties) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	values := make(map[string]string)
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			if len(values) >= MaxProperties {
				return fmt.Errorf("%w: property count", ErrLimit)
			}
			var text string
			if err := decoder.DecodeElement(&text, &value); err != nil {
				return err
			}
			name := value.Name.Local
			if _, exists := values[name]; exists {
				return fmt.Errorf("%w: duplicate property", ErrUnsafePOM)
			}
			text = strings.TrimSpace(text)
			if len(text) > MaxPropertyValue {
				return fmt.Errorf("%w: property value", ErrLimit)
			}
			values[name] = text
		case xml.EndElement:
			if value.Name == start.Name {
				*p = values
				return nil
			}
		}
	}
}

type pomModel struct {
	Path         string
	Dir          string
	GroupID      string
	ArtifactID   string
	Version      string
	Packaging    string
	Parent       *xmlParent
	Properties   map[string]string
	Management   []xmlDependency
	Dependencies []xmlDependency
	Modules      []string
}

func parsePOM(pomPath string, data []byte) (*pomModel, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty POM", ErrUnsafePOM)
	}
	if len(data) > MaxPOMBytes {
		return nil, fmt.Errorf("%w: POM exceeds %d bytes", ErrLimit, MaxPOMBytes)
	}
	// A UTF-8 BOM is not content and must not make an otherwise valid POM fail.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	if err := validateXML(data); err != nil {
		return nil, err
	}
	var raw xmlProject
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: XML decode", ErrUnsafePOM)
	}
	if len(raw.Dependencies) > MaxDependenciesPerPOM || len(raw.DependencyManagement.Dependencies) > MaxDependenciesPerPOM {
		return nil, fmt.Errorf("%w: dependency count", ErrLimit)
	}
	model := &pomModel{
		Path:         pomPath,
		Dir:          path.Dir(pomPath),
		GroupID:      strings.TrimSpace(raw.GroupID),
		ArtifactID:   strings.TrimSpace(raw.ArtifactID),
		Version:      strings.TrimSpace(raw.Version),
		Packaging:    strings.TrimSpace(raw.Packaging),
		Parent:       raw.Parent,
		Properties:   map[string]string(raw.Properties),
		Management:   raw.DependencyManagement.Dependencies,
		Dependencies: raw.Dependencies,
	}
	// Maven never inherits artifactId; a POM without it cannot identify a module.
	if model.ArtifactID == "" {
		return nil, fmt.Errorf("%w: artifactId is required", ErrUnsafePOM)
	}
	if model.Packaging == "" {
		model.Packaging = "jar"
	}
	for _, module := range raw.Modules {
		module = strings.TrimSpace(module)
		if module != "" {
			model.Modules = append(model.Modules, module)
		}
	}
	return model, nil
}

// validateXML rejects DTD/entity directives, multiple roots and pathological
// nesting before any typed decoding. Go does not expand external entities, but
// repository XML is still untrusted data and unsupported constructs fail closed.
func validateXML(data []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	depth, tokens := 0, 0
	rootSeen, rootClosed := false, false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: malformed XML", ErrUnsafePOM)
		}
		tokens++
		if tokens > MaxXMLTokens {
			return fmt.Errorf("%w: XML token count", ErrLimit)
		}
		switch value := token.(type) {
		case xml.Directive:
			return fmt.Errorf("%w: XML directives are not permitted", ErrUnsafePOM)
		case xml.StartElement:
			if rootClosed {
				return fmt.Errorf("%w: trailing XML root", ErrUnsafePOM)
			}
			if !rootSeen {
				rootSeen = true
				if value.Name.Local != "project" {
					return fmt.Errorf("%w: root element must be project", ErrUnsafePOM)
				}
			}
			depth++
			if depth > MaxXMLDepth {
				return fmt.Errorf("%w: XML depth", ErrLimit)
			}
		case xml.EndElement:
			depth--
			if depth == 0 {
				rootClosed = true
			}
		case xml.CharData:
			if rootClosed && len(bytes.TrimSpace(value)) != 0 {
				return fmt.Errorf("%w: trailing XML content", ErrUnsafePOM)
			}
		}
	}
	if !rootSeen || !rootClosed || depth != 0 {
		return fmt.Errorf("%w: incomplete XML", ErrUnsafePOM)
	}
	return nil
}

func pomErrorReason(err error) string {
	switch {
	case errors.Is(err, ErrLimit):
		return "limit"
	case errors.Is(err, ErrUnsafePOM):
		return "unsafe_or_malformed"
	default:
		return "unreadable"
	}
}

// ---------------------------------------------------------------------------
// Local model resolution

type coordinates struct {
	GroupID    string
	ArtifactID string
	Version    string
}

type propertySet struct {
	Values map[string]string
	Origin map[string]string
}

type managementEntry struct {
	GroupID    string
	ArtifactID string
	Type       string
	Classifier string
	Version    string
	Scope      string
	POMPath    string
}

type resolution struct {
	models      map[string]*pomModel
	visiting    map[string]bool
	coords      map[string]coordinates
	props       map[string]propertySet
	parent      map[string]string
	management  map[string]map[string]managementEntry
	problems    []string
	moduleEdges map[string][]string
}

func newResolution(models map[string]*pomModel) *resolution {
	return &resolution{
		models:      models,
		visiting:    make(map[string]bool),
		coords:      make(map[string]coordinates, len(models)),
		props:       make(map[string]propertySet, len(models)),
		parent:      make(map[string]string, len(models)),
		management:  make(map[string]map[string]managementEntry, len(models)),
		moduleEdges: make(map[string][]string),
	}
}

func (r *resolution) problem(code string) {
	r.problems = append(r.problems, code)
}

func (r *resolution) resolve(model *pomModel) (coordinates, propertySet) {
	if cached, ok := r.coords[model.Path]; ok {
		return cached, r.props[model.Path]
	}
	if r.visiting[model.Path] {
		r.problem("parent_cycle:" + model.Path)
		return coordinates{GroupID: model.GroupID, ArtifactID: model.ArtifactID, Version: model.Version}, localProperties(model)
	}
	r.visiting[model.Path] = true
	defer delete(r.visiting, model.Path)

	coords := coordinates{GroupID: model.GroupID, ArtifactID: model.ArtifactID, Version: model.Version}
	props := localProperties(model)
	if model.Parent != nil {
		parentPath := parentPOM(model)
		switch {
		case parentPath == "":
			r.problem("parent_unresolved:" + model.Path)
		case r.models[parentPath] == nil:
			r.problem("parent_missing:" + model.Path)
		case r.visiting[parentPath]:
			// Never create a parent edge back into the active chain: later
			// management inheritance would recurse forever.
			r.problem("parent_cycle:" + model.Path)
		default:
			parentCoords, parentProps := r.resolve(r.models[parentPath])
			if parentMatches(model.Parent, parentCoords) {
				r.parent[model.Path] = parentPath
				if coords.GroupID == "" {
					coords.GroupID = parentCoords.GroupID
				}
				if coords.Version == "" {
					coords.Version = parentCoords.Version
				}
				for name, value := range parentProps.Values {
					props.Values[name] = value
					props.Origin[name] = parentProps.Origin[name]
				}
			} else {
				r.problem("parent_coordinates_mismatch:" + model.Path)
			}
		}
	}
	// Child properties override inherited values; origin tracks the defining POM.
	for name, value := range model.Properties {
		props.Values[name] = value
		props.Origin[name] = model.Path
	}
	builtins := map[string]string{
		"project.groupId": coords.GroupID, "pom.groupId": coords.GroupID,
		"project.artifactId": coords.ArtifactID, "pom.artifactId": coords.ArtifactID,
		"project.version": coords.Version, "pom.version": coords.Version,
	}
	if resolved, missing := interpolate(coords.GroupID, props.Values, builtins, 0); missing == "" {
		coords.GroupID = resolved
	}
	if resolved, missing := interpolate(coords.Version, props.Values, builtins, 0); missing == "" {
		coords.Version = resolved
	}
	r.coords[model.Path] = coords
	r.props[model.Path] = props
	return coords, props
}

func localProperties(model *pomModel) propertySet {
	props := propertySet{Values: make(map[string]string, len(model.Properties)), Origin: make(map[string]string, len(model.Properties))}
	for name, value := range model.Properties {
		props.Values[name] = value
		props.Origin[name] = model.Path
	}
	return props
}

func parentPOM(model *pomModel) string {
	if model.Parent == nil {
		return ""
	}
	relative := strings.TrimSpace(model.Parent.RelativePath)
	if relative == "" {
		relative = "../pom.xml"
	}
	relative = strings.ReplaceAll(relative, "\\", "/")
	if strings.HasPrefix(relative, "/") {
		return ""
	}
	clean := path.Clean(path.Join(model.Dir, relative))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return ""
	}
	if path.Base(clean) != "pom.xml" {
		clean = path.Join(clean, "pom.xml")
	}
	return clean
}

func parentMatches(declaration *xmlParent, parent coordinates) bool {
	if declaration.GroupID != "" && declaration.GroupID != parent.GroupID {
		return false
	}
	if declaration.ArtifactID != "" && declaration.ArtifactID != parent.ArtifactID {
		return false
	}
	if declaration.Version != "" && declaration.Version != parent.Version {
		return false
	}
	return true
}

func interpolate(value string, properties, builtins map[string]string, depth int) (string, string) {
	if depth > MaxPropertyDepth {
		return "", "<depth>"
	}
	var out strings.Builder
	for index := 0; index < len(value); {
		start := strings.Index(value[index:], "${")
		if start < 0 {
			out.WriteString(value[index:])
			break
		}
		start += index
		out.WriteString(value[index:start])
		end := strings.IndexByte(value[start+2:], '}')
		if end < 0 {
			return "", "<syntax>"
		}
		end += start + 2
		name := value[start+2 : end]
		if name == "" {
			return "", "<syntax>"
		}
		raw, ok := properties[name]
		if !ok {
			raw, ok = builtins[name]
		}
		if !ok {
			return "", name
		}
		resolved, missing := interpolate(raw, properties, builtins, depth+1)
		if missing != "" {
			return "", missing
		}
		out.WriteString(resolved)
		if out.Len() > MaxPropertyValue {
			return "", "<size>"
		}
		index = end + 1
	}
	return out.String(), ""
}

func (r *resolution) applyModuleEdges() {
	for _, pomPath := range sortedKeys(r.models) {
		model := r.models[pomPath]
		for _, module := range model.Modules {
			modulePath := path.Clean(path.Join(model.Dir, strings.ReplaceAll(module, "\\", "/")))
			if modulePath == "." || modulePath == ".." || strings.HasPrefix(modulePath, "../") {
				r.problem("module_invalid:" + pomPath)
				continue
			}
			if path.Base(modulePath) != "pom.xml" {
				modulePath = path.Join(modulePath, "pom.xml")
			}
			if r.models[modulePath] == nil {
				r.problem("module_missing:" + modulePath)
				continue
			}
			r.moduleEdges[pomPath] = append(r.moduleEdges[pomPath], modulePath)
		}
	}
}

func (r *resolution) managementFor(model *pomModel) map[string]managementEntry {
	if cached, ok := r.management[model.Path]; ok {
		return cached
	}
	entries := make(map[string]managementEntry)
	if parentPath := r.parent[model.Path]; parentPath != "" {
		for key, entry := range r.managementFor(r.models[parentPath]) {
			entries[key] = entry
		}
	}
	for _, dependency := range model.Management {
		entry, ok := managementEntryFrom(dependency, model.Path)
		if !ok {
			r.problem("invalid_management:" + model.Path)
			continue
		}
		entries[managementKey(entry.GroupID, entry.ArtifactID, entry.Type, entry.Classifier)] = entry
	}
	r.management[model.Path] = entries
	return entries
}

func managementEntryFrom(dependency xmlDependency, pomPath string) (managementEntry, bool) {
	groupID := strings.TrimSpace(dependency.GroupID)
	artifactID := strings.TrimSpace(dependency.ArtifactID)
	if groupID == "" || artifactID == "" {
		return managementEntry{}, false
	}
	entry := managementEntry{
		GroupID:    groupID,
		ArtifactID: artifactID,
		Type:       defaultType(dependency.Type),
		Classifier: strings.TrimSpace(dependency.Classifier),
		Version:    strings.TrimSpace(dependency.Version),
		Scope:      strings.TrimSpace(dependency.Scope),
		POMPath:    pomPath,
	}
	return entry, true
}

func managementKey(groupID, artifactID, dependencyType, classifier string) string {
	return groupID + ":" + artifactID + ":" + dependencyType + ":" + classifier
}

func buildModules(models map[string]*pomModel, r *resolution) ([]Module, []string, int) {
	modules := make([]Module, 0, len(models))
	roots := []string{}
	moduleCount := 0
	for _, pomPath := range sortedKeys(models) {
		model := models[pomPath]
		coords, _ := r.resolve(model)
		packaging := defaultPackaging(model.Packaging)
		moduleDirs := make([]string, 0, len(r.moduleEdges[pomPath]))
		for _, modulePath := range r.moduleEdges[pomPath] {
			moduleDirs = append(moduleDirs, path.Dir(modulePath))
		}
		sort.Strings(moduleDirs)
		module := Module{
			POM:        pomPath,
			Directory:  model.Dir,
			GroupID:    coords.GroupID,
			ArtifactID: coords.ArtifactID,
			Version:    coords.Version,
			Packaging:  packaging,
			Parent:     r.parent[pomPath],
			Aggregator: packaging == "pom" && len(moduleDirs) > 0,
			ModuleDirs: moduleDirs,
		}
		if module.Parent == "" {
			roots = append(roots, pomPath)
		}
		if packaging != "pom" {
			moduleCount++
		}
		modules = append(modules, module)
	}
	sort.Strings(roots)
	return modules, roots, moduleCount
}

func buildDependencies(models map[string]*pomModel, r *resolution) []Dependency {
	dependencies := []Dependency{}
	for _, pomPath := range sortedKeys(models) {
		model := models[pomPath]
		coords, props := r.resolve(model)
		builtins := map[string]string{
			"project.groupId": coords.GroupID, "pom.groupId": coords.GroupID,
			"project.artifactId": coords.ArtifactID, "pom.artifactId": coords.ArtifactID,
			"project.version": coords.Version, "pom.version": coords.Version,
		}
		management := r.managementFor(model)
		seen := make(map[string]bool)
		for _, declaration := range model.Dependencies {
			groupID := strings.TrimSpace(declaration.GroupID)
			artifactID := strings.TrimSpace(declaration.ArtifactID)
			if groupID == "" || artifactID == "" {
				r.problem("invalid_dependency:" + pomPath)
				continue
			}
			dependencyType := defaultType(declaration.Type)
			classifier := strings.TrimSpace(declaration.Classifier)
			scope := strings.TrimSpace(declaration.Scope)
			versionExpression := strings.TrimSpace(declaration.Version)
			managementPOM := ""
			if versionExpression == "" {
				if entry, ok := management[managementKey(groupID, artifactID, dependencyType, classifier)]; ok {
					versionExpression = entry.Version
					managementPOM = entry.POMPath
					if scope == "" {
						scope = entry.Scope
					}
				}
			}
			if scope == "" {
				scope = "compile"
			}
			dependency := Dependency{
				Module:         model.Dir,
				GroupID:        groupID,
				ArtifactID:     artifactID,
				Scope:          scope,
				Type:           dependencyType,
				Optional:       strings.EqualFold(strings.TrimSpace(declaration.Optional), "true"),
				Direct:         true,
				DeclarationPOM: pomPath,
				ManagementPOM:  managementPOM,
				VersionStatus:  "unresolved",
			}
			property, propertyPOM := usedProperty(versionExpression, props)
			if property != "" {
				dependency.Property = property
				dependency.PropertyPOM = propertyPOM
			}
			if versionExpression == "" {
				dependency.VersionReason = "missing_version"
			} else if resolved, missing := interpolate(versionExpression, props.Values, builtins, 0); missing != "" {
				dependency.VersionReason = "unresolved_property:" + missing
			} else if resolved = strings.TrimSpace(resolved); resolved == "" {
				dependency.VersionReason = "empty_version"
			} else {
				dependency.Version = resolved
				dependency.VersionStatus = "resolved"
			}
			key := managementKey(groupID, artifactID, dependencyType, classifier)
			if seen[key] {
				dependency.Duplicate = true
			}
			seen[key] = true
			dependencies = append(dependencies, dependency)
		}
	}
	sort.Slice(dependencies, func(i, j int) bool {
		a, b := dependencies[i], dependencies[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.GroupID != b.GroupID {
			return a.GroupID < b.GroupID
		}
		if a.ArtifactID != b.ArtifactID {
			return a.ArtifactID < b.ArtifactID
		}
		if a.DeclarationPOM != b.DeclarationPOM {
			return a.DeclarationPOM < b.DeclarationPOM
		}
		return a.Version < b.Version
	})
	return dependencies
}

// usedProperty records the first property actually referenced by a version
// expression and the POM where its effective value was defined.
func usedProperty(expression string, props propertySet) (string, string) {
	for index := 0; index < len(expression); {
		start := strings.Index(expression[index:], "${")
		if start < 0 {
			break
		}
		start += index
		end := strings.IndexByte(expression[start+2:], '}')
		if end < 0 {
			break
		}
		end += start + 2
		name := expression[start+2 : end]
		if origin, ok := props.Origin[name]; ok {
			return name, origin
		}
		index = end + 1
	}
	return "", ""
}

func defaultType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "jar"
	}
	return value
}

func defaultPackaging(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "jar"
	}
	return value
}

func sortedKeys(models map[string]*pomModel) []string {
	keys := make([]string, 0, len(models))
	for key := range models {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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
