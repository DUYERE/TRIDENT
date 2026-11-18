// Package sbom converts the declaration-level Maven report into a deterministic
// CycloneDX 1.5 JSON document. It never executes Maven, resolves a dependency
// tree or claims runtime reachability.
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"trident/internal/reach"
	"trident/internal/sca"
)

const (
	SchemaVersion = 1
	ToolVersion   = "0.2.0-p0.2+r2-sbom-cyclonedx-1.5-artifact-hash"
	SpecVersion   = "1.5"
	BOMFormat     = "CycloneDX"
)

type Options struct {
	SnapshotHash string
	ToolVersion  string
	Partial      bool
	// Reachability carries the caller-provided bounded call-graph results keyed
	// by module, dependency and declared version. Only results computed in this
	// process are accepted; the SBOM never invents reachability itself.
	Reachability map[string]reach.Reachability
}

type Document struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	SerialNumber    string          `json:"serialNumber"`
	Version         int             `json:"version"`
	Metadata        Metadata        `json:"metadata"`
	Components      []Component     `json:"components"`
	Dependencies    []Dependency    `json:"dependencies"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type Metadata struct {
	Tools      Tools      `json:"tools"`
	Component  Component  `json:"component"`
	Properties []Property `json:"properties,omitempty"`
}

type Tools struct {
	Components []Component `json:"components"`
}

type Component struct {
	Type       string     `json:"type"`
	BOMRef     string     `json:"bom-ref"`
	Group      string     `json:"group,omitempty"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Hashes     []Hash     `json:"hashes,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

// Hash is a CycloneDX hash object. Only locally observed SHA-256 values are
// emitted; caller-catalog hashes remain evidence in the SCA report, not SBOM
// provenance.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

type Vulnerability struct {
	BOMRef      string     `json:"bom-ref,omitempty"`
	ID          string     `json:"id"`
	Source      Source     `json:"source,omitempty"`
	Ratings     []Rating   `json:"ratings,omitempty"`
	Description string     `json:"description,omitempty"`
	Detail      string     `json:"detail,omitempty"`
	Analysis    Analysis   `json:"analysis"`
	Affects     []Affect   `json:"affects,omitempty"`
	Properties  []Property `json:"properties,omitempty"`
}

type Source struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type Rating struct {
	Severity      string `json:"severity"`
	Method        string `json:"method,omitempty"`
	Justification string `json:"justification,omitempty"`
}

type Analysis struct {
	State         string `json:"state"`
	Justification string `json:"justification,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type Affect struct {
	Ref string `json:"ref"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Build normalizes the SCA declaration report into a stable CycloneDX BOM.
// Serial numbers are derived from the snapshot hash so identical inputs produce
// byte-identical documents; no wall-clock timestamp is embedded.
func Build(report sca.Report, opts Options) (Document, error) {
	if len(opts.SnapshotHash) != 64 {
		return Document{}, fmt.Errorf("sbom requires a pinned snapshot hash")
	}
	if _, err := hex.DecodeString(opts.SnapshotHash); err != nil {
		return Document{}, fmt.Errorf("invalid snapshot hash")
	}
	toolVersion := opts.ToolVersion
	if toolVersion == "" {
		toolVersion = ToolVersion
	}
	rootRef := "trident:snapshot:" + opts.SnapshotHash
	document := Document{
		BOMFormat:    BOMFormat,
		SpecVersion:  SpecVersion,
		SerialNumber: serialNumber(opts.SnapshotHash),
		Version:      1,
		Metadata: Metadata{
			Tools: Tools{Components: []Component{{
				Type: "application", BOMRef: "trident:tool:" + toolVersion,
				Name: "TRIDENT", Version: toolVersion,
			}}},
			Component: Component{
				Type: "application", BOMRef: rootRef, Name: "TRIDENT pinned source snapshot",
				Version: opts.SnapshotHash,
			},
			Properties: metadataProperties(report, opts),
		},
		Components:   []Component{},
		Dependencies: []Dependency{},
	}

	components := map[string]*Component{}
	for _, dependency := range report.Dependencies {
		if dependency.ArtifactID == "" {
			continue
		}
		ref := componentRef(dependency)
		component, exists := components[ref]
		if !exists {
			component = &Component{
				Type: "library", BOMRef: ref, Group: dependency.GroupID, Name: dependency.ArtifactID,
				Version: dependency.Version, PURL: purl(dependency),
			}
			components[ref] = component
		}
		if dependency.Module != "" {
			component.Properties = appendUnique(component.Properties, Property{Name: "trident:module", Value: dependency.Module})
		}
		if dependency.DeclarationPOM != "" {
			component.Properties = appendUnique(component.Properties, Property{Name: "trident:declaration_pom", Value: dependency.DeclarationPOM})
		}
		if dependency.VersionStatus != "" {
			component.Properties = appendUnique(component.Properties, Property{Name: "trident:version_status", Value: dependency.VersionStatus})
		}
		component.Properties = appendUnique(component.Properties, Property{Name: "trident:runtime_status", Value: "not_run"})
	}
	refs := make([]string, 0, len(components))
	for ref := range components {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	hashes := artifactHashes(report)
	for _, ref := range refs {
		component := components[ref]
		if observed, ok := hashes[ref]; ok {
			component.Hashes = observed
		}
		sortProperties(component.Properties)
		document.Components = append(document.Components, *component)
	}
	document.Dependencies = append(document.Dependencies, Dependency{Ref: rootRef, DependsOn: append([]string{}, refs...)})
	sort.Strings(document.Dependencies[0].DependsOn)
	for _, ref := range refs {
		document.Dependencies = append(document.Dependencies, Dependency{Ref: ref})
	}

	for _, match := range report.AdvisoryMatches {
		if match.FindingStatus != "candidate" {
			continue
		}
		dependency := findDependency(report.Dependencies, match)
		ref := componentRef(dependency)
		if _, ok := components[ref]; !ok {
			continue
		}
		reachItem, hasReach := opts.Reachability[vexKey(match)]
		analysis, reachProperties := vexAnalysis(match, reachItem, hasReach)
		vulnerability := Vulnerability{
			BOMRef:      "trident:advisory:" + match.AdvisoryID + ":" + ref,
			ID:          match.AdvisoryID,
			Source:      Source{Name: "TRIDENT local advisory catalog"},
			Ratings:     []Rating{{Severity: "unknown", Method: "other", Justification: "declared version only; runtime exploitation not verified"}},
			Description: "Declared dependency " + match.Dependency + " " + match.DeclaredVersion + " matches an exact advisory version case.",
			Detail:      "Declaration-level exact-version match. Dependency reachability, classpath and runtime exploitation are unverified; runtime_status=not_run.",
			Analysis:    analysis,
			Affects:     []Affect{{Ref: ref}},
			Properties:  append([]Property{{Name: "trident:runtime_status", Value: "not_run"}}, reachProperties...),
		}
		document.Vulnerabilities = append(document.Vulnerabilities, vulnerability)
	}
	sort.Slice(document.Vulnerabilities, func(i, j int) bool {
		if document.Vulnerabilities[i].ID != document.Vulnerabilities[j].ID {
			return document.Vulnerabilities[i].ID < document.Vulnerabilities[j].ID
		}
		return document.Vulnerabilities[i].BOMRef < document.Vulnerabilities[j].BOMRef
	})
	return document, nil
}

// vexAnalysis derives the CycloneDX VEX analysis from the caller-supplied
// bounded call-graph result. The mapping is deliberately conservative:
// "unreachable" is a bounded-graph negative, so it only yields
// not_affected/code_not_reachable with its boundary spelled out; a reachable
// path never upgrades to "exploitable" because static evidence cannot prove
// runtime exploitation, and every unknown reason stays in triage.
func vexAnalysis(match sca.AdvisoryMatch, item reach.Reachability, hasReach bool) (Analysis, []Property) {
	if !hasReach {
		return Analysis{State: "in_triage", Detail: "Requires runtime and reachability evidence before any impact conclusion."}, nil
	}
	properties := []Property{
		{Name: "trident:reachability", Value: item.Reachability},
		{Name: "trident:reachability_tool", Value: item.RuntimeStatus},
	}
	switch item.Reachability {
	case "unreachable":
		properties = append(properties, Property{Name: "trident:reachability_claim", Value: item.Reason})
		return Analysis{
			State:         "not_affected",
			Justification: "code_not_reachable",
			Detail:        "No path from any inventoried HTTP entrypoint to this dependency in the bounded import/type-ref graph (depth " + fmt.Sprint(reach.MaxPathDepth) + " hops). Reflection, dynamic dispatch, framework wiring and external configuration stay outside this claim; runtime_status=not_run.",
		}, properties
	case "reachable":
		properties = append(properties, Property{Name: "trident:reachability_claim", Value: item.Reason})
		return Analysis{
			State:  "in_triage",
			Detail: "Bounded entry call graph found an entry-to-import path (" + fmt.Sprint(len(item.Paths)) + " path(s)); static reachability does not prove runtime exploitation. runtime_status=not_run.",
		}, properties
	default:
		properties = append(properties, Property{Name: "trident:reachability_claim", Value: item.Reason})
		return Analysis{
			State:  "in_triage",
			Detail: "Bounded call graph could not decide reachability: " + item.Reason + ". runtime_status=not_run.",
		}, properties
	}
}

func vexKey(match sca.AdvisoryMatch) string {
	return match.Module + "\x00" + match.Dependency + "\x00" + match.DeclaredVersion
}

func metadataProperties(report sca.Report, opts Options) []Property {
	reachProperty := "unverified"
	if len(opts.Reachability) > 0 {
		reachProperty = "bounded_entry_call_graph"
	}
	properties := []Property{
		{Name: "trident:snapshot_hash", Value: opts.SnapshotHash},
		{Name: "trident:runtime_status", Value: "not_run"},
		{Name: "trident:sca_resolution", Value: "declaration_only"},
		{Name: "trident:artifact_hashes", Value: report.Coverage.ArtifactHashes},
		{Name: "trident:transitive_tree", Value: "not_available"},
		{Name: "trident:dependency_reachability", Value: reachProperty},
		{Name: "trident:vex_basis", Value: reachProperty},
		{Name: "trident:partial", Value: fmt.Sprintf("%t", opts.Partial || report.Partial)},
	}
	for _, limitation := range report.Limitations {
		properties = append(properties, Property{Name: "trident:limitation", Value: limitation})
	}
	sortProperties(properties)
	return properties
}

func componentRef(dependency sca.Dependency) string {
	if dependency.Ecosystem != "" {
		if value := purl(dependency); value != "" {
			return value
		}
		return "trident:" + dependency.Ecosystem + ":" + dependency.Name
	}
	return mavenRef(dependency.GroupID, dependency.ArtifactID, dependency.Version)
}

func mavenRef(group, artifact, version string) string {
	if version != "" && safePURLPart(version) {
		return "pkg:maven/" + refPart(group, artifact) + "@" + version
	}
	return "trident:maven:" + refPart(group, artifact)
}

// artifactHashes maps observed local artifact hashes onto component refs. A
// component may have both jar and pom hashes; duplicates are removed and the
// values are stable-ordered.
func artifactHashes(report sca.Report) map[string][]Hash {
	index := map[string][]Hash{}
	for _, artifact := range report.Artifacts {
		if artifact.Status != "observed" || artifact.SHA256 == "" {
			continue
		}
		ref := mavenRef(artifact.GroupID, artifact.ArtifactID, artifact.Version)
		hash := Hash{Alg: "SHA-256", Content: artifact.SHA256}
		duplicate := false
		for _, existing := range index[ref] {
			if existing == hash {
				duplicate = true
				break
			}
		}
		if !duplicate {
			index[ref] = append(index[ref], hash)
		}
	}
	for ref := range index {
		sort.Slice(index[ref], func(i, j int) bool {
			return index[ref][i].Content < index[ref][j].Content
		})
	}
	return index
}

func purl(dependency sca.Dependency) string {
	if dependency.Version == "" || !safePURLPart(dependency.Version) {
		return ""
	}
	switch dependency.Ecosystem {
	case "npm":
		name := dependency.Name
		if name == "" {
			name = refPart(dependency.GroupID, dependency.ArtifactID)
		}
		return purlWithNamespace("npm", npmNamespace(name), npmName(name), dependency.Version)
	case "composer":
		return purlWithNamespace("composer", dependency.GroupID, dependency.ArtifactID, dependency.Version)
	case "nuget":
		return purlWithNamespace("nuget", "", dependency.ArtifactID, dependency.Version)
	case "pip", "python":
		name := dependency.Name
		if name == "" {
			name = dependency.ArtifactID
		}
		return purlWithNamespace("pypi", "", strings.ToLower(name), dependency.Version)
	case "go":
		module := dependency.Name
		if module == "" {
			module = refPart(dependency.GroupID, dependency.ArtifactID)
		}
		return purlWithNamespace("golang", "", module, dependency.Version)
	}
	if !safePURLPart(dependency.GroupID) || !safePURLPart(dependency.ArtifactID) {
		return ""
	}
	return "pkg:maven/" + refPart(dependency.GroupID, dependency.ArtifactID) + "@" + dependency.Version
}

func purlWithNamespace(kind, namespace, name, version string) string {
	if name == "" || !safePURLPath(name) || (namespace != "" && !safePURLPath(namespace)) {
		return ""
	}
	if namespace == "" {
		return "pkg:" + kind + "/" + name + "@" + version
	}
	return "pkg:" + kind + "/" + namespace + "/" + name + "@" + version
}

func npmNamespace(name string) string {
	if index := strings.Index(name, "/"); strings.HasPrefix(name, "@") && index > 0 {
		return strings.ReplaceAll(name[:index], "@", "%40")
	}
	return ""
}

func npmName(name string) string {
	if index := strings.Index(name, "/"); strings.HasPrefix(name, "@") && index > 0 {
		return name[index+1:]
	}
	return name
}

func safePURLPath(value string) bool {
	for _, r := range value {
		if r <= ' ' || r == '\\' || r == '?' || r == '#' || r == '@' {
			return false
		}
	}
	return true
}

func refPart(group, artifact string) string {
	if group == "" {
		return artifact
	}
	return group + "/" + artifact
}

func safePURLPart(value string) bool {
	if value == "" {
		return true
	}
	for _, r := range value {
		if r <= ' ' || r == '/' || r == '\\' || r == '?' || r == '#' || r == '%' || r == '@' || r == ':' {
			return false
		}
	}
	return true
}

func findDependency(dependencies []sca.Dependency, match sca.AdvisoryMatch) sca.Dependency {
	for _, dependency := range dependencies {
		name := dependency.Name
		if name == "" {
			name = dependency.GroupID + ":" + dependency.ArtifactID
		}
		if dependency.Module == match.Module && (name == match.Dependency || dependency.GroupID+":"+dependency.ArtifactID == match.Dependency) && dependency.Version == match.DeclaredVersion {
			return dependency
		}
	}
	return sca.Dependency{GroupID: strings.SplitN(match.Dependency, ":", 2)[0], ArtifactID: match.Dependency, Version: match.DeclaredVersion}
}

func appendUnique(properties []Property, property Property) []Property {
	for _, existing := range properties {
		if existing == property {
			return properties
		}
	}
	return append(properties, property)
}

func sortProperties(properties []Property) {
	sort.Slice(properties, func(i, j int) bool {
		if properties[i].Name != properties[j].Name {
			return properties[i].Name < properties[j].Name
		}
		return properties[i].Value < properties[j].Value
	})
}

func serialNumber(snapshotHash string) string {
	sum := sha256.Sum256([]byte("trident-sbom-v1:" + snapshotHash))
	bytes := sum[:16]
	bytes[6] = (bytes[6] & 0x0f) | 0x50
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}
