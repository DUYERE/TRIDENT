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

	"trident/internal/sca"
)

const (
	SchemaVersion = 1
	ToolVersion   = "0.2.0-p0.2+r2-sbom-cyclonedx-1.5"
	SpecVersion   = "1.5"
	BOMFormat     = "CycloneDX"
)

type Options struct {
	SnapshotHash string
	ToolVersion  string
	Partial      bool
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
	Properties []Property `json:"properties,omitempty"`
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
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
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
	for _, ref := range refs {
		component := components[ref]
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
		vulnerability := Vulnerability{
			BOMRef:      "trident:advisory:" + match.AdvisoryID + ":" + ref,
			ID:          match.AdvisoryID,
			Source:      Source{Name: "TRIDENT local advisory catalog"},
			Ratings:     []Rating{{Severity: "unknown", Method: "other", Justification: "declared version only; runtime exploitation not verified"}},
			Description: "Declared dependency " + match.Dependency + " " + match.DeclaredVersion + " matches an exact advisory version case.",
			Detail:      "Declaration-level exact-version match. Dependency reachability, classpath and runtime exploitation are unverified; runtime_status=not_run.",
			Analysis:    Analysis{State: "in_triage", Detail: "Requires runtime and reachability evidence before any impact conclusion."},
			Affects:     []Affect{{Ref: ref}},
			Properties:  []Property{{Name: "trident:runtime_status", Value: "not_run"}},
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

func metadataProperties(report sca.Report, opts Options) []Property {
	properties := []Property{
		{Name: "trident:snapshot_hash", Value: opts.SnapshotHash},
		{Name: "trident:runtime_status", Value: "not_run"},
		{Name: "trident:sca_resolution", Value: "declaration_only"},
		{Name: "trident:transitive_tree", Value: "not_available"},
		{Name: "trident:dependency_reachability", Value: "unverified"},
		{Name: "trident:partial", Value: fmt.Sprintf("%t", opts.Partial || report.Partial)},
	}
	for _, limitation := range report.Limitations {
		properties = append(properties, Property{Name: "trident:limitation", Value: limitation})
	}
	sortProperties(properties)
	return properties
}

func componentRef(dependency sca.Dependency) string {
	if dependency.Version != "" && safePURLPart(dependency.Version) {
		return "pkg:maven/" + refPart(dependency.GroupID, dependency.ArtifactID) + "@" + dependency.Version
	}
	return "trident:maven:" + refPart(dependency.GroupID, dependency.ArtifactID)
}

func purl(dependency sca.Dependency) string {
	if dependency.Version == "" || !safePURLPart(dependency.Version) || !safePURLPart(dependency.GroupID) || !safePURLPart(dependency.ArtifactID) {
		return ""
	}
	return "pkg:maven/" + refPart(dependency.GroupID, dependency.ArtifactID) + "@" + dependency.Version
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
		if dependency.Module == match.Module && dependency.GroupID+":"+dependency.ArtifactID == match.Dependency && dependency.Version == match.DeclaredVersion {
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
