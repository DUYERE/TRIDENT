// Package sarif converts TRIDENT's static finding report into a deterministic
// SARIF 2.1.0 log for CI consumption. It does not add, upgrade or execute any
// finding; runtime_status remains not_run.
package sarif

import (
	"fmt"
	"sort"
	"strings"

	"trident/internal/findings"
)

const (
	SchemaVersion = "2.1.0"
	SchemaURI     = "https://json.schemastore.org/sarif-2.1.0.json"
	ToolName      = "TRIDENT"
)

type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool       Tool        `json:"tool"`
	Results    []Result    `json:"results"`
	Properties PropertyBag `json:"properties,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID               string      `json:"id"`
	Name             string      `json:"name,omitempty"`
	ShortDescription Message     `json:"shortDescription"`
	FullDescription  Message     `json:"fullDescription,omitempty"`
	HelpURI          string      `json:"helpUri,omitempty"`
	DefaultConfig    RuleConfig  `json:"defaultConfiguration"`
	Properties       PropertyBag `json:"properties,omitempty"`
}

type RuleConfig struct {
	Level string `json:"level"`
}

type Message struct {
	Text string `json:"text"`
}

type Result struct {
	RuleID     string      `json:"ruleId"`
	RuleIndex  int         `json:"ruleIndex"`
	Level      string      `json:"level"`
	Message    Message     `json:"message"`
	Locations  []Location  `json:"locations"`
	Properties PropertyBag `json:"properties,omitempty"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region,omitempty"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

type PropertyBag map[string]any

type ruleMeta struct {
	rule findings.Finding
}

// Build converts one findings report. Refuted findings are emitted at level
// "none" so CI consumers can see the negative control without treating it as a
// vulnerability.
func Build(report findings.Report, toolVersion string) (Log, error) {
	if report.SnapshotHash == "" {
		return Log{}, fmt.Errorf("sarif requires a snapshot hash")
	}
	version := toolVersion
	if version == "" {
		version = report.ToolVersion
	}
	rules := map[string]ruleMeta{}
	for _, finding := range report.Findings {
		id := ruleID(finding)
		if existing, ok := rules[id]; !ok || finding.CWE < existing.rule.CWE {
			rules[id] = ruleMeta{rule: finding}
		}
	}
	ruleIDs := make([]string, 0, len(rules))
	for id := range rules {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	index := make(map[string]int, len(ruleIDs))
	driverRules := make([]Rule, 0, len(ruleIDs))
	for position, id := range ruleIDs {
		index[id] = position
		finding := rules[id].rule
		driverRules = append(driverRules, Rule{
			ID:               id,
			Name:             finding.Kind,
			ShortDescription: Message{Text: finding.Category},
			FullDescription:  Message{Text: finding.Title},
			DefaultConfig:    RuleConfig{Level: levelFor(finding.Status)},
			Properties: PropertyBag{
				"cwe":             finding.CWE,
				"category":        finding.Category,
				"runtime_status":  "not_run",
				"analysis_origin": strings.Join(finding.SourceAnalyses, ","),
			},
		})
	}
	results := make([]Result, 0, len(report.Findings))
	for _, finding := range report.Findings {
		locations := resultLocations(finding)
		if len(locations) == 0 {
			continue
		}
		results = append(results, Result{
			RuleID:    ruleID(finding),
			RuleIndex: index[ruleID(finding)],
			Level:     levelFor(finding.Status),
			Message:   Message{Text: resultMessage(finding)},
			Locations: locations,
			Properties: PropertyBag{
				"finding_id":     finding.ID,
				"kind":           finding.Kind,
				"category":       finding.Category,
				"cwe":            finding.CWE,
				"status":         finding.Status,
				"runtime_status": finding.RuntimeStatus,
				"severity":       finding.Severity,
			},
		})
	}
	sort.SliceStable(results, func(i, j int) bool {
		left, right := results[i], results[j]
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		leftURI, rightURI := left.Locations[0].PhysicalLocation.ArtifactLocation.URI, right.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if leftURI != rightURI {
			return leftURI < rightURI
		}
		return left.Locations[0].PhysicalLocation.Region.StartLine < right.Locations[0].PhysicalLocation.Region.StartLine
	})
	return Log{
		Schema:  SchemaURI,
		Version: SchemaVersion,
		Runs: []Run{{
			Tool:    Tool{Driver: Driver{Name: ToolName, Version: version, Rules: driverRules}},
			Results: results,
			Properties: PropertyBag{
				"snapshot_hash":  report.SnapshotHash,
				"analysis_kind":  report.AnalysisKind,
				"partial":        report.Partial,
				"runtime_status": report.Coverage.RuntimeStatus,
				"limitations":    report.Limitations,
			},
		}},
	}, nil
}

func ruleID(finding findings.Finding) string {
	kind := finding.Kind
	if kind == "" {
		kind = finding.CWE
	}
	return "trident/" + kind
}

func levelFor(status string) string {
	switch status {
	case "static_confirmed":
		return "warning"
	case "refuted":
		return "none"
	default:
		return "note"
	}
}

func resultMessage(finding findings.Finding) string {
	location := ""
	if finding.Endpoint != nil {
		location = " at " + finding.Endpoint.Path
	}
	if finding.Component != nil {
		location = " in " + finding.Component.Dependency + " " + finding.Component.DeclaredVersion
	}
	return fmt.Sprintf("%s%s: %s. Static status=%s; runtime_status=%s.", finding.Category, location, finding.Title, finding.Status, finding.RuntimeStatus)
}

func resultLocations(finding findings.Finding) []Location {
	var locations []Location
	seen := map[string]bool{}
	for _, evidence := range finding.Evidence {
		if evidence.File == "" || evidence.StartLine < 1 {
			continue
		}
		end := evidence.EndLine
		if end < evidence.StartLine {
			end = evidence.StartLine
		}
		key := fmt.Sprintf("%s:%d:%d", evidence.File, evidence.StartLine, end)
		if seen[key] {
			continue
		}
		seen[key] = true
		locations = append(locations, Location{PhysicalLocation: PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: evidence.File},
			Region:           Region{StartLine: evidence.StartLine, EndLine: end},
		}})
	}
	return locations
}
