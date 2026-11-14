// Package sarif converts TRIDENT's static finding report into a deterministic
// SARIF 2.1.0 log for CI consumption. It does not add, upgrade or execute any
// finding; runtime_status remains not_run.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"trident/internal/findings"
)

const (
	SchemaVersion = "2.1.0"
	SchemaURI     = "https://json.schemastore.org/sarif-2.1.0.json"
	ToolName      = "TRIDENT"
)

// GitHub code scanning consumes security-severity (0.0-10.0) to classify
// results and precision/tags for rule metadata. The mapping below is fixed and
// derived only from the static status; runtime evidence never raises it.
const (
	SecuritySeverityConfirmed    = "7.5" // >= 7 renders as "high"
	SecuritySeverityInconclusive = "3.0" // < 4 renders as "low" alongside "note"
	SecuritySeverityRefuted      = "0.0" // renders as "none"; negative control only
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
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          PropertyBag       `json:"properties,omitempty"`
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
				"cwe":               finding.CWE,
				"category":          finding.Category,
				"runtime_status":    "not_run",
				"analysis_origin":   strings.Join(finding.SourceAnalyses, ","),
				"security-severity": securitySeverityFor(finding.Status),
				"precision":         precisionFor(finding.Status),
				"problem.severity":  levelFor(finding.Status),
				"problem.precision": precisionFor(finding.Status),
				"tags":              ruleTags(finding),
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
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": locationFingerprint(ruleID(finding), locations[0]),
			},
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

// securitySeverityFor maps the static status onto the GitHub code scanning
// 0.0-10.0 scale. Inconclusive results stay below the "medium" threshold so an
// unconfirmed hypothesis can never surface above its evidence.
func securitySeverityFor(status string) string {
	switch status {
	case "static_confirmed":
		return SecuritySeverityConfirmed
	case "refuted":
		return SecuritySeverityRefuted
	default:
		return SecuritySeverityInconclusive
	}
}

// precisionFor mirrors the reviewer-facing semantics: only a statically
// confirmed dataflow deserves "high" precision; everything else is advisory.
func precisionFor(status string) string {
	if status == "static_confirmed" {
		return "high"
	}
	return "low"
}

// ruleTags classifies a rule for GitHub code scanning: the "security" tag
// enables the security view, and a parseable CWE tag links the rule to the
// GitHub Advisory Database.
func ruleTags(finding findings.Finding) []string {
	tags := []string{"security"}
	if number, ok := cweNumber(finding.CWE); ok {
		tags = append(tags, "CWE-"+strconv.Itoa(number))
	}
	return tags
}

func cweNumber(cwe string) (int, bool) {
	value := strings.TrimSpace(strings.ToUpper(cwe))
	if !strings.HasPrefix(value, "CWE-") {
		return 0, false
	}
	number, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(value, "CWE-")))
	if err != nil || number <= 0 {
		return 0, false
	}
	return number, true
}

// locationFingerprint derives the deterministic GitHub "primaryLocationLineHash"
// from the rule id and primary location, so code scanning can merge alerts
// across uploads without any runtime state.
func locationFingerprint(rule string, location Location) string {
	primary := location.PhysicalLocation
	seed := fmt.Sprintf("%s|%s|%d", rule, primary.ArtifactLocation.URI, primary.Region.StartLine)
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:16])
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
