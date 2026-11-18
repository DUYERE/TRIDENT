package dataflow

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"text/scanner"

	"trident/internal/project"
)

// Sink anchoring scans every project method, not only HTTP endpoints. An
// anchor is a code location that needs human review; it is never an
// exploitability claim because no attacker-controlled source is proven.

const (
	SinkAnchorToolVersion = "0.2.0-p0.5+r1-sink-anchor-v1"
	SinkAnchorKind        = "sink_anchored_v1"
	MaxSinkAnchors        = 2000
)

type SinkAnchorReport struct {
	SchemaVersion int          `json:"schema_version"`
	ToolVersion   string       `json:"tool_version"`
	SnapshotHash  string       `json:"snapshot_hash"`
	AnalysisKind  string       `json:"analysis_kind"`
	Partial       bool         `json:"partial"`
	Anchors       []SinkAnchor `json:"anchors"`
	Coverage      SinkCoverage `json:"coverage"`
	Limitations   []string     `json:"limitations"`
}

type SinkAnchor struct {
	ID                 string           `json:"id"`
	Category           string           `json:"category"`
	CWE                string           `json:"cwe"`
	Status             string           `json:"status"`
	Severity           string           `json:"severity"`
	RuntimeStatus      string           `json:"runtime_status"`
	EvidenceStrength   string           `json:"evidence_strength"`
	API                string           `json:"api"`
	File               string           `json:"file"`
	SHA256             string           `json:"sha256"`
	Line               int              `json:"line"`
	Class              string           `json:"class"`
	Method             string           `json:"method"`
	Symbol             string           `json:"symbol"`
	ParameterReachable bool             `json:"parameter_reachable"`
	Parameters         []string         `json:"parameters,omitempty"`
	Evidence           []AnchorEvidence `json:"evidence"`
	Limitations        []string         `json:"limitations"`
}

type AnchorEvidence struct {
	Kind   string `json:"kind"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Line   int    `json:"line"`
	Detail string `json:"detail,omitempty"`
}

type SinkCoverage struct {
	FilesScanned   int           `json:"files_scanned"`
	FilesRejected  int           `json:"files_rejected"`
	MethodsScanned int           `json:"methods_scanned"`
	Anchors        int           `json:"anchors"`
	ByCategory     []AnchorCount `json:"by_category"`
	RuntimeStatus  string        `json:"runtime_status"`
}

type AnchorCount struct {
	Key   string `json:"key"`
	Value int    `json:"value"`
}

type sinkAnchorRule struct {
	names       []string
	category    categorySpec
	requireType []string
}

var sinkAnchorRules = []sinkAnchorRule{
	{names: []string{"readObject", "readUnshared", "deserialize"}, category: deserializationCategory},
	{names: []string{"parseExpression"}, category: templateCategory},
	{names: []string{"executeQuery", "executeUpdate", "createNativeQuery", "queryForObject", "queryForList", "createQuery"}, category: sqlCategory},
	{names: []string{"exec"}, category: commandCategory},
	{names: []string{"transferTo"}, category: uploadCategory},
	{names: []string{"parse", "read", "transform", "unmarshal", "build", "parseText"}, category: xxeCategory,
		requireType: []string{"DocumentBuilder", "SAXParser", "SAXReader", "XMLReader", "Transformer", "Unmarshaller", "SAXBuilder", "Digester"}},
	{names: []string{"openConnection", "openStream", "getForObject", "exchange"}, category: ssrfCategory},
	{names: []string{"search", "lookup", "authenticate"}, category: ldapCategory,
		requireType: []string{"DirContext", "InitialDirContext", "LdapTemplate", "LdapContext"}},
	{names: []string{"readAllBytes", "readString", "readAllLines", "newInputStream", "newOutputStream"}, category: pathCategory},
}

// InspectSinks returns a deterministic, endpoint-independent sink inventory.
// covered optionally removes (file:line) pairs already represented by endpoint
// findings when the report is merged into `audit dataflow`.
func InspectSinks(ctx context.Context, snapshot *project.Snapshot, covered map[string]bool) (SinkAnchorReport, error) {
	if snapshot == nil || snapshot.Hash() == "" {
		return SinkAnchorReport{}, fmt.Errorf("%w: pinned snapshot required", ErrLimit)
	}
	report := SinkAnchorReport{
		SchemaVersion: SchemaVersion, ToolVersion: SinkAnchorToolVersion,
		SnapshotHash: snapshot.Hash(), AnalysisKind: SinkAnchorKind,
		Anchors:  []SinkAnchor{},
		Coverage: SinkCoverage{RuntimeStatus: "not_run", ByCategory: []AnchorCount{}},
		Limitations: []string{
			"no_proven_source: a method parameter is not proof of attacker-controlled input; every anchor stays inconclusive",
			"sink_declaration_only: the API name and its arguments were observed in source, not executed",
			"no_endpoint_required: methods without HTTP annotations are scanned, including main, scheduled jobs and listeners",
			"no_call_graph: framework registration, reflection, dependency injection and cross-method flows are not resolved",
			"no_runtime_verification: runtime_status is always not_run",
			"absence_is_not_safety: no anchor at a location does not mean the code is safe",
		},
	}
	files, rejected, problems, err := parseProject(ctx, snapshot)
	if err != nil {
		return SinkAnchorReport{}, err
	}
	report.Partial = rejected > 0
	if rejected > 0 {
		report.Limitations = append(report.Limitations, "parse_rejected_files")
	}
	report.Limitations = append(report.Limitations, problems...)
	index := newProjectModel(files)
	report.Coverage.FilesScanned = len(files)
	report.Coverage.FilesRejected = rejected
	report.Coverage.MethodsScanned = index.methodCount
	byCategory := map[string]int{}
	seen := map[string]bool{}
	for _, file := range files {
		select {
		case <-ctx.Done():
			return SinkAnchorReport{}, ctx.Err()
		default:
		}
		for _, class := range file.Classes {
			for _, method := range class.Methods {
				if method.BodyStart < 0 || method.BodyEnd <= method.BodyStart {
					continue
				}
				for _, anchor := range anchorsInMethod(method, covered) {
					key := strings.Join([]string{anchor.File, fmt.Sprintf("%d", anchor.Line), anchor.API, anchor.CWE}, ":")
					if seen[key] {
						continue
					}
					seen[key] = true
					if len(report.Anchors) >= MaxSinkAnchors {
						report.Partial = true
						report.Limitations = append(report.Limitations, "sink_anchor_limit")
						break
					}
					report.Anchors = append(report.Anchors, anchor)
					byCategory[anchor.Category]++
				}
			}
		}
	}
	sort.Slice(report.Anchors, func(i, j int) bool {
		a, b := report.Anchors[i], report.Anchors[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.CWE != b.CWE {
			return a.CWE < b.CWE
		}
		return a.API < b.API
	})
	keys := make([]string, 0, len(byCategory))
	for key := range byCategory {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		report.Coverage.ByCategory = append(report.Coverage.ByCategory, AnchorCount{Key: key, Value: byCategory[key]})
	}
	report.Coverage.Anchors = len(report.Anchors)
	sort.Strings(report.Limitations)
	report.Limitations = dedupe(report.Limitations)
	return report, nil
}

func anchorsInMethod(method *methodModel, covered map[string]bool) []SinkAnchor {
	out := []SinkAnchor{}
	tokens := method.File.Tokens
	localTypes := map[string]string{}
	parameters := make([]string, 0, len(method.Params))
	for _, param := range method.Params {
		localTypes[param.Name] = param.Type
		parameters = append(parameters, param.Name)
	}
	for i := method.BodyStart + 1; i < method.BodyEnd; i++ {
		if tokens[i].Text != "(" || i <= method.BodyStart+1 {
			continue
		}
		nameIndex := i - 1
		if tokens[nameIndex].Tok != scanner.Ident {
			continue
		}
		name := tokens[nameIndex].Text
		close := matchDelimiter(tokens, i, "(", ")")
		if close < 0 || close >= method.BodyEnd {
			continue
		}
		receiver, _ := callReceiver(tokens, nameIndex, method.BodyStart)
		typeName := receiverType(method, receiver, localTypes)
		rule, ok := anchorRuleFor(name, typeName, tokens, nameIndex)
		if !ok {
			continue
		}
		line := tokens[nameIndex].Line
		key := fmt.Sprintf("%s:%d", method.File.Path, line)
		if covered != nil && covered[key] {
			continue
		}
		args := splitTopLevel(tokens[i+1 : close])
		argumentText := ""
		for _, arg := range args {
			for _, tok := range arg {
				argumentText += " " + tok.Text
			}
		}
		reachable := false
		for _, param := range parameters {
			if param != "" && strings.Contains(argumentText, " "+param) {
				reachable = true
				break
			}
		}
		api := callAPI(receiver, name)
		strength := "sink_observed"
		if reachable {
			strength = "parameter_reachable"
		}
		limitations := []string{
			"no_proven_source: method parameters are not proven attacker-controlled",
			"static evidence only; no request, deployment or exploitability claim",
		}
		if reachable {
			limitations = append(limitations, "parameter_reachable_lexically: argument text contains a method parameter name; no data-flow proof")
		}
		sort.Strings(limitations)
		out = append(out, SinkAnchor{
			ID:       strings.Join([]string{"sink:" + rule.category.CWE, method.File.Path, fmt.Sprintf("%d", line), api}, ":"),
			Category: rule.category.Label, CWE: rule.category.CWE,
			Status: "inconclusive", Severity: "unknown", RuntimeStatus: "not_run",
			EvidenceStrength: strength, API: api,
			File: method.File.Path, SHA256: method.File.SHA256, Line: line,
			Class: method.Class.Name, Method: method.Name,
			Symbol:             method.Class.Name + "." + method.Name,
			ParameterReachable: reachable, Parameters: parameters,
			Evidence: []AnchorEvidence{
				{Kind: "sink", File: method.File.Path, SHA256: method.File.SHA256, Line: line, Detail: api},
				{Kind: "method", File: method.File.Path, SHA256: method.File.SHA256, Line: method.Line, Detail: method.Class.Name + "." + method.Name},
			},
			Limitations: limitations,
		})
	}
	return out
}

func anchorRuleFor(name, typeName string, tokens []javaToken, nameIndex int) (sinkAnchorRule, bool) {
	for _, rule := range sinkAnchorRules {
		matched := false
		for _, candidate := range rule.names {
			if candidate == name {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if len(rule.requireType) > 0 {
			ok := false
			for _, allowed := range rule.requireType {
				if typeName == allowed || strings.HasSuffix(typeName, "."+allowed) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		if name == "exec" && !isRuntimeExec(tokens, nameIndex) {
			continue
		}
		return rule, true
	}
	return sinkAnchorRule{}, false
}
