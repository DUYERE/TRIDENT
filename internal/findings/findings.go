// Package findings normalizes the declaration-level Maven/SCA report, the
// annotation-level Spring MVC inventory and the bounded JDBC dataflow report
// into a single evidence-backed finding model.
//
// It never compiles or runs Java, never resolves a dependency tree, never runs
// a model and never upgrades static evidence to runtime confirmation. A
// finding's status is always a static assessment; runtime_status stays not_run
// until a separate, explicitly authorized runtime test exists.
package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"trident/internal/audit"
	"trident/internal/authz"
	"trident/internal/dataflow"
	"trident/internal/project"
	"trident/internal/sca"
)

const (
	SchemaVersion = 1
	ToolVersion   = "0.2.0-p0.2+r4-finding-evidence"

	MaxFindings = 20_000
	MaxEvidence = 256
)

var ErrLimit = errors.New("finding evidence limit")

type Options struct {
	// AdvisoryPath is an explicit local advisory catalog. Without it the report
	// still unifies endpoint and dataflow evidence but contains no SCA findings.
	AdvisoryPath string
}

type Report struct {
	SchemaVersion int       `json:"schema_version"`
	ToolVersion   string    `json:"tool_version"`
	SnapshotHash  string    `json:"snapshot_hash"`
	AnalysisKind  string    `json:"analysis_kind"`
	Partial       bool      `json:"partial"`
	Findings      []Finding `json:"findings"`
	Coverage      Coverage  `json:"coverage"`
	Limitations   []string  `json:"limitations"`
}

type Finding struct {
	ID             string        `json:"id"`
	Kind           string        `json:"kind"`
	Category       string        `json:"category"`
	CWE            string        `json:"cwe"`
	Severity       string        `json:"severity"`
	Status         string        `json:"status"`
	RuntimeStatus  string        `json:"runtime_status"`
	Title          string        `json:"title"`
	Endpoint       *EndpointRef  `json:"endpoint,omitempty"`
	Component      *ComponentRef `json:"component,omitempty"`
	Evidence       []Evidence    `json:"evidence"`
	Hypotheses     []Hypothesis  `json:"hypotheses"`
	SourceAnalyses []string      `json:"source_analyses"`
	Limitations    []string      `json:"limitations"`
}

type EndpointRef struct {
	Path        string   `json:"path"`
	HTTPMethods []string `json:"http_methods"`
	Symbol      string   `json:"symbol"`
	File        string   `json:"file"`
	SHA256      string   `json:"sha256"`
	StartLine   int      `json:"start_line"`
	EndLine     int      `json:"end_line"`
}

type ComponentRef struct {
	Module          string `json:"module"`
	Dependency      string `json:"dependency"`
	DeclaredVersion string `json:"declared_version,omitempty"`
	DeclarationPOM  string `json:"declaration_pom"`
	ManagementPOM   string `json:"management_pom,omitempty"`
	PropertyPOM     string `json:"property_pom,omitempty"`
	AdvisoryID      string `json:"advisory_id"`
}

// Evidence is one concrete, snapshot-pinned fact. Advisory evidence has no file
// or digest because the catalog is caller-supplied configuration, not source.
type Evidence struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	File       string `json:"file,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	StartLine  int    `json:"start_line,omitempty"`
	EndLine    int    `json:"end_line,omitempty"`
	Anchor     string `json:"anchor,omitempty"`
	AnchorLine int    `json:"anchor_line,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Origin     string `json:"origin"`
	OriginRef  string `json:"origin_ref,omitempty"`
}

// Hypothesis is a testable claim. Status values are supported, unsupported and
// unverified; unverified is not "false", it means the required evidence was not
// collected in this authorized scope.
type Hypothesis struct {
	ID               string   `json:"id"`
	Statement        string   `json:"statement"`
	Status           string   `json:"status"`
	EvidenceIDs      []string `json:"evidence_ids"`
	RequiredEvidence []string `json:"required_evidence,omitempty"`
	Reason           string   `json:"reason,omitempty"`
}

type Coverage struct {
	FindingsTotal           int    `json:"findings_total"`
	FindingsStaticConfirmed int    `json:"findings_static_confirmed"`
	FindingsRefuted         int    `json:"findings_refuted"`
	FindingsInconclusive    int    `json:"findings_inconclusive"`
	HypothesesSupported     int    `json:"hypotheses_supported"`
	HypothesesUnsupported   int    `json:"hypotheses_unsupported"`
	HypothesesUnverified    int    `json:"hypotheses_unverified"`
	ScaDependencies         int    `json:"sca_dependencies_declared"`
	ScaCandidates           int    `json:"sca_advisory_candidates"`
	ScaUnknown              int    `json:"sca_advisory_unknown"`
	ScaNotAffected          int    `json:"sca_advisory_not_affected"`
	EndpointsInventoried    int    `json:"endpoints_inventoried"`
	DataflowFindings        int    `json:"dataflow_findings"`
	AuthzControls           int    `json:"authz_controls"`
	AuthzUnprotected        int    `json:"authz_unprotected"`
	AuthzFindings           int    `json:"authz_findings"`
	JavaAST                 string `json:"java_ast"`
	ScaResolution           string `json:"sca_resolution"`
	TaintAnalysis           string `json:"taint_analysis"`
	RuntimeStatus           string `json:"runtime_status"`
	DependencyReachability  string `json:"dependency_reachability"`
}

// Analyze runs the three read-only analyses on the same pinned snapshot and
// links their evidence. Every sub-analysis keeps its own failure semantics:
// integrity errors abort, unsupported inputs are reported as partial.
func Analyze(ctx context.Context, snapshot *project.Snapshot, opts Options) (Report, error) {
	if snapshot == nil || snapshot.Hash() == "" {
		return Report{}, fmt.Errorf("%w: pinned snapshot required", ErrLimit)
	}
	scaReport, err := sca.Inspect(ctx, snapshot, sca.Options{AdvisoryPath: opts.AdvisoryPath})
	if err != nil {
		return Report{}, err
	}
	endpoints, err := audit.Inspect(ctx, snapshot)
	if err != nil {
		return Report{}, err
	}
	flows, err := dataflow.Analyze(ctx, snapshot)
	if err != nil {
		return Report{}, err
	}
	authzReport, err := authz.Analyze(ctx, snapshot)
	if err != nil {
		return Report{}, err
	}

	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   ToolVersion,
		SnapshotHash:  snapshot.Hash(),
		AnalysisKind:  "unified_finding_evidence_v1",
		Findings:      []Finding{},
		Coverage: Coverage{
			ScaDependencies:        len(scaReport.Dependencies),
			EndpointsInventoried:   len(endpoints.Endpoints),
			DataflowFindings:       len(flows.Findings),
			AuthzControls:          len(authzReport.Controls),
			AuthzUnprotected:       authzReport.Coverage.Unprotected,
			AuthzFindings:          len(authzReport.Findings),
			JavaAST:                "not_available",
			ScaResolution:          "declaration_only",
			TaintAnalysis:          "bounded_lexical_multi_category",
			RuntimeStatus:          "not_run",
			DependencyReachability: "unverified",
		},
		Limitations: []string{
			"static_runtime_separation: finding.status is static evidence only; runtime_status stays not_run until a separate authorized runtime test",
			"sca_declaration_only: POM declarations and exact advisory version cases; no resolved dependency tree, classpath or artifact hash",
			"advisory_exact_version_only: ranges, aliases and repository resolution remain outside this slice",
			"dependency_reachability_unverified: no dependency import graph or request-to-component call path is modeled",
			"endpoint_inventory_annotation_only: routes are annotation-level, not deployed routes",
			"dataflow_bounded_lexical: no Java AST, branch sensitivity, alias/points-to or external library implementation; non-SQL sink findings appear only when that sink is observed",
			"authz_control_inventory_lexical: annotations, XML blocks and common Java config chains are matched textually; filter-chain order, custom AOP and external gateways are not evaluated",
			"authz_unprotected_is_inconclusive: absence of a recognized control does not prove an endpoint is reachable without authentication",
			"absence_is_not_safety: inconclusive means required evidence was not collected, not that the code is safe",
			"correlation_not_exploitation: linking a dependency, an endpoint and a flow is context, not runtime proof",
		},
	}
	report.Partial = scaReport.Partial || endpoints.Partial || flows.Partial || authzReport.Partial
	if scaReport.Partial {
		report.Limitations = append(report.Limitations, "sca_report_partial")
	}
	if endpoints.Partial {
		report.Limitations = append(report.Limitations, "endpoint_inventory_partial")
	}
	if flows.Partial {
		report.Limitations = append(report.Limitations, "dataflow_report_partial")
	}
	if authzReport.Partial {
		report.Limitations = append(report.Limitations, "authz_report_partial")
	}
	if opts.AdvisoryPath == "" {
		report.Limitations = append(report.Limitations, "advisory_catalog_not_provided")
	}

	entries := entryDigests(snapshot)
	for _, flow := range flows.Findings {
		if len(report.Findings) >= MaxFindings {
			report.Partial = true
			report.Limitations = append(report.Limitations, "finding_limit")
			break
		}
		report.Findings = append(report.Findings, fromDataflow(flow))
	}
	for _, authzFinding := range authzReport.Findings {
		if len(report.Findings) >= MaxFindings {
			report.Partial = true
			report.Limitations = append(report.Limitations, "finding_limit")
			break
		}
		report.Findings = append(report.Findings, fromAuthz(authzFinding, entries))
	}

	dependencies := dependencyIndex(scaReport.Dependencies)
	for _, match := range scaReport.AdvisoryMatches {
		switch match.FindingStatus {
		case "candidate":
			report.Coverage.ScaCandidates++
			if len(report.Findings) >= MaxFindings {
				report.Partial = true
				report.Limitations = append(report.Limitations, "finding_limit")
				continue
			}
			report.Findings = append(report.Findings, fromAdvisory(match, dependencies, entries, len(endpoints.Endpoints)))
		case "none":
			report.Coverage.ScaNotAffected++
		default:
			report.Coverage.ScaUnknown++
		}
	}

	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if statusRank(a.Status) != statusRank(b.Status) {
			return statusRank(a.Status) < statusRank(b.Status)
		}
		return a.ID < b.ID
	})
	for i := range report.Findings {
		report.Coverage.FindingsTotal++
		switch report.Findings[i].Status {
		case "static_confirmed":
			report.Coverage.FindingsStaticConfirmed++
		case "refuted":
			report.Coverage.FindingsRefuted++
		default:
			report.Coverage.FindingsInconclusive++
		}
		for _, hypothesis := range report.Findings[i].Hypotheses {
			switch hypothesis.Status {
			case "supported":
				report.Coverage.HypothesesSupported++
			case "unsupported":
				report.Coverage.HypothesesUnsupported++
			default:
				report.Coverage.HypothesesUnverified++
			}
		}
	}
	sort.Strings(report.Limitations)
	report.Limitations = dedupe(report.Limitations)
	return report, nil
}

func fromDataflow(flow dataflow.Finding) Finding {
	sources := &evidenceSet{seen: map[string]string{}}
	routeID := sources.add(Evidence{
		Kind:      "route",
		File:      flow.Endpoint.File,
		SHA256:    flow.Endpoint.SHA256,
		StartLine: flow.Endpoint.StartLine,
		EndLine:   flow.Endpoint.EndLine,
		Detail:    strings.Join(flow.Endpoint.HTTPMethods, ",") + " " + flow.Endpoint.Path,
		Origin:    "audit",
		OriginRef: flow.Endpoint.Symbol,
	})
	sourceIDs := []string{}
	for _, source := range flow.Sources {
		id := sources.add(Evidence{
			Kind:      "source",
			File:      source.File,
			StartLine: source.Line,
			EndLine:   source.Line,
			Detail:    source.Type + " " + source.Parameter + " bindings=" + strings.Join(source.Bindings, ","),
			Origin:    "dataflow",
			OriginRef: flow.ID,
		})
		if id != "" {
			sourceIDs = append(sourceIDs, id)
		}
	}
	flowIDs := []string{}
	for _, step := range flow.Flow {
		id := sources.add(Evidence{
			Kind:      "flow_step",
			File:      step.File,
			SHA256:    step.SHA256,
			StartLine: step.Line,
			EndLine:   step.Line,
			Detail:    step.Kind + ": " + step.Detail,
			Origin:    "dataflow",
			OriginRef: flow.ID,
		})
		if id != "" {
			flowIDs = append(flowIDs, id)
		}
	}
	sinkID, protectionID, boundaryID := "", "", ""
	if flow.Sink != nil {
		sinkID = sources.add(Evidence{Kind: "sink", File: flow.Sink.File, SHA256: flow.Sink.SHA256, StartLine: flow.Sink.Line, EndLine: flow.Sink.Line, Detail: flow.Sink.API, Origin: "dataflow", OriginRef: flow.ID})
	}
	if flow.Protection != nil {
		protectionID = sources.add(Evidence{Kind: "protection", File: flow.Protection.File, SHA256: flow.Protection.SHA256, StartLine: flow.Protection.Line, EndLine: flow.Protection.Line, Detail: flow.Protection.API + ": " + flow.Protection.Detail, Origin: "dataflow", OriginRef: flow.ID})
	}
	if flow.Boundary != nil {
		boundaryID = sources.add(Evidence{Kind: "boundary", File: flow.Boundary.File, SHA256: flow.Boundary.SHA256, StartLine: flow.Boundary.Line, EndLine: flow.Boundary.Line, Detail: flow.Boundary.Kind + ": " + flow.Boundary.Detail, Origin: "dataflow", OriginRef: flow.ID})
	}
	for _, item := range flow.Evidence {
		sources.add(Evidence{
			Kind:       "method",
			File:       item.File,
			SHA256:     item.SHA256,
			StartLine:  item.StartLine,
			EndLine:    item.EndLine,
			Anchor:     item.Anchor,
			AnchorLine: item.AnchorLine,
			Origin:     "dataflow",
			OriginRef:  flow.ID,
		})
	}

	id := "dataflow:" + flow.ID
	parameter := ""
	if len(flow.Sources) > 0 {
		parameter = flow.Sources[0].Parameter
	}
	limitations := append([]string{}, flow.Limitations...)
	if sources.truncated {
		limitations = append(limitations, "evidence_truncated")
	}
	finding := Finding{
		ID:             id,
		Kind:           flowKind(flow),
		Category:       flow.Category,
		CWE:            flow.CWE,
		Severity:       flow.Severity,
		Status:         flow.Status,
		RuntimeStatus:  "not_run",
		Title:          fmt.Sprintf("%s in %s parameter %q", flow.Category, flow.Endpoint.Path, parameter),
		Endpoint:       &EndpointRef{Path: flow.Endpoint.Path, HTTPMethods: append([]string{}, flow.Endpoint.HTTPMethods...), Symbol: flow.Endpoint.Symbol, File: flow.Endpoint.File, SHA256: flow.Endpoint.SHA256, StartLine: flow.Endpoint.StartLine, EndLine: flow.Endpoint.EndLine},
		Evidence:       sources.items,
		SourceAnalyses: []string{"audit", "dataflow"},
		Limitations:    limitations,
	}
	hypothesisIDs := []string{routeID}
	hypothesisIDs = append(hypothesisIDs, sourceIDs...)
	hypothesisIDs = append(hypothesisIDs, sinkID, protectionID, boundaryID)
	hypothesisIDs = append(hypothesisIDs, flowIDs...)
	finding.Hypotheses = []Hypothesis{
		{
			ID:          id + ":source_to_sink",
			Statement:   flowStatement(flow),
			Status:      flowHypothesisStatus(flow.Status),
			EvidenceIDs: nonEmpty(hypothesisIDs),
			Reason:      flowHypothesisReason(flow),
		},
		{
			ID:               id + ":runtime_exploitation",
			Statement:        "the finding is exploitable in a deployed runtime context",
			Status:           "unverified",
			EvidenceIDs:      nonEmpty([]string{sinkID}),
			RequiredEvidence: []string{"runtime_reproduction", "deployed_route", "authentication_and_input_context"},
			Reason:           runtimeReason(flow.Status),
		},
	}
	if flow.Status == "refuted" && protectionID != "" {
		finding.Hypotheses = append(finding.Hypotheses, Hypothesis{
			ID:          id + ":value_binding",
			Statement:   "observed value binding prevents this parameter from changing SQL text",
			Status:      "supported",
			EvidenceIDs: []string{protectionID},
			Reason:      "only this parameter and this observed binding are covered",
		})
	}
	return finding
}

func fromAuthz(item authz.Finding, entries map[string]string) Finding {
	set := &evidenceSet{seen: map[string]string{}}
	digest := entries[item.File]
	routeID := set.add(Evidence{
		Kind: "route", File: item.File, SHA256: digest, StartLine: item.StartLine, EndLine: item.EndLine,
		Detail: strings.Join(item.HTTPMethods, ",") + " " + item.Path, Origin: "audit", OriginRef: item.Symbol,
	})
	methodID := set.add(Evidence{
		Kind: "method", File: item.File, SHA256: digest, StartLine: item.MethodLine, EndLine: item.EndLine,
		Detail: "controller method with no recognized authorization control", Origin: "authz", OriginRef: item.ID,
	})
	absenceID := set.add(Evidence{
		Kind: "control_absence", Detail: item.Reason, Origin: "authz", OriginRef: item.ID,
	})
	limitations := []string{
		"authz_control_inventory_lexical: no filter-chain order, custom AOP, Spring EL or external gateway evaluation",
		"authz_unprotected_is_inconclusive: a custom or container-level control may still protect this route",
		"runtime_not_verified: no HTTP request or deployed security configuration is exercised",
	}
	if set.truncated {
		limitations = append(limitations, "evidence_truncated")
	}
	return Finding{
		ID: item.ID, Kind: item.Kind, Category: "Broken access control", CWE: item.CWE,
		Severity: "unknown", Status: "inconclusive", RuntimeStatus: "not_run",
		Title:    "Missing authentication or authorization control on " + item.Path,
		Endpoint: &EndpointRef{Path: item.Path, HTTPMethods: append([]string{}, item.HTTPMethods...), Symbol: item.Symbol, File: item.File, SHA256: digest, StartLine: item.StartLine, EndLine: item.EndLine},
		Evidence: set.items, SourceAnalyses: []string{"audit", "authz"}, Limitations: limitations,
		Hypotheses: []Hypothesis{
			{
				ID:        item.ID + ":missing_control",
				Statement: "no authentication or authorization control covers this route",
				Status:    "unverified", EvidenceIDs: nonEmpty([]string{routeID, methodID, absenceID}),
				RequiredEvidence: []string{"controller_or_filter_chain", "deployed_security_chain", "runtime_unauthenticated_request"},
				Reason:           "static control inventory only; custom or container-level protection is unverified",
			},
			{
				ID:        item.ID + ":runtime_exploitation",
				Statement: "an unauthenticated request can access the route in a deployed runtime",
				Status:    "unverified", EvidenceIDs: nonEmpty([]string{routeID}),
				RequiredEvidence: []string{"runtime_http_response", "authentication_context", "deployed_route"},
				Reason:           "no HTTP request is executed",
			},
		},
	}
}

func fromAdvisory(match sca.AdvisoryMatch, dependencies map[string]sca.Dependency, entries map[string]string, endpoints int) Finding {
	dependency := dependencies[dependencyKey(match.Module, match.Dependency, match.DeclaredVersion)]
	set := &evidenceSet{seen: map[string]string{}}
	pomIDs := []string{}
	seenPOM := map[string]bool{}
	for _, pom := range []string{dependency.DeclarationPOM, dependency.ManagementPOM, dependency.PropertyPOM} {
		if pom == "" || seenPOM[pom] {
			continue
		}
		seenPOM[pom] = true
		id := set.add(Evidence{
			Kind:      "pom",
			File:      pom,
			SHA256:    entries[pom],
			Detail:    "declares " + match.Dependency + " " + match.DeclaredVersion,
			Origin:    "sca",
			OriginRef: match.AdvisoryID,
		})
		if id != "" {
			pomIDs = append(pomIDs, id)
		}
	}
	advisoryID := set.add(Evidence{
		Kind:      "advisory",
		Detail:    match.AdvisoryID + " exact version case matched for " + match.DeclaredVersion,
		Origin:    "sca",
		OriginRef: match.AdvisoryID,
	})

	id := "sca:" + match.AdvisoryID + ":" + match.Module + ":" + match.Dependency + ":" + match.DeclaredVersion
	limitations := []string{
		"declaration_level_only: POM declaration and exact version case; no resolved dependency tree or runtime classpath",
		"runtime_exploitation_not_verified: advisory version presence does not establish a vulnerable callsite",
		"dependency_reachability_unverified: no import graph or request-to-component call path",
	}
	if set.truncated {
		limitations = append(limitations, "evidence_truncated")
	}
	finding := Finding{
		ID:            id,
		Kind:          "vulnerable_dependency",
		Category:      "Vulnerable dependency declaration",
		CWE:           "CWE-1395",
		Severity:      "unknown",
		Status:        "inconclusive",
		RuntimeStatus: "not_run",
		Title:         fmt.Sprintf("declared dependency %s %s matches %s", match.Dependency, match.DeclaredVersion, match.AdvisoryID),
		Component: &ComponentRef{
			Module:          match.Module,
			Dependency:      match.Dependency,
			DeclaredVersion: match.DeclaredVersion,
			DeclarationPOM:  dependency.DeclarationPOM,
			ManagementPOM:   dependency.ManagementPOM,
			PropertyPOM:     dependency.PropertyPOM,
			AdvisoryID:      match.AdvisoryID,
		},
		Evidence:       set.items,
		SourceAnalyses: []string{"sca", "audit"},
		Limitations:    limitations,
	}
	evidenceIDs := append([]string{}, pomIDs...)
	if advisoryID != "" {
		evidenceIDs = append(evidenceIDs, advisoryID)
	}
	finding.Hypotheses = []Hypothesis{
		{
			ID:          id + ":declared_version_matches_advisory",
			Statement:   "the declared dependency version matches an exact advisory version case",
			Status:      "supported",
			EvidenceIDs: evidenceIDs,
		},
		{
			ID:               id + ":dependency_reachable_from_http_entrypoint",
			Statement:        "the vulnerable dependency is reachable from an inventoried HTTP entrypoint",
			Status:           "unverified",
			RequiredEvidence: []string{"dependency_import_graph", "request_to_component_call_path"},
			Reason:           fmt.Sprintf("no_dependency_import_or_call_graph; %d inventoried endpoints are context only", endpoints),
		},
		{
			ID:               id + ":runtime_exploitation",
			Statement:        "the advisory is exploitable in a deployed runtime context",
			Status:           "unverified",
			RequiredEvidence: []string{"runtime_classpath", "runtime_reproduction", "deployment_context"},
			Reason:           "runtime_status_not_run",
		},
	}
	return finding
}

func flowKind(flow dataflow.Finding) string {
	switch flow.CWE {
	case "CWE-78":
		return "command_injection"
	case "CWE-918":
		return "ssrf"
	case "CWE-22":
		return "path_traversal"
	case "CWE-1336":
		return "template_injection"
	case "CWE-79":
		return "xss"
	case "CWE-502":
		return "deserialization"
	case "CWE-611":
		return "xxe"
	case "CWE-90":
		return "ldap_injection"
	case "CWE-434":
		return "unrestricted_upload"
	}
	return "sql_injection"
}

func flowStatement(flow dataflow.Finding) string {
	switch flowKind(flow) {
	case "command_injection":
		return "an HTTP request parameter reaches an OS command execution sink through the observed static flow"
	case "ssrf":
		return "an HTTP request parameter reaches an outbound request sink through the observed static flow"
	case "path_traversal":
		return "an HTTP request parameter reaches a file access sink through the observed static flow"
	case "template_injection":
		return "an HTTP request parameter reaches a template evaluation sink through the observed static flow"
	case "xss":
		return "an HTTP request parameter reaches an HTTP response writer sink through the observed static flow"
	case "deserialization":
		return "an HTTP request parameter reaches a deserialization read sink through the observed static flow"
	case "xxe":
		return "an HTTP request parameter reaches an XML parser sink through the observed static flow"
	case "ldap_injection":
		return "an HTTP request parameter reaches an LDAP query sink through the observed static flow"
	case "unrestricted_upload":
		return "an HTTP request parameter reaches a file upload write sink through the observed static flow"
	}
	return "an HTTP request parameter reaches a JDBC SQL sink through the observed static flow"
}

func flowHypothesisStatus(status string) string {
	switch status {
	case "static_confirmed":
		return "supported"
	case "refuted":
		return "unsupported"
	default:
		return "unverified"
	}
}

func flowHypothesisReason(flow dataflow.Finding) string {
	if flow.Status == "inconclusive" {
		if flow.Boundary != nil {
			return "boundary:" + flow.Boundary.Kind
		}
		return "no_closed_path_to_" + flowKind(flow) + "_sink"
	}
	if flow.Status == "refuted" {
		return "only the observed value binding is covered"
	}
	return ""
}

func runtimeReason(status string) string {
	if status == "refuted" {
		return "static_negative_control_only"
	}
	return "runtime_status_not_run"
}

func statusRank(status string) int {
	switch status {
	case "static_confirmed":
		return 0
	case "inconclusive":
		return 1
	default:
		return 2
	}
}

type evidenceSet struct {
	items     []Evidence
	seen      map[string]string
	truncated bool
}

func (s *evidenceSet) add(item Evidence) string {
	key := item.Origin + "\x00" + item.Kind + "\x00" + item.File + "\x00" + strconv.Itoa(item.StartLine) + "\x00" + strconv.Itoa(item.EndLine) + "\x00" + item.Anchor + "\x00" + item.Detail
	if id, ok := s.seen[key]; ok {
		return id
	}
	if len(s.items) >= MaxEvidence {
		s.truncated = true
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	item.ID = "ev:" + hex.EncodeToString(sum[:8])
	s.seen[key] = item.ID
	s.items = append(s.items, item)
	return item.ID
}

func entryDigests(snapshot *project.Snapshot) map[string]string {
	entries := map[string]string{}
	for _, entry := range snapshot.Manifest().Entries {
		entries[entry.Path] = entry.SHA256
	}
	return entries
}

func dependencyIndex(dependencies []sca.Dependency) map[string]sca.Dependency {
	index := map[string]sca.Dependency{}
	for _, dependency := range dependencies {
		key := dependencyKey(dependency.Module, dependency.GroupID+":"+dependency.ArtifactID, dependency.Version)
		if _, ok := index[key]; !ok {
			index[key] = dependency
		}
	}
	return index
}

func dependencyKey(module, dependency, version string) string {
	return module + "\x00" + dependency + "\x00" + version
}

func nonEmpty(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func dedupe(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
