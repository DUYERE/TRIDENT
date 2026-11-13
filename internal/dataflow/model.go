// Package dataflow performs a bounded, deterministic source-to-sink pass for
// JDBC SQL construction on a pinned snapshot. It reuses the annotation-level
// endpoint inventory, never compiles or runs Java, and does not claim runtime
// exploitability or whole-application safety.
package dataflow

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"trident/internal/audit"
	"trident/internal/project"
)

const (
	SchemaVersion = 1
	ToolVersion   = "0.2.0-p0.2+r2-source-sink-flow-v9"

	MaxJavaFiles  = 2000
	MaxJavaBytes  = 2 << 20
	MaxJavaTokens = 500_000
	MaxMethods    = 50_000
	MaxDepth      = 8
	MaxFindings   = 10_000
	MaxFlowSteps  = 128
	MaxEvidence   = 64
)

var (
	ErrLimit       = errors.New("dataflow analysis limit")
	ErrUnsupported = errors.New("unsupported Java source")
)

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
	ID            string         `json:"id"`
	Category      string         `json:"category"`
	CWE           string         `json:"cwe"`
	Severity      string         `json:"severity"`
	Status        string         `json:"status"`
	RuntimeStatus string         `json:"runtime_status"`
	Endpoint      EndpointRef    `json:"endpoint"`
	Sources       []SourceRef    `json:"sources"`
	Sink          *SinkRef       `json:"sink,omitempty"`
	Protection    *ProtectionRef `json:"protection,omitempty"`
	Boundary      *BoundaryRef   `json:"boundary,omitempty"`
	Flow          []FlowStep     `json:"flow"`
	Evidence      []Evidence     `json:"evidence"`
	Limitations   []string       `json:"limitations"`
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

type SourceRef struct {
	Parameter string   `json:"parameter"`
	Type      string   `json:"type"`
	Bindings  []string `json:"bindings"`
	Binding   string   `json:"binding_name,omitempty"`
	File      string   `json:"file"`
	Line      int      `json:"line"`
}

type SinkRef struct {
	API    string `json:"api"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Line   int    `json:"line"`
}

type ProtectionRef struct {
	API    string `json:"api"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Line   int    `json:"line"`
	Detail string `json:"detail"`
}

type BoundaryRef struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Line   int    `json:"line"`
}

type FlowStep struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Line   int    `json:"line"`
}

type Evidence struct {
	File       string `json:"file"`
	SHA256     string `json:"sha256"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	Anchor     string `json:"anchor,omitempty"`
	AnchorLine int    `json:"anchor_line,omitempty"`
}

type Coverage struct {
	JavaFilesScanned     int    `json:"java_files_scanned"`
	JavaFilesRejected    int    `json:"java_files_rejected"`
	MethodsParsed        int    `json:"methods_parsed"`
	EndpointsInventoried int    `json:"endpoints_inventoried"`
	EndpointsAnalyzed    int    `json:"endpoints_analyzed"`
	FindingsConfirmed    int    `json:"findings_confirmed"`
	FindingsRefuted      int    `json:"findings_refuted"`
	FindingsInconclusive int    `json:"findings_inconclusive"`
	CallsResolved        int    `json:"calls_resolved"`
	CallsUnresolved      int    `json:"calls_unresolved"`
	DynamicBoundaries    int    `json:"dynamic_boundaries"`
	JavaAST              string `json:"java_ast"`
	TaintAnalysis        string `json:"taint_analysis"`
	RuntimeStatus        string `json:"runtime_status"`
	AnalysisScope        string `json:"analysis_scope"`
}

// categorySpec names one bounded source-to-sink rule. SQL keeps the original
// single-finding-per-parameter behavior; the other categories are emitted only
// when their sink or a sink-specific boundary is observed.
type categorySpec struct {
	Key      string
	Label    string
	CWE      string
	SinkKind string
	Noun     string
}

var (
	sqlCategory             = categorySpec{Key: "sql", Label: "SQL injection", CWE: "CWE-89", SinkKind: "sink", Noun: "JDBC SQL sink"}
	commandCategory         = categorySpec{Key: "command", Label: "Command injection", CWE: "CWE-78", SinkKind: "command_sink", Noun: "OS command sink"}
	ssrfCategory            = categorySpec{Key: "ssrf", Label: "Server-side request forgery", CWE: "CWE-918", SinkKind: "ssrf_sink", Noun: "outbound request sink"}
	pathCategory            = categorySpec{Key: "path", Label: "Path traversal", CWE: "CWE-22", SinkKind: "path_sink", Noun: "file access sink"}
	templateCategory        = categorySpec{Key: "template", Label: "Template injection", CWE: "CWE-1336", SinkKind: "template_sink", Noun: "template evaluation sink"}
	xssCategory             = categorySpec{Key: "xss", Label: "Cross-site scripting", CWE: "CWE-79", SinkKind: "xss_sink", Noun: "HTTP response writer sink"}
	deserializationCategory = categorySpec{Key: "deserialization", Label: "Unsafe deserialization", CWE: "CWE-502", SinkKind: "deserialization_sink", Noun: "deserialization read sink"}
	xxeCategory             = categorySpec{Key: "xxe", Label: "XML external entity", CWE: "CWE-611", SinkKind: "xxe_sink", Noun: "XML parser sink"}
	ldapCategory            = categorySpec{Key: "ldap", Label: "LDAP injection", CWE: "CWE-90", SinkKind: "ldap_sink", Noun: "LDAP query sink"}

	allCategories = []categorySpec{sqlCategory, commandCategory, ssrfCategory, pathCategory, templateCategory, xssCategory, deserializationCategory, xxeCategory, ldapCategory}
)

var requestBindings = map[string]bool{
	"RequestParam":     true,
	"PathVariable":     true,
	"RequestBody":      true,
	"RequestHeader":    true,
	"CookieValue":      true,
	"ModelAttribute":   true,
	"RequestPart":      true,
	"SessionAttribute": true,
}

// Analyze inventories Spring MVC endpoints, parses the same snapshot into a
// bounded method/field model, and traces request parameters into JDBC SQL
// sinks. Endpoint inventory gaps and parse rejections are reported as partial.
func Analyze(ctx context.Context, snapshot *project.Snapshot) (Report, error) {
	if snapshot == nil || snapshot.Hash() == "" {
		return Report{}, fmt.Errorf("%w: pinned snapshot required", ErrLimit)
	}
	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   ToolVersion,
		SnapshotHash:  snapshot.Hash(),
		AnalysisKind:  "source_sink_multi_category_v1",
		Findings:      []Finding{},
		Coverage: Coverage{
			JavaAST:       "not_available",
			TaintAnalysis: "bounded_lexical_multi_category",
			RuntimeStatus: "not_run",
			AnalysisScope: "single_parameter_multi_category_v9",
		},
		Limitations: []string{
			"sql_sink_scope: SQL findings model only Statement.execute*/prepareStatement SQL sinks and PreparedStatement value binding",
			"multi_category_sinks: OS command execution (Runtime.getRuntime().exec, ProcessBuilder command/start), SSRF (URL.openConnection/openStream, RestTemplate), path traversal (file stream/reader constructors, Files.*), template injection (SpelExpressionParser.parseExpression, template engine process), XSS (PrintWriter/JspWriter/ServletOutputStream writes), unsafe deserialization (ObjectInputStream/XMLDecoder readObject), XXE (DocumentBuilder/SAXParser.parse, XMLInputFactory.createXMLStreamReader, Unmarshaller.unmarshal, Transformer.transform) and LDAP injection (DirContext.search/lookup, LdapTemplate.search/lookup/authenticate) are modeled",
			"non_sql_sink_observed_only: non-SQL category findings are emitted only when that category sink or sink-specific boundary is observed for the parameter; absence is not safety",
			"lexical_flow_not_ast: no Java AST, control-flow, alias, points-to or branch sensitivity",
			"collection_taint_bounds: a tainted value written through List/Set/Map/Queue add/put marks that local or field container flow-insensitively; reads via get/values/keySet/entrySet/iterator propagate it, while clear/remove, cross-method container contents and element indices are not modeled",
			"builder_and_format_bounds: StringBuilder/StringBuffer append and builder.toString() require a known builder-typed receiver; String.format requires a literal pattern with a conversion specifier, otherwise the result is an inconclusive boundary",
			"return_value_bounds: tainted returns and builder parameter mutation are summarized only for resolved same-project calls; ambiguous dispatch, fields of other objects and external libraries stay unresolved",
			"interface_inheritance_bounds: parents and implementations are matched by simple name in the same package or a unique simple name; a bodyless interface/abstract call needs exactly one concrete override with a compatible signature, otherwise it is an ambiguous_dispatch boundary",
			"overload_and_parent_bounds: overloads are selected from simple inferred argument types (literals, locals, fields, casts, new, calls with known returns); remaining ties are ambiguous_overload, and a class with a parent outside the snapshot is unresolved_parent instead of assumed absent",
			"lambda_generic_varargs_bounds: lambdas match known functional interfaces or single-method project interfaces but their bodies are not analyzed; generics are erased and method type variables are substituted only from direct same-named parameters; varargs match the component type and explicit array arguments are not modeled",
			"deserialization_and_xss_bounds: unsafe deserialization requires a known ObjectInputStream/XMLDecoder local or field receiver before readObject; XSS requires a known response-writer receiver or a direct getWriter() chain, and reflected return values are not modeled",
			"field_taint_bounds: fields are tainted flow-insensitively per class lineage inside one endpoint analysis; instances, threads and clean reassignments are not distinguished",
			"bounded_cross_method: max depth 8; reflection targets and external libraries are unresolved",
			"absence_is_not_safety: no observed path yields inconclusive, not refuted",
			"route_inventory_from_annotation_audit: endpoint paths are annotation-level, not deployed routes",
			"runtime_status_not_run: static evidence does not prove exploitation",
		},
	}
	endpoints, err := audit.Inspect(ctx, snapshot)
	if err != nil {
		return Report{}, err
	}
	report.Coverage.EndpointsInventoried = len(endpoints.Endpoints)
	if endpoints.Partial {
		report.Partial = true
		report.Limitations = append(report.Limitations, "endpoint_inventory_partial")
	}
	files, rejected, problems, err := parseProject(ctx, snapshot)
	if err != nil {
		return Report{}, err
	}
	report.Coverage.JavaFilesScanned = len(files)
	report.Coverage.JavaFilesRejected = rejected
	report.Partial = report.Partial || rejected > 0
	report.Limitations = append(report.Limitations, problems...)
	if len(files) == 0 && rejected == 0 {
		report.Limitations = append(report.Limitations, "no_java_source_found")
	}
	nested := 0
	for _, file := range files {
		nested += file.Nested
	}
	if nested > 0 {
		report.Partial = true
		report.Limitations = append(report.Limitations, "nested_classes_skipped")
	}
	index := newProjectModel(files)
	report.Coverage.MethodsParsed = index.methodCount

	stopped := false
	for _, endpoint := range endpoints.Endpoints {
		analyzed := analyzeEndpoint(index, endpoint)
		if len(analyzed) == 0 {
			continue
		}
		report.Coverage.EndpointsAnalyzed++
		for _, finding := range analyzed {
			if len(report.Findings) >= MaxFindings {
				report.Limitations = append(report.Limitations, "finding_limit")
				report.Partial = true
				stopped = true
				break
			}
			report.Coverage.CallsResolved += finding.callsResolved
			report.Coverage.CallsUnresolved += finding.callsUnresolved
			report.Coverage.DynamicBoundaries += finding.dynamicBoundaries
			switch finding.Status {
			case "static_confirmed":
				report.Coverage.FindingsConfirmed++
			case "refuted":
				report.Coverage.FindingsRefuted++
			default:
				report.Coverage.FindingsInconclusive++
			}
			report.Findings = append(report.Findings, finding.Finding)
		}
		if stopped {
			break
		}
	}
	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.Endpoint.Path != b.Endpoint.Path {
			return a.Endpoint.Path < b.Endpoint.Path
		}
		return a.ID < b.ID
	})
	sort.Strings(report.Limitations)
	report.Limitations = dedupe(report.Limitations)
	return report, nil
}

type findingState struct {
	category          categorySpec
	categoryObserved  bool
	confirmed         bool
	dynamic           bool
	unresolved        bool
	binding           bool
	pathObserved      bool
	depthLimited      bool
	sink              *SinkRef
	protection        *ProtectionRef
	boundary          *BoundaryRef
	flow              []FlowStep
	evidence          map[string]Evidence
	limitations       map[string]bool
	visited           map[string]bool
	effectCache       map[string]methodEffects
	effectsActive     map[string]bool
	fields            map[string]taint
	callsResolved     int
	callsUnresolved   int
	dynamicBoundaries int
}

type analyzedFinding struct {
	Finding
	callsResolved     int
	callsUnresolved   int
	dynamicBoundaries int
}

func analyzeEndpoint(index *projectModel, endpoint audit.Endpoint) []analyzedFinding {
	if index.files[endpoint.File] == nil {
		return nil
	}
	class := index.classes[endpoint.Package+"."+endpoint.Class]
	if class == nil {
		return nil
	}
	method := class.method(endpoint.Method, len(endpoint.Parameters))
	if method == nil || method.BodyStart < 0 {
		return nil
	}
	results := []analyzedFinding{}
	for _, parameter := range endpoint.Parameters {
		if !hasRequestBinding(parameter.Bindings) {
			continue
		}
		source := SourceRef{
			Parameter: parameter.Name,
			Type:      parameter.Type,
			Bindings:  append([]string{}, parameter.Bindings...),
			Binding:   parameter.BindingName,
			File:      endpoint.File,
			Line:      parameter.Line,
		}
		for _, category := range allCategories {
			state := &findingState{
				category:    category,
				evidence:    map[string]Evidence{},
				limitations: map[string]bool{},
				visited:     map[string]bool{},
				fields:      map[string]taint{},
			}
			state.addEvidence(method)
			state.analyzeMethod(index, method, map[string]taint{parameter.Name: {source: source}}, 0)
			if category.Key != sqlCategory.Key && !state.categoryObserved {
				continue
			}
			results = append(results, state.buildFinding(endpoint, parameter, source))
		}
	}
	return results
}

// buildFinding turns one completed category analysis into the stable finding
// shape. SQL keeps the original per-parameter identity; other categories use
// their own CWE prefix.
func (s *findingState) buildFinding(endpoint audit.Endpoint, parameter audit.Parameter, source SourceRef) analyzedFinding {
	status := "inconclusive"
	severity := "unknown"
	limitations := []string{}
	switch {
	case s.confirmed:
		status, severity = "static_confirmed", "high"
		limitations = append(limitations, "static source evidence only; no runtime exploitation or production deployment was confirmed")
	case s.dynamic:
		limitations = append(limitations, "dynamic or reflective target prevented a closed call graph")
	case s.unresolved:
		limitations = append(limitations, "tainted data reached an unresolved call or library boundary")
	case s.binding:
		status, severity = "refuted", "none"
		limitations = append(limitations, "refuted only for the observed value binding on this parameter; not a whole-application safety proof")
	case s.pathObserved:
		limitations = append(limitations, "a taint path was observed but no "+s.category.Noun+" or binding was identified")
	default:
		limitations = append(limitations, "no observed taint path; absence of a path is not proof of safety")
	}
	if s.depthLimited {
		limitations = append(limitations, "cross-method depth limit reached")
	}
	for limitation := range s.limitations {
		limitations = append(limitations, limitation)
	}
	sort.Strings(limitations)
	limitations = dedupe(limitations)
	finding := Finding{
		ID:            s.category.CWE + ":" + endpoint.Path + ":" + parameter.Name,
		Category:      s.category.Label,
		CWE:           s.category.CWE,
		Severity:      severity,
		Status:        status,
		RuntimeStatus: "not_run",
		Endpoint: EndpointRef{
			Path:        endpoint.Path,
			HTTPMethods: append([]string{}, endpoint.HTTPMethods...),
			Symbol:      endpoint.Symbol,
			File:        endpoint.File,
			SHA256:      endpoint.SHA256,
			StartLine:   endpoint.StartLine,
			EndLine:     endpoint.EndLine,
		},
		Sources:     []SourceRef{source},
		Sink:        s.sink,
		Protection:  s.protection,
		Boundary:    s.boundary,
		Flow:        limitFlow(s.flow),
		Evidence:    sortedEvidence(s.evidence),
		Limitations: limitations,
	}
	return analyzedFinding{Finding: finding, callsResolved: s.callsResolved, callsUnresolved: s.callsUnresolved, dynamicBoundaries: s.dynamicBoundaries}
}

func hasRequestBinding(bindings []string) bool {
	for _, binding := range bindings {
		if requestBindings[binding] {
			return true
		}
	}
	return false
}

func limitFlow(flow []FlowStep) []FlowStep {
	if len(flow) > MaxFlowSteps {
		return flow[:MaxFlowSteps]
	}
	return flow
}

func sortedEvidence(values map[string]Evidence) []Evidence {
	evidence := make([]Evidence, 0, len(values))
	for _, value := range values {
		evidence = append(evidence, value)
	}
	sort.Slice(evidence, func(i, j int) bool {
		if evidence[i].File != evidence[j].File {
			return evidence[i].File < evidence[j].File
		}
		return evidence[i].StartLine < evidence[j].StartLine
	})
	if len(evidence) > MaxEvidence {
		evidence = evidence[:MaxEvidence]
	}
	return evidence
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
