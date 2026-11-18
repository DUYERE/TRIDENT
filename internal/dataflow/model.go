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
	"trident/internal/javaast"
	"trident/internal/project"
)

const (
	SchemaVersion = 1
	ToolVersion   = "0.2.0-p0.5+r1-source-sink-flow-v14"

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

// Options controls evidence volume. The default is the v14 low-noise view:
// findings are emitted only when the analyzer observed a sink, a protection,
// a boundary or an actual taint path. EmitUnobserved reproduces the v13/v1
// behaviour for regression fixtures.
type Options struct {
	EmitUnobserved     bool
	IncludeSinkAnchors bool
}

type Report struct {
	SchemaVersion int          `json:"schema_version"`
	ToolVersion   string       `json:"tool_version"`
	SnapshotHash  string       `json:"snapshot_hash"`
	AnalysisKind  string       `json:"analysis_kind"`
	Partial       bool         `json:"partial"`
	Findings      []Finding    `json:"findings"`
	ORM           OrmReport    `json:"orm"`
	SinkAnchors   []SinkAnchor `json:"sink_anchors,omitempty"`
	Coverage      Coverage     `json:"coverage"`
	Limitations   []string     `json:"limitations"`
}

type Finding struct {
	ID               string         `json:"id"`
	Category         string         `json:"category"`
	CWE              string         `json:"cwe"`
	Severity         string         `json:"severity"`
	Status           string         `json:"status"`
	RuntimeStatus    string         `json:"runtime_status"`
	EvidenceStrength string         `json:"evidence_strength"`
	Endpoint         EndpointRef    `json:"endpoint"`
	Sources          []SourceRef    `json:"sources"`
	Sink             *SinkRef       `json:"sink,omitempty"`
	Protection       *ProtectionRef `json:"protection,omitempty"`
	Boundary         *BoundaryRef   `json:"boundary,omitempty"`
	Orm              *OrmRef        `json:"orm,omitempty"`
	Flow             []FlowStep     `json:"flow"`
	Evidence         []Evidence     `json:"evidence"`
	Limitations      []string       `json:"limitations"`
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
	UnobservedPaths      int    `json:"unobserved_paths"`
	BoundaryOnly         int    `json:"boundary_only"`
	MyBatisMappers       int    `json:"mybatis_mappers"`
	MyBatisStatements    int    `json:"mybatis_statements"`
	MyBatisRefuted       int    `json:"mybatis_refuted"`
	MyBatisConfirmed     int    `json:"mybatis_confirmed"`
	MyBatisBoundaries    int    `json:"mybatis_boundaries"`
	SinkAnchors          int    `json:"sink_anchors"`
	CallsResolved        int    `json:"calls_resolved"`
	CallsUnresolved      int    `json:"calls_unresolved"`
	DynamicBoundaries    int    `json:"dynamic_boundaries"`
	JavaAST              string `json:"java_ast"`
	JavaASTTypes         int    `json:"java_ast_types"`
	JavaASTMethods       int    `json:"java_ast_methods"`
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
	uploadCategory          = categorySpec{Key: "upload", Label: "Unrestricted file upload", CWE: "CWE-434", SinkKind: "upload_sink", Noun: "file upload sink"}

	allCategories = []categorySpec{sqlCategory, commandCategory, ssrfCategory, pathCategory, templateCategory, xssCategory, deserializationCategory, xxeCategory, ldapCategory, uploadCategory}
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
	"QueryParam":       true,
	"PathParam":        true,
	"FormParam":        true,
	"HeaderParam":      true,
	"CookieParam":      true,
	"MatrixParam":      true,
	"BeanParam":        true,
}

// Analyze inventories Spring MVC endpoints, parses the same snapshot into a
// bounded method/field model, and traces request parameters into JDBC SQL
// sinks. Endpoint inventory gaps and parse rejections are reported as partial.
func Analyze(ctx context.Context, snapshot *project.Snapshot) (Report, error) {
	return AnalyzeWithOptions(ctx, snapshot, Options{})
}

func AnalyzeWithOptions(ctx context.Context, snapshot *project.Snapshot, opts Options) (Report, error) {
	if snapshot == nil || snapshot.Hash() == "" {
		return Report{}, fmt.Errorf("%w: pinned snapshot required", ErrLimit)
	}
	analysisKind := "source_sink_multi_category_v2"
	if opts.EmitUnobserved {
		analysisKind = "source_sink_multi_category_v1"
	}
	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   ToolVersion,
		SnapshotHash:  snapshot.Hash(),
		AnalysisKind:  analysisKind,
		Findings:      []Finding{},
		ORM:           emptyOrmReport(),
		Coverage: Coverage{
			JavaAST:       "not_available",
			TaintAnalysis: "bounded_lexical_multi_category",
			RuntimeStatus: "not_run",
			AnalysisScope: "single_parameter_multi_category_v14",
		},
		Limitations: []string{
			"sql_sink_scope: SQL findings model Statement.execute*/prepareStatement, JdbcTemplate/NamedParameterJdbcTemplate query/update/execute family, JPA EntityManager/Hibernate Session createQuery/createNativeQuery, and PreparedStatement value binding",
			"multi_category_sinks: OS command execution (Runtime.getRuntime().exec, ProcessBuilder command/start), SSRF (URL.openConnection/openStream, RestTemplate, HttpRequest.uri and WebClient.uri), path traversal (file stream/reader constructors, Files.*), template injection (SpelExpressionParser.parseExpression, template engine process), XSS (PrintWriter/JspWriter/ServletOutputStream writes), unsafe deserialization (ObjectInputStream/XMLDecoder readObject, including new ObjectInputStream(...)/new XMLDecoder(...) chains), XXE (DocumentBuilder/SAXParser/SAXReader.parse, SAXReader/XMLReader.read, XMLInputFactory.createXMLStreamReader/createXMLEventReader, Unmarshaller.unmarshal, Transformer.transform, SAXBuilder/Digester.parse, DocumentHelper.parseText), LDAP injection (DirContext.search/lookup, LdapTemplate.search/lookup/authenticate) and unrestricted upload (MultipartFile.transferTo, Part.write) are modeled",
			"non_sql_sink_observed_only: non-SQL category findings are emitted only when that category sink or sink-specific boundary is observed for the parameter; absence is not safety",
			"lexical_flow_not_ast: taint matching uses bounded lexical flow; the restricted AST contributes only uniquely resolved call targets when the lexer resolver is unresolved or ambiguous, not source/sink or control-flow semantics",
			"java_ast_call_targets: AST call edges are keyed by file+line+call name and never widen the lexer method set; ambiguity, control-flow, branch sensitivity and full cross-method taint remain out of scope",
			"collection_taint_bounds: a tainted value written through List/Set/Map/Queue add/put marks that local or field container flow-insensitively; literal-index set/add and array element writes are tracked per element (name[0]) and literal-index get/remove operate on that element, while clear drops the container and its element taints; non-literal indices fall back to the container aggregate; resolved calls can mutate a caller collection or array parameter, while target-object containers and instance/thread state are not modeled",
			"builder_and_format_bounds: StringBuilder/StringBuffer append and builder.toString() require a known builder-typed receiver; String.format requires a literal pattern with a conversion specifier, otherwise the result is an inconclusive boundary",
			"return_value_bounds: tainted returns and builder parameter mutation are summarized only for resolved same-project calls; ambiguous dispatch, fields of other objects and external libraries stay unresolved",
			"interface_inheritance_bounds: parents and implementations are matched by simple name in the same package or a unique simple name; a bodyless interface/abstract call needs exactly one concrete override with a compatible signature, otherwise it is an ambiguous_dispatch boundary",
			"overload_and_parent_bounds: overloads are selected from simple inferred argument types (literals, locals, fields, casts, new, calls with known returns); remaining ties are ambiguous_overload, and a class with a parent outside the snapshot is unresolved_parent instead of assumed absent",
			"lambda_generic_varargs_bounds: lambdas match known functional interfaces or single-method project interfaces but their bodies are not analyzed; generics are erased and method type variables are substituted only from direct same-named parameters; varargs match the component type and explicit array arguments are not modeled",
			"deserialization_and_xss_bounds: unsafe deserialization accepts a known ObjectInputStream/XMLDecoder local or field receiver, or a direct new ObjectInputStream(...)/new XMLDecoder(...).readObject() chain; XSS requires a known response-writer receiver or a direct getWriter() chain; a tainted String/CharSequence return from a response-body endpoint is confirmed only when produces declares text/html or application/xhtml+xml, refuted for an explicit non-HTML content type, and otherwise kept as an inconclusive reflected_return boundary because escaping and content negotiation are not resolved",
			"field_taint_bounds: fields are tainted flow-insensitively per class lineage inside one endpoint analysis; instances, threads and clean reassignments are not distinguished",
			"bounded_cross_method: max depth 8; reflection targets and external libraries are unresolved",
			"absence_is_not_safety: no observed path yields inconclusive, not refuted",
			"route_inventory_from_annotation_audit: endpoint paths are annotation-level, not deployed routes",
			"runtime_status_not_run: static evidence does not prove exploitation",
		},
	}
	if opts.EmitUnobserved {
		report.Limitations = append(report.Limitations,
			"unobserved_paths_emitted_compat: v1 compatibility mode emits a finding even when no sink, protection, boundary or taint path was observed",
			"analysis_kind_v1_compat: this report uses the legacy source_sink_multi_category_v1 semantics")
	} else {
		report.Limitations = append(report.Limitations,
			"unobserved_paths_not_emitted: parameter/category pairs with no observed sink, protection, boundary or taint path are counted in coverage.unobserved_paths instead of producing findings; absence is not safety",
			"evidence_strength_tiers: findings carry evidence_strength=sink|protection|boundary; unobserved appears only in --emit-unobserved mode",
			"generic_boundaries_suppressed: unresolved_call boundaries without a category-specific observation are counted in coverage.boundary_only; reflection, ambiguous dispatch, overload and unresolved-parent boundaries remain findings")
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
	ormReport, ormIndex, ormErr := scanOrm(ctx, snapshot, files)
	if ormErr != nil {
		report.Limitations = append(report.Limitations, "mybatis_scan_failed")
		ormIndex = nil
	} else {
		report.ORM = ormReport
		report.Limitations = append(report.Limitations, ormReport.Limitations...)
		report.Coverage.MyBatisMappers = len(ormReport.Mappers)
		report.Coverage.MyBatisStatements = len(ormReport.Statements)
	}
	report.Coverage.JavaFilesScanned = len(files)
	report.Coverage.JavaFilesRejected = rejected
	report.Partial = report.Partial || rejected > 0
	report.Limitations = append(report.Limitations, problems...)
	if len(files) == 0 && rejected == 0 {
		report.Limitations = append(report.Limitations, "no_java_source_found")
	}
	ast, astErr := javaast.Analyze(ctx, snapshot)
	if astErr != nil {
		report.Limitations = append(report.Limitations, "java_ast_unavailable")
	} else if len(ast.Files) > 0 {
		report.Coverage.JavaAST = "restricted_subset"
		if ast.Partial || ast.Coverage.FilesRejected > 0 {
			report.Coverage.JavaAST = "partial"
			report.Partial = true
		}
		report.Coverage.JavaASTTypes = ast.Coverage.TypesIndexed
		report.Coverage.JavaASTMethods = ast.Coverage.MethodsIndexed
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
	index.applyJavaAST(ast)
	report.Coverage.MethodsParsed = index.methodCount

	stopped := false
	for _, endpoint := range endpoints.Endpoints {
		analyzed, stats := analyzeEndpoint(index, endpoint, opts, ormIndex)
		report.Coverage.UnobservedPaths += stats.unobserved
		report.Coverage.BoundaryOnly += stats.boundaryOnly
		report.Coverage.MyBatisRefuted += stats.mybatisRefuted
		report.Coverage.MyBatisBoundaries += stats.mybatisBoundary
		if len(analyzed) == 0 {
			continue
		}
		report.Coverage.EndpointsAnalyzed++
		for _, finding := range analyzed {
			if finding.Orm != nil {
				switch finding.Status {
				case "refuted":
					report.Coverage.MyBatisRefuted++
				case "static_confirmed":
					report.Coverage.MyBatisConfirmed++
				}
			}
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
	if opts.IncludeSinkAnchors {
		covered := map[string]bool{}
		for _, finding := range report.Findings {
			if finding.Sink != nil {
				covered[fmt.Sprintf("%s:%d", finding.Sink.File, finding.Sink.Line)] = true
			}
			for _, step := range finding.Flow {
				covered[fmt.Sprintf("%s:%d", step.File, step.Line)] = true
			}
		}
		anchors, anchorErr := InspectSinks(ctx, snapshot, covered)
		if anchorErr != nil {
			report.Limitations = append(report.Limitations, "sink_anchor_scan_failed")
		} else {
			report.SinkAnchors = anchors.Anchors
			report.Coverage.SinkAnchors = len(anchors.Anchors)
			report.Partial = report.Partial || anchors.Partial
		}
	}
	sort.Strings(report.Limitations)
	report.Limitations = dedupe(report.Limitations)
	return report, nil
}

type findingState struct {
	category           categorySpec
	categoryObserved   bool
	confirmed          bool
	dynamic            bool
	unresolved         bool
	binding            bool
	encoded            bool
	responseBody       bool
	produces           []string
	producesUnresolved bool
	pathObserved       bool
	depthLimited       bool
	sink               *SinkRef
	protection         *ProtectionRef
	boundary           *BoundaryRef
	orm                *OrmRef
	ormIndex           *OrmIndex
	flow               []FlowStep
	evidence           map[string]Evidence
	limitations        map[string]bool
	visited            map[string]bool
	effectCache        map[string]methodEffects
	effectsActive      map[string]bool
	fields             map[string]taint
	endpoint           *methodModel
	callsResolved      int
	callsUnresolved    int
	dynamicBoundaries  int
}

type analyzedFinding struct {
	Finding
	callsResolved     int
	callsUnresolved   int
	dynamicBoundaries int
}

type endpointStats struct {
	unobserved      int
	boundaryOnly    int
	mybatisRefuted  int
	mybatisBoundary int
}

func analyzeEndpoint(index *projectModel, endpoint audit.Endpoint, opts Options, ormIndex *OrmIndex) ([]analyzedFinding, endpointStats) {
	stats := endpointStats{}
	if index.files[endpoint.File] == nil {
		return nil, stats
	}
	class := index.classes[endpoint.Package+"."+endpoint.Class]
	if class == nil {
		return nil, stats
	}
	method := class.method(endpoint.Method, len(endpoint.Parameters))
	if method == nil || method.BodyStart < 0 {
		return nil, stats
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
				category:           category,
				endpoint:           method,
				responseBody:       endpoint.ResponseBody,
				produces:           append([]string{}, endpoint.Produces...),
				producesUnresolved: endpoint.ProducesStatus == "unresolved",
				evidence:           map[string]Evidence{},
				limitations:        map[string]bool{},
				visited:            map[string]bool{},
				fields:             map[string]taint{},
				ormIndex:           ormIndex,
			}
			state.addEvidence(method)
			state.analyzeMethod(index, method, map[string]taint{parameter.Name: {source: source}}, 0)
			if opts.EmitUnobserved {
				// v1 compatibility: SQL always emitted, other categories only
				// when their sink/boundary was observed.
				if category.Key != sqlCategory.Key && !state.categoryObserved {
					continue
				}
			} else if category.Key != sqlCategory.Key && !state.categoryObserved {
				// Non-SQL categories still require their own sink/boundary
				// observation; generic unresolved calls are not category evidence.
				stats.unobserved++
				continue
			} else if !state.hasObservation() {
				// v14: no sink, protection or boundary means no finding.
				stats.unobserved++
				continue
			} else if !state.confirmed && state.protection == nil && !state.categoryObserved &&
				state.boundary != nil && state.boundary.Kind == "unresolved_call" {
				// A generic "taint entered an unresolvable call" boundary has
				// no category-specific evidence. It stays in coverage instead
				// of flooding the finding list; reflection, ambiguous dispatch,
				// overload and parent boundaries remain first-class findings.
				stats.boundaryOnly++
				continue
			} else if state.orm != nil && state.category.Key == sqlCategory.Key && !state.confirmed {
				// A MyBatis #{} binding is safety evidence, not a vulnerability
				// finding; framework-internal ${} and ambiguous methods are
				// coverage facts, not per-parameter conclusions.
				if state.protection != nil {
					stats.mybatisRefuted++
				} else {
					stats.mybatisBoundary++
				}
				continue
			}
			results = append(results, state.buildFinding(endpoint, parameter, source))
		}
	}
	return results, stats
}

// hasObservation reports whether the analysis produced any evidence at all.
// It is the gate that removes "nothing was observed" findings from the default
// report without hiding real unresolved boundaries.
func (s *findingState) hasObservation() bool {
	return s.confirmed || s.dynamic || s.unresolved || s.binding || s.encoded ||
		s.categoryObserved || s.sink != nil || s.protection != nil ||
		s.boundary != nil || s.orm != nil
}

func (s *findingState) evidenceStrength() string {
	switch {
	case s.confirmed || s.sink != nil:
		return "sink"
	case s.binding || s.encoded || s.protection != nil:
		return "protection"
	case s.dynamic || s.unresolved || s.boundary != nil || s.categoryObserved || s.pathObserved:
		return "boundary"
	default:
		return "unobserved"
	}
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
	case s.encoded:
		status, severity = "refuted", "none"
		limitations = append(limitations, "refuted only for the declared produces content type on this return; not a whole-application safety proof")
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
		ID:               s.category.CWE + ":" + endpoint.Path + ":" + parameter.Name,
		Category:         s.category.Label,
		CWE:              s.category.CWE,
		Severity:         severity,
		Status:           status,
		RuntimeStatus:    "not_run",
		EvidenceStrength: s.evidenceStrength(),
		Orm:              s.orm,
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
