// Package authz performs a bounded authorization-control inventory over the
// same lexical endpoint model used by package audit. It recognizes common
// Spring Security, MVC interceptor, servlet filter and manual session checks;
// it does not evaluate expressions, filter-chain order or runtime behavior.
package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"trident/internal/audit"
	"trident/internal/project"
)

const (
	SchemaVersion = 1
	ToolVersion   = "0.2.0-p0.2+r4-authz-inventory-v1"
	MaxFiles      = 4000
	MaxFileBytes  = 2 << 20
)

const (
	RequirementAuthenticated = "authenticated"
	RequirementRole          = "role"
	RequirementPublic        = "public"
	RequirementDeny          = "deny"
	RequirementUnknown       = "unknown"
)

type Report struct {
	SchemaVersion int                `json:"schema_version"`
	ToolVersion   string             `json:"tool_version"`
	SnapshotHash  string             `json:"snapshot_hash"`
	AnalysisKind  string             `json:"analysis_kind"`
	Partial       bool               `json:"partial"`
	Controls      []Control          `json:"controls"`
	Endpoints     []EndpointDecision `json:"endpoints"`
	Findings      []Finding          `json:"findings"`
	Coverage      Coverage           `json:"coverage"`
	Limitations   []string           `json:"limitations"`
	RuntimeStatus string             `json:"runtime_status"`
	Error         string             `json:"error,omitempty"`
}

type Control struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	File         string   `json:"file"`
	Line         int      `json:"line"`
	Order        int      `json:"order"`
	Paths        []string `json:"paths"`
	Excluded     []string `json:"excluded,omitempty"`
	Methods      []string `json:"methods,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Requirement  string   `json:"requirement"`
	SourceClass  string   `json:"source_class,omitempty"`
	Status       string   `json:"status"`
	Note         string   `json:"note,omitempty"`
	Declarations []string `json:"declarations,omitempty"`
}

type EndpointDecision struct {
	Path            string   `json:"path"`
	HTTPMethods     []string `json:"http_methods,omitempty"`
	File            string   `json:"file"`
	Class           string   `json:"class"`
	Method          string   `json:"method"`
	Symbol          string   `json:"symbol"`
	StartLine       int      `json:"start_line"`
	MethodLine      int      `json:"method_line"`
	EndLine         int      `json:"end_line"`
	Decision        string   `json:"decision"`
	Requirement     string   `json:"requirement"`
	MatchedControls []string `json:"matched_controls,omitempty"`
	Reason          string   `json:"reason"`
	FindingStatus   string   `json:"finding_status,omitempty"`
	RuntimeStatus   string   `json:"runtime_status"`
}

type Finding struct {
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	CWE           string   `json:"cwe"`
	Path          string   `json:"path"`
	HTTPMethods   []string `json:"http_methods,omitempty"`
	File          string   `json:"file"`
	Symbol        string   `json:"symbol"`
	StartLine     int      `json:"start_line"`
	MethodLine    int      `json:"method_line"`
	EndLine       int      `json:"end_line"`
	Status        string   `json:"status"`
	Reason        string   `json:"reason"`
	RuntimeStatus string   `json:"runtime_status"`
	Evidence      []string `json:"evidence"`
}

type Coverage struct {
	JavaFilesScanned   int    `json:"java_files_scanned"`
	XMLFilesScanned    int    `json:"xml_files_scanned"`
	Endpoints          int    `json:"endpoints"`
	Protected          int    `json:"protected"`
	Public             int    `json:"public"`
	Unprotected        int    `json:"unprotected"`
	Unknown            int    `json:"unknown"`
	Controls           int    `json:"controls"`
	UnresolvedControls int    `json:"unresolved_controls"`
	RuntimeStatus      string `json:"runtime_status"`
}

type javaSource struct {
	Path    string
	Content string
	Lines   []string
	Package string
	Class   string
}

type classLookup struct {
	byName    map[string]string
	ambiguous map[string]bool
}

var (
	javaPackagePattern = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_][\w.]*)\s*;`)
	javaClassPattern   = regexp.MustCompile(`(?m)\b(?:class|interface|enum)\s+([A-Za-z_$][\w$]*)`)
	beanPattern        = regexp.MustCompile(`<(?:[A-Za-z0-9_.-]+:)?bean\b([^>]*)>`)
	attributePattern   = regexp.MustCompile(`([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*["']([^"']*)["']`)
	quotedValuePattern = regexp.MustCompile(`["']([^"']+)["']`)
	securityMethod     = regexp.MustCompile(`@(PreAuthorize|PostAuthorize|Secured|RolesAllowed|PermitAll|DenyAll|PreFilter|PostFilter)\b`)
	securityClass      = regexp.MustCompile(`@(PreAuthorize|PostAuthorize|Secured|RolesAllowed|PermitAll|DenyAll)\b`)
)

// Analyze inventories authorization controls and classifies every resolved
// endpoint. Unprotected classifications remain static and inconclusive.
func Analyze(ctx context.Context, snapshot *project.Snapshot) (Report, error) {
	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   ToolVersion,
		AnalysisKind:  "authorization_control_inventory",
		Controls:      []Control{},
		Endpoints:     []EndpointDecision{},
		Findings:      []Finding{},
		Coverage:      Coverage{RuntimeStatus: "not_run"},
		Limitations: []string{
			"lexical_control_inventory_not_ast: annotations, XML blocks and common Java config chains are matched textually",
			"filter_chain_order_not_evaluated: Spring Security first-match order is approximated only by declaration order in one file",
			"custom_auth_not_modeled: custom filters, AOP, Spring EL expressions and external gateways are not evaluated",
			"context_path_not_modeled: declared paths are compared without servlet context-path or rewrite rules",
			"unprotected_is_inconclusive: absence of a recognized control does not prove an endpoint is reachable without authentication",
			"manual_session_checks_are_unknown: a session read is recorded but not proven to guard every execution path",
			"runtime_status_not_run: no HTTP request, deployment or filter execution is performed",
		},
		RuntimeStatus: "not_run",
	}
	if snapshot == nil || snapshot.Hash() == "" {
		return report, fmt.Errorf("pinned snapshot required")
	}
	report.SnapshotHash = snapshot.Hash()
	inventory, err := audit.Inspect(ctx, snapshot)
	if err != nil {
		return report, err
	}
	report.Partial = inventory.Partial
	sources, lookup, err := loadJavaSources(ctx, snapshot)
	if err != nil {
		return report, err
	}
	xmlFiles, err := loadXMLFiles(ctx, snapshot)
	if err != nil {
		return report, err
	}
	report.Coverage.JavaFilesScanned = len(sources)
	report.Coverage.XMLFilesScanned = len(xmlFiles)
	controls := scanXMLControls(xmlFiles, lookup, sources)
	controls = append(controls, scanJavaControls(sources, lookup)...)
	sort.SliceStable(controls, func(i, j int) bool { return controls[i].Order < controls[j].Order })
	for index := range controls {
		controls[index].ID = fmt.Sprintf("ctl-%03d", index+1)
		if controls[index].Status == "" {
			controls[index].Status = "observed"
		}
	}
	report.Controls = controls
	report.Coverage.Controls = len(controls)
	for _, control := range controls {
		if control.Status != "observed" {
			report.Coverage.UnresolvedControls++
		}
	}
	controllers := map[string]audit.Controller{}
	for _, controller := range inventory.Controllers {
		controllers[controller.File+"\x00"+controller.Class] = controller
	}
	for _, endpoint := range inventory.Endpoints {
		controller := controllers[endpoint.File+"\x00"+endpoint.Class]
		decision := evaluateEndpoint(endpoint, controller, sources[endpoint.File], controls)
		report.Endpoints = append(report.Endpoints, decision)
		switch decision.Decision {
		case "protected":
			report.Coverage.Protected++
		case "public":
			report.Coverage.Public++
		case "unprotected":
			report.Coverage.Unprotected++
			report.Findings = append(report.Findings, findingFor(decision))
		default:
			report.Coverage.Unknown++
		}
	}
	report.Coverage.Endpoints = len(report.Endpoints)
	if report.Coverage.UnresolvedControls > 0 {
		report.Partial = true
		report.Limitations = append(report.Limitations, "unresolved_controls_present: some controls could not be resolved to a class or path")
	}
	sort.Slice(report.Findings, func(i, j int) bool {
		if report.Findings[i].Path != report.Findings[j].Path {
			return report.Findings[i].Path < report.Findings[j].Path
		}
		return report.Findings[i].Symbol < report.Findings[j].Symbol
	})
	sort.Strings(report.Limitations)
	report.Limitations = dedupe(report.Limitations)
	return report, nil
}

func loadJavaSources(ctx context.Context, snapshot *project.Snapshot) (map[string]javaSource, classLookup, error) {
	lookup := classLookup{byName: map[string]string{}, ambiguous: map[string]bool{}}
	sources := map[string]javaSource{}
	var files []string
	for _, entry := range snapshot.Manifest().Entries {
		if strings.HasSuffix(entry.Path, ".java") {
			files = append(files, entry.Path)
		}
	}
	sort.Strings(files)
	if len(files) > MaxFiles {
		return nil, lookup, fmt.Errorf("%w: Java file count exceeds %d", audit.ErrLimit, MaxFiles)
	}
	for _, file := range files {
		data, err := snapshot.ReadFile(ctx, file)
		if err != nil {
			return nil, lookup, err
		}
		if len(data) == 0 || len(data) > MaxFileBytes || !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
			continue
		}
		content := string(data)
		source := javaSource{Path: file, Content: content, Lines: strings.Split(content, "\n")}
		if match := javaPackagePattern.FindStringSubmatch(content); match != nil {
			source.Package = strings.TrimSpace(match[1])
		}
		if match := javaClassPattern.FindStringSubmatch(content); match != nil {
			source.Class = match[1]
		}
		sources[file] = source
		if source.Class != "" {
			simple := source.Class
			if lookup.ambiguous[simple] {
				// Keep the ambiguous marker; the fully-qualified name may still resolve.
			} else if previous, exists := lookup.byName[simple]; exists && previous != file {
				lookup.ambiguous[simple] = true
				delete(lookup.byName, simple)
			} else {
				lookup.byName[simple] = file
			}
			if source.Package != "" {
				lookup.byName[source.Package+"."+source.Class] = file
			}
		}
	}
	return sources, lookup, nil
}

func loadXMLFiles(ctx context.Context, snapshot *project.Snapshot) (map[string]string, error) {
	files := map[string]string{}
	var paths []string
	for _, entry := range snapshot.Manifest().Entries {
		if strings.HasSuffix(entry.Path, ".xml") {
			paths = append(paths, entry.Path)
		}
	}
	sort.Strings(paths)
	if len(paths) > MaxFiles {
		return nil, fmt.Errorf("%w: XML file count exceeds %d", audit.ErrLimit, MaxFiles)
	}
	for _, file := range paths {
		data, err := snapshot.ReadFile(ctx, file)
		if err != nil {
			return nil, err
		}
		if len(data) == 0 || len(data) > MaxFileBytes || !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
			continue
		}
		files[file] = string(data)
	}
	return files, nil
}

func evaluateEndpoint(endpoint audit.Endpoint, controller audit.Controller, source javaSource, controls []Control) EndpointDecision {
	decision := EndpointDecision{
		Path: endpoint.Path, HTTPMethods: append([]string{}, endpoint.HTTPMethods...),
		File: endpoint.File, Class: endpoint.Class, Method: endpoint.Method, Symbol: endpoint.Symbol,
		StartLine: endpoint.StartLine, MethodLine: endpoint.MethodLine, EndLine: endpoint.EndLine,
		Decision: "unknown", Requirement: RequirementUnknown, RuntimeStatus: "not_run",
	}
	if endpoint.PathStatus != "resolved" {
		decision.Reason = "unresolved_route_path"
		return decision
	}
	methodRequirement, methodNotes := annotationRequirement(source.Lines, endpoint.StartLine, endpoint.MethodLine, securityMethod)
	classRequirement, classNotes := classAnnotationRequirement(source.Lines, controller.StartLine, securityClass)
	manual, manualNote := manualControl(source.Lines, endpoint.MethodLine, endpoint.EndLine)

	var securityControls []Control
	var otherControls []Control
	for _, control := range controls {
		switch control.Kind {
		case "spring_security_java", "spring_security_xml":
			securityControls = append(securityControls, control)
		default:
			otherControls = append(otherControls, control)
		}
	}
	securityRequirement := ""
	for _, control := range securityControls {
		if !controlApplies(control, endpoint.Path, endpoint.HTTPMethods) {
			continue
		}
		decision.MatchedControls = append(decision.MatchedControls, control.ID)
		securityRequirement = control.Requirement
		break
	}
	otherProtected, otherPublic, otherUnknown := false, false, false
	for _, control := range otherControls {
		if !controlApplies(control, endpoint.Path, endpoint.HTTPMethods) {
			continue
		}
		decision.MatchedControls = append(decision.MatchedControls, control.ID)
		switch control.Requirement {
		case RequirementAuthenticated, RequirementRole, RequirementDeny:
			otherProtected = true
		case RequirementPublic:
			otherPublic = true
		default:
			otherUnknown = true
		}
	}
	explicitRequirement, explicitNotes := methodRequirement, methodNotes
	explicitReason := "method_security_annotation"
	if explicitRequirement == "" {
		explicitRequirement, explicitNotes = classRequirement, classNotes
		explicitReason = "class_security_annotation"
	}
	if explicitRequirement != "" {
		decision.Reason = explicitReason
		if len(explicitNotes) > 0 {
			decision.Reason += ":" + strings.Join(explicitNotes, ",")
		}
		switch explicitRequirement {
		case RequirementPublic:
			// A method/class permitAll does not disable an independent
			// interceptor or filter, so a protected secondary control wins.
			if otherProtected || securityRequirement == RequirementAuthenticated ||
				securityRequirement == RequirementRole || securityRequirement == RequirementDeny {
				decision.Decision = "protected"
				decision.Requirement = RequirementAuthenticated
				decision.Reason = "explicit_permit_with_protected_global_control"
			} else if otherUnknown || securityRequirement == RequirementUnknown {
				decision.Decision = "unknown"
				decision.Requirement = RequirementUnknown
			} else {
				decision.Decision = "public"
				decision.Requirement = RequirementPublic
			}
		case RequirementAuthenticated, RequirementRole, RequirementDeny:
			decision.Decision = "protected"
			decision.Requirement = explicitRequirement
		}
		return decision
	}
	if securityRequirement == RequirementAuthenticated || securityRequirement == RequirementRole || securityRequirement == RequirementDeny {
		decision.Decision = "protected"
		decision.Requirement = securityRequirement
		decision.Reason = "spring_security_" + securityRequirement
		return decision
	}
	if otherProtected {
		decision.Decision = "protected"
		decision.Requirement = RequirementAuthenticated
		decision.Reason = "interceptor_or_filter_observed"
		return decision
	}
	if securityRequirement == RequirementUnknown || otherUnknown {
		decision.Decision = "unknown"
		decision.Requirement = RequirementUnknown
		decision.Reason = "control_requirement_unresolved"
		return decision
	}
	if manual != "" {
		decision.Decision = "unknown"
		decision.Requirement = RequirementUnknown
		decision.Reason = "manual_control_observed:" + manual
		if manualNote != "" {
			decision.Reason += ":" + manualNote
		}
		return decision
	}
	if securityRequirement == RequirementPublic || otherPublic {
		decision.Decision = "public"
		decision.Requirement = RequirementPublic
		decision.Reason = "public_control_observed"
		return decision
	}
	if isLoginPath(endpoint.Path) {
		decision.Decision = "public"
		decision.Requirement = RequirementPublic
		decision.Reason = "login_endpoint_without_observed_control"
		return decision
	}
	decision.Decision = "unprotected"
	decision.Requirement = "none"
	decision.Reason = "no_authentication_or_authorization_control_observed"
	decision.FindingStatus = "inconclusive"
	return decision
}

func controlApplies(control Control, endpointPath string, methods []string) bool {
	if control.Status != "observed" && control.Requirement == RequirementUnknown {
		return false
	}
	if len(control.Methods) > 0 && !methodsIntersect(control.Methods, methods) {
		return false
	}
	for _, excluded := range control.Excluded {
		if matchPath(excluded, endpointPath) {
			return false
		}
	}
	for _, pattern := range control.Paths {
		if matchPath(pattern, endpointPath) {
			return true
		}
	}
	return false
}

func methodsIntersect(declared, actual []string) bool {
	if len(actual) == 0 {
		return true
	}
	for _, left := range declared {
		for _, right := range actual {
			if strings.EqualFold(left, right) {
				return true
			}
		}
	}
	return false
}

func annotationRequirement(lines []string, start, end int, pattern *regexp.Regexp) (string, []string) {
	if start < 1 {
		start = 1
	}
	if end < start {
		end = start
	}
	if start > len(lines) {
		return "", nil
	}
	if end > len(lines) {
		end = len(lines)
	}
	requirement := ""
	var notes []string
	for index := start - 1; index < end; index++ {
		matches := pattern.FindAllStringSubmatch(lines[index], -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			notes = append(notes, match[1])
			switch match[1] {
			case "PermitAll":
				requirement = RequirementPublic
			case "DenyAll":
				requirement = RequirementDeny
			default:
				if requirement != RequirementDeny {
					requirement = RequirementAuthenticated
				}
			}
		}
	}
	return requirement, dedupe(notes)
}

func classAnnotationRequirement(lines []string, classLine int, pattern *regexp.Regexp) (string, []string) {
	if classLine < 1 {
		return "", nil
	}
	start := classLine - 40
	if start < 1 {
		start = 1
	}
	return annotationRequirement(lines, start, classLine, pattern)
}

func manualControl(lines []string, methodLine, endLine int) (string, string) {
	if methodLine < 1 || endLine < methodLine || methodLine > len(lines) {
		return "", ""
	}
	if endLine > len(lines) {
		endLine = len(lines)
	}
	var body strings.Builder
	for index := methodLine - 1; index < endLine; index++ {
		body.WriteString(lines[index])
		body.WriteString("\n")
	}
	content := body.String()
	lower := strings.ToLower(content)
	switch {
	case strings.Contains(lower, "securitycontextholder") || strings.Contains(lower, "isauthenticated"):
		return "security_context_check", ""
	case strings.Contains(lower, "getsession") && strings.Contains(lower, "getattribute"):
		return "session_attribute_read", ""
	case strings.Contains(lower, "authenticationprincipal") || strings.Contains(lower, "principal "):
		return "principal_parameter", ""
	}
	return "", ""
}

func isLoginPath(value string) bool {
	lower := strings.ToLower(value)
	return strings.HasSuffix(lower, "/login") || strings.HasSuffix(lower, "/dologin")
}

func findingFor(decision EndpointDecision) Finding {
	raw := decision.Path + "\x00" + decision.Symbol + "\x00" + decision.File
	sum := sha256.Sum256([]byte(raw))
	evidence := []string{
		"http_endpoint:" + decision.Path,
		"source:" + decision.File,
		fmt.Sprintf("symbol:%s:%d", decision.Symbol, decision.MethodLine),
	}
	return Finding{
		ID: "authz:" + hex.EncodeToString(sum[:8]), Kind: "missing_authentication_or_authorization",
		CWE: "CWE-306", Path: decision.Path, HTTPMethods: append([]string{}, decision.HTTPMethods...),
		File: decision.File, Symbol: decision.Symbol, StartLine: decision.StartLine,
		MethodLine: decision.MethodLine, EndLine: decision.EndLine, Status: "inconclusive", Reason: decision.Reason,
		RuntimeStatus: "not_run", Evidence: evidence,
	}
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

func lineOf(content string, offset int) int {
	if offset <= 0 {
		return 1
	}
	if offset > len(content) {
		offset = len(content)
	}
	return strings.Count(content[:offset], "\n") + 1
}

func xmlAttributes(fragment string) map[string]string {
	attributes := map[string]string{}
	for _, match := range attributePattern.FindAllStringSubmatch(fragment, -1) {
		if len(match) >= 3 {
			attributes[strings.ToLower(match[1])] = match[2]
		}
	}
	return attributes
}

func quotedValues(value string) []string {
	var out []string
	for _, match := range quotedValuePattern.FindAllStringSubmatch(value, -1) {
		if len(match) >= 2 && strings.TrimSpace(match[1]) != "" {
			out = append(out, strings.TrimSpace(match[1]))
		}
	}
	return out
}

func classAfter(content string, offset int) string {
	if offset < 0 || offset >= len(content) {
		return ""
	}
	rest := content[offset:]
	match := javaClassPattern.FindStringSubmatch(rest)
	if match == nil {
		return ""
	}
	return match[1]
}
