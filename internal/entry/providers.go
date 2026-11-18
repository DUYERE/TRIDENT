package entry

import (
	"sort"
	"strconv"
	"strings"

	"trident/internal/authz"
	"trident/internal/codescan"
	"trident/internal/evidence"
)

// JavaAuditProvider normalizes the existing Java annotation-level endpoint
// inventory and optional authorization decisions.
type JavaAuditProvider struct{}

func (JavaAuditProvider) Name() string { return "java_audit" }

func (JavaAuditProvider) Collect(input Input) (Contribution, error) {
	if input.JavaAudit == nil {
		return Contribution{Limitations: []string{"java_audit_not_run"}}, nil
	}
	decisions := map[string]authz.EndpointDecision{}
	if input.Authz != nil {
		for _, decision := range input.Authz.Endpoints {
			decisions[decision.Symbol] = decision
		}
	}
	report := input.JavaAudit
	entries := make([]evidence.Entry, 0, len(report.Endpoints))
	for _, endpoint := range report.Endpoints {
		pathStatus := endpoint.PathStatus
		if pathStatus == "" {
			pathStatus = "unknown"
		}
		item := evidence.Entry{
			ID:          stableID("java_audit", endpoint.File, endpoint.StartLine, endpoint.Path, endpoint.Symbol),
			Language:    "java",
			Framework:   "Java annotation",
			Kind:        evidence.KindAnnotationRoute,
			Source:      "java_audit",
			HTTPMethods: append([]string(nil), endpoint.HTTPMethods...),
			Path:        endpoint.Path,
			PathStatus:  pathStatus,
			Symbol:      endpoint.Symbol,
			Class:       endpoint.Class,
			Method:      endpoint.Method,
			File:        endpoint.File,
			SHA256:      endpoint.SHA256,
			StartLine:   endpoint.StartLine,
			EndLine:     endpoint.EndLine,
			MethodLine:  endpoint.MethodLine,
			Confidence:  "annotation",
			Reason:      endpoint.PathReason,
		}
		if endpoint.Annotation != "" {
			item.Framework = "Java annotation: " + endpoint.Annotation
		}
		for _, parameter := range endpoint.Parameters {
			item.Parameters = append(item.Parameters, evidence.Parameter{
				Name:        parameter.Name,
				Type:        parameter.Type,
				Bindings:    append([]string(nil), parameter.Bindings...),
				BindingName: parameter.BindingName,
				Required:    parameter.Required,
				Line:        parameter.Line,
			})
		}
		if decision, ok := decisions[endpoint.Symbol]; ok {
			item.Authz = &evidence.Authz{
				Decision:        decision.Decision,
				Requirement:     decision.Requirement,
				Reason:          decision.Reason,
				MatchedControls: append([]string(nil), decision.MatchedControls...),
				RuntimeStatus:   decision.RuntimeStatus,
			}
		}
		entries = append(entries, item)
	}
	status := "scanned"
	if report.Coverage.JavaFilesScanned == 0 {
		status = "no_source_files"
	} else if report.Partial {
		status = "partial"
	}
	limitations := append([]string(nil), report.Limitations...)
	if input.Authz == nil {
		limitations = append(limitations, "authz_not_run")
	}
	return Contribution{
		Entries: entries,
		Coverage: []evidence.LanguageCoverage{{
			Source:        "java_audit",
			Capability:    Capability,
			Language:      "java",
			FilesScanned:  report.Coverage.JavaFilesScanned,
			FilesRejected: report.Coverage.JavaFilesRejected,
			Entries:       len(entries),
			Status:        status,
			Reason:        "annotation_level_inventory",
		}},
		Partial:     report.Partial,
		Limitations: limitations,
	}, nil
}

// CodeRouteProvider normalizes codescan's declared routes. It does not start a
// code audit: without a cached report it reports an explicit limitation.
type CodeRouteProvider struct{}

func (CodeRouteProvider) Name() string { return "codescan" }

func (CodeRouteProvider) Collect(input Input) (Contribution, error) {
	if input.CodeAudit == nil {
		return Contribution{Limitations: []string{"code_audit_not_run"}}, nil
	}
	report := input.CodeAudit
	entries := make([]evidence.Entry, 0, len(report.Routes))
	for _, route := range report.Routes {
		if route.Kind == "convention" || route.PathStatus == "convention_candidate" {
			// Convention candidates are visible in the code view but are not
			// authoritative entry evidence; including them would turn one
			// ThinkPHP project into hundreds of guessed endpoints.
			continue
		}
		pathStatus := route.PathStatus
		if pathStatus == "" {
			pathStatus = "declared"
		}
		reason := "route_declaration_not_deployment"
		switch pathStatus {
		case "dynamic_unresolved":
			reason = "route_path_not_literal"
		case "declared":
			if route.Source == "database" {
				reason = "database_urlconfig_row"
			}
		}
		entries = append(entries, evidence.Entry{
			ID:          stableID("codescan", route.File, route.Line, route.Path, route.Symbol),
			Language:    route.Language,
			Kind:        evidence.KindRouteDeclaration,
			Source:      "codescan",
			HTTPMethods: append([]string(nil), route.HTTPMethods...),
			Path:        route.Path,
			PathStatus:  pathStatus,
			Target:      route.Target,
			Symbol:      route.Symbol,
			File:        route.File,
			SHA256:      route.SHA256,
			StartLine:   route.Line,
			EndLine:     route.Line,
			Confidence:  "route_declaration",
			Reason:      reason,
		})
	}
	coverage := make([]evidence.LanguageCoverage, 0, len(report.Languages))
	routeByLanguage := map[string]int{}
	for _, route := range report.Routes {
		if route.Kind == "convention" || route.PathStatus == "convention_candidate" {
			continue
		}
		routeByLanguage[route.Language]++
	}
	seenLanguages := map[string]struct{}{}
	for _, language := range report.Languages {
		seenLanguages[language.Language] = struct{}{}
		coverage = append(coverage, evidence.LanguageCoverage{
			Source:        "codescan",
			Capability:    Capability,
			Language:      language.Language,
			FilesScanned:  language.FilesScanned,
			FilesRejected: language.FilesRejected,
			Entries:       routeByLanguage[language.Language],
			Status:        language.Status,
			Reason:        "route_declaration_scan",
		})
	}
	routeLanguages := map[string]int{}
	for language, count := range routeByLanguage {
		routeLanguages[language] = count
	}
	for language, count := range routeLanguages {
		if _, ok := seenLanguages[language]; ok {
			continue
		}
		coverage = append(coverage, evidence.LanguageCoverage{
			Source:     "codescan",
			Capability: Capability,
			Language:   language,
			Entries:    count,
			Status:     "observed",
			Reason:     "route_declaration_scan",
		})
	}
	sort.Slice(coverage, func(i, j int) bool { return coverage[i].Language < coverage[j].Language })
	return Contribution{
		Entries:     entries,
		Coverage:    coverage,
		Partial:     codeEntryPartial(report),
		Limitations: codeEntryLimitations(report),
	}, nil
}

// codeEntryPartial is entry-specific. A symbol/call/finding cap does not make
// route evidence incomplete, so it must not turn entry_partial on.
func codeEntryPartial(report *codescan.Report) bool {
	if report == nil || !report.Partial {
		return false
	}
	for _, limitation := range report.Limitations {
		switch limitation {
		case "file_limit", "file_too_large", "lex_rejected", "statement_limit":
			return true
		}
	}
	return false
}

func codeEntryLimitations(report *codescan.Report) []string {
	if report == nil {
		return nil
	}
	out := make([]string, 0, len(report.Limitations))
	for _, limitation := range report.Limitations {
		if strings.HasPrefix(limitation, "symbol_") ||
			limitation == "call_limit" || limitation == "unresolved_limit" {
			continue
		}
		out = append(out, limitation)
	}
	return out
}

func entryAuthzKey(file string, line int) string {
	return file + "\x00" + strconv.Itoa(line)
}

// ApplicationEntryProvider normalizes the filename-level application entry
// candidates. These are never route declarations.
type ApplicationEntryProvider struct{}

func (ApplicationEntryProvider) Name() string { return "application_entry" }

func (ApplicationEntryProvider) Collect(input Input) (Contribution, error) {
	if input.ApplicationEntries == nil {
		return Contribution{Limitations: []string{"entrypoint_not_run"}}, nil
	}
	report := input.ApplicationEntries
	entries := make([]evidence.Entry, 0, len(report.Entries))
	byLanguage := map[string]int{}
	filenameByLanguage := map[string]int{}
	requestByLanguage := map[string]int{}
	scriptDecisions := map[string]authz.LanguageAdapter{}
	if input.Authz != nil {
		for _, adapter := range input.Authz.LanguageAdapters {
			if adapter.Language == "php" && adapter.Scope == "request_script" {
				scriptDecisions[entryAuthzKey(adapter.File, adapter.Line)] = adapter
			}
		}
	}
	for _, item := range report.Entries {
		byLanguage[item.Language]++
		confidence := "filename_heuristic"
		kind := evidence.KindApplicationEntry
		if item.Kind == "request_script" {
			confidence = "request_script_heuristic"
			kind = evidence.KindRequestScript
			requestByLanguage[item.Language]++
		} else {
			filenameByLanguage[item.Language]++
		}
		entryItem := evidence.Entry{
			ID:         stableID("application_entry", item.Path, item.Line, "", item.Language),
			Language:   item.Language,
			Framework:  item.Framework,
			Kind:       kind,
			Source:     "application_entry",
			PathStatus: "not_applicable",
			File:       item.Path,
			SHA256:     item.SHA256,
			StartLine:  item.Line,
			EndLine:    item.Line,
			Confidence: confidence,
			Reason:     item.Reason,
		}
		if kind == evidence.KindRequestScript {
			if decision, ok := scriptDecisions[entryAuthzKey(item.Path, item.Line)]; ok {
				entryItem.Authz = &evidence.Authz{
					Decision:        decision.Decision,
					Requirement:     decision.Requirement,
					Reason:          decision.Reason,
					MatchedControls: append([]string(nil), decision.MatchedControls...),
					RuntimeStatus:   "not_run",
				}
			}
		}
		entries = append(entries, entryItem)
	}
	languages := make([]string, 0, len(byLanguage))
	for language := range byLanguage {
		languages = append(languages, language)
	}
	sort.Strings(languages)
	coverage := make([]evidence.LanguageCoverage, 0, len(languages))
	for _, language := range languages {
		status := "filename_heuristic"
		reason := "known_entry_filename"
		if requestByLanguage[language] > 0 && filenameByLanguage[language] == 0 {
			status = "request_script_heuristic"
			reason = "php_request_superglobal_observed"
		} else if requestByLanguage[language] > 0 {
			status = "mixed_entry_heuristics"
			reason = "known_entry_filename_and_request_superglobal"
		}
		coverage = append(coverage, evidence.LanguageCoverage{
			Source:     "application_entry",
			Capability: Capability,
			Language:   language,
			Entries:    byLanguage[language],
			Status:     status,
			Reason:     reason,
		})
	}
	return Contribution{
		Entries:  entries,
		Coverage: coverage,
		Partial:  report.Partial,
		Limitations: append(
			[]string{"entry_candidate_not_deployed_route"},
			report.Limitations...,
		),
	}, nil
}

// Compile-time checks keep the built-in providers aligned with the interface.
var (
	_ Provider = JavaAuditProvider{}
	_ Provider = CodeRouteProvider{}
	_ Provider = ApplicationEntryProvider{}
)
