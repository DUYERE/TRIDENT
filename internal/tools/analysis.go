package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"trident/internal/audit"
	"trident/internal/codescan"
	"trident/internal/entry"
	"trident/internal/evidence"
	"trident/internal/findings"
	"trident/internal/project"
	"trident/internal/sca"
)

const (
	analysisSchemaVersion = 1
	analysisDefaultLimit  = 10
	analysisMaxLimit      = 25
	analysisMaxOffset     = 100_000
	analysisMaxCitations  = 24
)

// AnalysisOptions binds local analysis configuration to a Run. The advisory
// catalog is caller-supplied configuration, never snapshot content.
type AnalysisOptions struct {
	AdvisoryPath string
	AdvisoryDir  string
	// CodeReport binds the console's cached multi-language rule report so the
	// Agent quotes the same evidence the findings page shows instead of
	// re-deriving it. Nil keeps the legacy Java-only view.
	CodeReport *codescan.Report
}

type analysisCache struct {
	findings findings.Report
	sca      sca.Report
	audit    audit.Report
	code     *codescan.Report
	err      error
}

type analysisResponse struct {
	SchemaVersion      int            `json:"schema_version"`
	Tool               string         `json:"tool"`
	SnapshotHash       string         `json:"snapshot_hash"`
	Total              int            `json:"total"`
	Offset             int            `json:"offset"`
	Limit              int            `json:"limit"`
	Partial            bool           `json:"partial"`
	AdvisoryConfigured bool           `json:"advisory_configured"`
	Counts             map[string]int `json:"counts,omitempty"`
	Coverage           any            `json:"coverage,omitempty"`
	Manifests          []sca.Manifest `json:"manifests,omitempty"`
	Limitations        []string       `json:"limitations"`
	Items              any            `json:"items"`
	Citations          []Evidence     `json:"citations,omitempty"`
}

// symbolQueryResponse is declaration browsing for the Agent. It reuses the
// console's cached code report when one is bound and otherwise lazily derives
// the same bounded lexical index, so symbols and findings do not diverge.
type symbolQueryResponse struct {
	SchemaVersion int                        `json:"schema_version"`
	Tool          string                     `json:"tool"`
	SnapshotHash  string                     `json:"snapshot_hash"`
	Available     bool                       `json:"available"`
	Reason        string                     `json:"reason,omitempty"`
	Total         int                        `json:"total"`
	Offset        int                        `json:"offset"`
	Limit         int                        `json:"limit"`
	Partial       bool                       `json:"partial"`
	SymbolPartial bool                       `json:"symbol_partial"`
	Counts        map[string]int             `json:"counts,omitempty"`
	Coverage      any                        `json:"coverage,omitempty"`
	Limitations   []string                   `json:"limitations"`
	Items         []codescan.Symbol          `json:"items"`
	Languages     []codescan.LanguageSummary `json:"languages"`
	Kinds         []codescan.Count           `json:"kinds"`
	RuntimeStatus string                     `json:"runtime_status"`
}

type findingView struct {
	ID            string                 `json:"id"`
	Kind          string                 `json:"kind"`
	Category      string                 `json:"category"`
	CWE           string                 `json:"cwe"`
	Severity      string                 `json:"severity"`
	Status        string                 `json:"status"`
	RuntimeStatus string                 `json:"runtime_status"`
	Title         string                 `json:"title"`
	Language      string                 `json:"language,omitempty"`
	Endpoint      *findings.EndpointRef  `json:"endpoint,omitempty"`
	Component     *findings.ComponentRef `json:"component,omitempty"`
	Location      string                 `json:"location,omitempty"`
	Citations     []Evidence             `json:"citations,omitempty"`
}

// findingLocation gives endpoint-less merged code findings a stable
// file:line handle so the Agent can cite them like any other finding.
func findingLocation(finding findings.Finding) string {
	if finding.Endpoint != nil || finding.Component != nil {
		return ""
	}
	for _, item := range finding.Evidence {
		if item.Kind == "sink" && item.File != "" {
			line := item.StartLine
			if line < 1 {
				line = item.EndLine
			}
			return fmt.Sprintf("%s:%d", item.File, line)
		}
	}
	return ""
}

// findingLanguage reports the source language of a finding for the Agent's
// language filter. Merged code-audit findings carry "language=" in their
// SourceAnalyses; the Java unified model (annotation inventory, dataflow, SCA)
// is always Java.
func findingLanguage(finding findings.Finding) string {
	if strings.HasPrefix(finding.ID, "code:") {
		for _, entry := range finding.SourceAnalyses {
			if value, ok := strings.CutPrefix(entry, "language="); ok && value != "" {
				return value
			}
		}
		return "unknown"
	}
	return "java"
}

// findingCategoryKeys returns every category key a finding may be filtered by:
// the unified-model kind mapping and, for code-audit findings, the rule's own
// category. category=sql therefore matches both sql_injection and php.sql.query.
func findingCategoryKeys(finding findings.Finding) []string {
	keys := []string{}
	if mapped := categoryKeyForFinding(finding.Kind); mapped != "" {
		keys = append(keys, mapped)
	}
	if finding.Category != "" && finding.Category != finding.Kind {
		keys = append(keys, finding.Category)
	}
	return keys
}

func containsName(values []string, want string) bool {
	return slices.Contains(values, want)
}

type dependencyView struct {
	Module         string `json:"module"`
	Ecosystem      string `json:"ecosystem,omitempty"`
	Name           string `json:"name,omitempty"`
	GroupID        string `json:"group_id"`
	ArtifactID     string `json:"artifact_id"`
	Version        string `json:"version,omitempty"`
	Scope          string `json:"scope"`
	VersionStatus  string `json:"version_status"`
	DeclarationPOM string `json:"declaration_pom"`
	Manifest       string `json:"manifest,omitempty"`
}

type advisoryMatchView struct {
	AdvisoryID      string `json:"advisory_id"`
	Module          string `json:"module"`
	Dependency      string `json:"dependency"`
	DeclaredVersion string `json:"declared_version,omitempty"`
	VersionStatus   string `json:"version_status"`
	FindingStatus   string `json:"finding_status"`
	RuntimeStatus   string `json:"runtime_status"`
}

type endpointView struct {
	audit.Endpoint
	Language   string     `json:"language,omitempty"`
	Framework  string     `json:"framework,omitempty"`
	Kind       string     `json:"kind,omitempty"`
	Source     string     `json:"source,omitempty"`
	PathStatus string     `json:"path_status,omitempty"`
	Target     string     `json:"target,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	Confidence string     `json:"confidence,omitempty"`
	Citations  []Evidence `json:"citations,omitempty"`
}

// analysisState runs the read-only analyses once per registry. A failure is
// cached as a terminal error instead of being retried for every tool call.
func (r *Registry) advisoryConfigured() bool {
	return r.analysisOptions.AdvisoryPath != "" || r.analysisOptions.AdvisoryDir != ""
}

func (r *Registry) analysisState(ctx context.Context) (*analysisCache, error) {
	if r == nil || r.snapshot == nil {
		return nil, os.ErrClosed
	}
	r.analysisMu.Lock()
	defer r.analysisMu.Unlock()
	if r.analysis != nil {
		return r.analysis, r.analysis.err
	}
	state := &analysisCache{}
	scaReport, scaErr := sca.Inspect(ctx, r.snapshot, sca.Options{AdvisoryPath: r.analysisOptions.AdvisoryPath, AdvisoryDir: r.analysisOptions.AdvisoryDir})
	endpointReport, auditErr := audit.Inspect(ctx, r.snapshot)
	findingReport, findingErr := findings.Analyze(ctx, r.snapshot, findings.Options{AdvisoryPath: r.analysisOptions.AdvisoryPath})
	switch {
	case findingErr != nil:
		state.err = fmt.Errorf("analysis failed: %w", findingErr)
	case scaErr != nil:
		state.err = fmt.Errorf("SCA analysis failed: %w", scaErr)
	case auditErr != nil:
		state.err = fmt.Errorf("endpoint inventory failed: %w", auditErr)
	default:
		// Merge the console's cached multi-language report so list_findings and
		// the findings page agree; without it an Agent could not see PHP or
		// other non-Java findings at all.
		if r.analysisOptions.CodeReport != nil {
			merged := codescan.AsFindingsReport(*r.analysisOptions.CodeReport)
			findingReport.Findings = append(findingReport.Findings, merged.Findings...)
			for _, finding := range merged.Findings {
				switch finding.Status {
				case "static_confirmed":
					findingReport.Coverage.FindingsStaticConfirmed++
				case "refuted":
					findingReport.Coverage.FindingsRefuted++
				default:
					findingReport.Coverage.FindingsInconclusive++
				}
				findingReport.Coverage.FindingsTotal++
			}
		}
		state.findings = findingReport
		state.sca = scaReport
		state.audit = endpointReport
		if r.analysisOptions.CodeReport != nil {
			state.code = r.analysisOptions.CodeReport
		}
	}
	r.analysis = state
	return state, state.err
}

func analysisPage(values map[string]any) (limit, offset int, err error) {
	limit = integerValue(values, "limit")
	if limit == 0 {
		limit = analysisDefaultLimit
	}
	if limit < 1 || limit > analysisMaxLimit {
		return 0, 0, fmt.Errorf("%w: limit must be between 1 and %d", ErrArguments, analysisMaxLimit)
	}
	offset = integerValue(values, "offset")
	if offset < 0 || offset > analysisMaxOffset {
		return 0, 0, fmt.Errorf("%w: offset must be between 0 and %d", ErrArguments, analysisMaxOffset)
	}
	return limit, offset, nil
}

func analysisQuery(values map[string]any) (string, error) {
	query := stringValue(values, "q")
	if len(query) > 256 {
		return "", fmt.Errorf("%w: q exceeds 256 bytes", ErrArguments)
	}
	return strings.ToLower(query), nil
}

func pageBounds(total, offset, limit int) (int, int) {
	if offset >= total {
		return 0, 0
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return offset, end
}

func (r *Registry) inspectDependencies(ctx context.Context, values map[string]any) (analysisResponse, error) {
	limit, offset, err := analysisPage(values)
	if err != nil {
		return analysisResponse{}, err
	}
	state, err := r.analysisState(ctx)
	if err != nil {
		return analysisResponse{}, err
	}
	dependencies := state.sca.Dependencies
	start, end := pageBounds(len(dependencies), offset, limit)
	items := make([]dependencyView, 0, end-start)
	for _, dependency := range dependencies[start:end] {
		items = append(items, dependencyView{
			Module: dependency.Module, Ecosystem: dependency.Ecosystem, Name: dependency.Name,
			GroupID: dependency.GroupID, ArtifactID: dependency.ArtifactID,
			Version: dependency.Version, Scope: dependency.Scope, VersionStatus: dependency.VersionStatus,
			DeclarationPOM: dependency.DeclarationPOM, Manifest: dependency.Manifest,
		})
	}
	return analysisResponse{
		SchemaVersion: analysisSchemaVersion, Tool: "inspect_dependencies", SnapshotHash: r.snapshot.Hash(),
		Total: len(dependencies), Offset: offset, Limit: limit, Partial: state.sca.Partial,
		AdvisoryConfigured: r.advisoryConfigured(),
		Counts: map[string]int{
			"modules": state.sca.Project.ModuleCount, "poms": state.sca.Project.POMCount,
			"manifests": state.sca.Coverage.ManifestFilesScanned, "manifest_dependencies": state.sca.Coverage.ManifestDependencies,
			"dependencies_declared": len(state.sca.Dependencies), "dependencies_unresolved": state.sca.Coverage.DependenciesUnresolved,
		},
		Coverage: state.sca.Coverage, Manifests: append([]sca.Manifest(nil), state.sca.Manifests...), Limitations: state.sca.Limitations, Items: items,
	}, nil
}

func (r *Registry) matchAdvisories(ctx context.Context, values map[string]any) (analysisResponse, error) {
	limit, offset, err := analysisPage(values)
	if err != nil {
		return analysisResponse{}, err
	}
	state, err := r.analysisState(ctx)
	if err != nil {
		return analysisResponse{}, err
	}
	matches := state.sca.AdvisoryMatches
	start, end := pageBounds(len(matches), offset, limit)
	items := make([]advisoryMatchView, 0, end-start)
	for _, match := range matches[start:end] {
		items = append(items, advisoryMatchView{
			AdvisoryID: match.AdvisoryID, Module: match.Module, Dependency: match.Dependency,
			DeclaredVersion: match.DeclaredVersion, VersionStatus: match.VersionStatus,
			FindingStatus: match.FindingStatus, RuntimeStatus: match.RuntimeStatus,
		})
	}
	limitations := append([]string{}, state.sca.Limitations...)
	if !r.advisoryConfigured() {
		limitations = append(limitations, "advisory_catalog_not_configured")
	}
	return analysisResponse{
		SchemaVersion: analysisSchemaVersion, Tool: "match_advisories", SnapshotHash: r.snapshot.Hash(),
		Total: len(matches), Offset: offset, Limit: limit, Partial: state.sca.Partial,
		AdvisoryConfigured: r.advisoryConfigured(),
		Counts: map[string]int{
			"advisory_matches": len(matches), "advisories_loaded": state.sca.Coverage.AdvisoriesLoaded,
			"dependencies_declared": len(state.sca.Dependencies),
		},
		Coverage: state.sca.Coverage, Limitations: dedupeStrings(limitations), Items: items,
	}, nil
}

func (r *Registry) queryEndpoints(ctx context.Context, values map[string]any) (analysisResponse, error) {
	limit, offset, err := analysisPage(values)
	if err != nil {
		return analysisResponse{}, err
	}
	query, err := analysisQuery(values)
	if err != nil {
		return analysisResponse{}, err
	}
	state, err := r.analysisState(ctx)
	if err != nil {
		return analysisResponse{}, err
	}
	partial := state.audit.Partial
	limitations := append([]string{}, state.audit.Limitations...)
	coverage := any(state.audit.Coverage)
	counts := map[string]int{
		"controllers": state.audit.Coverage.ControllersFound, "endpoints": len(state.audit.Endpoints),
		"unresolved_paths": state.audit.Coverage.UnresolvedPaths, "duplicate_routes": state.audit.Coverage.DuplicateRoutes,
	}
	var filtered []endpointView
	if state.code != nil {
		evidenceReport, buildErr := entry.NewRegistry().Build(ctx, entry.Input{
			Snapshot: r.snapshot, JavaAudit: &state.audit, CodeAudit: state.code,
		})
		if buildErr != nil {
			return analysisResponse{}, buildErr
		}
		partial = evidenceReport.Partial
		limitations = append([]string{}, evidenceReport.Limitations...)
		coverage = evidenceReport.Coverage
		counts = map[string]int{"entries": len(evidenceReport.Entries)}
		for _, entry := range evidenceReport.Entries {
			if entry.Kind != evidence.KindRouteDeclaration && entry.Kind != evidence.KindAnnotationRoute {
				continue
			}
			if query != "" && !strings.Contains(strings.ToLower(entry.Path+" "+entry.Symbol+" "+entry.File+" "+strings.Join(entry.HTTPMethods, ",")), query) {
				continue
			}
			filtered = append(filtered, endpointView{
				Endpoint: audit.Endpoint{
					Path: entry.Path, HTTPMethods: append([]string(nil), entry.HTTPMethods...), File: entry.File,
					Class: entry.Class, Method: entry.Method, Symbol: entry.Symbol, SHA256: entry.SHA256,
					StartLine: entry.StartLine, EndLine: entry.EndLine, MethodLine: entry.MethodLine,
					PathStatus: entry.PathStatus, PathReason: entry.Reason,
				},
				Language: entry.Language, Framework: entry.Framework, Kind: entry.Kind, Source: entry.Source,
				PathStatus: entry.PathStatus, Target: entry.Target, Reason: entry.Reason, Confidence: entry.Confidence,
			})
		}
	} else {
		for _, endpoint := range state.audit.Endpoints {
			if query != "" && !strings.Contains(strings.ToLower(endpoint.Path+" "+endpoint.Symbol+" "+endpoint.File+" "+strings.Join(endpoint.HTTPMethods, ",")), query) {
				continue
			}
			filtered = append(filtered, endpointView{Endpoint: endpoint})
		}
	}
	start, end := pageBounds(len(filtered), offset, limit)
	items := make([]endpointView, 0, end-start)
	citations := make([]Evidence, 0, end-start)
	for index := start; index < end; index++ {
		endpoint := filtered[index]
		line := endpoint.MethodLine
		if line <= 0 {
			line = endpoint.StartLine
		}
		candidate := r.citation(endpoint.File, endpoint.SHA256, line, line)
		item := endpoint
		if candidate.Path != "" {
			if observed, observeErr := r.observeCitations(ctx, []Evidence{candidate}); observeErr != nil {
				return analysisResponse{}, observeErr
			} else if len(observed) == 1 {
				item.Citations = observed
				citations = append(citations, observed...)
			}
		}
		items = append(items, item)
	}
	return analysisResponse{
		SchemaVersion: analysisSchemaVersion, Tool: "query_endpoints", SnapshotHash: r.snapshot.Hash(),
		Total: len(filtered), Offset: offset, Limit: limit, Partial: partial,
		AdvisoryConfigured: r.advisoryConfigured(),
		Counts:             counts,
		Coverage:           coverage, Limitations: limitations, Items: items,
		Citations: dedupeEvidence(citations),
	}, nil
}

func (r *Registry) querySymbols(ctx context.Context, values map[string]any) (symbolQueryResponse, error) {
	limit, offset, err := analysisPage(values)
	if err != nil {
		return symbolQueryResponse{}, err
	}
	query, err := analysisQuery(values)
	if err != nil {
		return symbolQueryResponse{}, err
	}
	language := strings.ToLower(strings.TrimSpace(stringValue(values, "language")))
	kind := strings.ToLower(strings.TrimSpace(stringValue(values, "kind")))
	if len(language) > 16 || len(kind) > 16 {
		return symbolQueryResponse{}, fmt.Errorf("%w: language or kind exceeds 16 bytes", ErrArguments)
	}
	state, err := r.analysisState(ctx)
	if err != nil {
		return symbolQueryResponse{}, err
	}
	report, err := r.symbolReport(ctx, state)
	if err != nil {
		return symbolQueryResponse{}, err
	}
	matched := make([]codescan.Symbol, 0, len(report.Symbols))
	byKind := map[string]int{}
	for _, symbol := range report.Symbols {
		if language != "" && language != "all" && symbol.Language != language {
			continue
		}
		if kind != "" && kind != "all" && symbol.Kind != kind {
			continue
		}
		if query != "" && !symbolQueryMatches(symbol, query) {
			continue
		}
		byKind[symbol.Kind]++
		matched = append(matched, symbol)
	}
	start, end := pageBounds(len(matched), offset, limit)
	items := make([]codescan.Symbol, 0, end-start)
	items = append(items, matched[start:end]...)
	kinds := make([]codescan.Count, 0, len(byKind))
	for key, value := range byKind {
		kinds = append(kinds, codescan.Count{Key: key, Value: value})
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i].Key < kinds[j].Key })
	return symbolQueryResponse{
		SchemaVersion: analysisSchemaVersion, Tool: "query_symbols", SnapshotHash: r.snapshot.Hash(),
		Available: true, Total: len(matched), Offset: offset, Limit: limit,
		Partial: report.Partial, SymbolPartial: report.SymbolPartial,
		Counts:        map[string]int{"symbols": len(report.Symbols), "matched": len(matched)},
		Coverage:      report.Coverage,
		Limitations:   append([]string(nil), report.Limitations...),
		Items:         items,
		Languages:     append([]codescan.LanguageSummary(nil), report.Languages...),
		Kinds:         kinds,
		RuntimeStatus: "not_run",
	}, nil
}

// symbolReport prefers the console's cached report so the Agent sees the same
// symbol index as the Web page; a CLI registry without one derives it once.
func (r *Registry) symbolReport(ctx context.Context, state *analysisCache) (*codescan.Report, error) {
	if state != nil && state.code != nil {
		return state.code, nil
	}
	r.analysisMu.Lock()
	defer r.analysisMu.Unlock()
	if r.lateCode != nil {
		return r.lateCode, nil
	}
	report, err := codescan.Analyze(ctx, r.snapshot, codescan.Options{})
	if err != nil {
		return nil, fmt.Errorf("symbol analysis failed: %w", err)
	}
	r.lateCode = &report
	return r.lateCode, nil
}

func symbolQueryMatches(symbol codescan.Symbol, query string) bool {
	parts := []string{
		symbol.Name, symbol.QualifiedName, symbol.Container, symbol.File,
		symbol.Kind, symbol.Language,
	}
	return strings.Contains(strings.ToLower(strings.Join(parts, " ")), query)
}

func (r *Registry) traceDataflow(ctx context.Context, values map[string]any) (analysisResponse, error) {
	return r.findingPage(ctx, values, "trace_dataflow", true)
}

func (r *Registry) listFindings(ctx context.Context, values map[string]any) (analysisResponse, error) {
	return r.findingPage(ctx, values, "list_findings", false)
}

func (r *Registry) findingPage(ctx context.Context, values map[string]any, tool string, dataflowOnly bool) (analysisResponse, error) {
	limit, offset, err := analysisPage(values)
	if err != nil {
		return analysisResponse{}, err
	}
	query, err := analysisQuery(values)
	if err != nil {
		return analysisResponse{}, err
	}
	category := strings.ToLower(stringValue(values, "category"))
	status := strings.ToLower(stringValue(values, "status"))
	language := strings.ToLower(stringValue(values, "language"))
	if category != "" && category != "all" && !validCategory(category) {
		return analysisResponse{}, fmt.Errorf("%w: unsupported category", ErrArguments)
	}
	if status != "" && status != "all" && status != "static_confirmed" && status != "inconclusive" && status != "refuted" {
		return analysisResponse{}, fmt.Errorf("%w: unsupported status", ErrArguments)
	}
	state, err := r.analysisState(ctx)
	if err != nil {
		return analysisResponse{}, err
	}
	languages := map[string]int{}
	for _, finding := range state.findings.Findings {
		if lang := findingLanguage(finding); lang != "" {
			languages[lang]++
		}
	}
	filtered := make([]findings.Finding, 0, len(state.findings.Findings))
	for _, finding := range state.findings.Findings {
		if dataflowOnly && (finding.Kind == "vulnerable_dependency" || strings.HasPrefix(finding.ID, "code:")) {
			continue
		}
		if category != "" && category != "all" && !containsName(findingCategoryKeys(finding), category) {
			continue
		}
		if language != "" && language != "all" && findingLanguage(finding) != language {
			continue
		}
		if status != "" && status != "all" && finding.Status != status {
			continue
		}
		if query != "" && !findingMatches(finding, query) {
			continue
		}
		filtered = append(filtered, finding)
	}
	start, end := pageBounds(len(filtered), offset, limit)
	items := make([]findingView, 0, end-start)
	citations := make([]Evidence, 0, 2*(end-start))
	for _, finding := range filtered[start:end] {
		candidates := r.findingCitations(finding)
		observed, observeErr := r.observeCitations(ctx, candidates)
		if observeErr != nil {
			return analysisResponse{}, observeErr
		}
		items = append(items, findingView{
			ID: finding.ID, Kind: finding.Kind, Category: finding.Category, CWE: finding.CWE,
			Severity: finding.Severity, Status: finding.Status, RuntimeStatus: finding.RuntimeStatus,
			Title: finding.Title, Endpoint: finding.Endpoint, Component: finding.Component, Citations: observed,
			Location: findingLocation(finding), Language: findingLanguage(finding),
		})
		citations = append(citations, observed...)
	}
	partial := state.findings.Partial
	limitations := append([]string{}, state.findings.Limitations...)
	if len(items) == 0 {
		limitations = append(limitations, "no_matching_findings: absence is not a safety proof")
	}
	counts := map[string]int{
		"findings_total": len(state.findings.Findings), "static_confirmed": state.findings.Coverage.FindingsStaticConfirmed,
		"inconclusive": state.findings.Coverage.FindingsInconclusive, "refuted": state.findings.Coverage.FindingsRefuted,
	}
	for name, count := range languages {
		counts["language_"+name] = count
	}
	return analysisResponse{
		SchemaVersion: analysisSchemaVersion, Tool: tool, SnapshotHash: r.snapshot.Hash(),
		Total: len(filtered), Offset: offset, Limit: limit, Partial: partial,
		AdvisoryConfigured: r.advisoryConfigured(),
		Counts:             counts, Coverage: state.findings.Coverage, Limitations: dedupeStrings(limitations), Items: items,
		Citations: dedupeEvidence(citations),
	}, nil
}

func (r *Registry) findingCitations(finding findings.Finding) []Evidence {
	priority := map[string]int{"sink": 0, "route": 1, "source": 2, "flow_step": 3, "boundary": 4, "protection": 5}
	type candidate struct {
		rank int
		item Evidence
	}
	candidates := make([]candidate, 0, len(finding.Evidence))
	for _, evidence := range finding.Evidence {
		rank, ok := priority[evidence.Kind]
		if !ok || evidence.File == "" || evidence.StartLine < 1 {
			continue
		}
		sha := evidence.SHA256
		if sha == "" {
			sha = r.manifestDigest(evidence.File)
		}
		end := evidence.EndLine
		if end < evidence.StartLine {
			end = evidence.StartLine
		}
		if end-evidence.StartLine > 16 {
			end = evidence.StartLine
		}
		item := r.citation(evidence.File, sha, evidence.StartLine, end)
		if item.Path == "" {
			continue
		}
		candidates = append(candidates, candidate{rank: rank, item: item})
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].rank < candidates[j].rank })
	result := make([]Evidence, 0, 2)
	for _, candidate := range candidates {
		if len(result) >= 2 {
			break
		}
		result = append(result, candidate.item)
	}
	return result
}

func (r *Registry) citation(path, sha string, start, end int) Evidence {
	if r == nil || r.snapshot == nil || !validEvidencePath(path) || start < 1 || end < start {
		return Evidence{}
	}
	if sha == "" {
		sha = r.manifestDigest(path)
	}
	if !validDigest(sha) {
		return Evidence{}
	}
	return Evidence{SnapshotHash: r.snapshot.Hash(), Path: path, SHA256: sha, StartLine: start, EndLine: end}
}

func (r *Registry) manifestDigest(path string) string {
	for _, entry := range r.snapshot.Manifest().Entries {
		if entry.Path == path {
			return entry.SHA256
		}
	}
	return ""
}

// observeCitations proves the cited lines were actually read from the pinned
// snapshot. Only observed citations are returned to the model; the evidence
// ledger is updated via the same parser used for read_source.
func (r *Registry) observeCitations(ctx context.Context, candidates []Evidence) ([]Evidence, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	if len(candidates) > analysisMaxCitations {
		candidates = candidates[:analysisMaxCitations]
	}
	observed := make([]Evidence, 0, len(candidates))
	seen := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		key := fmt.Sprintf("%s\x00%s\x00%d\x00%d", candidate.Path, candidate.SHA256, candidate.StartLine, candidate.EndLine)
		if seen[key] || candidate.Path == "" {
			continue
		}
		seen[key] = true
		result, err := r.snapshot.Read(ctx, project.ReadOptions{
			Path: candidate.Path, StartLine: candidate.StartLine, Limit: candidate.EndLine - candidate.StartLine + 1,
		})
		if err != nil {
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, project.ErrToolOptions) || errors.Is(err, project.ErrToolCursor) {
				continue
			}
			return nil, err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, err
		}
		evidence, err := ExtractEvidence("read_source", encoded)
		if err != nil {
			return nil, err
		}
		r.remember(evidence)
		if r.ValidateEvidence(candidate) == nil {
			observed = append(observed, candidate)
		}
	}
	return dedupeEvidence(observed), nil
}

func validCategory(category string) bool {
	switch category {
	case "sql", "command", "ssrf", "path", "template", "xss", "deserialization", "xxe", "ldap", "upload", "dependency", "redirect", "xpath":
		return true
	}
	return false
}

func categoryKeyForFinding(kind string) string {
	switch kind {
	case "sql_injection":
		return "sql"
	case "command_injection":
		return "command"
	case "path_traversal":
		return "path"
	case "template_injection":
		return "template"
	case "ldap_injection":
		return "ldap"
	case "unrestricted_upload":
		return "upload"
	case "vulnerable_dependency":
		return "dependency"
	}
	return kind
}

func findingMatches(finding findings.Finding, query string) bool {
	fields := []string{finding.ID, finding.Kind, finding.Category, finding.CWE, finding.Title, findingLocation(finding), findingLanguage(finding)}
	if finding.Endpoint != nil {
		fields = append(fields, finding.Endpoint.Path, finding.Endpoint.Symbol, finding.Endpoint.File)
	}
	if finding.Component != nil {
		fields = append(fields, finding.Component.Dependency, finding.Component.DeclaredVersion, finding.Component.AdvisoryID)
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}

// listRules exposes the built-in rule set so the Agent can understand what the
// code-audit engine can observe before citing rule IDs. Metadata only: pattern
// bodies, caller-supplied rules and any analysis semantics are not included.
func (r *Registry) listRules(ctx context.Context, values map[string]any) (analysisResponse, error) {
	query, err := analysisQuery(values)
	if err != nil {
		return analysisResponse{}, err
	}
	category := strings.ToLower(stringValue(values, "category"))
	language := strings.ToLower(stringValue(values, "language"))
	all := codescan.RuleSummaries()
	filtered := make([]codescan.RuleSummary, 0, len(all))
	for _, rule := range all {
		if category != "" && category != "all" && rule.Category != category {
			continue
		}
		if language != "" && language != "all" && !containsName(rule.Languages, language) {
			continue
		}
		if query != "" {
			haystack := strings.ToLower(strings.Join([]string{rule.ID, rule.Category, rule.CWE, rule.Title, strings.Join(rule.Languages, " ")}, " "))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		filtered = append(filtered, rule)
	}
	limitations := []string{
		"rules_are_data_not_semantics: selectors are declarative name patterns, not type resolution or a call graph",
		"builtin_rules_only: caller-supplied rule files are not listed; the report ruleset_version carries their data digest",
	}
	return analysisResponse{
		SchemaVersion: analysisSchemaVersion, Tool: "list_rules", SnapshotHash: r.snapshot.Hash(),
		Total: len(filtered), Offset: 0, Limit: len(filtered), Partial: false,
		Counts: map[string]int{
			"rules_builtin_total": len(all), "languages_supported": 7,
		},
		Limitations: limitations, Items: filtered,
	}, nil
}

func dedupeStrings(values []string) []string {
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

func dedupeEvidence(values []Evidence) []Evidence {
	result := make([]Evidence, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		key := fmt.Sprintf("%s\x00%s\x00%d\x00%d", value.Path, value.SHA256, value.StartLine, value.EndLine)
		if value.Path == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, value)
	}
	return result
}
