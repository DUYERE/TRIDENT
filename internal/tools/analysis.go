package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"trident/internal/audit"
	"trident/internal/findings"
	"trident/internal/project"
	"trident/internal/sca"
)

const (
	analysisSchemaVersion = 1
	analysisDefaultLimit  = 10
	analysisMaxLimit      = 10
	analysisMaxOffset     = 100_000
	analysisMaxCitations  = 24
)

// AnalysisOptions binds local analysis configuration to a Run. The advisory
// catalog is caller-supplied configuration, never snapshot content.
type AnalysisOptions struct {
	AdvisoryPath string
}

type analysisCache struct {
	findings findings.Report
	sca      sca.Report
	audit    audit.Report
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
	Limitations        []string       `json:"limitations"`
	Items              any            `json:"items"`
	Citations          []Evidence     `json:"citations,omitempty"`
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
	Endpoint      *findings.EndpointRef  `json:"endpoint,omitempty"`
	Component     *findings.ComponentRef `json:"component,omitempty"`
	Citations     []Evidence             `json:"citations,omitempty"`
}

type dependencyView struct {
	Module         string `json:"module"`
	GroupID        string `json:"group_id"`
	ArtifactID     string `json:"artifact_id"`
	Version        string `json:"version,omitempty"`
	Scope          string `json:"scope"`
	VersionStatus  string `json:"version_status"`
	DeclarationPOM string `json:"declaration_pom"`
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
	Citations []Evidence `json:"citations,omitempty"`
}

// analysisState runs the read-only analyses once per registry. A failure is
// cached as a terminal error instead of being retried for every tool call.
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
	scaReport, scaErr := sca.Inspect(ctx, r.snapshot, sca.Options{AdvisoryPath: r.analysisOptions.AdvisoryPath})
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
		state.findings = findingReport
		state.sca = scaReport
		state.audit = endpointReport
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
			Module: dependency.Module, GroupID: dependency.GroupID, ArtifactID: dependency.ArtifactID,
			Version: dependency.Version, Scope: dependency.Scope, VersionStatus: dependency.VersionStatus,
			DeclarationPOM: dependency.DeclarationPOM,
		})
	}
	return analysisResponse{
		SchemaVersion: analysisSchemaVersion, Tool: "inspect_dependencies", SnapshotHash: r.snapshot.Hash(),
		Total: len(dependencies), Offset: offset, Limit: limit, Partial: state.sca.Partial,
		AdvisoryConfigured: r.analysisOptions.AdvisoryPath != "",
		Counts: map[string]int{
			"modules": state.sca.Project.ModuleCount, "poms": state.sca.Project.POMCount,
			"dependencies_declared": len(state.sca.Dependencies), "dependencies_unresolved": state.sca.Coverage.DependenciesUnresolved,
		},
		Coverage: state.sca.Coverage, Limitations: state.sca.Limitations, Items: items,
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
	if r.analysisOptions.AdvisoryPath == "" {
		limitations = append(limitations, "advisory_catalog_not_configured")
	}
	return analysisResponse{
		SchemaVersion: analysisSchemaVersion, Tool: "match_advisories", SnapshotHash: r.snapshot.Hash(),
		Total: len(matches), Offset: offset, Limit: limit, Partial: state.sca.Partial,
		AdvisoryConfigured: r.analysisOptions.AdvisoryPath != "",
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
	filtered := make([]audit.Endpoint, 0, len(state.audit.Endpoints))
	for _, endpoint := range state.audit.Endpoints {
		if query != "" && !strings.Contains(strings.ToLower(endpoint.Path+" "+endpoint.Symbol+" "+endpoint.File+" "+strings.Join(endpoint.HTTPMethods, ",")), query) {
			continue
		}
		filtered = append(filtered, endpoint)
	}
	start, end := pageBounds(len(filtered), offset, limit)
	items := make([]endpointView, 0, end-start)
	citations := make([]Evidence, 0, end-start)
	for _, endpoint := range filtered[start:end] {
		line := endpoint.MethodLine
		if line <= 0 {
			line = endpoint.StartLine
		}
		candidate := r.citation(endpoint.File, endpoint.SHA256, line, line)
		item := endpointView{Endpoint: endpoint}
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
		Total: len(filtered), Offset: offset, Limit: limit, Partial: state.audit.Partial,
		AdvisoryConfigured: r.analysisOptions.AdvisoryPath != "",
		Counts: map[string]int{
			"controllers": state.audit.Coverage.ControllersFound, "endpoints": len(state.audit.Endpoints),
			"unresolved_paths": state.audit.Coverage.UnresolvedPaths, "duplicate_routes": state.audit.Coverage.DuplicateRoutes,
		},
		Coverage: state.audit.Coverage, Limitations: state.audit.Limitations, Items: items,
		Citations: dedupeEvidence(citations),
	}, nil
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
	filtered := make([]findings.Finding, 0, len(state.findings.Findings))
	for _, finding := range state.findings.Findings {
		if dataflowOnly && finding.Kind == "vulnerable_dependency" {
			continue
		}
		if category != "" && category != "all" && categoryKeyForFinding(finding.Kind) != category {
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
		})
		citations = append(citations, observed...)
	}
	partial := state.findings.Partial
	limitations := append([]string{}, state.findings.Limitations...)
	if len(items) == 0 {
		limitations = append(limitations, "no_matching_findings: absence is not a safety proof")
	}
	return analysisResponse{
		SchemaVersion: analysisSchemaVersion, Tool: tool, SnapshotHash: r.snapshot.Hash(),
		Total: len(filtered), Offset: offset, Limit: limit, Partial: partial,
		AdvisoryConfigured: r.analysisOptions.AdvisoryPath != "",
		Counts: map[string]int{
			"findings_total": len(state.findings.Findings), "static_confirmed": state.findings.Coverage.FindingsStaticConfirmed,
			"inconclusive": state.findings.Coverage.FindingsInconclusive, "refuted": state.findings.Coverage.FindingsRefuted,
		},
		Coverage: state.findings.Coverage, Limitations: dedupeStrings(limitations), Items: items,
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
	case "sql", "command", "ssrf", "path", "template", "xss", "deserialization", "xxe", "ldap", "upload", "dependency":
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
	fields := []string{finding.ID, finding.Kind, finding.Category, finding.CWE, finding.Title}
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
