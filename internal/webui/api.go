package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"trident/internal/audit"
	"trident/internal/dataflow"
	"trident/internal/findings"
	"trident/internal/project"
	"trident/internal/sbom"
	"trident/internal/sca"
)

type categoryMeta struct {
	Key   string
	Label string
	CWE   string
}

// categoryOrder fixes the console's category cards and counts. The order
// matches the dataflow package's sink categories plus the dependency kind.
var categoryOrder = []categoryMeta{
	{Key: "sql", Label: "SQL 注入", CWE: "CWE-89"},
	{Key: "command", Label: "命令注入", CWE: "CWE-78"},
	{Key: "ssrf", Label: "服务端请求伪造", CWE: "CWE-918"},
	{Key: "path", Label: "路径遍历", CWE: "CWE-22"},
	{Key: "template", Label: "模板注入", CWE: "CWE-1336"},
	{Key: "xss", Label: "跨站脚本", CWE: "CWE-79"},
	{Key: "deserialization", Label: "不安全反序列化", CWE: "CWE-502"},
	{Key: "xxe", Label: "XML 外部实体", CWE: "CWE-611"},
	{Key: "ldap", Label: "LDAP 注入", CWE: "CWE-90"},
	{Key: "authz", Label: "认证/授权缺失", CWE: "CWE-306"},
	{Key: "dependency", Label: "依赖漏洞候选", CWE: "CWE-1395"},
}

func categoryKey(kind string) string {
	switch kind {
	case "sql_injection":
		return "sql"
	case "command_injection":
		return "command"
	case "ssrf":
		return "ssrf"
	case "path_traversal":
		return "path"
	case "template_injection":
		return "template"
	case "xss":
		return "xss"
	case "deserialization":
		return "deserialization"
	case "xxe":
		return "xxe"
	case "ldap_injection":
		return "ldap"
	case "missing_authentication_or_authorization":
		return "authz"
	case "vulnerable_dependency":
		return "dependency"
	}
	return kind
}

type snapshotInfo struct {
	Hash          string              `json:"hash"`
	Source        string              `json:"source"`
	Manifest      int                 `json:"manifest_version"`
	PolicyVersion string              `json:"policy_version"`
	ToolVersion   string              `json:"tool_version"`
	TotalFiles    int                 `json:"total_files"`
	TotalBytes    int64               `json:"total_bytes"`
	ExcludedCount int                 `json:"excluded_count"`
	Partial       bool                `json:"partial"`
	Warnings      []string            `json:"warnings"`
	Extensions    []project.PathCount `json:"extensions"`
	Directories   []project.PathCount `json:"directories"`
}

type toolVersions struct {
	Findings string `json:"findings"`
	SCA      string `json:"sca"`
	Audit    string `json:"audit"`
	Dataflow string `json:"dataflow"`
}

type analysisInfo struct {
	GeneratedAt            string         `json:"generated_at"`
	DurationMS             int64          `json:"duration_ms"`
	Partial                bool           `json:"partial"`
	RuntimeStatus          string         `json:"runtime_status"`
	AnalysisKind           string         `json:"analysis_kind"`
	AdvisoryConfigured     bool           `json:"advisory_configured"`
	JavaAST                string         `json:"java_ast"`
	TaintAnalysis          string         `json:"taint_analysis"`
	SCAResolution          string         `json:"sca_resolution"`
	DependencyReachability string         `json:"dependency_reachability"`
	ToolVersions           toolVersions   `json:"tool_versions"`
	EndpointCoverage       audit.Coverage `json:"endpoint_coverage"`
	SCACoverage            sca.Coverage   `json:"sca_coverage"`
}

type statusCounts struct {
	Total        int `json:"total"`
	Confirmed    int `json:"static_confirmed"`
	Inconclusive int `json:"inconclusive"`
	Refuted      int `json:"refuted"`
}

type categorySummary struct {
	Key          string `json:"key"`
	Label        string `json:"label"`
	CWE          string `json:"cwe"`
	Total        int    `json:"total"`
	Confirmed    int    `json:"static_confirmed"`
	Inconclusive int    `json:"inconclusive"`
	Refuted      int    `json:"refuted"`
}

type overviewResponse struct {
	SchemaVersion int               `json:"schema_version"`
	Product       string            `json:"product"`
	ToolVersion   string            `json:"tool_version"`
	StartedAt     string            `json:"started_at"`
	Snapshot      snapshotInfo      `json:"snapshot"`
	Analysis      analysisInfo      `json:"analysis"`
	Counts        statusCounts      `json:"counts"`
	Coverage      findings.Coverage `json:"coverage"`
	Categories    []categorySummary `json:"categories"`
	Limitations   []string          `json:"limitations"`
}

func (c *Console) handleOverview(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	inspect, err := c.snapshot.Inspect(r.Context(), project.InspectOptions{})
	if err != nil {
		mapProjectError(w, err)
		return
	}
	manifest := c.snapshot.Manifest()
	counts := statusCounts{}
	categories := make([]categorySummary, len(categoryOrder))
	index := map[string]int{}
	for i, meta := range categoryOrder {
		categories[i] = categorySummary{Key: meta.Key, Label: meta.Label, CWE: meta.CWE}
		index[meta.Key] = i
	}
	for _, finding := range state.findings.Findings {
		counts.Total++
		switch finding.Status {
		case "static_confirmed":
			counts.Confirmed++
		case "refuted":
			counts.Refuted++
		default:
			counts.Inconclusive++
		}
		position, ok := index[categoryKey(finding.Kind)]
		if !ok {
			continue
		}
		category := &categories[position]
		category.Total++
		switch finding.Status {
		case "static_confirmed":
			category.Confirmed++
		case "refuted":
			category.Refuted++
		default:
			category.Inconclusive++
		}
	}
	report := overviewResponse{
		SchemaVersion: SchemaVersion,
		Product:       Product,
		ToolVersion:   c.version,
		StartedAt:     c.startedAt.Format("2006-01-02T15:04:05Z07:00"),
		Analysis: analysisInfo{
			GeneratedAt:            state.at.Format("2006-01-02T15:04:05Z07:00"),
			DurationMS:             state.duration.Milliseconds(),
			Partial:                state.findings.Partial,
			RuntimeStatus:          "not_run",
			AnalysisKind:           state.findings.AnalysisKind,
			AdvisoryConfigured:     c.advisoryPath != "",
			JavaAST:                state.findings.Coverage.JavaAST,
			TaintAnalysis:          state.findings.Coverage.TaintAnalysis,
			SCAResolution:          state.findings.Coverage.ScaResolution,
			DependencyReachability: state.findings.Coverage.DependencyReachability,
			ToolVersions:           toolVersions{Findings: findings.ToolVersion, SCA: sca.ToolVersion, Audit: audit.ToolVersion, Dataflow: dataflow.ToolVersion},
			EndpointCoverage:       state.audit.Coverage,
			SCACoverage:            state.sca.Coverage,
		},
		Counts:      counts,
		Coverage:    state.findings.Coverage,
		Categories:  categories,
		Limitations: state.findings.Limitations,
	}
	report.Snapshot = snapshotInfo{
		Hash:          c.snapshot.Hash(),
		Source:        manifest.Source,
		Manifest:      manifest.Version,
		PolicyVersion: manifest.PolicyVersion,
		ToolVersion:   manifest.ToolVersion,
		TotalFiles:    manifest.TotalFiles,
		TotalBytes:    manifest.TotalBytes,
		ExcludedCount: len(manifest.Excluded),
		Partial:       manifest.Partial,
		Warnings:      append([]string{}, manifest.Warnings...),
		Extensions:    inspect.Extensions,
		Directories:   inspect.Directories,
	}
	writeJSON(w, http.StatusOK, report)
}

type findingSummary struct {
	ID              string                 `json:"id"`
	Kind            string                 `json:"kind"`
	Category        string                 `json:"category"`
	CWE             string                 `json:"cwe"`
	Severity        string                 `json:"severity"`
	Status          string                 `json:"status"`
	RuntimeStatus   string                 `json:"runtime_status"`
	Title           string                 `json:"title"`
	Endpoint        *findings.EndpointRef  `json:"endpoint,omitempty"`
	Component       *findings.ComponentRef `json:"component,omitempty"`
	EvidenceCount   int                    `json:"evidence_count"`
	HypothesisCount int                    `json:"hypothesis_count"`
	Limitations     []string               `json:"limitations"`
}

type findingsResponse struct {
	SchemaVersion int              `json:"schema_version"`
	Total         int              `json:"total"`
	Filtered      int              `json:"filtered"`
	Counts        statusCounts     `json:"counts"`
	Items         []findingSummary `json:"items"`
	Limit         int              `json:"limit"`
	Offset        int              `json:"offset"`
	Partial       bool             `json:"partial"`
	Limitations   []string         `json:"limitations"`
}

func (c *Console) handleFindings(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	limit, err := queryInt(r, "limit", DefaultLimit, 1, MaxLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	offset, err := queryOffset(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	status, err := queryText(r, "status", 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	category, err := queryText(r, "category", 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	query, err := queryText(r, "q", 256)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	needle := strings.ToLower(query)
	counts := statusCounts{}
	matched := make([]findings.Finding, 0, len(state.findings.Findings))
	for _, finding := range state.findings.Findings {
		counts.Total++
		switch finding.Status {
		case "static_confirmed":
			counts.Confirmed++
		case "refuted":
			counts.Refuted++
		default:
			counts.Inconclusive++
		}
		if status != "" && status != "all" && finding.Status != status {
			continue
		}
		if category != "" && category != "all" && categoryKey(finding.Kind) != category {
			continue
		}
		if needle != "" && !findingMatches(finding, needle) {
			continue
		}
		matched = append(matched, finding)
	}
	response := findingsResponse{SchemaVersion: SchemaVersion, Total: counts.Total, Filtered: len(matched), Counts: counts, Items: []findingSummary{}, Limit: limit, Offset: offset, Partial: state.findings.Partial, Limitations: state.findings.Limitations}
	if offset < len(matched) {
		end := offset + limit
		if end > len(matched) {
			end = len(matched)
		}
		for _, finding := range matched[offset:end] {
			response.Items = append(response.Items, findingSummary{
				ID: finding.ID, Kind: finding.Kind, Category: finding.Category, CWE: finding.CWE,
				Severity: finding.Severity, Status: finding.Status, RuntimeStatus: finding.RuntimeStatus,
				Title: finding.Title, Endpoint: finding.Endpoint, Component: finding.Component,
				EvidenceCount: len(finding.Evidence), HypothesisCount: len(finding.Hypotheses),
				Limitations: finding.Limitations,
			})
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func findingMatches(finding findings.Finding, needle string) bool {
	fields := []string{finding.ID, finding.Kind, finding.Category, finding.CWE, finding.Title}
	if finding.Endpoint != nil {
		fields = append(fields, finding.Endpoint.Path, finding.Endpoint.Symbol, finding.Endpoint.File, strings.Join(finding.Endpoint.HTTPMethods, ","))
	}
	if finding.Component != nil {
		fields = append(fields, finding.Component.Dependency, finding.Component.DeclaredVersion, finding.Component.AdvisoryID)
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}
	return false
}

func (c *Console) handleFinding(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	id, err := queryText(r, "id", 2048)
	if err != nil || id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "finding id is required")
		return
	}
	for _, finding := range state.findings.Findings {
		if finding.ID == id {
			writeJSON(w, http.StatusOK, finding)
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "finding not present in this snapshot report")
}

type endpointsResponse struct {
	SchemaVersion int              `json:"schema_version"`
	Total         int              `json:"total"`
	Items         []audit.Endpoint `json:"items"`
	Partial       bool             `json:"partial"`
	Coverage      audit.Coverage   `json:"coverage"`
	Limitations   []string         `json:"limitations"`
	Limit         int              `json:"limit"`
	Offset        int              `json:"offset"`
}

func (c *Console) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	limit, err := queryInt(r, "limit", DefaultLimit, 1, MaxLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	offset, err := queryOffset(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	query, err := queryText(r, "q", 256)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	needle := strings.ToLower(query)
	matched := make([]audit.Endpoint, 0, len(state.audit.Endpoints))
	for _, endpoint := range state.audit.Endpoints {
		if needle != "" {
			fields := []string{endpoint.Path, endpoint.Symbol, endpoint.File, endpoint.Class, endpoint.Method, strings.Join(endpoint.HTTPMethods, ",")}
			hit := false
			for _, field := range fields {
				if strings.Contains(strings.ToLower(field), needle) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		matched = append(matched, endpoint)
	}
	response := endpointsResponse{SchemaVersion: SchemaVersion, Total: len(matched), Items: []audit.Endpoint{}, Partial: state.audit.Partial, Coverage: state.audit.Coverage, Limitations: state.audit.Limitations, Limit: limit, Offset: offset}
	if offset < len(matched) {
		end := offset + limit
		if end > len(matched) {
			end = len(matched)
		}
		response.Items = append(response.Items, matched[offset:end]...)
	}
	writeJSON(w, http.StatusOK, response)
}

type dependenciesResponse struct {
	SchemaVersion int        `json:"schema_version"`
	Report        sca.Report `json:"report"`
}

func (c *Console) handleDependencies(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, dependenciesResponse{SchemaVersion: SchemaVersion, Report: state.sca})
}

func (c *Console) handleFiles(w http.ResponseWriter, r *http.Request) {
	limit, err := queryInt(r, "limit", DefaultLimit, 1, MaxLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	prefix, err := queryText(r, "prefix", 1024)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	cursor, err := queryText(r, "cursor", 2048)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := c.snapshot.List(r.Context(), project.ListOptions{Prefix: prefix, Limit: limit, Cursor: cursor})
	if err != nil {
		mapProjectError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (c *Console) handleFile(w http.ResponseWriter, r *http.Request) {
	filePath, err := queryText(r, "path", 1024)
	if err != nil || filePath == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "path is required")
		return
	}
	limit, err := queryInt(r, "limit", MaxLimit, 1, MaxLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	startLine, err := queryInt(r, "start_line", 0, 0, 10_000_000)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	cursor, err := queryText(r, "cursor", 2048)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := c.snapshot.Read(r.Context(), project.ReadOptions{Path: filePath, StartLine: startLine, Limit: limit, Cursor: cursor})
	if err != nil {
		mapProjectError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (c *Console) handleSearch(w http.ResponseWriter, r *http.Request) {
	query, err := queryText(r, "q", 256)
	if err != nil || query == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "q is required and must contain at most 256 bytes")
		return
	}
	limit, err := queryInt(r, "limit", DefaultLimit, 1, MaxLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	prefix, err := queryText(r, "prefix", 1024)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	cursor, err := queryText(r, "cursor", 2048)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := c.snapshot.Search(r.Context(), project.SearchOptions{Query: query, Prefix: prefix, Limit: limit, Cursor: cursor})
	if err != nil {
		mapProjectError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleSBOM returns a deterministic CycloneDX 1.5 document built from the
// same declaration-level SCA report. It is not an effective dependency tree.
func (c *Console) handleSBOM(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	document, err := sbom.Build(state.sca, sbom.Options{SnapshotHash: c.snapshot.Hash(), ToolVersion: sbom.ToolVersion, Partial: state.sca.Partial})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "sbom_failed", err.Error())
		return
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "SBOM encoding failed")
		return
	}
	short := c.snapshot.Hash()
	if len(short) > 12 {
		short = short[:12]
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="trident-sbom-%s.cdx.json"`, short))
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

// handleReport returns the unified evidence report as a download. It is the
// same JSON as `trident audit findings`, not a new report format.
func (c *Console) handleReport(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	encoded, err := json.Marshal(state.findings)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "report encoding failed")
		return
	}
	short := c.snapshot.Hash()
	if len(short) > 12 {
		short = short[:12]
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="trident-findings-%s.json"`, short))
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}
