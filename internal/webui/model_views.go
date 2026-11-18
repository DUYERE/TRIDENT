package webui

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"trident/internal/authz"
	"trident/internal/codescan"
	entrycap "trident/internal/entry"
	"trident/internal/entrypoint"
	"trident/internal/evidence"
	"trident/internal/javaast"
)

// authzCounts summarises the endpoint decision distribution. The four states
// are the same ones the CLI prints; none of them proves runtime exposure.
type authzCounts struct {
	Protected   int `json:"protected"`
	Public      int `json:"public"`
	Unprotected int `json:"unprotected"`
	Unknown     int `json:"unknown"`
}

// authzLanguageCount keeps the per-language distribution separate from the
// Java endpoint counts. FileEvidence counts observations that are not attached
// to any entry, so a reviewer can tell "no route evidence" apart from "no
// control on an entry".
type authzLanguageCount struct {
	Language     string `json:"language"`
	Protected    int    `json:"protected"`
	Public       int    `json:"public"`
	Unprotected  int    `json:"unprotected"`
	Unknown      int    `json:"unknown"`
	Total        int    `json:"total"`
	FileEvidence int    `json:"file_evidence"`
}

var authzLanguageOrder = []string{"java", "php", "csharp", "python", "javascript", "typescript", "go"}

type authzResponse struct {
	SchemaVersion     int                      `json:"schema_version"`
	ToolVersion       string                   `json:"tool_version"`
	SnapshotHash      string                   `json:"snapshot_hash"`
	AnalysisKind      string                   `json:"analysis_kind"`
	Partial           bool                     `json:"partial"`
	Total             int                      `json:"total"`
	Counts            authzCounts              `json:"counts"`
	Endpoints         []authz.EndpointDecision `json:"endpoints"`
	LanguageAdapters  []authz.LanguageAdapter  `json:"language_adapters"`
	FileEvidence      []authz.LanguageAdapter  `json:"file_evidence"`
	FileEvidenceTotal int                      `json:"file_evidence_total"`
	LanguageCounts    []authzLanguageCount     `json:"language_counts"`
	Controls          []authz.Control          `json:"controls"`
	Chains            []authz.FilterChain      `json:"chains"`
	Coverage          authz.Coverage           `json:"coverage"`
	Limitations       []string                 `json:"limitations"`
	RuntimeStatus     string                   `json:"runtime_status"`
	Limit             int                      `json:"limit"`
	Offset            int                      `json:"offset"`
}

func (c *Console) handleAuthz(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	report := state.authz
	decision := strings.TrimSpace(r.URL.Query().Get("decision"))
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, err := queryInt(r, "limit", DefaultLimit, 1, MaxLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	offset, err := queryInt(r, "offset", 0, 0, 1<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	counts := authzCounts{}
	matched := make([]authz.EndpointDecision, 0, len(report.Endpoints))
	for _, endpoint := range report.Endpoints {
		switch endpoint.Decision {
		case "protected":
			counts.Protected++
		case "public":
			counts.Public++
		case "unprotected":
			counts.Unprotected++
		default:
			counts.Unknown++
		}
		if decision != "" && decision != "all" && endpoint.Decision != decision {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(endpoint.Path+" "+endpoint.Symbol+" "+endpoint.Requirement), query) {
			continue
		}
		matched = append(matched, endpoint)
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if rank(matched[i].Decision) != rank(matched[j].Decision) {
			return rank(matched[i].Decision) < rank(matched[j].Decision)
		}
		return matched[i].Path < matched[j].Path
	})
	page := pageSlice(matched, offset, limit)
	applicationReport, err := entrypoint.Inspect(r.Context(), c.snapshotRef())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	var codeAudit *codescan.Report
	if codeReport, _, codeErr := c.codeAudit(r.Context()); codeErr == nil {
		codeAudit = &codeReport
	}
	unified, err := entrycap.NewRegistry().Build(r.Context(), entrycap.Input{
		Snapshot:           c.snapshotRef(),
		JavaAudit:          &state.audit,
		Authz:              &report,
		CodeAudit:          codeAudit,
		ApplicationEntries: &applicationReport,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	attached, fileEvidence := splitLanguageAdapters(report.LanguageAdapters, unified.Entries)
	languageCounts := buildLanguageCounts(attached, fileEvidence, counts)
	writeJSON(w, http.StatusOK, authzResponse{
		SchemaVersion:     report.SchemaVersion,
		ToolVersion:       report.ToolVersion,
		SnapshotHash:      report.SnapshotHash,
		AnalysisKind:      report.AnalysisKind,
		Partial:           report.Partial,
		Total:             len(matched),
		Counts:            counts,
		Endpoints:         page,
		LanguageAdapters:  attached,
		FileEvidence:      fileEvidence,
		FileEvidenceTotal: len(fileEvidence),
		LanguageCounts:    languageCounts,
		Controls:          report.Controls,
		Chains:            report.Chains,
		Coverage:          report.Coverage,
		Limitations:       report.Limitations,
		RuntimeStatus:     report.RuntimeStatus,
		Limit:             limit,
		Offset:            offset,
	})
}

// splitLanguageAdapters binds language evidence to the unified entry list.
// A file-scope adapter is attached only when that file is an entry; when a
// request-script decision already covers the file, the coarse file-scope
// observation is dropped to avoid double counting.
func splitLanguageAdapters(adapters []authz.LanguageAdapter, entries []evidence.Entry) ([]authz.LanguageAdapter, []authz.LanguageAdapter) {
	if len(adapters) == 0 {
		return nil, nil
	}
	requestScriptKind := map[string]string{}
	requestScriptFile := map[string]bool{}
	fileKind := map[string]string{}
	for _, item := range entries {
		switch item.Kind {
		case evidence.KindRequestScript:
			requestScriptKind[entryFileLine(item.File, item.StartLine)] = item.Kind
			requestScriptFile[item.File] = true
		case evidence.KindRouteDeclaration:
			fileKind[item.File] = item.Kind
		case evidence.KindApplicationEntry:
			if _, ok := fileKind[item.File]; !ok {
				fileKind[item.File] = item.Kind
			}
		}
	}
	attached := make([]authz.LanguageAdapter, 0, len(adapters))
	fileEvidence := make([]authz.LanguageAdapter, 0, len(adapters))
	for _, adapter := range adapters {
		out := adapter
		out.EntryKind = ""
		switch {
		case adapter.Scope == "request_script":
			out.EntryKind = requestScriptKind[entryFileLine(adapter.File, adapter.Line)]
		case requestScriptFile[adapter.File]:
			continue
		default:
			out.EntryKind = fileKind[adapter.File]
		}
		if out.EntryKind == "" {
			fileEvidence = append(fileEvidence, out)
			continue
		}
		attached = append(attached, out)
	}
	return attached, fileEvidence
}

func entryFileLine(file string, line int) string {
	return file + "\x00" + strconv.Itoa(line)
}

func buildLanguageCounts(attached, fileEvidence []authz.LanguageAdapter, java authzCounts) []authzLanguageCount {
	rows := map[string]*authzLanguageCount{}
	for _, language := range authzLanguageOrder {
		rows[language] = &authzLanguageCount{Language: language}
	}
	row := func(language string) *authzLanguageCount {
		if existing, ok := rows[language]; ok {
			return existing
		}
		created := &authzLanguageCount{Language: language}
		rows[language] = created
		return created
	}
	javaRow := row("java")
	javaRow.Protected, javaRow.Public, javaRow.Unprotected, javaRow.Unknown = java.Protected, java.Public, java.Unprotected, java.Unknown
	javaRow.Total = java.Protected + java.Public + java.Unprotected + java.Unknown
	for _, adapter := range attached {
		target := row(adapter.Language)
		switch adapter.Decision {
		case "protected":
			target.Protected++
		case "public":
			target.Public++
		case "unprotected":
			target.Unprotected++
		default:
			target.Unknown++
		}
		target.Total++
	}
	for _, adapter := range fileEvidence {
		row(adapter.Language).FileEvidence++
	}
	out := make([]authzLanguageCount, 0, len(rows))
	for _, language := range authzLanguageOrder {
		out = append(out, *rows[language])
	}
	extra := make([]string, 0, len(rows))
	for language := range rows {
		found := false
		for _, ordered := range authzLanguageOrder {
			if ordered == language {
				found = true
				break
			}
		}
		if !found {
			extra = append(extra, language)
		}
	}
	sort.Strings(extra)
	for _, language := range extra {
		out = append(out, *rows[language])
	}
	return out
}

// rank orders the most actionable decisions first: an endpoint with no
// recognised control is what a reviewer opens first.
func rank(decision string) int {
	switch decision {
	case "unprotected":
		return 0
	case "unknown":
		return 1
	case "public":
		return 2
	default:
		return 3
	}
}

type modelTypeSummary struct {
	FQN         string `json:"fqn"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Methods     int    `json:"methods"`
	Fields      int    `json:"fields"`
	Annotations int    `json:"annotations"`
	Extends     string `json:"extends,omitempty"`
	Nested      int    `json:"nested"`
}

type modelResponse struct {
	SchemaVersion   int                        `json:"schema_version"`
	Enabled         bool                       `json:"enabled"`
	Reason          string                     `json:"reason,omitempty"`
	ToolVersion     string                     `json:"tool_version,omitempty"`
	SnapshotHash    string                     `json:"snapshot_hash"`
	AnalysisKind    string                     `json:"analysis_kind,omitempty"`
	Partial         bool                       `json:"partial"`
	Total           int                        `json:"total"`
	Types           []modelTypeSummary         `json:"types"`
	Coverage        *javaast.Coverage          `json:"coverage,omitempty"`
	Limitations     []string                   `json:"limitations,omitempty"`
	RuntimeStatus   string                     `json:"runtime_status"`
	Limit           int                        `json:"limit"`
	Offset          int                        `json:"offset"`
	Symbols         []codescan.Symbol          `json:"symbols"`
	Calls           []codescan.Call            `json:"calls"`
	Unresolved      []codescan.Unresolved      `json:"unresolved"`
	SymbolLanguages []codescan.LanguageSummary `json:"symbol_languages"`
	SymbolPartial   bool                       `json:"symbol_partial"`
	SymbolReason    string                     `json:"symbol_reason,omitempty"`
}

func (c *Console) handleModel(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	if state.model == nil {
		symbols, calls, unresolved, symbolLanguages, symbolPartial, symbolReason := c.cachedSymbolPayload()
		writeJSON(w, http.StatusOK, modelResponse{
			SchemaVersion: SchemaVersion,
			Enabled:       false,
			Reason:        state.modelErr,
			SnapshotHash:  c.snapshotRef().Hash(),
			Types:         []modelTypeSummary{},
			RuntimeStatus: "not_run",
			Symbols:       symbols, Calls: calls, Unresolved: unresolved,
			SymbolLanguages: symbolLanguages, SymbolPartial: symbolPartial, SymbolReason: symbolReason,
		})
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, err := queryInt(r, "limit", DefaultLimit, 1, MaxLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	offset, err := queryInt(r, "offset", 0, 0, 1<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	all := make([]modelTypeSummary, 0, len(state.model.Types))
	for _, item := range state.model.Types {
		if query != "" && !strings.Contains(strings.ToLower(item.FQN+" "+item.File), query) {
			continue
		}
		all = append(all, modelTypeSummary{
			FQN: item.FQN, Name: item.Name, Kind: item.Kind, File: item.File, Line: item.Line,
			Methods: len(item.Methods), Fields: len(item.Fields), Annotations: len(item.Annotations),
			Extends: item.Extends, Nested: len(item.Nested),
		})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].FQN < all[j].FQN })
	coverage := state.model.Coverage
	symbols, calls, unresolved, symbolLanguages, symbolPartial, symbolReason := c.cachedSymbolPayload()
	writeJSON(w, http.StatusOK, modelResponse{
		SchemaVersion:   state.model.SchemaVersion,
		Enabled:         true,
		ToolVersion:     state.model.ToolVersion,
		SnapshotHash:    state.model.SnapshotHash,
		AnalysisKind:    state.model.AnalysisKind,
		Partial:         state.model.Partial,
		Total:           len(all),
		Types:           pageSlice(all, offset, limit),
		Coverage:        &coverage,
		Limitations:     state.model.Limitations,
		RuntimeStatus:   state.model.Coverage.RuntimeStatus,
		Limit:           limit,
		Offset:          offset,
		Symbols:         symbols,
		Calls:           calls,
		Unresolved:      unresolved,
		SymbolLanguages: symbolLanguages,
		SymbolPartial:   symbolPartial,
		SymbolReason:    symbolReason,
	})
}

type modelTypeResponse struct {
	SchemaVersion int                `json:"schema_version"`
	Type          javaast.TypeInfo   `json:"type"`
	Outgoing      []javaast.CallEdge `json:"outgoing"`
	Incoming      []javaast.CallEdge `json:"incoming"`
	RuntimeStatus string             `json:"runtime_status"`
}

func (c *Console) handleModelType(w http.ResponseWriter, r *http.Request) {
	state, err := c.analyze(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	if state.model == nil {
		writeError(w, http.StatusNotFound, "model_disabled", state.modelErr)
		return
	}
	fqn := strings.TrimSpace(r.URL.Query().Get("fqn"))
	if fqn == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "需要 fqn 参数")
		return
	}
	var found *javaast.TypeInfo
	for i := range state.model.Types {
		if state.model.Types[i].FQN == fqn {
			found = &state.model.Types[i]
			break
		}
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "type_not_found", "未在该快照的语义模型中索引该类型："+fqn)
		return
	}
	prefix := fqn + "#"
	outgoing := make([]javaast.CallEdge, 0, 16)
	incoming := make([]javaast.CallEdge, 0, 16)
	for _, edge := range state.model.Calls {
		if strings.HasPrefix(edge.Caller, prefix) {
			outgoing = append(outgoing, edge)
		}
		if strings.HasPrefix(edge.Target, prefix) {
			incoming = append(incoming, edge)
		}
	}
	writeJSON(w, http.StatusOK, modelTypeResponse{
		SchemaVersion: SchemaVersion,
		Type:          *found,
		Outgoing:      capEdges(outgoing, 200),
		Incoming:      capEdges(incoming, 200),
		RuntimeStatus: "not_run",
	})
}

func capEdges(edges []javaast.CallEdge, limit int) []javaast.CallEdge {
	if len(edges) <= limit {
		return edges
	}
	return edges[:limit]
}

// cachedSymbolPayload exposes only an already computed multi-language report.
// It never starts code audit from the Java model page: opening the model page
// must not silently launch a second heavy analysis.
func (c *Console) cachedSymbolPayload() ([]codescan.Symbol, []codescan.Call, []codescan.Unresolved, []codescan.LanguageSummary, bool, string) {
	report, reason, ok := c.codeAuditCached()
	if !ok {
		if reason == "" {
			reason = "analysis_pending: 打开「代码审计」页运行多语言分析后，这里会显示符号索引"
		}
		return []codescan.Symbol{}, []codescan.Call{}, []codescan.Unresolved{}, []codescan.LanguageSummary{}, false, reason
	}
	return capSymbols(report.Symbols), capCalls(report.Calls), capUnresolved(report.Unresolved),
		append([]codescan.LanguageSummary(nil), report.Languages...), report.SymbolPartial, ""
}

func pageSlice[T any](items []T, offset, limit int) []T {
	if offset >= len(items) {
		return []T{}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}
