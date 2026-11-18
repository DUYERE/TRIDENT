package webui

import (
	"net/http"
	"sort"
	"strings"

	"trident/internal/codescan"
)

// symbolResponse is the paged lexical symbol browser. It reads the same cached
// codescan report as /api/code-audit; it never starts a second analysis.
type symbolResponse struct {
	SchemaVersion int                        `json:"schema_version"`
	ToolVersion   string                     `json:"tool_version"`
	SnapshotHash  string                     `json:"snapshot_hash"`
	AnalysisKind  string                     `json:"analysis_kind"`
	Available     bool                       `json:"available"`
	Reason        string                     `json:"reason,omitempty"`
	Partial       bool                       `json:"partial"`
	SymbolPartial bool                       `json:"symbol_partial"`
	Total         int                        `json:"total"`
	Limit         int                        `json:"limit"`
	Offset        int                        `json:"offset"`
	Items         []codescan.Symbol          `json:"items"`
	Languages     []codescan.LanguageSummary `json:"languages"`
	Kinds         []codescan.Count           `json:"kinds"`
	Limitations   []string                   `json:"limitations"`
	RuntimeStatus string                     `json:"runtime_status"`
}

func (c *Console) handleSymbols(w http.ResponseWriter, r *http.Request) {
	if _, err := c.analyze(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	report, reason, err := c.codeAudit(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "symbols_failed", err.Error())
		return
	}
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
	language := strings.TrimSpace(r.URL.Query().Get("language"))
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))

	response := symbolResponse{
		SchemaVersion: SchemaVersion, ToolVersion: codescan.ToolVersion,
		SnapshotHash: c.SnapshotHash(), AnalysisKind: codescan.AnalysisKind,
		Available: reason == "", Reason: reason,
		Partial: report.Partial, SymbolPartial: report.SymbolPartial,
		Limit: limit, Offset: offset, Items: []codescan.Symbol{},
		Languages: []codescan.LanguageSummary{}, Kinds: []codescan.Count{},
		Limitations: append([]string(nil), report.Limitations...), RuntimeStatus: "not_run",
	}
	if !response.Available {
		writeJSON(w, http.StatusOK, response)
		return
	}

	matched := make([]codescan.Symbol, 0, len(report.Symbols))
	byKind := map[string]int{}
	for _, symbol := range report.Symbols {
		byKind[symbol.Kind]++
		if language != "" && language != "all" && symbol.Language != language {
			continue
		}
		if kind != "" && kind != "all" && symbol.Kind != kind {
			continue
		}
		if query != "" && !symbolMatches(symbol, query) {
			continue
		}
		matched = append(matched, symbol)
	}
	response.Total = len(matched)
	response.Items = pageSlice(matched, offset, limit)
	response.Languages = append([]codescan.LanguageSummary(nil), report.Languages...)
	response.Kinds = sortedSymbolKinds(byKind)
	writeJSON(w, http.StatusOK, response)
}

func symbolMatches(symbol codescan.Symbol, query string) bool {
	parts := []string{
		symbol.Name, symbol.QualifiedName, symbol.Container, symbol.File,
		symbol.Kind, symbol.Language,
	}
	return strings.Contains(strings.ToLower(strings.Join(parts, " ")), query)
}

func sortedSymbolKinds(values map[string]int) []codescan.Count {
	out := make([]codescan.Count, 0, len(values))
	for key, value := range values {
		out = append(out, codescan.Count{Key: key, Value: value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
