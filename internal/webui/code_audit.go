package webui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"trident/internal/codescan"
)

// codeAudit computes the multi-language report lazily, once per snapshot. The
// result (including a skip reason or a failure) is cached so a slow project
// cannot freeze every request. It is intentionally independent of analyze().
func (c *Console) codeAudit(ctx context.Context) (codescan.Report, string, error) {
	c.codeMu.Lock()
	defer c.codeMu.Unlock()
	if c.codeState != nil {
		return *c.codeState, "", nil
	}
	if c.codeReason != "" || c.codeFatal != nil {
		return codescan.Report{}, c.codeReason, c.codeFatal
	}
	snapshot := c.snapshotRef()
	if cached, ok := c.loadCodeCache(snapshot.Hash()); ok {
		c.codeState = cached
		return *cached, "", nil
	}
	supported := 0
	for _, entry := range snapshot.Manifest().Entries {
		if codescan.SupportsFile(entry.Path) {
			supported++
		}
	}
	if supported > MaxCodeAuditFiles {
		c.codeReason = fmt.Sprintf("项目包含 %d 个受支持源码文件，超过控制台代码审计上限 %d；请用 audit code CLI 分析", supported, MaxCodeAuditFiles)
		return codescan.Report{}, c.codeReason, nil
	}
	started := time.Now()
	// The analysis must outlive the HTTP request that started it: a page
	// refresh cancels the request context, and caching "context canceled" as a
	// terminal failure would freeze the report until the next restart. A 10
	// minute ceiling keeps a runaway run bounded without being user-visible.
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
	defer cancel()
	report, err := codescan.Analyze(runCtx, snapshot, codescan.Options{})
	if err != nil {
		// Surface the real failure on stderr: silent caching here cost a whole
		// debugging session once ("context canceled" froze the page).
		fmt.Fprintf(os.Stderr, "TRIDENT code audit failed after %s: %v\n", time.Since(started).Round(time.Millisecond), err)
		if errors.Is(err, context.Canceled) {
			// Request cancellation stays retryable; the detached run context
			// makes this rare, but a poisoned cache must never happen.
			return codescan.Report{}, "", err
		}
		c.codeFatal = err
		return codescan.Report{}, "", err
	}
	c.codeState = &report
	c.saveCodeCache(report)
	return report, "", nil
}

// codeAuditCached reports an already computed result without starting work.
func (c *Console) codeAuditCached() (codescan.Report, string, bool) {
	c.codeMu.Lock()
	defer c.codeMu.Unlock()
	if c.codeState != nil {
		return *c.codeState, "", true
	}
	return codescan.Report{}, c.codeReason, false
}

// codeAuditResponse is a read-only view of the bounded multi-language rule
// report. It adds filtering and pagination only; no analysis semantics, no
// execution and no runtime claims are introduced here.
type codeAuditResponse struct {
	SchemaVersion   int                        `json:"schema_version"`
	ToolVersion     string                     `json:"tool_version"`
	SnapshotHash    string                     `json:"snapshot_hash"`
	AnalysisKind    string                     `json:"analysis_kind"`
	RuleSetVersion  string                     `json:"ruleset_version"`
	Partial         bool                       `json:"partial"`
	FilePartial     bool                       `json:"file_partial"`
	SymbolPartial   bool                       `json:"symbol_partial"`
	FindingPartial  bool                       `json:"finding_partial"`
	Available       bool                       `json:"available"`
	Reason          string                     `json:"reason,omitempty"`
	Total           int                        `json:"total"`
	Limit           int                        `json:"limit"`
	Offset          int                        `json:"offset"`
	Items           []codescan.Finding         `json:"items"`
	Languages       []codescan.LanguageSummary `json:"languages"`
	Coverage        codescan.Coverage          `json:"coverage"`
	Routes          []codescan.Route           `json:"routes"`
	Files           []codescan.FileSummary     `json:"files"`
	RejectedFiles   []codescan.FileSummary     `json:"rejected_files"`
	RejectedScopes  []codescan.Count           `json:"rejected_scopes"`
	Symbols         []codescan.Symbol          `json:"symbols"`
	Calls           []codescan.Call            `json:"calls"`
	Variables       []codescan.Variable        `json:"variables"`
	StringConstants []codescan.StringConstant  `json:"string_constants"`
	Unresolved      []codescan.Unresolved      `json:"unresolved"`
	SymbolLanguages []codescan.LanguageSummary `json:"symbol_languages"`
	ByLanguage      []codescan.Count           `json:"by_language"`
	ByCategory      []codescan.Count           `json:"by_category"`
	BySeverity      []codescan.Count           `json:"by_severity"`
	Limitations     []string                   `json:"limitations"`
	RuntimeStatus   string                     `json:"runtime_status"`
}

// codeAuditItemCap bounds the auxiliary lists served to the browser; the
// finding table itself remains paginated by the caller.
const codeAuditItemCap = 200

func (c *Console) handleCodeAudit(w http.ResponseWriter, r *http.Request) {
	if _, err := c.analyze(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "analysis_failed", err.Error())
		return
	}
	report, reason, err := c.codeAudit(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "code_audit_failed", err.Error())
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
	category := strings.TrimSpace(r.URL.Query().Get("category"))
	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	response := codeAuditResponse{
		SchemaVersion: SchemaVersion, ToolVersion: codescan.ToolVersion,
		SnapshotHash: c.SnapshotHash(), AnalysisKind: codescan.AnalysisKind,
		RuleSetVersion: report.RuleSetVersion, Partial: report.Partial,
		FilePartial: report.FilePartial, SymbolPartial: report.SymbolPartial, FindingPartial: report.FindingPartial,
		Available: reason == "", Reason: reason,
		Total: 0, Limit: limit, Offset: offset,
		Items: []codescan.Finding{}, Languages: report.Languages,
		Coverage: report.Coverage, Routes: capRoutes(report.Routes),
		Files: capFiles(report.Files), RejectedFiles: rejectedFiles(report.Files), RejectedScopes: rejectedScopeCounts(report.Files),
		Symbols: capSymbols(report.Symbols),
		Calls:   capCalls(report.Calls), Variables: capVariables(report.Variables), StringConstants: capStringConstants(report.StringConstants), Unresolved: capUnresolved(report.Unresolved),
		SymbolLanguages: append([]codescan.LanguageSummary(nil), report.Languages...),
		ByLanguage:      []codescan.Count{},
		ByCategory:      []codescan.Count{}, BySeverity: []codescan.Count{},
		Limitations:   append([]string(nil), report.Limitations...),
		RuntimeStatus: "not_run",
	}
	if !response.Available {
		response.Symbols = []codescan.Symbol{}
		response.Calls = []codescan.Call{}
		response.Unresolved = []codescan.Unresolved{}
		response.SymbolLanguages = []codescan.LanguageSummary{}
		response.Routes = []codescan.Route{}
		response.Files = []codescan.FileSummary{}
		response.RejectedFiles = []codescan.FileSummary{}
		response.RejectedScopes = []codescan.Count{}
		writeJSON(w, http.StatusOK, response)
		return
	}
	byLanguage := map[string]int{}
	byCategory := map[string]int{}
	bySeverity := map[string]int{}
	matched := make([]codescan.Finding, 0, len(report.Findings))
	for _, item := range report.Findings {
		byLanguage[item.Language]++
		byCategory[item.Category]++
		bySeverity[item.Severity]++
		if language != "" && language != "all" && item.Language != language {
			continue
		}
		if category != "" && category != "all" && item.Category != category {
			continue
		}
		if severity != "" && severity != "all" && item.Severity != severity {
			continue
		}
		if query != "" && !codeAuditMatches(item, query) {
			continue
		}
		matched = append(matched, item)
	}
	response.Total = len(matched)
	response.ByLanguage = sortedCounts(byLanguage)
	response.ByCategory = sortedCounts(byCategory)
	response.BySeverity = sortedCounts(bySeverity)
	if offset < len(matched) {
		end := offset + limit
		if end > len(matched) {
			end = len(matched)
		}
		response.Items = matched[offset:end]
	}
	writeJSON(w, http.StatusOK, response)
}

func codeAuditMatches(item codescan.Finding, query string) bool {
	parts := []string{item.RuleID, item.Title, item.File, item.CWE, item.Language, item.Category}
	if item.Sink != nil {
		parts = append(parts, item.Sink.Symbol)
	}
	if item.Source != nil {
		parts = append(parts, item.Source.Symbol)
	}
	return strings.Contains(strings.ToLower(strings.Join(parts, " ")), query)
}

func sortedCounts(values map[string]int) []codescan.Count {
	out := make([]codescan.Count, 0, len(values))
	for key, value := range values {
		out = append(out, codescan.Count{Key: key, Value: value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func countScannedLanguages(values []codescan.LanguageSummary) int {
	count := 0
	for _, item := range values {
		if item.Status == "scanned" {
			count++
		}
	}
	return count
}

func capRoutes(values []codescan.Route) []codescan.Route {
	if len(values) > codeAuditItemCap {
		return values[:codeAuditItemCap]
	}
	return append([]codescan.Route(nil), values...)
}

func capFiles(values []codescan.FileSummary) []codescan.FileSummary {
	if len(values) == 0 {
		return []codescan.FileSummary{}
	}
	if len(values) > codeAuditItemCap {
		return values[:codeAuditItemCap]
	}
	return append([]codescan.FileSummary(nil), values...)
}

func rejectedFiles(values []codescan.FileSummary) []codescan.FileSummary {
	out := make([]codescan.FileSummary, 0, len(values))
	for _, item := range values {
		if item.Status == "rejected" {
			out = append(out, item)
		}
	}
	return capFiles(out)
}

func rejectedScopeCounts(values []codescan.FileSummary) []codescan.Count {
	counts := map[string]int{}
	for _, item := range values {
		if item.Status != "rejected" {
			continue
		}
		scope := item.Scope
		if scope == "" {
			scope = "project"
		}
		counts[scope]++
	}
	out := make([]codescan.Count, 0, len(counts))
	for key, value := range counts {
		out = append(out, codescan.Count{Key: key, Value: value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func capSymbols(values []codescan.Symbol) []codescan.Symbol {
	if len(values) > codeAuditItemCap {
		return values[:codeAuditItemCap]
	}
	return append([]codescan.Symbol(nil), values...)
}

func capCalls(values []codescan.Call) []codescan.Call {
	if len(values) > codeAuditItemCap {
		return values[:codeAuditItemCap]
	}
	return append([]codescan.Call(nil), values...)
}

func capUnresolved(values []codescan.Unresolved) []codescan.Unresolved {
	if len(values) > codeAuditItemCap {
		return values[:codeAuditItemCap]
	}
	return append([]codescan.Unresolved(nil), values...)
}

func capVariables(values []codescan.Variable) []codescan.Variable {
	if len(values) > codeAuditItemCap {
		return values[:codeAuditItemCap]
	}
	return append([]codescan.Variable(nil), values...)
}

func capStringConstants(values []codescan.StringConstant) []codescan.StringConstant {
	if len(values) > codeAuditItemCap {
		return values[:codeAuditItemCap]
	}
	return append([]codescan.StringConstant(nil), values...)
}
