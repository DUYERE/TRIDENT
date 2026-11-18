package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trident/internal/codescan"
)

// Regression: a browser refresh cancels the HTTP request that started the
// lazy multi-language audit. That cancellation must not be cached as a
// terminal failure, and it must not poison later requests.
func TestCodeAuditSurvivesRequestCancellation(t *testing.T) {
	console, _ := newTestConsole(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := console.codeAudit(ctx); err != nil {
		t.Fatalf("canceled request context leaked into the lazy audit: %v", err)
	}
	report, _, err := console.codeAudit(context.Background())
	if err != nil {
		t.Fatalf("second request was poisoned by the canceled one: %v", err)
	}
	// The inline fixture triggers one code finding (java.sql.statement on
	// App.java); the findings page merges it into /api/findings.
	if len(report.Findings) != 1 {
		t.Fatalf("unexpected code findings: %+v", report.Findings)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/findings?limit=20", nil)
	request.Header.Set(RequestHeader, "console")
	request.Header.Set(TokenHeader, "test-token-0123456789abcdef")
	recorder := httptest.NewRecorder()
	console.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("findings: %d %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Body.String(); !strings.Contains(got, "code:java.sql.statement") {
		t.Fatalf("merged findings missing the code finding: %.400s", got)
	}
}

// Once the multi-language report is cached the overview must agree with the
// findings page: totals, confirmed counts and the SQL category all include it.
func TestOverviewMergesCachedCodeFindings(t *testing.T) {
	console, _ := newTestConsole(t)
	if _, _, err := console.codeAudit(context.Background()); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	request.Header.Set(TokenHeader, "test-token-0123456789abcdef")
	request.Header.Set(RequestHeader, "console")
	recorder := httptest.NewRecorder()
	console.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview: %d %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Counts struct {
			Total     int `json:"total"`
			Confirmed int `json:"static_confirmed"`
		} `json:"counts"`
		Code struct {
			Available bool `json:"available"`
			Findings  int  `json:"findings"`
		} `json:"code"`
		Categories []struct {
			Key       string `json:"key"`
			Total     int    `json:"total"`
			Confirmed int    `json:"static_confirmed"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Code.Available || payload.Code.Findings != 1 {
		t.Fatalf("code summary: %+v", payload.Code)
	}
	if payload.Counts.Total != 4 || payload.Counts.Confirmed != 2 {
		t.Fatalf("counts did not merge the code finding: %+v", payload.Counts)
	}
	sqlCategory := false
	for _, category := range payload.Categories {
		if category.Key == "sql" && category.Total == 2 && category.Confirmed == 2 {
			sqlCategory = true
		}
	}
	if !sqlCategory {
		t.Fatalf("sql category did not merge the code finding: %+v", payload.Categories)
	}
}

func TestCodeAuditExposesBoundedSymbolIndex(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/code-audit?limit=1", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("code audit: %d %s", response.StatusCode, body)
	}
	var payload codeAuditResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode code audit: %v", err)
	}
	if !payload.Available || payload.Coverage.SymbolsFound == 0 {
		t.Fatalf("symbol coverage missing: available=%v coverage=%+v", payload.Available, payload.Coverage)
	}
	foundApp := false
	for _, symbol := range payload.Symbols {
		if symbol.Name == "App" && symbol.Kind == "class" {
			foundApp = true
		}
	}
	if !foundApp {
		t.Fatalf("Java class symbol not exposed: %+v", payload.Symbols)
	}
	if len(payload.Calls) == 0 || len(payload.Unresolved) == 0 {
		t.Fatalf("calls/unresolved not exposed: calls=%+v unresolved=%+v", payload.Calls, payload.Unresolved)
	}
	if len(payload.SymbolLanguages) == 0 {
		t.Fatalf("symbol language summaries missing")
	}
	if len(payload.Symbols) > codeAuditItemCap || len(payload.Calls) > codeAuditItemCap || len(payload.Unresolved) > codeAuditItemCap {
		t.Fatalf("symbol lists exceeded API cap")
	}
	if payload.RejectedFiles == nil {
		t.Fatalf("rejected_files must be an empty list, not null")
	}
}

func TestRejectedFilesKeepOnlyRejectedAndCap(t *testing.T) {
	values := []codescan.FileSummary{
		{File: "keep.php", Language: "php", Status: "rejected", Reason: "lex_rejected"},
		{File: "skip.php", Language: "php", Status: "scanned"},
		{File: "keep.js", Language: "javascript", Status: "rejected", Reason: "file_too_large"},
	}
	got := rejectedFiles(values)
	if len(got) != 2 || got[0].File != "keep.php" || got[1].File != "keep.js" {
		t.Fatalf("rejected file filter: %+v", got)
	}
}

func TestCachedSymbolPartialUsesSymbolAxis(t *testing.T) {
	console, _ := newTestConsole(t)
	console.codeState = &codescan.Report{Partial: true, FilePartial: true}
	if _, _, _, _, partial, _ := console.cachedSymbolPayload(); partial {
		t.Fatalf("file partial leaked into symbol_partial")
	}
	console.codeState.SymbolPartial = true
	if _, _, _, _, partial, _ := console.cachedSymbolPayload(); !partial {
		t.Fatalf("symbol_partial not propagated")
	}
}

func TestRejectedScopeCounts(t *testing.T) {
	files := []codescan.FileSummary{
		{File: "app/a.php", Status: "rejected", Scope: "project"},
		{File: "vendor/b.php", Status: "rejected", Scope: "vendor"},
		{File: "dist/c.js", Status: "rejected", Scope: "generated"},
		{File: "app/d.php", Status: "scanned"},
	}
	counts := rejectedScopeCounts(files)
	if len(counts) != 3 {
		t.Fatalf("counts = %+v", counts)
	}
	for _, item := range counts {
		if item.Value != 1 {
			t.Fatalf("unexpected count: %+v", item)
		}
	}
}

func TestSymbolsEndpointFiltersAndPaginates(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/symbols?limit=1", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("symbols: %d %s", response.StatusCode, body)
	}
	var all symbolResponse
	if err := json.Unmarshal(body, &all); err != nil {
		t.Fatalf("decode symbols: %v", err)
	}
	if !all.Available || all.Total == 0 || len(all.Items) != 1 || all.Limit != 1 {
		t.Fatalf("symbol page: available=%v total=%d items=%d limit=%d", all.Available, all.Total, len(all.Items), all.Limit)
	}

	response, body = c.do(http.MethodGet, "/api/symbols?kind=class&q=App", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("filtered symbols: %d %s", response.StatusCode, body)
	}
	var filtered symbolResponse
	if err := json.Unmarshal(body, &filtered); err != nil {
		t.Fatalf("decode filtered symbols: %v", err)
	}
	if filtered.Total == 0 {
		t.Fatalf("filtered symbol query returned nothing")
	}
	for _, item := range filtered.Items {
		if item.Kind != "class" || !strings.Contains(strings.ToLower(item.Name+" "+item.QualifiedName+" "+item.File), "app") {
			t.Fatalf("filter leaked non-matching symbol: %+v", item)
		}
	}
}

func TestModelSymbolPayloadIsCachedOnly(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/model", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("model before audit: %d %s", response.StatusCode, body)
	}
	var pending modelResponse
	if err := json.Unmarshal(body, &pending); err != nil {
		t.Fatalf("decode pending model: %v", err)
	}
	if !strings.Contains(pending.SymbolReason, "analysis_pending") {
		t.Fatalf("model should advertise pending symbol analysis, got %q", pending.SymbolReason)
	}
	if len(pending.Symbols) != 0 {
		t.Fatalf("model invented symbols without code audit: %+v", pending.Symbols)
	}
	if console.codeState != nil {
		t.Fatal("/api/model started code audit unexpectedly")
	}

	response, body = c.do(http.MethodGet, "/api/code-audit?limit=1", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("code audit: %d %s", response.StatusCode, body)
	}
	response, body = c.do(http.MethodGet, "/api/model", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("model after audit: %d %s", response.StatusCode, body)
	}
	var payload modelResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode cached model: %v", err)
	}
	if payload.SymbolReason != "" || len(payload.Symbols) == 0 {
		t.Fatalf("cached symbols not attached: reason=%q symbols=%+v", payload.SymbolReason, payload.Symbols)
	}
}
