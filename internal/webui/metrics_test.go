package webui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func decodeMetrics(t *testing.T, body []byte) metricsSnapshot {
	t.Helper()
	var snapshot metricsSnapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		t.Fatalf("metrics payload: %v", err)
	}
	return snapshot
}

func TestConsolePrometheusScrapeEndpoint(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, _ := c.do(http.MethodGet, "/metrics", false, false)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("scrape without token: %d", response.StatusCode)
	}

	// Prometheus-style bearer token without the browser-only console header.
	req, err := http.NewRequest(http.MethodGet, server.URL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+console.Token())
	response, err = server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("bearer scrape: %d", response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("scrape content type: %s", contentType)
	}
	text := string(body)
	for _, name := range []string{
		"trident_console_build_info", "trident_console_uptime_seconds",
		"trident_console_requests_total", "trident_console_requests_unauthorized_total",
		"trident_console_requests_forbidden_total", "trident_console_analysis_runs_total",
		"trident_console_analysis_cache_hits_total", "trident_console_analysis_failures_total",
		"trident_console_analysis_cached", "trident_console_analysis_cached_ok",
		"trident_console_analysis_last_duration_milliseconds",
	} {
		if !strings.Contains(text, "# TYPE "+name) {
			t.Fatalf("scrape missing TYPE line for %s:\n%s", name, text)
		}
	}
	if !strings.Contains(text, `product="TRIDENT"`) {
		t.Fatalf("build_info labels missing:\n%s", text)
	}
	scrapeTotal := parsePrometheusCounter(t, text, "trident_console_requests_total")

	// The JSON endpoint must agree with the scrape: the JSON request itself is
	// one additional gated request counted after the scrape.
	response, jsonBody := c.do(http.MethodGet, "/api/metrics", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("json metrics: %d", response.StatusCode)
	}
	jsonSnapshot := decodeMetrics(t, jsonBody)
	if jsonSnapshot.Requests.Total != scrapeTotal+1 {
		t.Fatalf("scrape/JSON counter drift: scrape=%d json=%d", scrapeTotal, jsonSnapshot.Requests.Total)
	}

	// A bearer token also authorizes the JSON plane only when the console
	// header is present.
	req, err = http.NewRequest(http.MethodGet, server.URL+"/api/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+console.Token())
	response, err = server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("bearer without console header on the API plane: %d", response.StatusCode)
	}
}

func parsePrometheusCounter(t *testing.T, text, name string) int64 {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, name+" ") {
			fields := strings.Fields(strings.TrimPrefix(line, name+" "))
			if len(fields) != 1 {
				t.Fatalf("unexpected sample line: %q", line)
			}
			value, err := strconv.ParseInt(fields[0], 10, 64)
			if err != nil {
				t.Fatalf("sample value: %v", err)
			}
			return value
		}
	}
	t.Fatalf("sample line missing for %s", name)
	return 0
}

func TestConsoleHealthzAndMetrics(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/healthz", false, false)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("healthz without token: %d %s", response.StatusCode, body)
	}
	var health struct {
		Status  string `json:"status"`
		Product string `json:"product"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("healthz payload: %v", err)
	}
	if health.Status != "ok" || health.Product != Product || health.Version == "" {
		t.Fatalf("healthz payload: %+v", health)
	}

	response, _ = c.do(http.MethodGet, "/api/metrics", false, true)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("metrics without token: %d", response.StatusCode)
	}

	// Drive counters: one unauthorized, one forbidden, then a successful
	// analysis request pair (cold run + warm cache hit).
	response, _ = c.do(http.MethodGet, "/api/overview", true, false)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("missing console header: %d", response.StatusCode)
	}
	response, overviewBody := c.do(http.MethodGet, "/api/overview", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("overview: %d", response.StatusCode)
	}
	var overview overviewResponse
	if err := json.Unmarshal(overviewBody, &overview); err != nil {
		t.Fatalf("overview payload: %v", err)
	}
	if _, body := c.do(http.MethodGet, "/api/health", true, true); body == nil {
		t.Fatal("health request failed")
	}
	response, body = c.do(http.MethodGet, "/api/metrics", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("metrics: %d %s", response.StatusCode, body)
	}
	snapshot := decodeMetrics(t, body)
	if snapshot.Product != Product || snapshot.Version == "" || snapshot.UptimeSeconds < 0 {
		t.Fatalf("metrics identity: %+v", snapshot)
	}
	// total counts every gated request so far: the unauthorized metrics probe,
	// the forbidden overview, the overview, health and metrics itself.
	if snapshot.Requests.Total != 5 {
		t.Fatalf("requests.total: %d", snapshot.Requests.Total)
	}
	if snapshot.Requests.Unauthorized != 1 || snapshot.Requests.Forbidden != 1 {
		t.Fatalf("rejection counters: %+v", snapshot.Requests)
	}
	// The overview triggered the single cold analysis run; /api/health and
	// /api/metrics are lightweight and do not touch the analysis cache.
	if snapshot.Analysis.RunsTotal != 1 || snapshot.Analysis.CacheHitsTotal != 0 || snapshot.Analysis.FailuresTotal != 0 {
		t.Fatalf("analysis counters: %+v", snapshot.Analysis)
	}
	if !snapshot.Analysis.Cached || !snapshot.Analysis.CachedOK {
		t.Fatalf("analysis cache flags: %+v", snapshot.Analysis)
	}
	if snapshot.Analysis.LastDurationMS < 0 {
		t.Fatalf("last_duration_ms: %d", snapshot.Analysis.LastDurationMS)
	}

	// A second metrics read after more traffic must reflect the same analysis
	// run with additional cache hits, keeping counters monotonic.
	if _, body := c.do(http.MethodGet, "/api/overview", true, true); body == nil {
		t.Fatal("second overview failed")
	}
	response, body = c.do(http.MethodGet, "/api/metrics", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("second metrics: %d", response.StatusCode)
	}
	second := decodeMetrics(t, body)
	// second overview + the second metrics request itself.
	if second.Requests.Total != snapshot.Requests.Total+2 {
		t.Fatalf("requests.total monotonic: %d -> %d", snapshot.Requests.Total, second.Requests.Total)
	}
	// The second overview is a warm cache hit; the metrics read does not
	// analyze again.
	if second.Analysis.RunsTotal != 1 || second.Analysis.CacheHitsTotal != 1 {
		t.Fatalf("second analysis counters: %+v", second.Analysis)
	}
}
