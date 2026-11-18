package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestToolchainsEndpointReportsHostProfiles(t *testing.T) {
	console, _ := newTestConsole(t)
	server := httptest.NewServer(console.Handler())
	defer server.Close()
	c := &client{t: t, server: server, token: console.Token()}

	response, body := c.do(http.MethodGet, "/api/toolchains", true, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("toolchains: %d %s", response.StatusCode, body)
	}
	var payload struct {
		SchemaVersion int    `json:"schema_version"`
		Scope         string `json:"scope"`
		Toolchains    []struct {
			Profile    string `json:"profile"`
			Status     string `json:"status"`
			Limitation string `json:"limitation"`
		} `json:"toolchains"`
		Limitations []string `json:"limitations"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode toolchains: %v", err)
	}
	if payload.SchemaVersion != SchemaVersion || payload.Scope != "host_toolchain" {
		t.Fatalf("identity: %+v", payload)
	}
	if len(payload.Toolchains) != 8 {
		t.Fatalf("profiles: %+v", payload.Toolchains)
	}
	seen := map[string]bool{}
	for _, item := range payload.Toolchains {
		seen[item.Profile] = true
		if item.Status != "available" && item.Status != "toolchain_unavailable" {
			t.Fatalf("status: %+v", item)
		}
	}
	if !seen["php-lint"] || !seen["python-compile"] || !seen["node-check"] || !seen["go-test"] || !seen["dotnet-build"] {
		t.Fatalf("missing profiles: %+v", seen)
	}
	if len(payload.Limitations) == 0 || !strings.Contains(strings.Join(payload.Limitations, " "), "php_lint_syntax_only") {
		t.Fatalf("php limitation missing: %+v", payload.Limitations)
	}
}
