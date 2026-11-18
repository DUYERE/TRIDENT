package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const badAgentDSN = "postgres://trident_nope@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"

// Regression: a persisted Agent DSN that cannot connect must degrade to a
// reported reason instead of failing the whole console start, and the settings
// page must be able to clear or replace it at runtime.
func TestWorkspaceAgentDSN(t *testing.T) {
	workspace := t.TempDir()
	destination, _, hash := writeFixture(t)
	persisted := workspaceFile{AgentDSN: badAgentDSN}
	if err := saveWorkspaceConfig(workspace, persisted); err != nil {
		t.Fatal(err)
	}
	console, err := New(context.Background(), Options{
		Workspace: workspace, SnapshotDir: destination, SnapshotHash: hash,
		ProjectSource: filepath.Join(workspace, "source"),
		Token:         "test-token-0123456789abcdef", Version: "test-build",
	})
	if err != nil {
		t.Fatalf("unreachable persisted DSN must not fail the start: %v", err)
	}
	t.Cleanup(func() { _ = console.Close() })
	if console.agentStore != nil {
		t.Fatal("unreachable DSN must not yield an observation store")
	}
	console.agentStoreMu.Lock()
	connectError := console.agentConnectError
	console.agentStoreMu.Unlock()
	if connectError == "" || !strings.Contains(connectError, "打开 Agent 会话库失败") {
		t.Fatalf("expected a degraded-connect reason, got %q", connectError)
	}
	snapshot := console.buildConfigSnapshot()
	if !snapshot.Features.AgentDSNStored || snapshot.Features.AgentDSNError == "" || snapshot.Features.AgentStore {
		t.Fatalf("config snapshot: %+v", snapshot.Features)
	}

	// Saving an invalid DSN through the settings API is rejected with the
	// underlying connect error and keeps the stored value untouched.
	response, body := postConfig(t, console, map[string]any{"agent_dsn": badAgentDSN})
	if response.Code != http.StatusBadRequest || !strings.Contains(body, "agent_dsn_invalid") {
		t.Fatalf("invalid dsn save: %d %s", response.Code, body)
	}
	if file, err := loadWorkspaceConfig(workspace); err != nil || file.AgentDSN != badAgentDSN {
		t.Fatalf("rejected save must not touch the stored dsn: %+v %v", file.AgentDSN, err)
	}

	// Clearing removes the persisted DSN and returns the page to the
	// "not configured" precondition instead of the degraded state.
	response, body = postConfig(t, console, map[string]any{"agent_dsn_clear": true})
	if response.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", response.Code, body)
	}
	if file, err := loadWorkspaceConfig(workspace); err != nil || file.AgentDSN != "" {
		t.Fatalf("cleared dsn must not persist: %q %v", file.AgentDSN, err)
	}
	snapshot = console.buildConfigSnapshot()
	if snapshot.Features.AgentDSNStored || snapshot.Features.AgentDSNError != "" {
		t.Fatalf("features after clear: %+v", snapshot.Features)
	}
	threads := httptest.NewRequest(http.MethodGet, "/api/agent/threads", nil)
	threads.Header.Set(TokenHeader, "test-token-0123456789abcdef")
	threads.Header.Set(RequestHeader, "console")
	recorder := httptest.NewRecorder()
	console.Handler().ServeHTTP(recorder, threads)
	if recorder.Code != http.StatusPreconditionFailed || !strings.Contains(recorder.Body.String(), "agent_database_missing") {
		t.Fatalf("threads after clear: %d %s", recorder.Code, recorder.Body.String())
	}
}

// An explicit --agent-dsn that fails is a caller mistake and keeps the old
// fail-fast behaviour: the console must not start half-configured.
func TestExplicitAgentDSNFailureStopsStart(t *testing.T) {
	destination, _, hash := writeFixture(t)
	workspace := t.TempDir()
	if _, err := New(context.Background(), Options{
		Workspace: workspace, SnapshotDir: destination, SnapshotHash: hash,
		Token: "test-token-0123456789abcdef", Version: "test-build",
		AgentDSN: badAgentDSN, AgentDSNExplicit: true,
	}); err == nil {
		t.Fatal("explicit failing DSN must stop the start")
	}
}

// A workspace console without any DSN keeps working; the Agent page reports
// the precondition instead of a blank list.
func TestWorkspaceWithoutAgentDSNReportsPrecondition(t *testing.T) {
	workspace := t.TempDir()
	destination, _, hash := writeFixture(t)
	console, err := New(context.Background(), Options{
		Workspace: workspace, SnapshotDir: destination, SnapshotHash: hash,
		Token: "test-token-0123456789abcdef", Version: "test-build",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = console.Close() })
	request := httptest.NewRequest(http.MethodGet, "/api/agent/threads", nil)
	request.Header.Set(TokenHeader, "test-token-0123456789abcdef")
	request.Header.Set(RequestHeader, "console")
	recorder := httptest.NewRecorder()
	console.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusPreconditionFailed {
		t.Fatalf("threads: %d %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil || payload.Code != "agent_database_missing" {
		t.Fatalf("payload: %s", recorder.Body.String())
	}
}

// Regression: "not configured" hints must send the operator to the settings
// page, never back to a CLI restart. The runtime DSN, principal token and
// switch are all editable without restarting the console.
func TestUnconfiguredAgentHintsPointToSettings(t *testing.T) {
	workspace := t.TempDir()
	destination, _, hash := writeFixture(t)
	console, err := New(context.Background(), Options{
		Workspace: workspace, SnapshotDir: destination, SnapshotHash: hash,
		Token: "test-token-0123456789abcdef", Version: "test-build",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = console.Close() })
	for _, path := range []string{"/api/agent/threads", "/api/agent/steps?run_id=1"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set(TokenHeader, "test-token-0123456789abcdef")
		request.Header.Set(RequestHeader, "console")
		recorder := httptest.NewRecorder()
		console.Handler().ServeHTTP(recorder, request)
		body := recorder.Body.String()
		if recorder.Code != http.StatusPreconditionFailed || !strings.Contains(body, "agent_database_missing") {
			t.Fatalf("%s: %d %s", path, recorder.Code, body)
		}
		if !strings.Contains(body, "设置") || !strings.Contains(body, "无需重启") {
			t.Fatalf("%s must point at the settings page without a restart: %s", path, body)
		}
		if strings.Contains(body, "--agent-dsn") || strings.Contains(body, "重启即可") || strings.Contains(body, "start the console") {
			t.Fatalf("%s still suggests a CLI restart: %s", path, body)
		}
	}
}

func postConfig(t *testing.T, console *Console, payload map[string]any) (*httptest.ResponseRecorder, string) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(string(raw)))
	request.Header.Set(TokenHeader, "test-token-0123456789abcdef")
	request.Header.Set(RequestHeader, "console")
	recorder := httptest.NewRecorder()
	console.Handler().ServeHTTP(recorder, request)
	return recorder, recorder.Body.String()
}
