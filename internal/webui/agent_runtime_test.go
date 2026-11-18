package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentRuntimeStatusMasksCredentials(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	console.storedAgentDSN = "postgres://user:secret@127.0.0.1:55432/trident_test?sslmode=disable"
	console.storedAgentToken = "principal-token-value"
	recorder := httptest.NewRecorder()
	console.handleAgentRuntime(recorder, httptest.NewRequest(http.MethodGet, "/api/agent/runtime", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status failed: %d %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, leak := range []string{"secret", "principal-token-value", "user:"} {
		if strings.Contains(body, leak) {
			t.Fatalf("status leaked %q: %s", leak, body)
		}
	}
	var status agentRuntimeStatus
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.DSNStored || status.DSNTarget != "127.0.0.1:55432/trident_test" || !status.TokenStored {
		t.Fatalf("unexpected masked status: %+v", status)
	}
	if status.Enabled || status.Ready {
		t.Fatalf("a console without a write session must not report ready: %+v", status)
	}
}

func TestAgentRuntimeRejectsMissingAndBadCredentials(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	recorder := httptest.NewRecorder()
	console.handleAgentRuntimeUpdate(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/runtime",
		strings.NewReader(`{"enabled":true}`)))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "agent_dsn_missing") {
		t.Fatalf("missing DSN must be rejected: %d %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	console.handleAgentRuntimeUpdate(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/runtime",
		strings.NewReader(`{"enabled":true,"dsn":"://not-a-dsn","token":"t"}`)))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "agent_dsn_invalid") {
		t.Fatalf("invalid DSN must be rejected before persisting: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestAgentRuntimeDisablePersistsWithoutRestart(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	recorder := httptest.NewRecorder()
	console.handleAgentRuntimeUpdate(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/runtime",
		strings.NewReader(`{"enabled":false}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("disable failed: %d %s", recorder.Code, recorder.Body.String())
	}
	var status agentRuntimeStatus
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Enabled || status.Ready {
		t.Fatalf("disable did not take effect: %+v", status)
	}
	file, err := loadWorkspaceConfig(console.workspace)
	if err != nil {
		t.Fatal(err)
	}
	if file.AgentChatEnabled {
		t.Fatalf("disabled state must persist: %+v", file)
	}
	if console.chatState().enabled {
		t.Fatal("chat must be disabled immediately")
	}
}

func TestAgentRuntimeClearTokenDisablesAndPersists(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	console.storedAgentDSN = "postgres://user:secret@127.0.0.1:55432/trident_test"
	console.storedAgentToken = "token-to-clear"
	console.agentChatEnabled = true
	file, err := loadWorkspaceConfig(console.workspace)
	if err != nil {
		t.Fatal(err)
	}
	file.AgentDSN = console.storedAgentDSN
	file.AgentToken = console.storedAgentToken
	file.AgentChatEnabled = true
	if err := saveWorkspaceConfig(console.workspace, file); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	console.handleAgentRuntimeUpdate(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/runtime",
		strings.NewReader(`{"clear_token":true}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("clear token failed: %d %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "token-to-clear") {
		t.Fatal("response must not echo the token")
	}
	updated, err := loadWorkspaceConfig(console.workspace)
	if err != nil {
		t.Fatal(err)
	}
	if updated.AgentToken != "" || updated.AgentChatEnabled {
		t.Fatalf("clearing the token must disable the feature: %+v", updated)
	}
	if console.storedAgentToken != "" || console.agentChatEnabled {
		t.Fatalf("in-memory state not updated: token=%q enabled=%v", console.storedAgentToken, console.agentChatEnabled)
	}
}

func TestAgentRuntimeRefusesWhileBusy(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	console.chatActive = 7
	recorder := httptest.NewRecorder()
	console.handleAgentRuntimeUpdate(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/runtime",
		strings.NewReader(`{"enabled":false}`)))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "agent_busy") {
		t.Fatalf("busy console must refuse runtime changes: %d %s", recorder.Code, recorder.Body.String())
	}
}
