package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentQuickStatusMasksCredentials(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	token := strings.Repeat("a", 64)
	console.storedAgentDSN = "postgres://user:secret@127.0.0.1:55432/trident_test?sslmode=disable"
	console.storedAgentToken = token
	console.quickProbe = func(_ context.Context, _ string, tokens []string) quickProbeResult {
		if len(tokens) == 0 || tokens[0] != token {
			t.Fatalf("stored token must be offered first: %v", tokens)
		}
		return quickProbeResult{DSNOK: true, PrincipalFound: true, Role: "admin", Token: token}
	}
	recorder := httptest.NewRecorder()
	console.handleAgentRuntimeQuick(recorder, httptest.NewRequest(http.MethodGet, "/api/agent/runtime/quick", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("quick status failed: %d %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, leak := range []string{"secret", token, "user:"} {
		if strings.Contains(body, leak) {
			t.Fatalf("quick status leaked %q: %s", leak, body)
		}
	}
	var status agentQuickStatus
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Version != agentQuickVersion || !status.CanEnable || !status.DSNOK ||
		!status.PrincipalFound || status.PrincipalRole != "admin" ||
		status.DSNTarget != "127.0.0.1:55432/trident_test" {
		t.Fatalf("unexpected quick status: %+v", status)
	}
}

func TestAgentQuickStatusReportsMissingCandidates(t *testing.T) {
	t.Setenv("TRIDENT_DATABASE_URL", "")
	console := consoleWithModels(t, roleTestFile())
	console.quickProbe = func(_ context.Context, dsn string, tokens []string) quickProbeResult {
		if dsn != "" || len(tokens) != 0 {
			t.Fatalf("no candidates expected, got %q %v", dsn, tokens)
		}
		return quickProbeResult{Reason: "未发现会话库连接串"}
	}
	recorder := httptest.NewRecorder()
	console.handleAgentRuntimeQuick(recorder, httptest.NewRequest(http.MethodGet, "/api/agent/runtime/quick", nil))
	var status agentQuickStatus
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.CanEnable || status.DSNFound || status.DSNOK || status.PrincipalFound || status.Reason == "" {
		t.Fatalf("missing candidates must not be reported as ready: %+v", status)
	}
}

func TestAgentQuickCandidatesReadLocalSecrets(t *testing.T) {
	t.Setenv("TRIDENT_DATABASE_URL", "")
	root := t.TempDir()
	workspace := filepath.Join(root, ".trident")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	good := strings.Repeat("b", 64)
	if err := os.WriteFile(filepath.Join(root, "secrets", "admin.json"), []byte(`{"token":"`+good+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secrets", "bad.json"), []byte(`{"token":"short"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	console := &Console{workspace: workspace}
	dsn, tokens := console.quickCandidates()
	if dsn != "" || len(tokens) != 1 || tokens[0] != good {
		t.Fatalf("candidate discovery: dsn=%q tokens=%v", dsn, tokens)
	}
	stored := strings.Repeat("c", 64)
	console.storedAgentToken = stored
	_, tokens = console.quickCandidates()
	if len(tokens) != 2 || tokens[0] != stored {
		t.Fatalf("stored token must take priority: %v", tokens)
	}
}

func TestAgentQuickEnableRejectsUnavailableWithoutPersisting(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	console.quickProbe = func(_ context.Context, _ string, _ []string) quickProbeResult {
		return quickProbeResult{DSNOK: true, Reason: "本机令牌均无效或不具备创建 Run 权限"}
	}
	recorder := httptest.NewRecorder()
	console.handleAgentRuntimeQuickEnable(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/runtime/quick", nil))
	if recorder.Code != http.StatusPreconditionFailed || !strings.Contains(recorder.Body.String(), "agent_quick_unavailable") {
		t.Fatalf("unavailable quick setup must fail: %d %s", recorder.Code, recorder.Body.String())
	}
	file, err := loadWorkspaceConfig(console.workspace)
	if err != nil {
		t.Fatal(err)
	}
	if file.AgentToken != "" || file.AgentChatEnabled {
		t.Fatalf("failed quick setup must not persist anything: %+v", file)
	}
}

func TestAgentQuickEnableGuards(t *testing.T) {
	pinned := &Console{}
	recorder := httptest.NewRecorder()
	pinned.handleAgentRuntimeQuickEnable(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/runtime/quick", nil))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "pinned_console") {
		t.Fatalf("pinned console must refuse: %d %s", recorder.Code, recorder.Body.String())
	}
	busy := consoleWithModels(t, roleTestFile())
	busy.chatActive = 7
	recorder = httptest.NewRecorder()
	busy.handleAgentRuntimeQuickEnable(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/runtime/quick", nil))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "agent_busy") {
		t.Fatalf("busy console must refuse: %d %s", recorder.Code, recorder.Body.String())
	}
}

// The probe is only a pre-check: POST must re-open the real database and never
// persist a token just because discovery claimed it was valid.
func TestAgentQuickEnableRevalidatesBeforePersist(t *testing.T) {
	console := consoleWithModels(t, roleTestFile())
	console.storedAgentDSN = badAgentDSN
	token := strings.Repeat("d", 64)
	console.quickProbe = func(_ context.Context, _ string, _ []string) quickProbeResult {
		return quickProbeResult{DSNOK: true, PrincipalFound: true, Role: "admin", Token: token}
	}
	recorder := httptest.NewRecorder()
	console.handleAgentRuntimeQuickEnable(recorder, httptest.NewRequest(http.MethodPost, "/api/agent/runtime/quick", nil))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "agent_dsn_invalid") {
		t.Fatalf("POST must revalidate the DSN: %d %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), token) {
		t.Fatal("failed quick setup must not echo the token")
	}
	file, err := loadWorkspaceConfig(console.workspace)
	if err != nil {
		t.Fatal(err)
	}
	if file.AgentToken != "" || file.AgentChatEnabled {
		t.Fatalf("failed validation must not persist: %+v", file)
	}
}
