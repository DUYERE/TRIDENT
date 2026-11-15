package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"trident/internal/agent"
	"trident/internal/domain"
	openaiadapter "trident/internal/model/openai"
	"trident/internal/project"
	"trident/internal/store"
	"trident/internal/tools"
)

// Chat limits. They are enforced here as well as in the store so a browser
// request can never buy an unbounded run.
const (
	ChatMaxModelCalls = 32
	ChatMaxToolCalls  = 64
	ChatMaxTokens     = 400_000

	chatDefaultModelCalls = 12
	chatDefaultToolCalls  = 24
	chatDefaultTokens     = 131_072
	chatEgressWindow      = 10 * time.Minute
)

// agentChat holds the server-side model binding. The key itself is never stored:
// only the environment variable name is kept, and it is read per run.
type agentChat struct {
	enabled     bool
	reason      string
	endpoint    string
	model       string
	outputParam string
	keyEnv      string
	advisories  string
}

func (c *Console) chatState() agentChat {
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	return c.chat
}

// handleAgentChatState reports whether the composer can be used. It is
// available before a project is selected so the page can explain itself.
func (c *Console) handleAgentChatState(w http.ResponseWriter, _ *http.Request) {
	cfg := c.chatState()
	active := c.chatActiveRun()
	file := c.modelsSnapshot()
	profiles := make([]map[string]any, 0, len(file.Profiles))
	for _, profile := range file.Profiles {
		profiles = append(profiles, map[string]any{
			"id": profile.ID, "label": profile.Label, "model": profile.Model,
			"endpoint": profile.Endpoint, "key_present": os.Getenv(profile.KeyEnv) != "",
			"default": profile.ID == file.Default,
			"defaults": map[string]int64{
				"model_calls": profile.Defaults.ModelCalls,
				"tool_calls":  profile.Defaults.ToolCalls,
				"tokens":      profile.Defaults.Tokens,
			},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version":  SchemaVersion,
		"profiles":        profiles,
		"default_profile": file.Default,
		"enabled":         cfg.enabled,
		"reason":          cfg.reason,
		"endpoint":        cfg.endpoint,
		"model":           cfg.model,
		"key_present":     cfg.enabled && os.Getenv(cfg.keyEnv) != "",
		"active_run":      active,
		"last_error":      c.chatErrorSnapshot(),
		"running":         active > 0,
		"max_model_calls": ChatMaxModelCalls,
		"max_tool_calls":  ChatMaxToolCalls,
		"max_tokens":      ChatMaxTokens,
		"defaults": map[string]any{
			"model_calls": chatDefaultModelCalls,
			"tool_calls":  chatDefaultToolCalls,
			"tokens":      chatDefaultTokens,
		},
	})
}

func (c *Console) chatActiveRun() int64 {
	c.chatMu.Lock()
	defer c.chatMu.Unlock()
	return c.chatActive
}

type chatRequest struct {
	Goal          string `json:"goal"`
	ApproveEgress bool   `json:"approve_egress"`
	ProfileID     string `json:"profile_id"`
	MaxModelCalls int64  `json:"max_model_calls"`
	MaxToolCalls  int64  `json:"max_tool_calls"`
	MaxTokens     int64  `json:"max_tokens"`
}

type chatResponse struct {
	SchemaVersion int              `json:"schema_version"`
	RunID         int64            `json:"run_id"`
	State         string           `json:"state"`
	Goal          string           `json:"goal"`
	Limits        map[string]int64 `json:"limits"`
}

// handleAgentChat creates one run for the current project snapshot and starts it
// in the background. The browser polls /api/agent/steps for progress.
func (c *Console) handleAgentChat(w http.ResponseWriter, r *http.Request) {
	cfg := c.chatState()
	if !cfg.enabled {
		writeError(w, http.StatusConflict, "agent_chat_disabled", cfg.reason)
		return
	}
	if c.agentWrite == nil {
		writeError(w, http.StatusConflict, "agent_chat_disabled", "Agent 写库会话未初始化")
		return
	}
	snapshot := c.snapshotRef()
	if snapshot == nil {
		writeError(w, http.StatusConflict, "no_project", "尚未选择项目")
		return
	}
	body := http.MaxBytesReader(w, r.Body, 32<<10)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request chatRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求不是合法 JSON")
		return
	}
	goal := strings.TrimSpace(request.Goal)
	if goal == "" || len(goal) > 16384 {
		writeError(w, http.StatusBadRequest, "invalid_request", "目标不能为空且不超过 16384 字节")
		return
	}
	// Egress is the one decision the browser must make explicitly,每 run 一次.
	if !request.ApproveEgress {
		writeError(w, http.StatusPreconditionFailed, "egress_not_approved",
			"需要显式批准外发：本项目快照与该目标会被发送到已配置的模型端点")
		return
	}
	profile, found := c.profileByID(request.ProfileID)
	if request.ProfileID == "" {
		profile, found = c.defaultProfile()
	}
	if !found {
		writeError(w, http.StatusBadRequest, "profile_unknown", "模型库中没有该配置")
		return
	}
	if os.Getenv(profile.KeyEnv) == "" {
		writeError(w, http.StatusConflict, "agent_model_key_missing",
			fmt.Sprintf("模型密钥未设置：把 %s 放进控制台进程的环境变量", profile.KeyEnv))
		return
	}
	// The page no longer sends per-run limits, so the profile is the only source.
	// A hand-edited or legacy entry with zeroed defaults must not yield a
	// zero-call run.
	modelCalls := clampInt(request.MaxModelCalls, profileLimit(profile.Defaults.ModelCalls, chatDefaultModelCalls), 1, ChatMaxModelCalls)
	toolCalls := clampInt(request.MaxToolCalls, profileLimit(profile.Defaults.ToolCalls, chatDefaultToolCalls), 1, ChatMaxToolCalls)
	maxTokens := clampInt(request.MaxTokens, profileLimit(profile.Defaults.Tokens, chatDefaultTokens), 4096, ChatMaxTokens)

	c.chatMu.Lock()
	if c.chatActive != 0 {
		active := c.chatActive
		c.chatMu.Unlock()
		writeError(w, http.StatusConflict, "agent_chat_busy",
			fmt.Sprintf("已有 Run %d 在执行；同一控制台一次只允许一个 Run", active))
		return
	}
	c.chatMu.Unlock()

	key, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent_chat_failed", err.Error())
		return
	}
	config := agent.Config{
		Version: agent.Version, Endpoint: profile.Endpoint, Model: profile.Model,
		OutputParameter: cfg.outputParam, TimeoutSeconds: 60, MaxOutputTokens: 4096,
		MaxRequestBytes: 2 << 20, MaxResponseBytes: 512 << 10,
		EgressAllowed: true, EgressExpiresAt: time.Now().UTC().Add(chatEgressWindow),
	}
	if cfg.advisories != "" {
		config.AnalysisAdvisoryPath = cfg.advisories
	}
	if err := config.Validate(); err != nil {
		writeError(w, http.StatusConflict, "agent_chat_misconfigured", err.Error())
		return
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent_chat_failed", err.Error())
		return
	}
	run, err := c.agentWrite.CreateAgentRun(r.Context(), c.agentSession, store.CreateAgentRunParams{
		Key: "web-" + key, SnapshotPath: c.currentSnapshotDir(), SnapshotHash: snapshot.Hash(),
		Goal: goal, Config: encoded,
		Limits:   domainLimits(modelCalls, toolCalls, maxTokens),
		Deadline: config.EgressExpiresAt,
	})
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrDenied) {
			status = http.StatusForbidden
		}
		writeError(w, status, "agent_run_create_failed", err.Error())
		return
	}

	c.chatMu.Lock()
	c.chatActive = run.ID
	c.chatMu.Unlock()
	go c.executeChatRun(run.ID, config, snapshot.Hash(), profile.KeyEnv)

	writeJSON(w, http.StatusAccepted, chatResponse{
		SchemaVersion: SchemaVersion, RunID: run.ID, State: string(run.State), Goal: goal,
		Limits: map[string]int64{"model_calls": modelCalls, "tool_calls": toolCalls, "tokens": maxTokens},
	})
}

// profileLimit falls back to the built-in baseline when a profile carries no
// budget, so removing the per-run controls cannot accidentally produce zero.
func profileLimit(value, fallback int64) int64 {
	if value <= 0 {
		return fallback
	}
	return value
}

func clampInt(value, fallback, minimum, maximum int64) int64 {
	if value == 0 {
		return fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

// executeChatRun mirrors `trident agent run` but runs inside the console. It
// opens its own snapshot handle so a project switch cannot pull the source out
// from under a running analysis.
func (c *Console) executeChatRun(runID int64, config agent.Config, hash, keyEnv string) {
	defer func() {
		c.chatMu.Lock()
		if c.chatActive == runID {
			c.chatActive = 0
		}
		c.chatMu.Unlock()
	}()
	ctx := context.Background()
	snapshot, err := project.Open(ctx, c.currentSnapshotDirFor(runID), hash)
	if err != nil {
		c.recordChatError(runID, "打开快照失败："+err.Error())
		return
	}
	defer snapshot.Close()
	key := os.Getenv(keyEnv)
	if key == "" {
		c.recordChatError(runID, "模型密钥在运行期间不可用")
		return
	}
	client, err := openaiadapter.New(openaiadapter.Config{
		Endpoint: config.Endpoint, Model: config.Model, APIKey: key,
		Timeout:         time.Duration(config.TimeoutSeconds) * time.Second,
		MaxRequestBytes: config.MaxRequestBytes, MaxResponseBytes: config.MaxResponseBytes,
		OutputParameter: openaiadapter.OutputParameter(config.OutputParameter),
	})
	if err != nil {
		c.recordChatError(runID, "模型客户端初始化失败："+err.Error())
		return
	}
	defer client.CloseIdleConnections()
	registry := tools.NewWithAnalysis(snapshot, tools.AnalysisOptions{AdvisoryPath: config.AnalysisAdvisoryPath})
	runner, err := c.agentWrite.AcquireAgentRunner(ctx, c.agentSession, runID)
	if err != nil {
		c.recordChatError(runID, "获取 Run 执行权失败："+err.Error())
		return
	}
	defer runner.Close()
	if _, err := agent.Execute(ctx, runner, client, registry, false); err != nil {
		// The loop already committed its own terminal reason; this only surfaces
		// setup-level failures that never reached a step.
		c.recordChatError(runID, err.Error())
	}
}

// recordChatError keeps the last in-process failure so the page can explain a
// run that never produced steps.
func (c *Console) recordChatError(runID int64, message string) {
	c.chatMu.Lock()
	defer c.chatMu.Unlock()
	c.chatError = fmt.Sprintf("Run %d: %s", runID, message)
}

func (c *Console) chatErrorSnapshot() string {
	c.chatMu.Lock()
	defer c.chatMu.Unlock()
	return c.chatError
}

func domainLimits(modelCalls, toolCalls, maxTokens int64) domain.AgentLimits {
	return domain.AgentLimits{MaxModelCalls: modelCalls, MaxToolCalls: toolCalls, MaxTokens: maxTokens, MaxStoredBytes: 32 << 20}
}

// currentSnapshotDirFor returns the snapshot directory recorded for a run.
func (c *Console) currentSnapshotDirFor(runID int64) string {
	if run, err := c.agentWrite.GetAgentRun(context.Background(), c.agentSession, runID); err == nil {
		return run.SnapshotPath
	}
	return c.currentSnapshotDir()
}

type chatThread struct {
	ID           int64  `json:"id"`
	Goal         string `json:"goal"`
	State        string `json:"state"`
	Reason       string `json:"reason,omitempty"`
	ModelCalls   int64  `json:"model_calls"`
	ToolCalls    int64  `json:"tool_calls"`
	TokensUsed   int64  `json:"tokens_used"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	SnapshotHash string `json:"snapshot_hash"`
}

// handleAgentThreads lists runs for one snapshot hash so each project only sees
// its own conversations.
func (c *Console) handleAgentThreads(w http.ResponseWriter, r *http.Request) {
	if c.agentStore == nil {
		writeError(w, http.StatusPreconditionFailed, "agent_database_missing",
			"start the console with --agent-dsn to observe Agent runs")
		return
	}
	hash := strings.TrimSpace(r.URL.Query().Get("hash"))
	if hash == "" {
		hash = c.SnapshotHash()
	}
	runs, err := c.agentStore.ListAgentRunsReadOnly(r.Context(), 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent_query_failed", err.Error())
		return
	}
	threads := make([]chatThread, 0, len(runs))
	for _, run := range runs {
		if hash != "" && run.SnapshotHash != hash {
			continue
		}
		threads = append(threads, chatThread{
			ID: run.ID, Goal: run.Goal, State: string(run.State), Reason: run.Reason,
			ModelCalls: run.ModelCalls, ToolCalls: run.ToolCalls, TokensUsed: run.TokensUsed,
			CreatedAt: run.CreatedAt.Format(time.RFC3339), UpdatedAt: run.UpdatedAt.Format(time.RFC3339),
			SnapshotHash: run.SnapshotHash,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion, "total": len(threads), "threads": threads,
		"active_run": c.chatActiveRun(),
	})
}

// handleAgentChatCancel abandons the in-flight run at the transport level. The
// durable record keeps whatever steps were already committed; a cancelled run is
// reported as unknown by the agent loop, which is the honest state.
func (c *Console) handleAgentChatCancel(w http.ResponseWriter, r *http.Request) {
	runID, err := strconv.ParseInt(r.URL.Query().Get("run_id"), 10, 64)
	if err != nil || runID < 1 {
		writeError(w, http.StatusBadRequest, "invalid_request", "run_id 必须是正整数")
		return
	}
	c.chatMu.Lock()
	active := c.chatActive
	c.chatMu.Unlock()
	if active != runID {
		writeError(w, http.StatusConflict, "agent_chat_not_active", "该 Run 不是当前执行中的 Run")
		return
	}
	writeError(w, http.StatusNotImplemented, "cancel_unsupported",
		"当前版本不支持中途取消：Run 会执行到预算或完成；如需终止请关闭控制台进程")
}
