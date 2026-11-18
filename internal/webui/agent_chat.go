package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trident/internal/agent"
	"trident/internal/caseagent"
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
		key, keySource := c.profileKey(profile)
		profiles = append(profiles, map[string]any{
			"id": profile.ID, "label": profile.Label, "model": profile.Model,
			"endpoint": profile.Endpoint, "key_present": key != "", "key_source": keySource,
			"default": profile.ID == file.Roles.Main,
			"api":     profile.API, "capabilities": profile.Capabilities, "cost": profile.Cost,
			"roles": profileRoleRefs(file, profile.ID),
			"defaults": map[string]int64{
				"model_calls": profile.Defaults.ModelCalls,
				"tool_calls":  profile.Defaults.ToolCalls,
				"tokens":      profile.Defaults.Tokens,
			},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version":   SchemaVersion,
		"profiles":         profiles,
		"default_profile":  file.Default,
		"roles":            file.Roles,
		"resolved":         resolveRoles(file),
		"enabled":          cfg.enabled,
		"reason":           cfg.reason,
		"endpoint":         cfg.endpoint,
		"model":            cfg.model,
		"key_present":      cfg.enabled && c.mainKeyPresent(),
		"repair_available": strings.TrimSpace(c.workspace) != "",
		"active_run":       active,
		"last_error":       c.chatErrorSnapshot(),
		"running":          active > 0,
		"max_model_calls":  ChatMaxModelCalls,
		"max_tool_calls":   ChatMaxToolCalls,
		"max_tokens":       ChatMaxTokens,
		"defaults": map[string]any{
			"model_calls": chatDefaultModelCalls,
			"tool_calls":  chatDefaultToolCalls,
			"tokens":      chatDefaultTokens,
		},
	})
}

// mainKeyPresent reports whether the resolved main role has a usable key,
// regardless of whether it came from the workspace file or the environment.
func (c *Console) mainKeyPresent() bool {
	profile, ok := c.profileForRole(roleMain)
	if !ok {
		return false
	}
	key, _ := c.profileKey(profile)
	return key != ""
}

func (c *Console) chatActiveRun() int64 {
	c.chatMu.Lock()
	defer c.chatMu.Unlock()
	return c.chatActive
}

type chatRequest struct {
	Goal           string `json:"goal"`
	ApproveEgress  bool   `json:"approve_egress"`
	ApproveRepair  bool   `json:"approve_repair"`
	ProfileID      string `json:"profile_id"`
	ConversationID int64  `json:"conversation_id"`
	MaxModelCalls  int64  `json:"max_model_calls"`
	MaxToolCalls   int64  `json:"max_tool_calls"`
	MaxTokens      int64  `json:"max_tokens"`
}

type chatResponse struct {
	SchemaVersion  int              `json:"schema_version"`
	RunID          int64            `json:"run_id"`
	ConversationID int64            `json:"conversation_id"`
	State          string           `json:"state"`
	Goal           string           `json:"goal"`
	RepairEnabled  bool             `json:"repair_enabled"`
	Limits         map[string]int64 `json:"limits"`
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
		writeError(w, http.StatusConflict, "agent_chat_disabled", "对话未启用：在「设置 → Agent 与编排」里打开开关并填写会话库与主体令牌")
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
	if request.ApproveRepair && strings.TrimSpace(c.workspace) == "" {
		writeError(w, http.StatusPreconditionFailed, "repair_workspace_unavailable",
			"修复批准需要一个可写的 workspace；当前控制台是只读快照模式，未暴露 Case 工作副本")
		return
	}
	profile, found := c.profileByID(request.ProfileID)
	if request.ProfileID == "" {
		// No explicit override: resolve the main role, not the raw default, so
		// role assignment and follow-main stay authoritative.
		profile, found = c.profileForRole(roleMain)
	}
	if !found {
		writeError(w, http.StatusBadRequest, "profile_unknown", "模型库中没有该配置")
		return
	}
	apiKey, keySource := c.profileKey(profile)
	if apiKey == "" {
		writeError(w, http.StatusConflict, "agent_model_key_missing",
			fmt.Sprintf("模型密钥未配置：在「设置 → 模型」里填写 API Key（立即生效），或设置环境变量 %s 后重启", profile.KeyEnv))
		return
	}
	_ = keySource
	if !runtimeAPIs[profile.API] {
		writeError(w, http.StatusConflict, "model_protocol_unsupported",
			fmt.Sprintf("条目「%s」声明的协议 %s 当前没有适配器；控制台只实现 OpenAI Chat Completions，请改成兼容端点或在网关侧转换", profile.Label, profile.API))
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
	if c.orchEngine != nil && c.orchEngine.ActiveTask() != 0 {
		writeError(w, http.StatusConflict, "orchestration_busy",
			fmt.Sprintf("编排任务 %d 正在运行；编排与手动 Run 互斥，等它结束或先停止任务", c.orchEngine.ActiveTask()))
		return
	}

	conversation, err := c.ensureConversation(r.Context(), request.ConversationID, snapshot.Hash(), goal, string(domain.ConversationChat))
	if err != nil {
		if errors.Is(err, store.ErrDenied) {
			writeError(w, http.StatusNotFound, "conversation_not_found", "没有该会话，或会话属于其它项目快照")
			return
		}
		writeError(w, http.StatusInternalServerError, "conversation_create_failed", err.Error())
		return
	}

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
		RepairEnabled: request.ApproveRepair,
	}
	config.PriorContext = c.priorContextForConversation(r.Context(), conversation.ID)
	live := c.currentConfig()
	if live.AdvisoryPath != "" {
		config.AnalysisAdvisoryPath = live.AdvisoryPath
	} else if cfg.advisories != "" {
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
	if err := c.agentWrite.LinkConversationRun(r.Context(), c.agentSession, conversation.ID, run.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "conversation_link_failed", err.Error())
		return
	}

	c.chatMu.Lock()
	c.chatActive = run.ID
	c.chatMu.Unlock()
	go c.executeChatRun(run.ID, config, snapshot.Hash(), apiKey)

	writeJSON(w, http.StatusAccepted, chatResponse{
		SchemaVersion: SchemaVersion, RunID: run.ID, ConversationID: conversation.ID, State: string(run.State), Goal: goal,
		RepairEnabled: request.ApproveRepair,
		Limits:        map[string]int64{"model_calls": modelCalls, "tool_calls": toolCalls, "tokens": maxTokens},
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

// priorContextForConversation keeps continuity between Runs without treating
// earlier model output as fresh evidence or approval. A lookup failure degrades
// to an empty context; it never blocks the current Run.
func (c *Console) priorContextForConversation(ctx context.Context, conversationID int64) string {
	if conversationID == 0 || c.agentWrite == nil {
		return ""
	}
	_, runs, _, err := c.agentWrite.ConversationDetail(ctx, c.agentSession, conversationID)
	if err != nil {
		return ""
	}
	return agent.PriorContext(runs, agent.MaxPriorContextBytes)
}

// executeChatRun mirrors `trident agent run` but runs inside the console. It
// opens its own snapshot handle so a project switch cannot pull the source out
// from under a running analysis.
func (c *Console) executeChatRun(runID int64, config agent.Config, hash, apiKey string) {
	defer func() {
		c.chatMu.Lock()
		if c.chatActive == runID {
			c.chatActive = 0
		}
		c.chatMu.Unlock()
	}()
	ctx := context.Background()
	snapshotDir := c.currentSnapshotDirFor(runID)
	snapshot, err := project.Open(ctx, snapshotDir, hash)
	if err != nil {
		c.recordChatError(runID, "打开快照失败："+err.Error())
		return
	}
	defer snapshot.Close()
	if apiKey == "" {
		c.recordChatError(runID, "模型密钥在运行开始前不可用")
		return
	}
	client, err := openaiadapter.New(openaiadapter.Config{
		Endpoint: config.Endpoint, Model: config.Model, APIKey: apiKey,
		Timeout:         time.Duration(config.TimeoutSeconds) * time.Second,
		MaxRequestBytes: config.MaxRequestBytes, MaxResponseBytes: config.MaxResponseBytes,
		OutputParameter: openaiadapter.OutputParameter(config.OutputParameter),
	})
	if err != nil {
		c.recordChatError(runID, "模型客户端初始化失败："+err.Error())
		return
	}
	defer client.CloseIdleConnections()
	// A repair proposal asks the same provider for a complete unified diff, which
	// can legitimately take longer than the chat turn's short timeout. Keep the
	// probe and tool loop on the ordinary client, but give the nested proposal
	// request a bounded longer window.
	repairClient := client
	if config.RepairEnabled {
		repairClient, err = openaiadapter.New(openaiadapter.Config{
			Endpoint: config.Endpoint, Model: config.Model, APIKey: apiKey,
			Timeout:         180 * time.Second,
			MaxRequestBytes: config.MaxRequestBytes, MaxResponseBytes: config.MaxResponseBytes,
			OutputParameter: openaiadapter.OutputParameter(config.OutputParameter),
		})
		if err != nil {
			c.recordChatError(runID, "修复模型客户端初始化失败："+err.Error())
			return
		}
		defer repairClient.CloseIdleConnections()
	}
	// Bind the console's cached multi-language report so the Agent quotes the
	// same findings the user sees on the findings page instead of re-deriving
	// them. A failed or pending lazy audit just falls back to the Java view.
	// Advisory configuration is read from the live console config, not the
	// startup copy, so a settings change applies to the next chat run.
	liveConfig := c.currentConfig()
	analysisOptions := tools.AnalysisOptions{AdvisoryPath: liveConfig.AdvisoryPath, AdvisoryDir: liveConfig.AdvisoryDir}
	if codeReport, _, codeErr := c.codeAudit(ctx); codeErr == nil {
		analysisOptions.CodeReport = &codeReport
	}
	registry := tools.NewWithAnalysis(snapshot, analysisOptions)
	var runRegistry agent.ToolRegistry = registry
	if config.RepairEnabled {
		repairRegistry, repairErr := caseagent.New(caseagent.Options{
			Base: registry, Snapshot: snapshot, SnapshotDir: snapshotDir,
			Workspace: c.workspace, Catalog: c.cases, Approve: true,
			Client: repairClient, Model: config.Model, MaxOutput: caseagent.DefaultMaxOutputTokens,
		})
		if repairErr != nil {
			c.recordChatError(runID, "修复工具初始化失败："+repairErr.Error())
			return
		}
		runRegistry = repairRegistry
	}
	runner, err := c.agentWrite.AcquireAgentRunner(ctx, c.agentSession, runID)
	if err != nil {
		c.recordChatError(runID, "获取 Run 执行权失败："+err.Error())
		return
	}
	defer runner.Close()
	if _, err := agent.Execute(ctx, runner, client, runRegistry, false); err != nil {
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
		c.agentStoreMu.Lock()
		connectError := c.agentConnectError
		c.agentStoreMu.Unlock()
		if connectError != "" {
			writeError(w, http.StatusServiceUnavailable, "agent_database_unreachable",
				connectError+"；修复连接后在设置页重新保存会话库即可，历史记录仍在数据库中")
			return
		}
		writeError(w, http.StatusPreconditionFailed, "agent_database_missing",
			"未连接 Agent 会话库：在「设置 → Agent 与编排」填写会话库连接串并保存即可立即接入，无需重启；历史记录仍保存在数据库中")
		return
	}
	hash := strings.TrimSpace(r.URL.Query().Get("hash"))
	showAll := hash == "all"
	if hash == "" || showAll {
		hash = c.SnapshotHash()
	}
	runs, err := c.agentStore.ListAgentRunsReadOnly(r.Context(), 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent_query_failed", err.Error())
		return
	}
	threads := make([]chatThread, 0, len(runs))
	for _, run := range runs {
		if !showAll && hash != "" && run.SnapshotHash != hash {
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
