package webui

import (
	"net/http"
	"net/url"
	"strings"

	"trident/internal/orchestrator"
	"trident/internal/store"
)

// Agent runtime settings cover the three things that used to require restarting
// the console: enabling chat/orchestration, the session database DSN and the
// write principal token. They are validated against the real database before
// being persisted, applied immediately, and never returned to the browser.
type agentRuntimeStatus struct {
	SchemaVersion int    `json:"schema_version"`
	Enabled       bool   `json:"enabled"`
	Ready         bool   `json:"ready"`
	Reason        string `json:"reason,omitempty"`
	DSNStored     bool   `json:"dsn_stored"`
	DSNTarget     string `json:"dsn_target,omitempty"`
	TokenStored   bool   `json:"token_stored"`
	ActiveRun     int64  `json:"active_run"`
	ActiveTask    int64  `json:"active_task"`
	ModelReady    bool   `json:"model_ready"`
}

func (c *Console) agentRuntimeStatus() agentRuntimeStatus {
	c.cfgMu.Lock()
	enabled := c.agentChatEnabled
	dsn := c.storedAgentDSN
	tokenStored := c.storedAgentToken != ""
	c.cfgMu.Unlock()
	status := agentRuntimeStatus{
		SchemaVersion: SchemaVersion,
		Enabled:       enabled,
		DSNStored:     dsn != "",
		DSNTarget:     maskDSN(dsn),
		TokenStored:   tokenStored,
		ActiveRun:     c.chatActiveRun(),
	}
	if engine := c.orchEngine; engine != nil {
		status.ActiveTask = engine.ActiveTask()
	}
	cfg := c.chatState()
	status.Ready = enabled && c.agentWrite != nil && cfg.enabled
	if !status.Ready {
		status.Reason = firstNonEmpty(cfg.reason, "未启用")
	}
	if profile, ok := c.profileForRole(roleMain); ok {
		key, _ := c.profileKey(profile)
		status.ModelReady = key != ""
	}
	return status
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// maskDSN keeps host and database visible for recognition but never the user,
// password or query string.
func maskDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Hostname() == "" {
		return "已保存"
	}
	target := parsed.Host
	if name := strings.TrimPrefix(parsed.Path, "/"); name != "" {
		target += "/" + name
	}
	return target
}

func (c *Console) handleAgentRuntime(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, c.agentRuntimeStatus())
}

type agentRuntimeRequest struct {
	Enabled    *bool  `json:"enabled"`
	DSN        string `json:"dsn"`
	Token      string `json:"token"`
	ClearDSN   bool   `json:"clear_dsn"`
	ClearToken bool   `json:"clear_token"`
}

// handleAgentRuntimeUpdate applies the runtime connection settings. Every
// mutation is validated first; a bad DSN or token never replaces a working one.
func (c *Console) handleAgentRuntimeUpdate(w http.ResponseWriter, r *http.Request) {
	var request agentRuntimeRequest
	if err := decodeSmallJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	c.applyAgentRuntimeRequest(w, r, request)
}

// applyAgentRuntimeRequest is the single validation, persistence and hot-swap
// path shared by the manual form and one-click quick setup. A caller must not
// pre-approve anything: the DSN and token are re-validated against the real
// database here.
func (c *Console) applyAgentRuntimeRequest(w http.ResponseWriter, r *http.Request, request agentRuntimeRequest) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "固定快照模式不支持修改 Agent 运行时配置")
		return
	}
	if c.chatActiveRun() != 0 || (c.orchEngine != nil && c.orchEngine.ActiveTask() != 0) {
		writeError(w, http.StatusConflict, "agent_busy", "有 Run 或编排任务正在执行；等它结束或先停止再改运行时配置")
		return
	}

	c.cfgMu.Lock()
	enabled := c.agentChatEnabled
	dsn := c.storedAgentDSN
	token := c.storedAgentToken
	c.cfgMu.Unlock()
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	if request.ClearDSN {
		dsn = ""
		enabled = false
	}
	if request.ClearToken {
		token = ""
		enabled = false
	}
	if strings.TrimSpace(request.DSN) != "" {
		dsn = strings.TrimSpace(request.DSN)
	}
	if strings.TrimSpace(request.Token) != "" {
		token = strings.TrimSpace(request.Token)
	}
	if enabled && dsn == "" {
		writeError(w, http.StatusBadRequest, "agent_dsn_missing", "启用前需要填写 Agent 会话库连接串")
		return
	}
	if enabled && token == "" {
		writeError(w, http.StatusBadRequest, "agent_token_missing", "启用前需要填写具备创建 Run 权限的主体令牌")
		return
	}
	if len(token) > 512 || strings.ContainsFunc(token, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
		writeError(w, http.StatusBadRequest, "agent_token_invalid", "主体令牌格式不合法")
		return
	}

	// Validate the write connection before persisting anything. A newly typed
	// token is verified even when the switch is off, so "已保存" never means
	// "stored but already invalid".
	var pendingWrite *store.Store
	var pendingSession store.Session
	newToken := strings.TrimSpace(request.Token) != ""
	if dsn != "" && token != "" && (enabled || newToken) {
		writable, err := store.Open(r.Context(), dsn, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, "agent_dsn_invalid", "Agent 会话库连接失败："+err.Error())
			return
		}
		session, authErr := writable.Authenticate(r.Context(), token)
		if authErr != nil {
			writable.Close()
			writeError(w, http.StatusBadRequest, "agent_token_invalid", "Agent 令牌无效或已撤销")
			return
		}
		if enabled {
			pendingWrite, pendingSession = writable, session
		} else {
			writable.Close()
		}
	}

	file, err := loadWorkspaceConfig(c.workspace)
	if err != nil {
		if pendingWrite != nil {
			pendingWrite.Close()
		}
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}
	file.AgentDSN = dsn
	file.AgentToken = token
	file.AgentChatEnabled = enabled
	if err := saveWorkspaceConfig(c.workspace, file); err != nil {
		if pendingWrite != nil {
			pendingWrite.Close()
		}
		writeError(w, http.StatusInternalServerError, "workspace_error", err.Error())
		return
	}

	c.installAgentRuntime(enabled, dsn, token, pendingWrite, pendingSession)
	if enabled || dsn != "" {
		// The observation store follows the same DSN so the Agent page can read
		// history immediately. A failure here is reported but not fatal.
		if observation, obsErr := store.Open(r.Context(), dsn, false); obsErr == nil {
			c.swapAgentStore(observation)
		} else {
			c.agentStoreMu.Lock()
			c.agentConnectError = "打开 Agent 会话库失败：" + obsErr.Error()
			c.agentStoreMu.Unlock()
		}
	} else {
		c.swapAgentStore(nil)
	}
	writeJSON(w, http.StatusOK, c.agentRuntimeStatus())
}

// installAgentRuntime swaps the write store and orchestration engine. Callers
// must have verified that no run or task is active.
func (c *Console) installAgentRuntime(enabled bool, dsn, token string, writable *store.Store, session store.Session) {
	c.cfgMu.Lock()
	previous := c.agentWrite
	c.storedAgentDSN = dsn
	c.storedAgentToken = token
	c.agentChatEnabled = enabled
	c.chat.enabled = enabled
	if enabled {
		c.chat.reason = ""
	} else {
		c.chat.reason = "未启用：在「设置 → Agent 与编排」里开启（无需重启）"
	}
	c.cfgMu.Unlock()
	if previous != nil {
		previous.Close()
	}
	if !enabled {
		c.agentWrite = nil
		c.agentSession = store.Session{}
		c.orchEngine = nil
		return
	}
	c.agentWrite = writable
	c.agentSession = session
	c.orchEngine = orchestrator.New(writable, session)
}
