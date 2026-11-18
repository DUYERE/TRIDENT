package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"trident/internal/store"
)

const agentQuickVersion = "agent_runtime_quick_setup_v1"

// quickProbeResult is internal only. Token is never serialized; quickProbe may
// be replaced in tests so offline acceptance never needs a live database.
type quickProbeResult struct {
	DSNOK          bool
	PrincipalFound bool
	Role           string
	Token          string
	Reason         string
}

type agentQuickStatus struct {
	SchemaVersion  int    `json:"schema_version"`
	Version        string `json:"version"`
	Enabled        bool   `json:"enabled"`
	Ready          bool   `json:"ready"`
	DSNFound       bool   `json:"dsn_found"`
	DSNTarget      string `json:"dsn_target,omitempty"`
	DSNOK          bool   `json:"dsn_ok"`
	PrincipalFound bool   `json:"principal_found"`
	PrincipalRole  string `json:"principal_role,omitempty"`
	ModelReady     bool   `json:"model_ready"`
	CanEnable      bool   `json:"can_enable"`
	Reason         string `json:"reason,omitempty"`
}

// quickCandidates only reads configuration that already exists on this machine.
// It never invents a DSN, never starts a database and never creates a principal.
func (c *Console) quickCandidates() (string, []string) {
	c.cfgMu.Lock()
	dsn := strings.TrimSpace(c.storedAgentDSN)
	storedToken := strings.TrimSpace(c.storedAgentToken)
	c.cfgMu.Unlock()
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("TRIDENT_DATABASE_URL"))
	}
	tokens := make([]string, 0, 4)
	seen := make(map[string]bool)
	add := func(token string) {
		if !validPrincipalToken(token) || seen[token] {
			return
		}
		seen[token] = true
		tokens = append(tokens, token)
	}
	add(storedToken)
	if c.workspace != "" {
		roots := []string{filepath.Join(c.workspace, "secrets")}
		if parent := filepath.Dir(c.workspace); parent != c.workspace {
			roots = append(roots, filepath.Join(parent, "secrets"))
		}
		for _, root := range roots {
			entries, err := os.ReadDir(root)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
					continue
				}
				data, err := os.ReadFile(filepath.Join(root, entry.Name()))
				if err != nil {
					continue
				}
				var payload struct {
					Token string `json:"token"`
				}
				if json.Unmarshal(data, &payload) == nil {
					add(strings.TrimSpace(payload.Token))
				}
			}
		}
	}
	return dsn, tokens
}

func validPrincipalToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	return !strings.ContainsFunc(token, func(r rune) bool { return r < 0x21 || r == 0x7f })
}

// liveQuickProbe verifies candidates against the real database. Errors are
// reported with fixed wording so no connection string or credential leaks into
// a browser response.
func liveQuickProbe(ctx context.Context, dsn string, tokens []string) quickProbeResult {
	if strings.TrimSpace(dsn) == "" {
		return quickProbeResult{Reason: "未发现会话库连接串：展开「高级设置」填写一次，或先用 --agent-dsn 保存一次"}
	}
	writable, err := store.Open(ctx, dsn, false)
	if err != nil {
		return quickProbeResult{Reason: "会话库连接失败：确认数据库容器在运行、连接串正确"}
	}
	defer writable.Close()
	if len(tokens) == 0 {
		return quickProbeResult{DSNOK: true, Reason: "本机未找到主体令牌文件：展开「高级设置」粘贴令牌，或先执行 bootstrap 生成"}
	}
	for _, token := range tokens {
		session, err := writable.Authenticate(ctx, token)
		if err != nil {
			continue
		}
		info, err := writable.DescribePrincipal(ctx, session)
		if err != nil {
			continue
		}
		if info.Status != "active" || info.Kind != "human" || (info.Role != "admin" && info.Role != "scheduler") {
			continue
		}
		return quickProbeResult{DSNOK: true, PrincipalFound: true, Role: info.Role, Token: token}
	}
	return quickProbeResult{DSNOK: true, Reason: "本机令牌均无效或不具备创建 Run 权限（需要 active / human / admin 或 scheduler）"}
}

func (c *Console) probeQuick(ctx context.Context, dsn string, tokens []string) quickProbeResult {
	if c.quickProbe != nil {
		return c.quickProbe(ctx, dsn, tokens)
	}
	return liveQuickProbe(ctx, dsn, tokens)
}

func (c *Console) agentQuickStatus(ctx context.Context, dsn string, tokens []string) agentQuickStatus {
	probe := c.probeQuick(ctx, dsn, tokens)
	status := c.agentRuntimeStatus()
	return agentQuickStatus{
		SchemaVersion:  SchemaVersion,
		Version:        agentQuickVersion,
		Enabled:        status.Enabled,
		Ready:          status.Ready,
		DSNFound:       dsn != "",
		DSNTarget:      maskDSN(dsn),
		DSNOK:          probe.DSNOK,
		PrincipalFound: probe.PrincipalFound,
		PrincipalRole:  probe.Role,
		ModelReady:     status.ModelReady,
		CanEnable:      probe.DSNOK && probe.PrincipalFound && probe.Token != "",
		Reason:         probe.Reason,
	}
}

func (c *Console) handleAgentRuntimeQuick(w http.ResponseWriter, r *http.Request) {
	dsn, tokens := c.quickCandidates()
	writeJSON(w, http.StatusOK, c.agentQuickStatus(r.Context(), dsn, tokens))
}

// handleAgentRuntimeQuickEnable is a convenience wrapper: it discovers what is
// already on this machine and submits it through the exact same validation and
// persistence path as the manual form.
func (c *Console) handleAgentRuntimeQuickEnable(w http.ResponseWriter, r *http.Request) {
	if c.workspace == "" {
		writeError(w, http.StatusConflict, "pinned_console", "固定快照模式不支持快速启用")
		return
	}
	if c.chatActiveRun() != 0 || (c.orchEngine != nil && c.orchEngine.ActiveTask() != 0) {
		writeError(w, http.StatusConflict, "agent_busy", "有 Run 或编排任务正在执行；等它结束或先停止再改运行时配置")
		return
	}
	dsn, tokens := c.quickCandidates()
	probe := c.probeQuick(r.Context(), dsn, tokens)
	if !probe.DSNOK || !probe.PrincipalFound || probe.Token == "" {
		reason := probe.Reason
		if reason == "" {
			reason = "未发现可用的会话库连接串与主体令牌"
		}
		writeError(w, http.StatusPreconditionFailed, "agent_quick_unavailable", reason)
		return
	}
	enabled := true
	c.applyAgentRuntimeRequest(w, r, agentRuntimeRequest{Enabled: &enabled, DSN: dsn, Token: probe.Token})
}
