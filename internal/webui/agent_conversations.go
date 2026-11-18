package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trident/internal/domain"
	"trident/internal/store"
)

// conversationTitle keeps the rail readable without letting a long goal exceed
// the database's 512-byte title bound.
func conversationTitle(goal string) string {
	goal = strings.TrimSpace(goal)
	if i := strings.IndexAny(goal, "\r\n"); i >= 0 {
		goal = strings.TrimSpace(goal[:i])
	}
	if goal == "" {
		return "未命名会话"
	}
	const max = 512
	if len([]byte(goal)) <= max {
		return goal
	}
	limit := max - len([]byte("…"))
	var out strings.Builder
	used := 0
	for _, r := range goal {
		width := len([]byte(string(r)))
		if used+width > limit {
			break
		}
		out.WriteRune(r)
		used += width
	}
	return out.String() + "…"
}

func conversationMode(raw string) string {
	if strings.TrimSpace(raw) == string(domain.ConversationOrchestrate) {
		return string(domain.ConversationOrchestrate)
	}
	return string(domain.ConversationChat)
}

// ensureConversation returns an existing owner-scoped conversation or creates
// one for this snapshot. A supplied conversation id is rejected if it belongs
// to another snapshot: grouping across project snapshots would leak history.
func (c *Console) ensureConversation(ctx context.Context, conversationID int64, snapshotHash, goal, mode string) (domain.AgentConversation, error) {
	if c.agentWrite == nil {
		return domain.AgentConversation{}, store.ErrDenied
	}
	if conversationID > 0 {
		conversation, err := c.agentWrite.GetConversation(ctx, c.agentSession, conversationID)
		if err != nil {
			return domain.AgentConversation{}, err
		}
		if conversation.SnapshotHash != snapshotHash {
			return domain.AgentConversation{}, store.ErrDenied
		}
		return conversation, nil
	}
	key, err := randomToken()
	if err != nil {
		return domain.AgentConversation{}, err
	}
	return c.agentWrite.CreateConversation(ctx, c.agentSession, store.CreateConversationParams{
		Key:          "web-conv-" + key,
		SnapshotHash: snapshotHash,
		Title:        conversationTitle(goal),
		Mode:         conversationMode(mode),
	})
}

type conversationRunView struct {
	ID         int64  `json:"id"`
	Goal       string `json:"goal"`
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
	ModelCalls int64  `json:"model_calls"`
	ToolCalls  int64  `json:"tool_calls"`
	TokensUsed int64  `json:"tokens_used"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

type conversationTaskView struct {
	ID               int64  `json:"id"`
	Title            string `json:"title"`
	Goal             string `json:"goal"`
	State            string `json:"state"`
	Reason           string `json:"reason,omitempty"`
	PlannerRounds    int    `json:"planner_rounds"`
	MaxPlannerRounds int    `json:"max_planner_rounds"`
	IntentsSpawned   int    `json:"intents_spawned"`
	MaxIntents       int    `json:"max_intents"`
	MaxWorkers       int    `json:"max_workers"`
	Deadline         string `json:"deadline"`
	CreatedAt        string `json:"created_at"`
}

func (c *Console) handleAgentConversations(w http.ResponseWriter, r *http.Request) {
	if c.agentWrite == nil {
		writeError(w, http.StatusConflict, "agent_database_missing",
			"会话库未启用：在「设置 → Agent 与编排」里填写连接串与主体令牌并保存")
		return
	}
	hash := strings.TrimSpace(r.URL.Query().Get("hash"))
	if hash == "all" {
		hash = ""
	}
	items, err := c.agentWrite.ListConversations(r.Context(), c.agentSession, hash, 100)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrDenied) {
			status = http.StatusBadRequest
		}
		writeError(w, status, "conversation_query_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion,
		"total":          len(items),
		"conversations":  items,
		"active_run":     c.chatActiveRun(),
		"active_task":    c.orchEngine.ActiveTask(),
	})
}

type conversationRenameRequest struct {
	ID    int64  `json:"id"`
	Title string `json:"title"`
}

func (c *Console) handleAgentConversationRename(w http.ResponseWriter, r *http.Request) {
	if c.agentWrite == nil {
		writeError(w, http.StatusConflict, "agent_database_missing",
			"会话库未启用：在「设置 → Agent 与编排」里填写连接串与主体令牌并保存")
		return
	}
	body := http.MaxBytesReader(w, r.Body, 16<<10)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request conversationRenameRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求不是合法 JSON")
		return
	}
	if request.ID < 1 || strings.TrimSpace(request.Title) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id 必须是正整数且标题不能为空")
		return
	}
	conversation, err := c.agentWrite.UpdateConversationTitle(r.Context(), c.agentSession, request.ID, request.Title)
	if err != nil {
		status := http.StatusInternalServerError
		code := "conversation_rename_failed"
		if errors.Is(err, store.ErrDenied) {
			status, code = http.StatusNotFound, "conversation_not_found"
		}
		writeError(w, status, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion,
		"conversation":   conversation,
	})
}

func (c *Console) handleAgentConversationDetail(w http.ResponseWriter, r *http.Request) {
	if c.agentWrite == nil {
		writeError(w, http.StatusConflict, "agent_database_missing",
			"会话库未启用：在「设置 → Agent 与编排」里填写连接串与主体令牌并保存")
		return
	}
	conversationID, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || conversationID < 1 {
		writeError(w, http.StatusBadRequest, "invalid_request", "id 必须是正整数")
		return
	}
	conversation, runs, tasks, err := c.agentWrite.ConversationDetail(r.Context(), c.agentSession, conversationID)
	if err != nil {
		if errors.Is(err, store.ErrDenied) {
			writeError(w, http.StatusNotFound, "conversation_not_found", "没有该会话")
			return
		}
		writeError(w, http.StatusInternalServerError, "conversation_query_failed", err.Error())
		return
	}
	runViews := make([]conversationRunView, 0, len(runs))
	for _, run := range runs {
		runViews = append(runViews, conversationRunView{
			ID: run.ID, Goal: run.Goal, State: string(run.State), Reason: run.Reason,
			ModelCalls: run.ModelCalls, ToolCalls: run.ToolCalls, TokensUsed: run.TokensUsed,
			CreatedAt: run.CreatedAt.Format(time.RFC3339), UpdatedAt: run.UpdatedAt.Format(time.RFC3339),
		})
	}
	taskViews := make([]conversationTaskView, 0, len(tasks))
	for _, task := range tasks {
		taskViews = append(taskViews, conversationTaskView{
			ID: task.ID, Title: task.Title, Goal: task.Goal, State: string(task.State), Reason: task.Reason,
			PlannerRounds: task.PlannerRounds, MaxPlannerRounds: task.MaxPlannerRounds,
			IntentsSpawned: task.IntentsSpawned, MaxIntents: task.MaxIntents, MaxWorkers: task.MaxWorkers,
			Deadline: task.Deadline.Format(time.RFC3339), CreatedAt: task.CreatedAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion,
		"conversation":   conversation,
		"runs":           runViews,
		"tasks":          taskViews,
	})
}
