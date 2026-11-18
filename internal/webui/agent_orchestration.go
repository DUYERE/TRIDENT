package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trident/internal/domain"
	"trident/internal/orchestrator"
	"trident/internal/store"
)

// Orchestration limits mirror the chat path so a browser request can never buy
// an unbounded exploration.
const (
	orchestrationMaxRounds      = 12
	orchestrationMaxIntents     = 24
	orchestrationMaxWorkers     = 4
	orchestrationDefaultRounds  = 6
	orchestrationDefaultIntents = 12
	orchestrationDefaultWorkers = 2
	orchestrationDeadline       = 30 * time.Minute
)

type orchestrationCreateRequest struct {
	Title          string `json:"title"`
	Goal           string `json:"goal"`
	ApproveEgress  bool   `json:"approve_egress"`
	ProfileID      string `json:"profile_id"`
	ConversationID int64  `json:"conversation_id"`
	MaxRounds      int64  `json:"max_planner_rounds"`
	MaxIntents     int64  `json:"max_intents"`
	MaxWorkers     int64  `json:"max_workers"`
	DeadlineMin    int64  `json:"deadline_minutes"`
	MaxModelCalls  int64  `json:"max_model_calls"`
	MaxToolCalls   int64  `json:"max_tool_calls"`
	MaxTokens      int64  `json:"max_tokens"`
}

// handleOrchestrationCreate starts one orchestration task for the current
// snapshot. Creation and engine startup are one step from the browser's view;
// egress approval semantics match the single-run chat exactly.
func (c *Console) handleOrchestrationCreate(w http.ResponseWriter, r *http.Request) {
	if c.agentWrite == nil || c.orchEngine == nil {
		writeError(w, http.StatusConflict, "orchestration_disabled",
			"编排未启用：在「设置 → Agent 与编排」里打开开关，填写会话库连接串与主体令牌并保存（立即生效，无需重启）")
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
	var request orchestrationCreateRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求不是合法 JSON")
		return
	}
	title := strings.TrimSpace(request.Title)
	goal := strings.TrimSpace(request.Goal)
	if title == "" || len(title) > 512 {
		writeError(w, http.StatusBadRequest, "invalid_request", "标题不能为空且不超过 512 字节")
		return
	}
	if goal == "" || len(goal) > 16384 {
		writeError(w, http.StatusBadRequest, "invalid_request", "目标不能为空且不超过 16384 字节")
		return
	}
	if !request.ApproveEgress {
		writeError(w, http.StatusPreconditionFailed, "egress_not_approved",
			"需要显式批准外发：快照与目标会被发送到已配置的模型端点（每个编排会话一次独立调用）")
		return
	}
	// An explicit profile_id is a per-task override and applies to both roles.
	// Otherwise resolve the planner and worker slots independently.
	planner, worker := modelProfile{}, modelProfile{}
	plannerOK, workerOK := false, false
	if strings.TrimSpace(request.ProfileID) != "" {
		planner, plannerOK = c.profileByID(request.ProfileID)
		worker, workerOK = planner, plannerOK
	} else {
		planner, plannerOK = c.profileForRole(rolePlanner)
		worker, workerOK = c.profileForRole(roleWorker)
	}
	if !plannerOK || !workerOK {
		writeError(w, http.StatusBadRequest, "profile_unknown", "模型库中没有该配置")
		return
	}
	roleKeys := map[string]string{}
	for _, item := range []struct {
		role    string
		profile modelProfile
	}{{rolePlanner, planner}, {roleWorker, worker}} {
		key, _ := c.profileKey(item.profile)
		if key == "" {
			writeError(w, http.StatusConflict, "agent_model_key_missing",
				fmt.Sprintf("%s（%s）的模型密钥未配置：在「设置 → 模型」里填写 API Key（立即生效），或设置环境变量 %s 后重启",
					roleNames[item.role], item.profile.Label, item.profile.KeyEnv))
			return
		}
		roleKeys[item.role] = key
		if !runtimeAPIs[item.profile.API] {
			writeError(w, http.StatusConflict, "model_protocol_unsupported",
				fmt.Sprintf("%s（%s）声明的协议 %s 当前没有适配器；控制台只实现 OpenAI Chat Completions",
					roleNames[item.role], item.profile.Label, item.profile.API))
			return
		}
	}
	if c.chatActiveRun() != 0 {
		writeError(w, http.StatusConflict, "agent_chat_busy", "已有手动 Run 在执行；编排与手动 Run 互斥，等它结束再启动")
		return
	}
	if c.orchEngine.ActiveTask() != 0 {
		writeError(w, http.StatusConflict, "orchestration_busy",
			fmt.Sprintf("已有编排任务 %d 在运行；同一控制台一次只允许一个编排任务", c.orchEngine.ActiveTask()))
		return
	}
	rounds := clampInt(request.MaxRounds, orchestrationDefaultRounds, 1, orchestrationMaxRounds)
	intents := clampInt(request.MaxIntents, orchestrationDefaultIntents, 1, orchestrationMaxIntents)
	workers := clampInt(request.MaxWorkers, orchestrationDefaultWorkers, 1, orchestrationMaxWorkers)
	deadlineMinutes := clampInt(request.DeadlineMin, 30, 5, 240)
	modelCalls := clampInt(request.MaxModelCalls, profileLimit(planner.Defaults.ModelCalls, chatDefaultModelCalls), 1, 64)
	toolCalls := clampInt(request.MaxToolCalls, profileLimit(worker.Defaults.ToolCalls, chatDefaultToolCalls), 1, 256)
	maxTokens := clampInt(request.MaxTokens, profileLimit(worker.Defaults.Tokens, chatDefaultTokens), 4096, ChatMaxTokens)
	config := store.OrchestrationTaskConfig{
		PlannerProfileID: planner.ID, WorkerProfileID: worker.ID,
		MaxModelCalls: modelCalls, MaxToolCalls: toolCalls, MaxTokens: maxTokens,
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "orchestration_failed", err.Error())
		return
	}
	conversation, err := c.ensureConversation(r.Context(), request.ConversationID, snapshot.Hash(), title, string(domain.ConversationOrchestrate))
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
		writeError(w, http.StatusInternalServerError, "orchestration_failed", err.Error())
		return
	}
	task, err := c.agentWrite.CreateOrchestrationTask(r.Context(), c.agentSession, store.CreateOrchestrationTaskParams{
		Key: "web-orch-" + key, SnapshotPath: c.currentSnapshotDir(), SnapshotHash: snapshot.Hash(),
		Title: title, Goal: goal, Config: encoded,
		MaxPlannerRounds: int(rounds), MaxIntents: int(intents), MaxWorkers: int(workers),
		Deadline: time.Now().UTC().Add(time.Duration(deadlineMinutes) * time.Minute),
	})
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrDenied) {
			status = http.StatusForbidden
		}
		writeError(w, status, "orchestration_create_failed", err.Error())
		return
	}
	if err := c.agentWrite.LinkConversationTask(r.Context(), c.agentSession, conversation.ID, task.ID); err != nil {
		_, _ = c.agentWrite.TransitionOrchestrationTask(context.Background(), c.agentSession, task.ID,
			domain.OrchestrationCreated, domain.OrchestrationFailed, "会话关联失败："+err.Error())
		writeError(w, http.StatusInternalServerError, "conversation_link_failed", err.Error())
		return
	}
	outputParam := c.chatState().outputParam
	bindingOf := func(profile modelProfile, key string) orchestrator.SessionBinding {
		return orchestrator.SessionBinding{
			Endpoint: profile.Endpoint, Model: profile.Model, KeyEnv: profile.KeyEnv,
			APIKey: key, OutputParameter: outputParam, TimeoutSeconds: 60,
			MaxModelCalls: modelCalls, MaxToolCalls: toolCalls, MaxTokens: maxTokens,
		}
	}
	params := orchestrator.Params{
		TaskID: task.ID, SnapshotDir: c.currentSnapshotDir(), SnapshotHash: snapshot.Hash(),
		Binding: bindingOf(planner, roleKeys[rolePlanner]), Settlement: true, Advisories: c.chatState().advisories,
	}
	if worker.ID != planner.ID || worker.Endpoint != planner.Endpoint || worker.Model != planner.Model {
		workerBinding := bindingOf(worker, roleKeys[roleWorker])
		params.WorkerBinding = &workerBinding
	}
	err = c.orchEngine.Start(r.Context(), params)
	if err != nil {
		_, _ = c.agentWrite.TransitionOrchestrationTask(context.Background(), c.agentSession, task.ID,
			domain.OrchestrationCreated, domain.OrchestrationFailed, err.Error())
		if errors.Is(err, store.ErrOrchestrationBusy) {
			writeError(w, http.StatusConflict, "orchestration_busy",
				"数据库中已有该主体正在运行的编排任务（数据库级单任务约束）；先停止那个任务或等它结束")
			return
		}
		writeError(w, http.StatusConflict, "orchestration_start_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"schema_version": SchemaVersion, "task_id": task.ID, "conversation_id": conversation.ID, "state": string(task.State),
		"limits": map[string]int64{"planner_rounds": rounds, "intents": intents, "workers": workers,
			"model_calls": modelCalls, "tool_calls": toolCalls, "tokens": maxTokens},
	})
}

func (c *Console) handleOrchestrationList(w http.ResponseWriter, r *http.Request) {
	if c.agentWrite == nil {
		writeError(w, http.StatusConflict, "orchestration_disabled",
			"编排未启用：在「设置 → Agent 与编排」里打开开关并填写会话库连接串与主体令牌，保存后立即生效（无需重启）")
		return
	}
	tasks, err := c.agentWrite.ListOrchestrationTasks(r.Context(), c.agentSession, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "orchestration_query_failed", err.Error())
		return
	}
	items := make([]map[string]any, 0, len(tasks))
	for _, task := range tasks {
		items = append(items, map[string]any{
			"id": task.ID, "title": task.Title, "state": string(task.State), "reason": task.Reason,
			"goal": task.Goal, "snapshot_hash": task.SnapshotHash,
			"planner_rounds": task.PlannerRounds, "intents_spawned": task.IntentsSpawned,
			"max_planner_rounds": task.MaxPlannerRounds, "max_intents": task.MaxIntents,
			"deadline": task.Deadline.Format(time.RFC3339), "created_at": task.CreatedAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion, "total": len(items), "tasks": items,
		"active_task": c.orchEngine.ActiveTask(), "active_run": c.chatActiveRun(),
	})
}

func (c *Console) handleOrchestrationDetail(w http.ResponseWriter, r *http.Request) {
	if c.agentWrite == nil {
		writeError(w, http.StatusConflict, "orchestration_disabled",
			"编排未启用：在「设置 → Agent 与编排」里打开开关并填写会话库连接串与主体令牌，保存后立即生效（无需重启）")
		return
	}
	taskID, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || taskID < 1 {
		writeError(w, http.StatusBadRequest, "invalid_request", "id 必须是正整数")
		return
	}
	task, err := c.agentWrite.GetOrchestrationTask(r.Context(), c.agentSession, taskID)
	if err != nil {
		writeError(w, http.StatusNotFound, "orchestration_missing", err.Error())
		return
	}
	graph, err := c.agentWrite.OrchestrationGraph(r.Context(), c.agentSession, taskID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "orchestration_query_failed", err.Error())
		return
	}
	conversationID, _ := c.agentWrite.ConversationIDForTask(r.Context(), c.agentSession, taskID)
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion,
		"task": map[string]any{
			"id": task.ID, "title": task.Title, "goal": task.Goal, "state": string(task.State),
			"reason": task.Reason, "snapshot_hash": task.SnapshotHash,
			"planner_rounds": task.PlannerRounds, "intents_spawned": task.IntentsSpawned,
			"max_planner_rounds": task.MaxPlannerRounds, "max_intents": task.MaxIntents, "max_workers": task.MaxWorkers,
			"conversation_id": conversationID,
			"deadline":        task.Deadline.Format(time.RFC3339), "created_at": task.CreatedAt.Format(time.RFC3339),
		},
		"nodes": graph.Nodes, "edges": graph.Edges, "constraints": graph.Constraints,
	})
}

// steerAllowedState reports whether a task can still consume human steering.
// Created and running tasks can; terminal tasks cannot.
func steerAllowedState(state domain.OrchestrationState) bool {
	return state == domain.OrchestrationCreated || state == domain.OrchestrationRunning
}

type orchestrationSteerRequest struct {
	TaskID int64  `json:"task_id"`
	Kind   string `json:"kind"`
	Text   string `json:"text"`
}

// handleOrchestrationSteer implements the MainAgent steering verbs: a strategic
// hint, a direct intent, a new goal, or an operation constraint. Hints and
// direct intents both become open intent nodes whose payload records the human
// source; the engine picks them up on the next dispatch round.
func (c *Console) handleOrchestrationSteer(w http.ResponseWriter, r *http.Request) {
	if c.agentWrite == nil {
		writeError(w, http.StatusConflict, "orchestration_disabled",
			"编排未启用：在「设置 → Agent 与编排」里打开开关并填写会话库连接串与主体令牌，保存后立即生效（无需重启）")
		return
	}
	body := http.MaxBytesReader(w, r.Body, 16<<10)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request orchestrationSteerRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求不是合法 JSON")
		return
	}
	taskID, kind, text := request.TaskID, strings.ToLower(strings.TrimSpace(request.Kind)), strings.TrimSpace(request.Text)
	if taskID < 1 || (kind != "hint" && kind != "intent" && kind != "goal" && kind != "constraint") {
		writeError(w, http.StatusBadRequest, "invalid_request", "kind 必须是 hint/intent/goal/constraint")
		return
	}
	if text == "" || len(text) > 2048 {
		writeError(w, http.StatusBadRequest, "invalid_request", "text 不能为空且不超过 2048 字节")
		return
	}
	// Steering only makes sense while a task can still be driven. Without this
	// check a finished task accepts new goal/intent nodes that no planner will
	// ever read, leaving orphan rows in the graph.
	task, err := c.agentWrite.GetOrchestrationTask(r.Context(), c.agentSession, taskID)
	if err != nil {
		if errors.Is(err, store.ErrOrchestrationMissing) {
			writeError(w, http.StatusNotFound, "orchestration_task_missing", "任务不存在或不属于当前主体")
			return
		}
		writeError(w, http.StatusInternalServerError, "orchestration_query_failed", err.Error())
		return
	}
	if !steerAllowedState(task.State) {
		writeError(w, http.StatusConflict, "orchestration_steer_rejected",
			fmt.Sprintf("任务 %d 已处于 %s，不再接受新的 hint/intent/goal/constraint", taskID, task.State))
		return
	}
	switch kind {
	case "hint", "intent":
		node, err := c.agentWrite.AddOrchestrationNode(r.Context(), c.agentSession, taskID, store.AddOrchestrationNodeParams{
			Kind: domain.OrchNodeIntent, State: domain.OrchNodeOpen, Summary: text,
			Payload: mustJSONRaw(map[string]any{"type": "user_" + kind, "source": "human"}),
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "orchestration_steer_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"schema_version": SchemaVersion, "node_id": node.ID, "state": string(node.State)})
	case "goal":
		node, err := c.agentWrite.AddOrchestrationNode(r.Context(), c.agentSession, taskID, store.AddOrchestrationNodeParams{
			Kind: domain.OrchNodeGoal, State: domain.OrchNodeOpen, Summary: text,
			Payload: mustJSONRaw(map[string]any{"source": "human"}),
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "orchestration_steer_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"schema_version": SchemaVersion, "node_id": node.ID, "state": string(node.State)})
	case "constraint":
		kindField := "allow"
		if strings.HasPrefix(strings.ToLower(text), "禁止") || strings.HasPrefix(strings.ToLower(text), "deny") {
			kindField = "deny"
		}
		constraint, err := c.agentWrite.AddOrchestrationConstraint(r.Context(), c.agentSession, taskID, kindField, text)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "orchestration_steer_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"schema_version": SchemaVersion, "constraint_id": constraint.ID, "kind": constraint.Kind})
	}
}

func (c *Console) handleOrchestrationStop(w http.ResponseWriter, r *http.Request) {
	if c.agentWrite == nil || c.orchEngine == nil {
		writeError(w, http.StatusConflict, "orchestration_disabled", "Agent 写库会话未初始化")
		return
	}
	taskID, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || taskID < 1 {
		writeError(w, http.StatusBadRequest, "invalid_request", "id 必须是正整数")
		return
	}
	if !c.orchEngine.Stop(taskID) {
		writeError(w, http.StatusConflict, "orchestration_not_running", "该任务不是当前执行中的编排任务")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"schema_version": SchemaVersion, "stopped": taskID})
}

func mustJSONRaw(value map[string]any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}
