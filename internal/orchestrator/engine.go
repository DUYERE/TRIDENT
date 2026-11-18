// Package orchestrator drives the multi-agent exploration loop defined in
// docs/agent-orchestration-contract.md. It owns the exploration graph writes:
// planner and worker LLM sessions run as ordinary governed agent_runs with the
// same read-only tool surface, and their terminal envelopes reach the graph
// only after this engine parses and validates them. Nothing here upgrades a
// candidate to a confirmed finding, and runtime verification stays not_run.
package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"trident/internal/agent"
	"trident/internal/domain"
	openaiadapter "trident/internal/model/openai"
	"trident/internal/project"
	"trident/internal/store"
	"trident/internal/tools"
)

// SessionBinding is the resolved model profile shared by planner and worker
// sessions. The key is resolved from the environment per run, exactly like the
// console chat path, and is never stored.
type SessionBinding struct {
	Endpoint string
	Model    string
	KeyEnv   string
	// APIKey is the key resolved at task start (workspace file or environment).
	// It is kept in memory only and never written to the run config or graph.
	APIKey          string
	OutputParameter string
	MaxModelCalls   int64
	MaxToolCalls    int64
	MaxTokens       int64
	TimeoutSeconds  int64
}

// Params bundles everything the engine needs to drive one task. The engine runs
// inside the console process and borrows the console's write session.
type Params struct {
	TaskID       int64
	SnapshotDir  string
	SnapshotHash string
	// Binding is the planner role; WorkerBinding optionally carries a different
	// resolved worker endpoint. Nil means both roles share Binding.
	Binding       SessionBinding
	WorkerBinding *SessionBinding
	Settlement    bool
	Advisories    string
	// Planning marks the caller as a planner round: its session has no tools and
	// may explain with evidence already pinned on the graph.
	Planning bool
}

// graphStore is the exploration-graph persistence surface the engine needs.
// The production implementation is *store.Store; tests use an in-memory fake
// with the same CAS semantics.
type graphStore interface {
	GetOrchestrationTask(ctx context.Context, session store.Session, taskID int64) (domain.OrchestrationTask, error)
	TransitionOrchestrationTask(ctx context.Context, session store.Session, taskID int64, from, to domain.OrchestrationState, reason string) (domain.OrchestrationTask, error)
	BumpOrchestrationCounters(ctx context.Context, session store.Session, taskID int64, plannerRounds, intents int) error
	AddOrchestrationNode(ctx context.Context, session store.Session, taskID int64, params store.AddOrchestrationNodeParams) (domain.OrchestrationNode, error)
	UpdateOrchestrationNodeState(ctx context.Context, session store.Session, taskID int64, nodeID int64, to domain.OrchestrationNodeState) error
	AddOrchestrationEdge(ctx context.Context, session store.Session, taskID int64, fromID int64, rel domain.OrchestrationEdgeRel, toID int64) error
	OrchestrationGraph(ctx context.Context, session store.Session, taskID int64) (store.OrchestrationGraph, error)
}

// sessionRunner drives one planner/worker LLM session to a terminal envelope.
// The live implementation opens the pinned snapshot and runs a governed
// agent_runs loop; tests script envelopes directly so the orchestration
// mechanics are verifiable without a database or model.
type sessionRunner interface {
	runSession(ctx context.Context, params Params, binding SessionBinding, task domain.OrchestrationTask, key, goal string) (domain.AgentRun, *agent.FinalEnvelope, string, error)
}

// Engine runs one orchestration task at a time inside this process. The mutex
// guards this process only; cross-instance exclusivity is enforced by the
// database (migration 006: one 'running' task per principal), which Start
// claims synchronously before any work is scheduled.
type Engine struct {
	graph      graphStore
	sessions   sessionRunner
	session    store.Session
	mu         sync.Mutex
	activeTask int64
	cancel     context.CancelFunc
	running    bool
}

func New(st *store.Store, session store.Session) *Engine {
	return &Engine{graph: st, sessions: &liveSessionDriver{store: st, session: session}, session: session}
}

func (e *Engine) ActiveTask() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.activeTask
}

func (e *Engine) Start(parent context.Context, params Params) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return fmt.Errorf("orchestration busy: task %d is running", e.activeTask)
	}
	e.running = true
	e.activeTask = params.TaskID
	// The driver outlives the HTTP request that created it: the console calls
	// Start with r.Context(), and that context is canceled as soon as the 202
	// response is written. WithoutCancel keeps values while detaching from the
	// caller's cancellation; Stop() still cancels through e.cancel.
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	e.cancel = cancel
	e.mu.Unlock()
	// Claim created→running in the database before scheduling the goroutine.
	// The unique index on running tasks makes a second console's Start fail
	// deterministically instead of running a parallel driver for the same
	// principal; the refusal is surfaced to the caller, not swallowed.
	if _, err := e.graph.TransitionOrchestrationTask(ctx, e.session, params.TaskID,
		domain.OrchestrationCreated, domain.OrchestrationRunning, "engine started"); err != nil {
		e.mu.Lock()
		e.running = false
		e.activeTask = 0
		e.cancel = nil
		e.mu.Unlock()
		cancel()
		return fmt.Errorf("orchestration start refused: %w", err)
	}
	go func() {
		defer func() {
			e.mu.Lock()
			e.running = false
			e.activeTask = 0
			e.cancel = nil
			e.mu.Unlock()
		}()
		e.drive(ctx, params)
	}()
	return nil
}

func (e *Engine) Stop(taskID int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running || e.activeTask != taskID {
		return false
	}
	if e.cancel != nil {
		e.cancel()
	}
	return true
}

// orchestrationTaskConfig mirrors store.OrchestrationTaskConfig for decoding.
type orchestrationTaskConfig struct {
	PlannerProfileID string `json:"planner_profile_id"`
	WorkerProfileID  string `json:"worker_profile_id"`
	MaxModelCalls    int64  `json:"max_model_calls"`
	MaxToolCalls     int64  `json:"max_tool_calls"`
	MaxTokens        int64  `json:"max_tokens"`
}

// drive is the task's event loop. It is sequential by design: planner rounds
// run one at a time, workers of one round run concurrently and are awaited
// before the next planning round.
func (e *Engine) drive(ctx context.Context, params Params) {
	task, err := e.graph.GetOrchestrationTask(ctx, e.session, params.TaskID)
	if err != nil {
		return
	}
	var config orchestrationTaskConfig
	if err := json.Unmarshal(task.Config, &config); err != nil {
		e.finish(ctx, params, task, domain.OrchestrationFailed, "任务配置解析失败："+err.Error())
		return
	}
	// Start() claims created→running synchronously. A task that is still
	// 'created' here was driven directly (tests) or lost its claim; a task in
	// any other state must not be driven at all.
	if task.State == domain.OrchestrationCreated {
		if _, err := e.graph.TransitionOrchestrationTask(ctx, e.session, task.ID, domain.OrchestrationCreated, domain.OrchestrationRunning, "engine started"); err != nil {
			return
		}
		task.State = domain.OrchestrationRunning
	}
	if task.State != domain.OrchestrationRunning {
		return
	}
	goalNode, err := e.graph.AddOrchestrationNode(ctx, e.session, task.ID, store.AddOrchestrationNodeParams{
		Kind: domain.OrchNodeGoal, State: domain.OrchNodeOpen, Summary: truncateSummary(task.Goal, 2048),
	})
	if err != nil {
		e.finish(ctx, params, task, domain.OrchestrationFailed, "写目标节点失败："+err.Error())
		return
	}
	plannerBinding := params.Binding
	plannerBinding.MaxModelCalls = config.MaxModelCalls
	plannerBinding.MaxToolCalls = config.MaxToolCalls
	plannerBinding.MaxTokens = config.MaxTokens
	workerBinding := plannerBinding
	if params.WorkerBinding != nil {
		// A distinct worker endpoint is allowed: the two roles can resolve to
		// different model-library entries while sharing the task budget.
		workerBinding = *params.WorkerBinding
		workerBinding.MaxModelCalls = config.MaxModelCalls
		workerBinding.MaxToolCalls = config.MaxToolCalls
		workerBinding.MaxTokens = config.MaxTokens
	}

	var trigger string
	zeroRounds := 0
	completed := false
	reason := ""
	for round := 1; round <= task.MaxPlannerRounds; round++ {
		if ctx.Err() != nil {
			e.finish(ctx, params, task, domain.OrchestrationCancelled, "任务被停止")
			return
		}
		// Re-read the task every round: counters advance in the store while
		// this goroutine runs, and the intent-budget check below must see the
		// persisted values, not a stale copy.
		task, err = e.graph.GetOrchestrationTask(ctx, e.session, task.ID)
		if err != nil {
			e.finish(ctx, params, task, domain.OrchestrationFailed, "重读任务失败："+err.Error())
			return
		}
		graph, err := e.graph.OrchestrationGraph(ctx, e.session, task.ID)
		if err != nil {
			e.finish(ctx, params, task, domain.OrchestrationFailed, "读取探索图失败："+err.Error())
			return
		}
		if allGoalsMet(graph.Nodes) {
			completed, reason = true, "全部目标已判定达成"
			break
		}
		deadlineHit := !task.Deadline.IsZero() && !time.Now().Before(task.Deadline)
		if deadlineHit {
			completed, reason = true, "到达任务截止时间"
			break
		}
		// Intent budget exhaustion only means no new work can be dispatched. If
		// evidence-bearing records already exist, a planner round can still prove
		// the goal; ending here made every evidence-producing worker pointless
		// whenever the intent budget was reached first.
		if task.IntentsSpawned >= task.MaxIntents && countOpenIntents(graph.Nodes) == 0 && evidenceBearingRecords(graph.Nodes) == 0 {
			completed, reason = true, "意图预算已用尽且无未完成意图"
			break
		}
		if err := e.graph.BumpOrchestrationCounters(ctx, e.session, task.ID, 1, 0); err != nil {
			e.finish(ctx, params, task, domain.OrchestrationFailed, "任务计数推进失败："+err.Error())
			return
		}
		roundSummary, proved, err := e.plannerRound(ctx, params, plannerBinding, task, goalNode.ID, trigger, graph.Nodes, graph.Edges, graph.Constraints)
		if err != nil {
			// A failed planning round is not fatal: the graph is unchanged and
			// the next round retries with the same trigger. Record it.
			trigger = "上一轮规划失败：" + err.Error()
			if countRunningIntents(graph.Nodes) == 0 && round == task.MaxPlannerRounds {
				completed, reason = true, "规划轮次用尽（最后一轮失败："+err.Error()+"）"
				break
			}
			continue
		}
		if len(proved) > 0 && allGoalsMet(mustGraph(ctx, e, task.ID)) {
			completed, reason = true, "全部目标已判定达成"
			break
		}
		graph, err = e.graph.OrchestrationGraph(ctx, e.session, task.ID)
		if err != nil {
			e.finish(ctx, params, task, domain.OrchestrationFailed, "读取探索图失败："+err.Error())
			return
		}
		ready := pickReadyIntents(graph.Nodes, graph.Edges, task.MaxIntents)
		if len(ready) == 0 && countOpenIntents(graph.Nodes) == 0 {
			// One empty round is not enough to finish: a human steer (hint or
			// direct intent) can arrive between rounds, and the planner may
			// legitimately find nothing on the round right after a done wave.
			// Only two consecutive empty rounds with nothing in flight end the
			// task as "planner judged no uncovered direction".
			zeroRounds++
			if zeroRounds >= 2 {
				completed, reason = true, "规划者连续两轮判定无未覆盖方向且无未完成意图"
				break
			}
			trigger = roundSummary + "；等待操舵注入或复查态势（连续两轮判空才结束）"
			continue
		}
		zeroRounds = 0
		if len(ready) == 0 {
			trigger = "无新意图可派（新意图依赖在跑产出的前置）"
			continue
		}
		trigger = e.runWorkers(ctx, params, workerBinding, task, ready)
		if ctx.Err() != nil {
			e.finish(ctx, params, task, domain.OrchestrationCancelled, "任务被停止")
			return
		}
	}
	if !completed {
		completed, reason = true, "规划轮次用尽"
	}
	e.finish(ctx, params, task, domain.OrchestrationCompleted, reason)
}

func mustGraph(ctx context.Context, e *Engine, taskID int64) []domain.OrchestrationNode {
	graph, err := e.graph.OrchestrationGraph(ctx, e.session, taskID)
	if err != nil {
		return nil
	}
	return graph.Nodes
}

func (e *Engine) finish(ctx context.Context, params Params, task domain.OrchestrationTask, to domain.OrchestrationState, reason string) {
	_, _ = e.graph.TransitionOrchestrationTask(context.WithoutCancel(ctx), e.session, task.ID,
		domain.OrchestrationRunning, to, reason)
}

func allGoalsMet(nodes []domain.OrchestrationNode) bool {
	goals := 0
	for _, node := range nodes {
		if node.Kind == domain.OrchNodeGoal {
			goals++
			if node.State != domain.OrchNodeMet {
				return false
			}
		}
	}
	return goals > 0
}

func countOpenIntents(nodes []domain.OrchestrationNode) int {
	count := 0
	for _, node := range nodes {
		if node.Kind == domain.OrchNodeIntent && node.State == domain.OrchNodeOpen {
			count++
		}
	}
	return count
}

func countRunningIntents(nodes []domain.OrchestrationNode) int {
	count := 0
	for _, node := range nodes {
		if node.Kind == domain.OrchNodeIntent && node.State == domain.OrchNodeRunning {
			count++
		}
	}
	return count
}

// pickReadyIntents returns open intents whose task-level intent budget still
// allows dispatch, oldest first. Sorting happens here so determinism does not
// depend on the caller's node ordering.
func pickReadyIntents(nodes []domain.OrchestrationNode, edges []domain.OrchestrationEdge, maxIntents int) []domain.OrchestrationNode {
	ready := []domain.OrchestrationNode{}
	for _, node := range nodes {
		if node.Kind == domain.OrchNodeIntent && node.State == domain.OrchNodeOpen {
			ready = append(ready, node)
		}
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].ID < ready[j].ID })
	_ = edges
	if len(ready) > maxIntents {
		ready = ready[:maxIntents]
	}
	return ready
}

// plannerRound runs one planning session and writes its declarations to the
// graph. Trigger text is prepended so the planner looks at the actual change
// first, mirroring the reference implementation.
func (e *Engine) plannerRound(ctx context.Context, params Params, binding SessionBinding, task domain.OrchestrationTask, goalNodeID int64, trigger string, nodes []domain.OrchestrationNode, edges []domain.OrchestrationEdge, constraints []domain.OrchestrationConstraint) (string, []string, error) {
	goalText := buildPlannerGoal(task, trigger, nodes, edges, constraints)
	planningParams := params
	planningParams.Planning = true
	run, envelope, runState, err := e.sessions.runSession(ctx, planningParams, binding, task, fmt.Sprintf("orch-%d-planner-r%d", task.ID, task.PlannerRounds+1), goalText)
	if err != nil {
		return "", nil, err
	}
	proved := []string{}
	if envelope == nil {
		return runSummary(run, runState), proved, fmt.Errorf("会话未产出终局 JSON（%s）", runState)
	}
	// Goal verdicts are resolved against the graph, never against model text:
	// the reference must name a registered goal node, and the graph must already
	// hold at least one fact/candidate with pinned evidence. A planner sentence
	// alone cannot end the task as "达成".
	goals := goalNodeIndex(nodes)
	evidence := evidenceBearingRecords(nodes)
	refused := []string{}
	for _, goalID := range envelope.GoalProved {
		id, ok := agent.ParseGoalRef(goalID)
		if !ok {
			refused = append(refused, goalID+"（不是已登记的目标引用）")
			continue
		}
		if _, exists := goals[id]; !exists {
			refused = append(refused, goalID+"（图上没有这个目标节点）")
			continue
		}
		if evidence == 0 {
			refused = append(refused, goalID+"（图内没有任何带证据的记录）")
			continue
		}
		if err := e.graph.UpdateOrchestrationNodeState(ctx, e.session, task.ID, id, domain.OrchNodeMet); err != nil {
			refused = append(refused, goalID+"（状态写入失败）")
			continue
		}
		proved = append(proved, goalID)
	}
	summary := runSummary(run, runState)
	if len(refused) > 0 {
		summary += "；目标声明未采纳：" + strings.Join(refused, "；") + "。先派能产出证据的意图，再重新判定"
	}
	spawned := 0
	remaining := task.MaxIntents - task.IntentsSpawned
	if remaining < 0 {
		remaining = 0
	}
	for _, intent := range envelope.Intents {
		// max_intents is a task-level budget, not a per-round allowance: the
		// planner may return up to four intents per round, but the engine must
		// not write more nodes than the task still allows.
		if spawned >= remaining {
			break
		}
		node, err := e.graph.AddOrchestrationNode(ctx, e.session, task.ID, store.AddOrchestrationNodeParams{
			Kind: domain.OrchNodeIntent, State: domain.OrchNodeOpen,
			Summary: truncateSummary(intent.Summary, 2048),
			Payload: mustJSON(map[string]any{"asset_refs": intent.AssetRefs, "planner_run": run.ID}),
		})
		if err != nil {
			break
		}
		_ = e.graph.AddOrchestrationEdge(ctx, e.session, task.ID, goalNodeID, domain.OrchEdgeSpawns, node.ID)
		for _, parent := range intent.ParentIDs {
			_ = e.graph.AddOrchestrationEdge(ctx, e.session, task.ID, int64(parent), domain.OrchEdgeDerivedFrom, node.ID)
		}
		spawned++
	}
	if spawned > 0 {
		_ = e.graph.BumpOrchestrationCounters(ctx, e.session, task.ID, 0, spawned)
	}
	return summary, proved, nil
}

// goalNodeIndex resolves every goal node currently on the graph, including the
// ones a human steer injected, so a goal verdict is addressable by id.
func goalNodeIndex(nodes []domain.OrchestrationNode) map[int64]domain.OrchestrationNode {
	goals := map[int64]domain.OrchestrationNode{}
	for _, node := range nodes {
		if node.Kind == domain.OrchNodeGoal {
			goals[node.ID] = node
		}
	}
	return goals
}

// evidenceBearingRecords counts fact/candidate nodes that carry at least one
// pinned evidence reference. Goal proofs are refused while this is zero: an
// unattended planner declaration is self-attestation, not a result.
func evidenceBearingRecords(nodes []domain.OrchestrationNode) int {
	count := 0
	for _, node := range nodes {
		if node.Kind != domain.OrchNodeFact && node.Kind != domain.OrchNodeFindingCandidate {
			continue
		}
		var payload struct {
			Evidence []json.RawMessage `json:"evidence"`
		}
		if err := json.Unmarshal(node.Payload, &payload); err != nil {
			continue
		}
		if len(payload.Evidence) > 0 {
			count++
		}
	}
	return count
}

// runWorkers executes ready intents concurrently (bounded by the task config)
// and returns the trigger text for the next planning round.
func (e *Engine) runWorkers(ctx context.Context, params Params, binding SessionBinding, task domain.OrchestrationTask, ready []domain.OrchestrationNode) string {
	workers := task.MaxWorkers
	if workers < 1 {
		workers = 1
	}
	if workers > len(ready) {
		workers = len(ready)
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	triggers := []string{}
	for _, intent := range ready {
		if ctx.Err() != nil {
			break
		}
		_ = e.graph.UpdateOrchestrationNodeState(ctx, e.session, task.ID, intent.ID, domain.OrchNodeRunning)
		wg.Add(1)
		sem <- struct{}{}
		go func(intent domain.OrchestrationNode) {
			defer wg.Done()
			defer func() { <-sem }()
			trigger := e.workerRun(ctx, params, binding, task, intent)
			mu.Lock()
			triggers = append(triggers, trigger)
			mu.Unlock()
		}(intent)
	}
	wg.Wait()
	return strings.Join(triggers, "；")
}

func workerNodeState(runState string) domain.OrchestrationNodeState {
	switch runState {
	case string(domain.AgentRunBudgetExhausted):
		return domain.OrchNodeExhausted
	case string(domain.AgentRunFailed), string(domain.AgentRunUnknown), string(domain.AgentRunPaused):
		// unknown means the model attempt failed and the outcome is not assumed;
		// paused means the output was truncated. Neither may be recorded as done,
		// or an unfinished worker looks successful.
		return domain.OrchNodeBlocked
	case string(domain.AgentRunCancelled):
		return domain.OrchNodeCancelled
	default:
		return domain.OrchNodeDone
	}
}

func (e *Engine) workerRun(ctx context.Context, params Params, binding SessionBinding, task domain.OrchestrationTask, intent domain.OrchestrationNode) string {
	graph, err := e.graph.OrchestrationGraph(ctx, e.session, task.ID)
	if err != nil {
		_ = e.graph.UpdateOrchestrationNodeState(ctx, e.session, task.ID, intent.ID, domain.OrchNodeBlocked)
		return "意图 #" + fmtInt(intent.ID) + " 读取态势失败"
	}
	goalText := buildWorkerGoal(task, intent, graph.Nodes, graph.Edges, graph.Constraints)
	run, envelope, runState, err := e.sessions.runSession(ctx, params, binding, task, fmt.Sprintf("orch-%d-w%d", task.ID, intent.ID), goalText)
	if err != nil {
		_ = e.graph.UpdateOrchestrationNodeState(ctx, e.session, task.ID, intent.ID, domain.OrchNodeBlocked)
		return "意图 #" + fmtInt(intent.ID) + " 执行失败：" + err.Error()
	}
	state := workerNodeState(runState)
	if envelope == nil {
		_ = e.graph.UpdateOrchestrationNodeState(ctx, e.session, task.ID, intent.ID, state)
		return "意图 #" + fmtInt(intent.ID) + " 未产出终局 JSON（" + runState + "）"
	}
	written := 0
	seen := map[string]bool{}
	for _, fact := range envelope.Facts {
		node, err := e.graph.AddOrchestrationNode(ctx, e.session, task.ID, store.AddOrchestrationNodeParams{
			Kind: domain.OrchNodeFact, State: domain.OrchNodeDone,
			Summary: truncateSummary(fact.Summary, 2048), Confidence: fact.Confidence,
			Payload: mustJSON(map[string]any{"evidence": fact.Evidence, "run": run.ID}),
		})
		if err != nil {
			break
		}
		seen[fact.Summary] = true
		_ = e.graph.AddOrchestrationEdge(ctx, e.session, task.ID, intent.ID, domain.OrchEdgeYields, node.ID)
		written++
	}
	// The shared system prompt asks every session for hypotheses, so a worker
	// may answer there instead of in facts. A hypothesis is still an evidence-bearing
	// record; dropping it left the graph with zero evidence and made every goal
	// proof fail even after a successful worker run.
	for _, hypothesis := range envelope.Hypotheses {
		if len(hypothesis.Evidence) == 0 || seen[hypothesis.Statement] {
			continue
		}
		node, err := e.graph.AddOrchestrationNode(ctx, e.session, task.ID, store.AddOrchestrationNodeParams{
			Kind: domain.OrchNodeFact, State: domain.OrchNodeDone,
			Summary: truncateSummary(hypothesis.Statement, 2048), Confidence: "inferred",
			Payload: mustJSON(map[string]any{"evidence": hypothesis.Evidence, "run": run.ID, "source": "hypothesis"}),
		})
		if err != nil {
			break
		}
		_ = e.graph.AddOrchestrationEdge(ctx, e.session, task.ID, intent.ID, domain.OrchEdgeYields, node.ID)
		written++
	}
	for _, candidate := range envelope.Candidates {
		node, err := e.graph.AddOrchestrationNode(ctx, e.session, task.ID, store.AddOrchestrationNodeParams{
			Kind: domain.OrchNodeFindingCandidate, State: domain.OrchNodeOpen,
			Summary: truncateSummary(candidate.Title, 2048),
			Payload: mustJSON(map[string]any{"severity": candidate.Severity, "note": candidate.Note, "evidence": candidate.Evidence, "run": run.ID}),
		})
		if err != nil {
			break
		}
		_ = e.graph.AddOrchestrationEdge(ctx, e.session, task.ID, intent.ID, domain.OrchEdgeYields, node.ID)
		written++
	}
	_ = e.graph.UpdateOrchestrationNodeState(ctx, e.session, task.ID, intent.ID, state)
	return fmt.Sprintf("意图 #%d（%s）结束，状态 %s，写回 %d 条记录：%s", intent.ID, truncateSummary(intent.Summary, 120), state, written, truncateSummary(envelope.Summary, 300))
}

// finalEnvelopeFromStep accepts the shapes a run.completed step can carry.
// The agent loop commits the envelope itself as the step payload; older or
// wrapped producers put it under {"result": ...}. Both must parse, otherwise a
// completed planner run looks like "no final envelope" to the engine.
func finalEnvelopeFromStep(payload json.RawMessage) (*agent.FinalEnvelope, error) {
	var direct agent.FinalEnvelope
	if err := json.Unmarshal(payload, &direct); err == nil && strings.TrimSpace(direct.Summary) != "" {
		return &direct, nil
	}
	var wrapped struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(payload, &wrapped); err == nil && len(wrapped.Result) > 0 {
		var envelope agent.FinalEnvelope
		if err := json.Unmarshal(wrapped.Result, &envelope); err != nil {
			return nil, err
		}
		return &envelope, nil
	}
	return nil, errors.New("no final envelope in completed step")
}

func (d *liveSessionDriver) readFinal(ctx context.Context, runID int64) (*agent.FinalEnvelope, error) {
	steps, err := d.store.ListAgentRunSteps(ctx, d.session, runID, 0, 1000)
	if err != nil {
		return nil, err
	}
	for i := len(steps) - 1; i >= 0; i-- {
		if steps[i].Kind != domain.AgentStepCompleted {
			continue
		}
		return finalEnvelopeFromStep(steps[i].Payload)
	}
	return nil, errors.New("no completed step")
}

func runSummary(run domain.AgentRun, state string) string {
	return fmt.Sprintf("Run %d %s（模型调用 %d、工具调用 %d）", run.ID, state, run.ModelCalls, run.ToolCalls)
}

func truncateSummary(text string, limit int) string {
	trimmed := strings.TrimSpace(text)
	runes := []rune(trimmed)
	if len(runes) <= limit {
		return trimmed
	}
	return string(runes[:limit])
}

func mustJSON(value map[string]any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

func fmtInt(value int64) string {
	return fmt.Sprintf("%d", value)
}

// currentEnv reads an environment variable at call time; the value is never
// stored or logged.
func currentEnv(name string) string { return envValue(name) }

// liveSessionDriver is the production sessionRunner: it opens the pinned
// snapshot, builds the OpenAI client from the environment key at call time and
// drives one governed agent_runs loop per session.
type liveSessionDriver struct {
	store   *store.Store
	session store.Session
}

func (d *liveSessionDriver) runSession(ctx context.Context, params Params, binding SessionBinding, task domain.OrchestrationTask, key, goal string) (domain.AgentRun, *agent.FinalEnvelope, string, error) {
	snapshot, err := project.Open(ctx, params.SnapshotDir, params.SnapshotHash)
	if err != nil {
		return domain.AgentRun{}, nil, "", fmt.Errorf("打开快照失败: %w", err)
	}
	defer snapshot.Close()
	keyValue := binding.APIKey
	if keyValue == "" && binding.KeyEnv != "" {
		// Scripted tests and callers that still only carry the variable name fall
		// back to the environment.
		keyValue = envValue(binding.KeyEnv)
	}
	if keyValue == "" {
		return domain.AgentRun{}, nil, "", fmt.Errorf("模型密钥 %s 不可用", binding.KeyEnv)
	}
	client, err := openaiadapter.New(openaiadapter.Config{
		Endpoint: binding.Endpoint, Model: binding.Model, APIKey: keyValue,
		Timeout:         time.Duration(binding.TimeoutSeconds) * time.Second,
		MaxRequestBytes: 2 << 20, MaxResponseBytes: 512 << 10,
		OutputParameter: openaiadapter.OutputParameter(binding.OutputParameter),
	})
	if err != nil {
		return domain.AgentRun{}, nil, "", fmt.Errorf("模型客户端初始化失败: %w", err)
	}
	defer client.CloseIdleConnections()
	analysisOptions := tools.AnalysisOptions{AdvisoryPath: params.Advisories}
	registry := tools.NewWithAnalysis(snapshot, analysisOptions)
	config := agent.Config{
		Version: agent.Version, Endpoint: binding.Endpoint, Model: binding.Model,
		OutputParameter: binding.OutputParameter, TimeoutSeconds: binding.TimeoutSeconds,
		MaxOutputTokens: 8192, MaxRequestBytes: 2 << 20, MaxResponseBytes: 512 << 10,
		EgressAllowed:             true,
		EgressExpiresAt:           time.Now().UTC().Add(30 * time.Minute),
		SettlementEnabled:         params.Settlement,
		AllowUnobservedHypotheses: params.Planning,
	}
	if params.Advisories != "" {
		config.AnalysisAdvisoryPath = params.Advisories
	}
	if err := config.Validate(); err != nil {
		return domain.AgentRun{}, nil, "", fmt.Errorf("会话配置无效: %w", err)
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return domain.AgentRun{}, nil, "", err
	}
	run, err := d.store.CreateAgentRun(ctx, d.session, store.CreateAgentRunParams{
		Key: key, SnapshotPath: params.SnapshotDir, SnapshotHash: params.SnapshotHash,
		Goal: goal, Config: encoded,
		Limits: domain.AgentLimits{
			MaxModelCalls: binding.MaxModelCalls, MaxToolCalls: binding.MaxToolCalls,
			MaxTokens: binding.MaxTokens, MaxStoredBytes: 32 << 20,
		},
		Deadline: task.Deadline,
	})
	if err != nil {
		return domain.AgentRun{}, nil, "", fmt.Errorf("创建会话失败: %w", err)
	}
	runner, err := d.store.AcquireAgentRunner(ctx, d.session, run.ID)
	if err != nil {
		return run, nil, string(run.State), fmt.Errorf("获取执行权失败: %w", err)
	}
	defer runner.Close()
	finalRun, execErr := agent.Execute(ctx, runner, client, registry, false)
	if finalRun.State != domain.AgentRunCompleted {
		return finalRun, nil, string(finalRun.State), nil
	}
	envelope, err := d.readFinal(ctx, finalRun.ID)
	if err != nil {
		return finalRun, nil, string(finalRun.State), nil
	}
	_ = execErr
	return finalRun, envelope, string(finalRun.State), nil
}
