package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"trident/internal/agent"
	"trident/internal/domain"
	"trident/internal/store"
	"trident/internal/tools"
)

// fakeGraph mirrors the store's orchestration semantics in memory: CAS state
// transitions, append-only nodes/edges and per-task counters. It lets the whole
// drive() loop be exercised without a database.
type fakeGraph struct {
	mu            sync.Mutex
	task          domain.OrchestrationTask
	nodes         []domain.OrchestrationNode
	edges         []domain.OrchestrationEdge
	nextID        int64
	transitionErr error
}

func newFakeGraph(task domain.OrchestrationTask) *fakeGraph {
	task.ID = 1
	task.State = domain.OrchestrationCreated
	return &fakeGraph{task: task, nextID: 0}
}

func (f *fakeGraph) GetOrchestrationTask(ctx context.Context, _ store.Session, taskID int64) (domain.OrchestrationTask, error) {
	if err := ctx.Err(); err != nil {
		return domain.OrchestrationTask{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if taskID != f.task.ID {
		return domain.OrchestrationTask{}, store.ErrOrchestrationMissing
	}
	return f.task, nil
}

func (f *fakeGraph) TransitionOrchestrationTask(_ context.Context, _ store.Session, taskID int64, from, to domain.OrchestrationState, reason string) (domain.OrchestrationTask, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.transitionErr != nil {
		return domain.OrchestrationTask{}, f.transitionErr
	}
	if taskID != f.task.ID || f.task.State != from {
		return domain.OrchestrationTask{}, store.ErrOrchestrationState
	}
	f.task.State = to
	f.task.Reason = reason
	return f.task, nil
}

func (f *fakeGraph) BumpOrchestrationCounters(_ context.Context, _ store.Session, taskID int64, plannerRounds, intents int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if taskID != f.task.ID || f.task.State != domain.OrchestrationRunning {
		return store.ErrOrchestrationState
	}
	f.task.PlannerRounds += plannerRounds
	f.task.IntentsSpawned += intents
	return nil
}

func (f *fakeGraph) AddOrchestrationNode(_ context.Context, _ store.Session, taskID int64, params store.AddOrchestrationNodeParams) (domain.OrchestrationNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if taskID != f.task.ID {
		return domain.OrchestrationNode{}, store.ErrOrchestrationMissing
	}
	f.nextID++
	node := domain.OrchestrationNode{
		ID: f.nextID, TaskID: taskID, Kind: params.Kind, State: params.State,
		Summary: params.Summary, Confidence: params.Confidence, Payload: params.Payload,
	}
	f.nodes = append(f.nodes, node)
	return node, nil
}

func (f *fakeGraph) UpdateOrchestrationNodeState(_ context.Context, _ store.Session, taskID, nodeID int64, to domain.OrchestrationNodeState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if taskID != f.task.ID {
		return store.ErrOrchestrationMissing
	}
	for i := range f.nodes {
		if f.nodes[i].ID == nodeID {
			f.nodes[i].State = to
			return nil
		}
	}
	return store.ErrOrchestrationMissing
}

func (f *fakeGraph) AddOrchestrationEdge(_ context.Context, _ store.Session, taskID int64, fromID int64, rel domain.OrchestrationEdgeRel, toID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if taskID != f.task.ID {
		return store.ErrOrchestrationMissing
	}
	f.edges = append(f.edges, domain.OrchestrationEdge{FromID: fromID, Rel: rel, ToID: toID})
	return nil
}

func (f *fakeGraph) OrchestrationGraph(_ context.Context, _ store.Session, taskID int64) (store.OrchestrationGraph, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if taskID != f.task.ID {
		return store.OrchestrationGraph{}, store.ErrOrchestrationMissing
	}
	nodes := append([]domain.OrchestrationNode(nil), f.nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	return store.OrchestrationGraph{Nodes: nodes, Edges: append([]domain.OrchestrationEdge(nil), f.edges...)}, nil
}

func (f *fakeGraph) snapshot() ([]domain.OrchestrationNode, []domain.OrchestrationEdge, domain.OrchestrationTask) {
	f.mu.Lock()
	defer f.mu.Unlock()
	nodes := append([]domain.OrchestrationNode(nil), f.nodes...)
	edges := append([]domain.OrchestrationEdge(nil), f.edges...)
	return nodes, edges, f.task
}

// scriptedSessions returns pre-arranged terminal envelopes per session key so
// the drive loop's graph mechanics are fully verifiable without a model.
type scriptedSessions struct {
	mu       sync.Mutex
	calls    []string
	bindings map[string]SessionBinding
	byKey    map[string]scriptedOutcome
	onCall   func(key string)
}

type scriptedOutcome struct {
	envelope *agent.FinalEnvelope
	state    string
	err      error
}

func newScriptedSessions() *scriptedSessions {
	return &scriptedSessions{byKey: map[string]scriptedOutcome{}, bindings: map[string]SessionBinding{}}
}

func (s *scriptedSessions) put(key string, outcome scriptedOutcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKey[key] = outcome
}

func (s *scriptedSessions) runSession(_ context.Context, _ Params, binding SessionBinding, _ domain.OrchestrationTask, key, goal string) (domain.AgentRun, *agent.FinalEnvelope, string, error) {
	s.mu.Lock()
	s.calls = append(s.calls, key)
	s.bindings[key] = binding
	hook := s.onCall
	outcome, ok := s.byKey[key]
	s.mu.Unlock()
	if hook != nil {
		hook(key)
	}
	if !ok {
		return domain.AgentRun{ID: int64(len(s.calls)), State: domain.AgentRunFailed}, nil, "failed", fmt.Errorf("no scripted outcome for %s", key)
	}
	if outcome.err != nil {
		return domain.AgentRun{ID: int64(len(s.calls)), State: domain.AgentRunFailed}, nil, outcome.state, outcome.err
	}
	return domain.AgentRun{ID: int64(len(s.calls)), State: domain.AgentRunCompleted}, outcome.envelope, outcome.state, nil
}

func (s *scriptedSessions) callCount(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, key := range s.calls {
		if strings.HasPrefix(key, prefix) {
			count++
		}
	}
	return count
}

func envelope(summary string, intents []agent.PlannedIntent, facts []agent.ReportedFact, candidates []agent.ReportedCandidate, proved ...string) *agent.FinalEnvelope {
	return &agent.FinalEnvelope{
		Summary: summary, Hypotheses: []agent.Hypothesis{}, Limitations: []string{"static only"},
		Intents: intents, GoalProved: proved, Facts: facts, Candidates: candidates,
	}
}

func factNodeSummary(summary, confidence string) agent.ReportedFact {
	return agent.ReportedFact{Summary: summary, Confidence: confidence}
}

// evidenceFact is a worker record that carries pinned evidence. The goal gate
// only accepts a "proved" declaration when at least one such record exists.
func evidenceFact(summary, confidence string) agent.ReportedFact {
	return agent.ReportedFact{
		Summary: summary, Confidence: confidence,
		Evidence: []tools.Evidence{{
			SnapshotHash: strings.Repeat("a", 64), Path: "src/App.java",
			SHA256: strings.Repeat("b", 64), StartLine: 10, EndLine: 12,
		}},
	}
}

func orchestratorFixture(maxRounds, maxIntents, maxWorkers int) (*fakeGraph, *scriptedSessions, *Engine, Params) {
	task := domain.OrchestrationTask{
		Title: "fixture", Goal: "audit the fixture", MaxPlannerRounds: maxRounds,
		MaxIntents: maxIntents, MaxWorkers: maxWorkers,
		Deadline: time.Now().Add(time.Hour), Config: json.RawMessage(`{"max_model_calls":8,"max_tool_calls":24,"max_tokens":131072}`),
	}
	graph := newFakeGraph(task)
	sessions := newScriptedSessions()
	engine := &Engine{graph: graph, sessions: sessions, session: store.Session{}}
	params := Params{TaskID: 1, SnapshotDir: "unused", SnapshotHash: strings.Repeat("a", 64), Settlement: true}
	return graph, sessions, engine, params
}

// TestStartRefusesWhenDatabaseAlreadyHasRunningTask covers the multi-instance
// gap: the in-process mutex cannot see another console, the unique index on
// running tasks can, and Start must surface that refusal instead of scheduling
// a second driver.
func TestStartRefusesWhenDatabaseAlreadyHasRunningTask(t *testing.T) {
	graph, _, engine, params := orchestratorFixture(2, 4, 1)
	graph.transitionErr = store.ErrOrchestrationBusy
	if err := engine.Start(t.Context(), params); err == nil || !errors.Is(err, store.ErrOrchestrationBusy) {
		t.Fatalf("Start must refuse when another instance holds the running task: %v", err)
	}
	if engine.ActiveTask() != 0 {
		t.Fatal("engine stayed busy after a refused claim")
	}
	graph.mu.Lock()
	graph.transitionErr = nil
	graph.mu.Unlock()
	if err := engine.Start(t.Context(), params); err != nil {
		t.Fatalf("second Start after the lease was free: %v", err)
	}
	if engine.ActiveTask() != 1 {
		t.Fatalf("engine must claim the task, got %d", engine.ActiveTask())
	}
	engine.Stop(1)
}

// cancelBeforeGet cancels the caller's context right before drive's first
// database read, reproducing the console's r.Context() behavior after the
// 202 response is written.
type cancelBeforeGet struct {
	*fakeGraph
	cancel context.CancelFunc
}

func (g *cancelBeforeGet) GetOrchestrationTask(ctx context.Context, session store.Session, taskID int64) (domain.OrchestrationTask, error) {
	g.cancel()
	return g.fakeGraph.GetOrchestrationTask(ctx, session, taskID)
}

// TestStartDetachesFromRequestCancellation covers the live regression where
// Start received the HTTP request context: once the handler returned, drive's
// first read failed and the task stayed 'running' with no graph nodes forever.
func TestStartDetachesFromRequestCancellation(t *testing.T) {
	graph, _, engine, params := orchestratorFixture(0, 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	engine.graph = &cancelBeforeGet{fakeGraph: graph, cancel: cancel}
	if err := engine.Start(ctx, params); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		nodes, _, task := graph.snapshot()
		if task.State == domain.OrchestrationCompleted {
			if len(nodes) != 1 || nodes[0].Kind != domain.OrchNodeGoal {
				t.Fatalf("unexpected graph after detached drive: %+v", nodes)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("task stuck in %s with %d nodes after request cancellation", task.State, len(nodes))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestDriveProveGoalCompletes verifies the full loop: planner spawns one intent,
// a worker writes facts and candidates back, the planner proves the goal on the
// second round and the task completes with the graph intact.
func TestDriveProveGoalCompletes(t *testing.T) {
	graph, sessions, engine, params := orchestratorFixture(6, 12, 2)
	sessions.put("orch-1-planner-r1", scriptedOutcome{envelope: envelope("first round", []agent.PlannedIntent{{Summary: "audit login flow"}}, nil, nil)})

	sessions.put("orch-1-w2", scriptedOutcome{envelope: envelope("worker done", nil,
		[]agent.ReportedFact{evidenceFact("login accepts user input", "observed")},
		[]agent.ReportedCandidate{{Title: "unbounded query", Severity: "high", Note: "name-based"}})})

	// Second planner round: everything covered, prove the goal. The goal node
	// is the first node created by drive (id 1).
	sessions.put("orch-1-planner-r2", scriptedOutcome{envelope: envelope("proven", nil, nil, nil, "goal-1")})

	engine.drive(t.Context(), params)

	nodes, edges, task := graph.snapshot()
	if task.State != domain.OrchestrationCompleted {
		t.Fatalf("task must complete, got %s (%s)", task.State, task.Reason)
	}
	byKind := map[domain.OrchestrationNodeKind]int{}
	for _, node := range nodes {
		byKind[node.Kind]++
	}
	if byKind[domain.OrchNodeGoal] != 1 || byKind[domain.OrchNodeIntent] != 1 || byKind[domain.OrchNodeFact] != 1 || byKind[domain.OrchNodeFindingCandidate] != 1 {
		t.Fatalf("unexpected graph composition: %+v calls=%v nodes=%+v", byKind, sessions.calls, nodes)
	}
	goal := nodes[0]
	if goal.Kind != domain.OrchNodeGoal || goal.State != domain.OrchNodeMet {
		t.Fatalf("goal must be met, got %+v", goal)
	}
	intentState := map[int64]domain.OrchestrationNodeState{}
	for _, node := range nodes {
		intentState[node.ID] = node.State
	}
	if intentState[2] != domain.OrchNodeDone {
		t.Fatalf("intent must be done, got %+v", nodes)
	}
	// goal spawns intent; intent yields fact and candidate = 3 edges
	if len(edges) != 3 {
		t.Fatalf("expected 3 edges, got %+v", edges)
	}
	if sessions.callCount("orch-1-planner") != 2 {
		t.Fatalf("expected exactly two planner rounds, got %d; calls=%v", sessions.callCount("orch-1-planner"), sessions.calls)
	}
}

// TestDrivePlansWithSmallIntentBudget covers the live regression where a
// task-level max_intents of 2 finished before the first planner round: the
// guard assumed every round could spawn four intents and treated a small
// budget as already exhausted.
func TestDriveProofRoundRunsAfterIntentBudget(t *testing.T) {
	graph, sessions, engine, params := orchestratorFixture(3, 1, 1)
	sessions.put("orch-1-planner-r1", scriptedOutcome{envelope: envelope("first round", []agent.PlannedIntent{{Summary: "audit login flow"}}, nil, nil)})
	sessions.put("orch-1-w2", scriptedOutcome{envelope: envelope("worker done", nil,
		[]agent.ReportedFact{evidenceFact("login accepts user input", "observed")}, nil)})
	sessions.put("orch-1-planner-r2", scriptedOutcome{envelope: envelope("proven", nil, nil, nil, "goal-1")})
	engine.drive(t.Context(), params)
	nodes, _, task := graph.snapshot()
	if task.State != domain.OrchestrationCompleted || nodes[0].State != domain.OrchNodeMet {
		t.Fatalf("goal must be proved in a later round after the intent budget is spent: state=%s goal=%+v", task.State, nodes[0])
	}
	if sessions.callCount("orch-1-planner") != 2 {
		t.Fatalf("expected a proof round, got %d planner calls", sessions.callCount("orch-1-planner"))
	}
}

func TestDriveWritesHypothesesAsEvidenceFacts(t *testing.T) {
	graph, sessions, engine, params := orchestratorFixture(6, 12, 2)
	sessions.put("orch-1-planner-r1", scriptedOutcome{envelope: envelope("first round", []agent.PlannedIntent{{Summary: "audit login flow"}}, nil, nil)})
	// A real worker often answers in hypotheses (the shared system prompt asks
	// for them) instead of facts. Those still carry pinned evidence and must
	// become graph records, otherwise the goal can never be proved.
	sessions.put("orch-1-w2", scriptedOutcome{envelope: &agent.FinalEnvelope{
		Summary: "worker done",
		Hypotheses: []agent.Hypothesis{{Statement: "reflected value",
			Evidence: []tools.Evidence{{Path: "a.jsp", SHA256: "00", StartLine: 1, EndLine: 2}}}},
		Limitations: []string{},
	}})
	sessions.put("orch-1-planner-r2", scriptedOutcome{envelope: envelope("proven", nil, nil, nil, "goal-1")})
	engine.drive(t.Context(), params)
	nodes, _, task := graph.snapshot()
	if task.State != domain.OrchestrationCompleted {
		t.Fatalf("task must complete, got %s (%s)", task.State, task.Reason)
	}
	facts := 0
	for _, node := range nodes {
		if node.Kind == domain.OrchNodeFact {
			facts++
		}
	}
	if facts == 0 || nodes[0].State != domain.OrchNodeMet {
		t.Fatalf("hypothesis must become an evidence fact and prove the goal: facts=%d nodes=%+v", facts, nodes)
	}
}

func TestDrivePlansWithSmallIntentBudget(t *testing.T) {
	graph, sessions, engine, params := orchestratorFixture(2, 2, 1)
	sessions.put("orch-1-planner-r1", scriptedOutcome{envelope: envelope("round one", []agent.PlannedIntent{{Summary: "one"}}, nil, nil)})
	sessions.put("orch-1-w2", scriptedOutcome{envelope: envelope("worker done", nil, nil, nil)})
	sessions.put("orch-1-planner-r2", scriptedOutcome{envelope: envelope("nothing left", nil, nil, nil)})
	engine.drive(t.Context(), params)
	if sessions.callCount("orch-1-planner") != 2 {
		t.Fatalf("small intent budget must still plan; calls=%v", sessions.calls)
	}
	nodes, _, task := graph.snapshot()
	intents := 0
	for _, node := range nodes {
		if node.Kind == domain.OrchNodeIntent {
			intents++
		}
	}
	if intents != 1 || task.IntentsSpawned != 1 {
		t.Fatalf("unexpected intent usage: nodes=%d counter=%d", intents, task.IntentsSpawned)
	}
	if task.State != domain.OrchestrationCompleted {
		t.Fatalf("task must complete, got %s (%s)", task.State, task.Reason)
	}
}

// TestDriveCapsPlannerIntentsAtTaskBudget verifies the task-level max_intents
// is a hard cap even when the planner returns four intents in one round.
func TestDriveCapsPlannerIntentsAtTaskBudget(t *testing.T) {
	graph, sessions, engine, params := orchestratorFixture(1, 2, 1)
	sessions.put("orch-1-planner-r1", scriptedOutcome{envelope: envelope("spawn four", []agent.PlannedIntent{
		{Summary: "one"}, {Summary: "two"}, {Summary: "three"}, {Summary: "four"},
	}, nil, nil)})
	sessions.put("orch-1-w2", scriptedOutcome{envelope: envelope("worker done", nil, nil, nil)})
	sessions.put("orch-1-w3", scriptedOutcome{envelope: envelope("worker done", nil, nil, nil)})
	engine.drive(t.Context(), params)
	nodes, _, task := graph.snapshot()
	intents := 0
	for _, node := range nodes {
		if node.Kind == domain.OrchNodeIntent {
			intents++
		}
	}
	if intents != 2 || task.IntentsSpawned != 2 {
		t.Fatalf("intent budget must cap spawned nodes: nodes=%d counter=%d", intents, task.IntentsSpawned)
	}
}

// TestDriveStopsOnIntentBudget verifies the persisted counter check terminates
// the task once the intent budget is exhausted and nothing is open.
func TestDriveStopsOnIntentBudget(t *testing.T) {
	graph, sessions, engine, params := orchestratorFixture(6, 4, 2)
	sessions.put("orch-1-planner-r1", scriptedOutcome{envelope: envelope("spawn four", []agent.PlannedIntent{
		{Summary: "one"}, {Summary: "two"}, {Summary: "three"}, {Summary: "four"},
	}, nil, nil)})
	for id := 2; id <= 5; id++ {
		sessions.put(fmt.Sprintf("orch-1-w%d", id), scriptedOutcome{envelope: envelope("worker done", nil,
			[]agent.ReportedFact{factNodeSummary(fmt.Sprintf("fact %d", id), "observed")}, nil)})
	}
	sessions.put("orch-1-planner-r2", scriptedOutcome{envelope: envelope("spawn four more", []agent.PlannedIntent{
		{Summary: "five"}, {Summary: "six"}, {Summary: "seven"}, {Summary: "eight"},
	}, nil, nil)})
	for id := 6; id <= 9; id++ {
		sessions.put(fmt.Sprintf("orch-1-w%d", id), scriptedOutcome{envelope: envelope("worker done", nil, nil, nil)})
	}
	// Round 3 would spawn more, but the budget check must terminate first.
	sessions.put("orch-1-planner-r3", scriptedOutcome{envelope: envelope("should never run", []agent.PlannedIntent{{Summary: "over budget"}}, nil, nil)})

	engine.drive(t.Context(), params)

	_, _, task := graph.snapshot()
	if task.State != domain.OrchestrationCompleted {
		t.Fatalf("task must complete on budget, got %s (%s)", task.State, task.Reason)
	}
	if !strings.Contains(task.Reason, "意图预算已用尽") {
		t.Fatalf("completion reason must cite the intent budget, got %s", task.Reason)
	}
	if task.IntentsSpawned > 4 {
		t.Fatalf("intents over budget spawned: %d", task.IntentsSpawned)
	}
	if sessions.callCount("orch-1-planner-r3") != 0 {
		t.Fatal("planner round 3 must not run after the budget check")
	}
}

// TestDrivePicksUpSteerIntent verifies that an intent injected between rounds
// (the steer API writes an open node) is dispatched by the engine.
func TestDrivePicksUpSteerIntent(t *testing.T) {
	graph, sessions, engine, params := orchestratorFixture(6, 12, 2)
	sessions.put("orch-1-planner-r1", scriptedOutcome{envelope: envelope("no directions", nil, nil, nil)})
	sessions.put("orch-1-planner-r2", scriptedOutcome{envelope: envelope("steered direction covered", nil, nil, nil)})
	// Human steer: an open intent node arrives while round 2 is pending. The
	// hook fires when planner r1 finishes, i.e. before pickReadyIntents.
	sessions.mu.Lock()
	sessions.onCall = func(key string) {
		if key == "orch-1-planner-r2" {
			_, _ = graph.AddOrchestrationNode(context.Background(), store.Session{}, 1, store.AddOrchestrationNodeParams{
				Kind: domain.OrchNodeIntent, State: domain.OrchNodeOpen, Summary: "human steered direction",
				Payload: []byte(`{"type":"user_intent","source":"human"}`),
			})
		}
	}
	sessions.mu.Unlock()
	sessions.put("orch-1-w2", scriptedOutcome{envelope: envelope("steered worker done", nil,
		[]agent.ReportedFact{factNodeSummary("steered observation", "inferred")}, nil)})

	engine.drive(t.Context(), params)

	nodes, _, task := graph.snapshot()
	if task.State != domain.OrchestrationCompleted {
		t.Fatalf("task must complete, got %s", task.State)
	}
	steered := false
	for _, node := range nodes {
		if node.Summary == "human steered direction" && node.State == domain.OrchNodeDone {
			steered = true
		}
	}
	if !steered {
		t.Fatalf("steered intent was never dispatched: %+v", nodes)
	}
}

// TestDriveWorkerFailureMarksBlocked verifies a failing worker does not kill
// the task: the intent is blocked and the loop continues.
func TestDriveWorkerFailureMarksBlocked(t *testing.T) {
	graph, sessions, engine, params := orchestratorFixture(4, 12, 2)
	sessions.put("orch-1-planner-r1", scriptedOutcome{envelope: envelope("spawn one", []agent.PlannedIntent{{Summary: "doomed intent"}}, nil, nil)})
	sessions.put("orch-1-w2", scriptedOutcome{state: "failed", err: fmt.Errorf("model refused")})
	sessions.put("orch-1-planner-r2", scriptedOutcome{envelope: envelope("nothing more to do", nil, nil, nil)})

	engine.drive(t.Context(), params)

	nodes, _, task := graph.snapshot()
	if task.State != domain.OrchestrationCompleted {
		t.Fatalf("task must complete despite a blocked intent, got %s (%s)", task.State, task.Reason)
	}
	for _, node := range nodes {
		if node.Kind == domain.OrchNodeIntent && node.State != domain.OrchNodeBlocked {
			t.Fatalf("failed intent must be blocked, got %+v", node)
		}
	}
}

// TestDriveCancelledByStop verifies a cancelled context records the cancelled
// state instead of pretending completion.
func TestDriveCancelledByStop(t *testing.T) {
	graph, sessions, engine, params := orchestratorFixture(4, 12, 2)
	ctx, cancel := context.WithCancel(t.Context())
	sessions.mu.Lock()
	sessions.onCall = func(key string) {
		if strings.HasPrefix(key, "orch-1-planner") {
			cancel()
		}
	}
	sessions.mu.Unlock()
	sessions.put("orch-1-planner-r1", scriptedOutcome{envelope: envelope("first", []agent.PlannedIntent{{Summary: "intent"}}, nil, nil)})
	sessions.put("orch-1-w2", scriptedOutcome{envelope: envelope("done", nil, nil, nil)})
	sessions.put("orch-1-planner-r2", scriptedOutcome{envelope: envelope("never", nil, nil, nil)})

	engine.drive(ctx, params)

	_, _, task := graph.snapshot()
	if task.State != domain.OrchestrationCancelled {
		t.Fatalf("cancelled context must record cancelled, got %s (%s)", task.State, task.Reason)
	}
}

// TestDriveRefusesGoalWithoutGraphEvidence verifies that a planner declaring a
// goal proved cannot end the task while the graph holds no evidence-bearing
// record: the declaration is refused and reported in the next trigger text.
func TestDriveRefusesGoalWithoutGraphEvidence(t *testing.T) {
	graph, sessions, engine, params := orchestratorFixture(3, 12, 2)
	for round := 1; round <= 3; round++ {
		sessions.put(fmt.Sprintf("orch-1-planner-r%d", round), scriptedOutcome{
			envelope: envelope("declare done", nil, nil, nil, "goal-1")})
	}

	engine.drive(t.Context(), params)

	nodes, _, task := graph.snapshot()
	if nodes[0].State == domain.OrchNodeMet {
		t.Fatalf("goal met without any graph evidence: %+v", nodes[0])
	}
	if task.State != domain.OrchestrationCompleted || strings.Contains(task.Reason, "达成") {
		t.Fatalf("task must not complete as proved; got %s (%s)", task.State, task.Reason)
	}
}

// TestDriveProvesHumanGoalNode verifies that a goal node injected by steer is
// addressable: the planner proves both the engine goal and the human goal.
func TestDriveProvesHumanGoalNode(t *testing.T) {
	graph, sessions, engine, params := orchestratorFixture(4, 12, 2)
	sessions.put("orch-1-planner-r1", scriptedOutcome{envelope: envelope("first", []agent.PlannedIntent{{Summary: "audit login"}}, nil, nil)})
	sessions.put("orch-1-w2", scriptedOutcome{envelope: envelope("worker done", nil,
		[]agent.ReportedFact{evidenceFact("login accepts input", "observed")}, nil)})
	var humanGoalID int64
	sessions.mu.Lock()
	sessions.onCall = func(key string) {
		if key != "orch-1-w2" {
			return
		}
		// Human steer lands after the worker wave, so round 2 reads the new goal.
		node, _ := graph.AddOrchestrationNode(context.Background(), store.Session{}, 1, store.AddOrchestrationNodeParams{
			Kind: domain.OrchNodeGoal, State: domain.OrchNodeOpen, Summary: "human goal: verify 授权",
			Payload: []byte(`{"source":"human"}`),
		})
		humanGoalID = node.ID
		sessions.put("orch-1-planner-r2", scriptedOutcome{envelope: envelope("both proved", nil, nil, nil,
			"goal-1", fmt.Sprintf("goal-%d", node.ID))})
	}
	sessions.mu.Unlock()

	engine.drive(t.Context(), params)

	nodes, _, task := graph.snapshot()
	if task.State != domain.OrchestrationCompleted || !strings.Contains(task.Reason, "达成") {
		t.Fatalf("task must complete on both goals; got %s (%s)", task.State, task.Reason)
	}
	met := map[int64]domain.OrchestrationNodeState{}
	for _, node := range nodes {
		met[node.ID] = node.State
	}
	if met[1] != domain.OrchNodeMet || met[humanGoalID] != domain.OrchNodeMet {
		t.Fatalf("both goal nodes must be met (human goal id %d): %+v calls=%v", humanGoalID, nodes, sessions.calls)
	}
}

// TestDriveUsesRoleSpecificBindings verifies the planner and worker sessions
// can resolve to different model-library entries while sharing the task budget.
func TestDriveUsesRoleSpecificBindings(t *testing.T) {
	graph, sessions, engine, params := orchestratorFixture(6, 12, 2)
	params.Binding = SessionBinding{Endpoint: "https://planner.example.com", Model: "planner-model", KeyEnv: "PLANNER_KEY"}
	worker := SessionBinding{Endpoint: "https://worker.example.com", Model: "worker-model", KeyEnv: "WORKER_KEY"}
	params.WorkerBinding = &worker

	sessions.put("orch-1-planner-r1", scriptedOutcome{envelope: envelope("round one", []agent.PlannedIntent{{Summary: "audit login"}}, nil, nil)})
	sessions.put("orch-1-w2", scriptedOutcome{envelope: envelope("worker done", nil,
		[]agent.ReportedFact{evidenceFact("login accepts input", "observed")}, nil)})
	sessions.put("orch-1-planner-r2", scriptedOutcome{envelope: envelope("proven", nil, nil, nil, "goal-1")})

	engine.drive(t.Context(), params)

	sessions.mu.Lock()
	bindings := map[string]SessionBinding{}
	for key, binding := range sessions.bindings {
		bindings[key] = binding
	}
	sessions.mu.Unlock()

	planner, ok := bindings["orch-1-planner-r1"]
	if !ok || planner.Endpoint != "https://planner.example.com" || planner.Model != "planner-model" {
		t.Fatalf("planner binding not used: %+v", bindings)
	}
	workerCall, ok := bindings["orch-1-w2"]
	if !ok || workerCall.Endpoint != "https://worker.example.com" || workerCall.Model != "worker-model" {
		t.Fatalf("worker binding not used: %+v", bindings)
	}
	if planner.MaxModelCalls != 8 || planner.MaxTokens != 131072 || workerCall.MaxToolCalls != 24 {
		t.Fatalf("task budget not applied to both bindings: planner=%+v worker=%+v", planner, workerCall)
	}
	_, _, task := graph.snapshot()
	if task.State != domain.OrchestrationCompleted {
		t.Fatalf("task must complete with role bindings, got %s (%s)", task.State, task.Reason)
	}
}
