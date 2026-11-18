package orchestrator

import (
	"encoding/json"
	"strings"
	"testing"

	"trident/internal/domain"
)

func goalNode(id int64, state domain.OrchestrationNodeState) domain.OrchestrationNode {
	return domain.OrchestrationNode{ID: id, Kind: domain.OrchNodeGoal, State: state, Summary: "g"}
}

func intentNode(id int64, state domain.OrchestrationNodeState, summary string) domain.OrchestrationNode {
	return domain.OrchestrationNode{ID: id, Kind: domain.OrchNodeIntent, State: state, Summary: summary}
}

func TestAllGoalsMetRequiresEveryGoal(t *testing.T) {
	if !allGoalsMet([]domain.OrchestrationNode{goalNode(1, domain.OrchNodeMet), goalNode(2, domain.OrchNodeMet)}) {
		t.Fatal("all-met graph must report met")
	}
	if allGoalsMet([]domain.OrchestrationNode{goalNode(1, domain.OrchNodeMet), goalNode(2, domain.OrchNodeOpen)}) {
		t.Fatal("one open goal must not report met")
	}
	if allGoalsMet(nil) {
		t.Fatal("no goals must not report met (nothing was ever proven)")
	}
}

func TestPickReadyIntentsDeterministicAndBounded(t *testing.T) {
	nodes := []domain.OrchestrationNode{
		intentNode(3, domain.OrchNodeOpen, "third"),
		goalNode(1, domain.OrchNodeOpen),
		intentNode(2, domain.OrchNodeOpen, "second"),
		intentNode(4, domain.OrchNodeRunning, "busy"),
	}
	ready := pickReadyIntents(nodes, nil, 10)
	if len(ready) != 2 || ready[0].ID != 2 || ready[1].ID != 3 {
		t.Fatalf("ready list must be open intents in id order, got %+v", ready)
	}
	if capped := pickReadyIntents(nodes, nil, 1); len(capped) != 1 || capped[0].ID != 2 {
		t.Fatalf("cap must keep the oldest intent, got %+v", capped)
	}
}

func TestWorkerNodeStateMapsUnknownToBlocked(t *testing.T) {
	cases := map[string]domain.OrchestrationNodeState{
		"completed":        domain.OrchNodeDone,
		"budget_exhausted": domain.OrchNodeExhausted,
		"failed":           domain.OrchNodeBlocked,
		"unknown":          domain.OrchNodeBlocked,
		"paused":           domain.OrchNodeBlocked,
		"cancelled":        domain.OrchNodeCancelled,
	}
	for runState, want := range cases {
		if got := workerNodeState(runState); got != want {
			t.Errorf("workerNodeState(%q)=%q, want %q", runState, got, want)
		}
	}
}

func TestFinalEnvelopeFromCompletedStep(t *testing.T) {
	direct := json.RawMessage(`{"summary":"done","hypotheses":[],"limitations":[],"goal_proved":["goal-4"]}`)
	envelope, err := finalEnvelopeFromStep(direct)
	if err != nil || envelope.Summary != "done" || len(envelope.GoalProved) != 1 {
		t.Fatalf("direct payload must parse: env=%+v err=%v", envelope, err)
	}
	wrapped := json.RawMessage(`{"result":{"summary":"legacy","hypotheses":[],"limitations":[]}}`)
	envelope, err = finalEnvelopeFromStep(wrapped)
	if err != nil || envelope.Summary != "legacy" {
		t.Fatalf("legacy result wrapper must parse: env=%+v err=%v", envelope, err)
	}
	if _, err := finalEnvelopeFromStep(json.RawMessage(`{"reason":"budget"}`)); err == nil {
		t.Fatal("a payload without an envelope must be rejected")
	}
}

func TestPlannerGoalCarriesDisciplineAndGraph(t *testing.T) {
	task := domain.OrchestrationTask{ID: 7, Title: "t", Goal: "audit everything", MaxIntents: 12}
	nodes := []domain.OrchestrationNode{goalNode(1, domain.OrchNodeOpen), intentNode(2, domain.OrchNodeDone, "old direction")}
	constraints := []domain.OrchestrationConstraint{{ID: 1, TaskID: 7, Kind: "deny", Text: "禁止触碰 third_party"}}
	goal := buildPlannerGoal(task, "意图 #2 结束", nodes, nil, constraints)
	for _, needle := range []string{"硬底线", "goal_proved", "意图 #2 结束", "禁止触碰 third_party", "audit everything"} {
		if !strings.Contains(goal, needle) {
			t.Fatalf("planner goal missing %q", needle)
		}
	}
}

func TestPlannerGoalJSONExampleIsValid(t *testing.T) {
	task := domain.OrchestrationTask{ID: 7, Title: "t", Goal: "g", MaxIntents: 12}
	goal := buildPlannerGoal(task, "first round", nil, nil, nil)
	start := strings.Index(goal, `{"summary"`)
	if start < 0 {
		t.Fatal("planner goal carries no JSON example")
	}
	end := strings.Index(goal[start:], "\n\n")
	if end < 0 {
		end = len(goal) - start
	}
	example := goal[start : start+end]
	var parsed map[string]any
	if err := json.Unmarshal([]byte(example), &parsed); err != nil {
		t.Fatalf("planner JSON example is not valid JSON: %v\n%s", err, example)
	}
	if _, ok := parsed["goal_proved"]; !ok {
		t.Fatalf("planner JSON example must show goal_proved inside the object: %v", parsed)
	}
}

func TestWorkerGoalCarriesIntentAndWriteBackRules(t *testing.T) {
	task := domain.OrchestrationTask{ID: 7, Title: "t", Goal: "g"}
	intent := intentNode(9, domain.OrchNodeOpen, "trace login flow")
	intent.Payload = []byte(`{"asset_refs":["/api/login"]}`)
	goal := buildWorkerGoal(task, intent, nil, nil, nil)
	for _, needle := range []string{"trace login flow", "9", "/api/login", "candidates", "observed"} {
		if !strings.Contains(goal, needle) {
			t.Fatalf("worker goal missing %q", needle)
		}
	}
}
