package domain

import (
	"encoding/json"
	"time"
)

// Orchestration task and exploration-graph types. The graph stores only what
// the engine and humans wrote back: every LLM-produced record is a candidate or
// fact with pinned evidence, never a confirmed vulnerability, and runtime
// verification is always not_run.

type OrchestrationState string

const (
	OrchestrationCreated   OrchestrationState = "created"
	OrchestrationRunning   OrchestrationState = "running"
	OrchestrationCompleted OrchestrationState = "completed"
	OrchestrationCancelled OrchestrationState = "cancelled"
	OrchestrationFailed    OrchestrationState = "failed"
)

type OrchestrationNodeKind string

const (
	OrchNodeGoal              OrchestrationNodeKind = "goal"
	OrchNodeIntent            OrchestrationNodeKind = "intent"
	OrchNodeFact              OrchestrationNodeKind = "fact"
	OrchNodeFindingCandidate  OrchestrationNodeKind = "finding_candidate"
	OrchNodeDigest            OrchestrationNodeKind = "digest"
)

type OrchestrationNodeState string

const (
	OrchNodeOpen      OrchestrationNodeState = "open"
	OrchNodeRunning   OrchestrationNodeState = "running"
	OrchNodeDone      OrchestrationNodeState = "done"
	OrchNodeMet       OrchestrationNodeState = "met"
	OrchNodeExhausted OrchestrationNodeState = "exhausted"
	OrchNodeBlocked   OrchestrationNodeState = "blocked"
	OrchNodeCancelled OrchestrationNodeState = "cancelled"
	OrchNodeInvalid   OrchestrationNodeState = "invalid"
)

type OrchestrationEdgeRel string

const (
	OrchEdgeSpawns      OrchestrationEdgeRel = "spawns"
	OrchEdgeDerivedFrom OrchestrationEdgeRel = "derived_from"
	OrchEdgeYields      OrchestrationEdgeRel = "yields"
)

type OrchestrationTask struct {
	ID              int64           `json:"id"`
	OwnerID         int64           `json:"owner_id"`
	SnapshotPath    string          `json:"snapshot_path"`
	SnapshotHash    string          `json:"snapshot_hash"`
	Title           string          `json:"title"`
	Goal            string          `json:"goal"`
	State           OrchestrationState `json:"state"`
	Reason          string          `json:"reason"`
	Config          json.RawMessage `json:"config"`
	MaxPlannerRounds int           `json:"max_planner_rounds"`
	MaxIntents      int             `json:"max_intents"`
	MaxWorkers      int             `json:"max_workers"`
	PlannerRounds   int             `json:"planner_rounds"`
	IntentsSpawned  int             `json:"intents_spawned"`
	Deadline        time.Time       `json:"deadline"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

type OrchestrationNode struct {
	ID         int64                  `json:"id"`
	TaskID     int64                  `json:"task_id"`
	Kind       OrchestrationNodeKind  `json:"kind"`
	State      OrchestrationNodeState `json:"state"`
	Summary    string                 `json:"summary"`
	Confidence string                 `json:"confidence,omitempty"`
	Payload    json.RawMessage        `json:"payload"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

type OrchestrationEdge struct {
	FromID int64                `json:"from_id"`
	Rel    OrchestrationEdgeRel `json:"rel"`
	ToID   int64                `json:"to_id"`
}

type OrchestrationConstraint struct {
	ID     int64  `json:"id"`
	TaskID int64  `json:"task_id"`
	Kind   string `json:"kind"`
	Text   string `json:"text"`
}
