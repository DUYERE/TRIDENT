package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trident/internal/domain"
)

// Orchestration persistence. The exploration graph is engine-owned: LLM output
// reaches it only after the orchestrator parses and validates the terminal
// envelope, so nothing here trusts model text as a state transition. Reads and
// writes go through the same authenticated Store as agent_runs.

// orchestrationRunningIndex is the partial unique index (db migration 006) that
// allows one running task per principal across every console instance sharing
// this database. The name is part of the error contract below.
const orchestrationRunningIndex = "orchestration_tasks_one_running"

var (
	ErrOrchestrationMissing = errors.New("orchestration task or node not found")
	ErrOrchestrationState   = errors.New("orchestration state transition rejected")
	// ErrOrchestrationBusy means another console (or an earlier run of this one)
	// already holds the database-level running slot for this principal.
	ErrOrchestrationBusy = errors.New("another orchestration task is already running for this principal")
)

// classifyOrchestrationConflict turns the partial-index violation into a
// sentinel an API layer can map to 409. Everything else passes through
// unchanged.
func classifyOrchestrationConflict(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == orchestrationRunningIndex {
		return fmt.Errorf("%w: 数据库拒绝第二个运行中任务（%s）", ErrOrchestrationBusy, orchestrationRunningIndex)
	}
	return err
}

type CreateOrchestrationTaskParams struct {
	Key              string
	SnapshotPath     string
	SnapshotHash     string
	Title            string
	Goal             string
	Config           json.RawMessage
	MaxPlannerRounds int
	MaxIntents       int
	MaxWorkers       int
	Deadline         time.Time
}

type OrchestrationTaskConfig struct {
	PlannerProfileID string `json:"planner_profile_id"`
	WorkerProfileID  string `json:"worker_profile_id"`
	MaxModelCalls    int64  `json:"max_model_calls"`
	MaxToolCalls     int64  `json:"max_tool_calls"`
	MaxTokens        int64  `json:"max_tokens"`
}

func (c OrchestrationTaskConfig) Validate() error {
	if c.MaxModelCalls < 1 || c.MaxModelCalls > 64 {
		return fmt.Errorf("max_model_calls 必须在 1..64")
	}
	if c.MaxToolCalls < 1 || c.MaxToolCalls > 256 {
		return fmt.Errorf("max_tool_calls 必须在 1..256")
	}
	if c.MaxTokens < 4096 || c.MaxTokens > 1_000_000 {
		return fmt.Errorf("max_tokens 必须在 4096..1000000")
	}
	return nil
}

const orchestrationTaskColumns = `id, owner_id, snapshot_path, snapshot_hash, title, goal, state, reason, config_text, max_planner_rounds, max_intents, max_workers, planner_rounds, intents_spawned, deadline_at, created_at, updated_at`

func scanOrchestrationTask(row pgx.Row) (domain.OrchestrationTask, error) {
	var task domain.OrchestrationTask
	var config string
	err := row.Scan(&task.ID, &task.OwnerID, &task.SnapshotPath, &task.SnapshotHash, &task.Title, &task.Goal,
		&task.State, &task.Reason, &config, &task.MaxPlannerRounds, &task.MaxIntents, &task.MaxWorkers,
		&task.PlannerRounds, &task.IntentsSpawned, &task.Deadline, &task.CreatedAt, &task.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return task, ErrOrchestrationMissing
	}
	task.Config = json.RawMessage(config)
	return task, err
}

func (s *Store) CreateOrchestrationTask(ctx context.Context, ss Session, params CreateOrchestrationTaskParams) (domain.OrchestrationTask, error) {
	if params.Deadline.IsZero() || !params.Deadline.After(time.Now()) {
		return domain.OrchestrationTask{}, fmt.Errorf("%w: deadline 必须是未来时间", ErrOrchestrationState)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.OrchestrationTask{}, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return domain.OrchestrationTask{}, err
	}
	row := tx.QueryRow(ctx, `INSERT INTO orchestration_tasks
		(owner_id, creation_key, snapshot_path, snapshot_hash, title, goal, state, config_text, max_planner_rounds, max_intents, max_workers, deadline_at)
		VALUES ($1,$2,$3,$4,$5,$6,'created',$7::jsonb,$8,$9,$10,$11) RETURNING `+orchestrationTaskColumns,
		a.id, params.Key, params.SnapshotPath, params.SnapshotHash, params.Title, params.Goal,
		string(params.Config), params.MaxPlannerRounds, params.MaxIntents, params.MaxWorkers, params.Deadline)
	task, err := scanOrchestrationTask(row)
	if err != nil {
		return domain.OrchestrationTask{}, err
	}
	return task, tx.Commit(ctx)
}

func (s *Store) GetOrchestrationTask(ctx context.Context, ss Session, taskID int64) (domain.OrchestrationTask, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.OrchestrationTask{}, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return domain.OrchestrationTask{}, err
	}
	task, err := scanOrchestrationTask(tx.QueryRow(ctx, `SELECT `+orchestrationTaskColumns+` FROM orchestration_tasks WHERE id=$1 AND owner_id=$2`, taskID, a.id))
	if err != nil {
		return domain.OrchestrationTask{}, err
	}
	return task, tx.Commit(ctx)
}

func (s *Store) ListOrchestrationTasks(ctx context.Context, ss Session, limit int) ([]domain.OrchestrationTask, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	tasks := []domain.OrchestrationTask{}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return tasks, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return tasks, err
	}
	rows, err := tx.Query(ctx, `SELECT `+orchestrationTaskColumns+` FROM orchestration_tasks WHERE owner_id=$1 ORDER BY id DESC LIMIT $2`, a.id, limit)
	if err != nil {
		return tasks, err
	}
	defer rows.Close()
	for rows.Next() {
		task, err := scanOrchestrationTask(rows)
		if err != nil {
			return tasks, err
		}
		tasks = append(tasks, task)
	}
	if err := rows.Err(); err != nil {
		return tasks, err
	}
	return tasks, tx.Commit(ctx)
}

// TransitionOrchestrationTask advances the task state with a compare-and-set on
// the current state, so engine goroutines and human stops cannot interleave.
func (s *Store) TransitionOrchestrationTask(ctx context.Context, ss Session, taskID int64, from, to domain.OrchestrationState, reason string) (domain.OrchestrationTask, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 4096 {
		reason = reason[:4096]
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.OrchestrationTask{}, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return domain.OrchestrationTask{}, err
	}
	task, err := scanOrchestrationTask(tx.QueryRow(ctx, `UPDATE orchestration_tasks SET state=$3, reason=$4, updated_at=clock_timestamp()
		WHERE id=$1 AND owner_id=$2 AND state=$5 RETURNING `+orchestrationTaskColumns,
		taskID, a.id, string(to), reason, string(from)))
	if err != nil {
		if errors.Is(err, ErrOrchestrationMissing) {
			return task, ErrOrchestrationState
		}
		return task, classifyOrchestrationConflict(err)
	}
	return task, tx.Commit(ctx)
}

func (s *Store) BumpOrchestrationCounters(ctx context.Context, ss Session, taskID int64, plannerRounds, intents int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE orchestration_tasks SET planner_rounds=planner_rounds+$3, intents_spawned=intents_spawned+$4, updated_at=clock_timestamp()
		WHERE id=$1 AND owner_id=$2 AND state='running'`, taskID, a.id, plannerRounds, intents)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrOrchestrationState
	}
	return tx.Commit(ctx)
}

type AddOrchestrationNodeParams struct {
	Kind       domain.OrchestrationNodeKind
	State      domain.OrchestrationNodeState
	Summary    string
	Confidence string
	Payload    json.RawMessage
}

// normalizeNodePayload keeps the jsonb column valid: most nodes carry no
// payload, and an empty string is not valid JSON for jsonb.
func normalizeNodePayload(payload json.RawMessage) string {
	if strings.TrimSpace(string(payload)) == "" {
		return "{}"
	}
	return string(payload)
}

func (s *Store) AddOrchestrationNode(ctx context.Context, ss Session, taskID int64, params AddOrchestrationNodeParams) (domain.OrchestrationNode, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.OrchestrationNode{}, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return domain.OrchestrationNode{}, err
	}
	var node domain.OrchestrationNode
	var payload string
	err = tx.QueryRow(ctx, `INSERT INTO orchestration_nodes (task_id, kind, state, summary, confidence, payload_text)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb) RETURNING id, task_id, kind, state, summary, confidence, payload_text, created_at, updated_at`,
		taskID, string(params.Kind), string(params.State), params.Summary, params.Confidence, normalizeNodePayload(params.Payload)).
		Scan(&node.ID, &node.TaskID, &node.Kind, &node.State, &node.Summary, &node.Confidence, &payload, &node.CreatedAt, &node.UpdatedAt)
	if err != nil {
		return domain.OrchestrationNode{}, err
	}
	node.Payload = json.RawMessage(payload)
	// Confirm the task belongs to the authenticated owner before committing.
	var ownerOK bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM orchestration_tasks WHERE id=$1 AND owner_id=$2)`, taskID, a.id).Scan(&ownerOK); err != nil {
		return domain.OrchestrationNode{}, err
	}
	if !ownerOK {
		return domain.OrchestrationNode{}, ErrOrchestrationMissing
	}
	return node, tx.Commit(ctx)
}

// UpdateOrchestrationNodeState moves one node to a new engine-owned state.
func (s *Store) UpdateOrchestrationNodeState(ctx context.Context, ss Session, taskID int64, nodeID int64, to domain.OrchestrationNodeState) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE orchestration_nodes n SET state=$3, updated_at=clock_timestamp()
		FROM orchestration_tasks t WHERE n.task_id=t.id AND n.id=$1 AND t.owner_id=$2`, nodeID, a.id, string(to))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrOrchestrationMissing
	}
	return tx.Commit(ctx)
}

func (s *Store) AddOrchestrationEdge(ctx context.Context, ss Session, taskID int64, fromID int64, rel domain.OrchestrationEdgeRel, toID int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return err
	}
	var ownerOK bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM orchestration_tasks WHERE id=$1 AND owner_id=$2)`, taskID, a.id).Scan(&ownerOK); err != nil {
		return err
	}
	if !ownerOK {
		return ErrOrchestrationMissing
	}
	_, err = tx.Exec(ctx, `INSERT INTO orchestration_edges (task_id, from_id, rel, to_id) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, taskID, fromID, string(rel), toID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) AddOrchestrationConstraint(ctx context.Context, ss Session, taskID int64, kind, text string) (domain.OrchestrationConstraint, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.OrchestrationConstraint{}, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return domain.OrchestrationConstraint{}, err
	}
	var ownerOK bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM orchestration_tasks WHERE id=$1 AND owner_id=$2)`, taskID, a.id).Scan(&ownerOK); err != nil {
		return domain.OrchestrationConstraint{}, err
	}
	if !ownerOK {
		return domain.OrchestrationConstraint{}, ErrOrchestrationMissing
	}
	var constraint domain.OrchestrationConstraint
	err = tx.QueryRow(ctx, `INSERT INTO orchestration_constraints (task_id, kind, text) VALUES ($1,$2,$3)
		ON CONFLICT (task_id, kind, text) DO UPDATE SET text=EXCLUDED.text RETURNING id, task_id, kind, text`,
		taskID, kind, text).Scan(&constraint.ID, &constraint.TaskID, &constraint.Kind, &constraint.Text)
	if err != nil {
		return domain.OrchestrationConstraint{}, err
	}
	return constraint, tx.Commit(ctx)
}

// OrchestrationGraph is one task's full exploration graph for the detail API.
type OrchestrationGraph struct {
	Nodes       []domain.OrchestrationNode       `json:"nodes"`
	Edges       []domain.OrchestrationEdge       `json:"edges"`
	Constraints []domain.OrchestrationConstraint `json:"constraints"`
}

func (s *Store) OrchestrationGraph(ctx context.Context, ss Session, taskID int64) (OrchestrationGraph, error) {
	graph := OrchestrationGraph{Nodes: []domain.OrchestrationNode{}, Edges: []domain.OrchestrationEdge{}, Constraints: []domain.OrchestrationConstraint{}}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return graph, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return graph, err
	}
	var ownerOK bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM orchestration_tasks WHERE id=$1 AND owner_id=$2)`, taskID, a.id).Scan(&ownerOK); err != nil {
		return graph, err
	}
	if !ownerOK {
		return graph, ErrOrchestrationMissing
	}
	nodeRows, err := tx.Query(ctx, `SELECT id, task_id, kind, state, summary, confidence, payload_text, created_at, updated_at FROM orchestration_nodes WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return graph, err
	}
	for nodeRows.Next() {
		var node domain.OrchestrationNode
		var payload string
		if err := nodeRows.Scan(&node.ID, &node.TaskID, &node.Kind, &node.State, &node.Summary, &node.Confidence, &payload, &node.CreatedAt, &node.UpdatedAt); err != nil {
			nodeRows.Close()
			return graph, err
		}
		node.Payload = json.RawMessage(payload)
		graph.Nodes = append(graph.Nodes, node)
	}
	if err := nodeRows.Err(); err != nil {
		nodeRows.Close()
		return graph, err
	}
	nodeRows.Close()
	edgeRows, err := tx.Query(ctx, `SELECT from_id, rel, to_id FROM orchestration_edges WHERE task_id=$1 ORDER BY from_id, to_id`, taskID)
	if err != nil {
		return graph, err
	}
	for edgeRows.Next() {
		var edge domain.OrchestrationEdge
		if err := edgeRows.Scan(&edge.FromID, &edge.Rel, &edge.ToID); err != nil {
			edgeRows.Close()
			return graph, err
		}
		graph.Edges = append(graph.Edges, edge)
	}
	if err := edgeRows.Err(); err != nil {
		edgeRows.Close()
		return graph, err
	}
	edgeRows.Close()
	constraintRows, err := tx.Query(ctx, `SELECT id, task_id, kind, text FROM orchestration_constraints WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return graph, err
	}
	for constraintRows.Next() {
		var constraint domain.OrchestrationConstraint
		if err := constraintRows.Scan(&constraint.ID, &constraint.TaskID, &constraint.Kind, &constraint.Text); err != nil {
			constraintRows.Close()
			return graph, err
		}
		graph.Constraints = append(graph.Constraints, constraint)
	}
	if err := constraintRows.Err(); err != nil {
		constraintRows.Close()
		return graph, err
	}
	constraintRows.Close()
	return graph, tx.Commit(ctx)
}
