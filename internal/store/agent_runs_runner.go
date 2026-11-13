package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"trident/internal/domain"
)

// [01] A runner owns one acquired PostgreSQL session, never a pool-level advisory lock.
// No transaction remains open between Get/Tx/ListSteps calls or during HTTP/filesystem work.
type AgentRunner struct {
	mu      sync.Mutex
	conn    *pgxpool.Conn
	session Session
	runID   int64
	lockKey int64
}

func discardAgentConnection(conn *pgxpool.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return conn.Hijack().Close(ctx)
}

func (s *Store) AcquireAgentRunner(ctx context.Context, ss Session, runID int64) (*AgentRunner, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			// [02] Even an interrupted lock acquisition has unknown session state: never pool it.
			_ = discardAgentConnection(conn)
		}
	}()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return nil, err
	}
	if _, err = ownedAgentRun(ctx, tx, a, runID, false); err != nil {
		return nil, err
	}
	var lockKey int64
	// Schema OID avoids false contention between independent integration-test schemas.
	if err = tx.QueryRow(ctx, `SELECT hashtextextended('trident.agent.runner/'||current_database()||'/'||'agent_runs'::regclass::oid::text||'/'||$1::bigint::text,0)`, runID).Scan(&lockKey); err != nil {
		return nil, err
	}
	var locked bool
	if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&locked); err != nil {
		return nil, err
	}
	if !locked {
		return nil, fmt.Errorf("%w: agent runner already acquired", ErrConflict)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	keep = true
	return &AgentRunner{conn: conn, session: ss, runID: runID, lockKey: lockKey}, nil
}

func (r *AgentRunner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn == nil {
		return nil
	}
	conn := r.conn
	r.conn = nil
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var unlocked bool
	err := conn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, r.lockKey).Scan(&unlocked)
	if err == nil && unlocked {
		conn.Release()
		return nil
	}
	if err == nil {
		err = fmt.Errorf("%w: agent runner session lock lost", ErrStale)
	}
	return errors.Join(err, discardAgentConnection(conn))
}

func (r *AgentRunner) begin(ctx context.Context) (pgx.Tx, actor, error) {
	if r.conn == nil {
		return nil, actor{}, ErrStale
	}
	tx, err := r.conn.Begin(ctx)
	if err != nil {
		return nil, actor{}, err
	}
	a, err := agentActor(ctx, tx, r.session)
	if err != nil {
		rollbackAgentTx(tx)
		return nil, actor{}, err
	}
	return tx, a, nil
}

func (r *AgentRunner) Get(ctx context.Context) (domain.AgentRun, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, a, err := r.begin(ctx)
	if err != nil {
		return domain.AgentRun{}, err
	}
	defer rollbackAgentTx(tx)
	run, err := ownedAgentRun(ctx, tx, a, r.runID, false)
	if err != nil {
		return domain.AgentRun{}, err
	}
	return run, tx.Commit(ctx)
}

func (r *AgentRunner) ListSteps(ctx context.Context, afterSeq int64, limit int) ([]domain.AgentStep, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, a, err := r.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollbackAgentTx(tx)
	if _, err = ownedAgentRun(ctx, tx, a, r.runID, false); err != nil {
		return nil, err
	}
	steps, err := readAgentSteps(ctx, tx, r.runID, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	return steps, tx.Commit(ctx)
}

func (r *AgentRunner) Steps(ctx context.Context, afterSeq int64, limit int) ([]domain.AgentStep, error) {
	return r.ListSteps(ctx, afterSeq, limit)
}

func normalizeAgentTransition(p AgentTransition) (AgentTransition, []byte, string, error) {
	if !agentKey(p.Key) || p.ExpectedVersion < 1 {
		return p, nil, "", ErrConflict
	}
	var err error
	p.Payload, err = canonicalAgentJSON(p.Payload, agentPayloadMaxBytes, true)
	if err != nil {
		return p, nil, "", err
	}
	if p.Checkpoint != nil {
		p.Checkpoint, err = canonicalAgentJSON(p.Checkpoint, agentCheckpointMaxBytes, false)
		if err != nil {
			return p, nil, "", err
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return p, nil, "", err
	}
	return p, raw, agentHash(raw), nil
}

// [03] Settlement is bound to the latest prepared event, not merely to an aggregate reserved counter.
// Unknown+resume abandons the old pending call without refunding it; future calls cannot release it.
func validateAgentJournal(ctx context.Context, tx pgx.Tx, runID int64, p AgentTransition) error {
	if p.Kind == domain.AgentStepModelPrepared || p.Kind == domain.AgentStepModelCompleted {
		var kind domain.AgentStepKind
		var raw string
		err := tx.QueryRow(ctx, `SELECT kind,request_text FROM agent_run_steps WHERE run_id=$1 AND kind IN ('model.prepared','model.completed','run.unknown','run.resumed') ORDER BY seq DESC LIMIT 1`, runID).Scan(&kind, &raw)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if p.Kind == domain.AgentStepModelPrepared {
			if kind == domain.AgentStepModelPrepared {
				return ErrConflict
			}
			return nil
		}
		if kind != domain.AgentStepModelPrepared {
			return ErrConflict
		}
		var prepared AgentTransition
		if err = json.Unmarshal([]byte(raw), &prepared); err != nil {
			return err
		}
		if p.ReservedTokenDelta != 0 && p.ReservedTokenDelta != -prepared.ReservedTokenDelta {
			return ErrConflict
		}
	}
	if p.Kind == domain.AgentStepToolStarted || p.Kind == domain.AgentStepToolCompleted {
		var kind domain.AgentStepKind
		err := tx.QueryRow(ctx, `SELECT kind FROM agent_run_steps WHERE run_id=$1 AND kind IN ('tool.started','tool.completed') ORDER BY seq DESC LIMIT 1`, runID).Scan(&kind)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if (p.Kind == domain.AgentStepToolStarted && kind == domain.AgentStepToolStarted) || (p.Kind == domain.AgentStepToolCompleted && kind != domain.AgentStepToolStarted) {
			return ErrConflict
		}
	}
	return nil
}

func (r *AgentRunner) Tx(ctx context.Context, params AgentTransition) (domain.AgentRun, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, request, hash, err := normalizeAgentTransition(params)
	if err != nil {
		return domain.AgentRun{}, err
	}
	tx, a, err := r.begin(ctx)
	if err != nil {
		return domain.AgentRun{}, err
	}
	defer rollbackAgentTx(tx)
	// [04] Every transaction reauthenticates and verifies ownership BEFORE even an idempotent replay.
	run, err := ownedAgentRun(ctx, tx, a, r.runID, true)
	if err != nil {
		return domain.AgentRun{}, err
	}
	old, err := replayAgentStep(ctx, tx, r.runID, p.Key, hash)
	if err == nil {
		return old, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return domain.AgentRun{}, err
	}
	next, err := applyAgentTransition(run, p)
	if err != nil {
		return domain.AgentRun{}, err
	}
	var live bool
	// [05] Evaluate wall clock only after acquiring the row lock, not from a stale lock-wait snapshot.
	if err = tx.QueryRow(ctx, `SELECT deadline_at>clock_timestamp() FROM agent_runs WHERE id=$1`, r.runID).Scan(&live); err != nil {
		return domain.AgentRun{}, err
	}
	if !live && !agentTerminal(next.State) && p.Kind != domain.AgentStepPaused && p.Kind != domain.AgentStepUnknown && p.Kind != domain.AgentStepModelCompleted && p.Kind != domain.AgentStepToolCompleted {
		return domain.AgentRun{}, ErrDenied
	}
	if err = validateAgentJournal(ctx, tx, r.runID, p); err != nil {
		return domain.AgentRun{}, err
	}
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&next.UpdatedAt); err != nil {
		return domain.AgentRun{}, err
	}
	growth := len(next.Checkpoint) + len(next.Reason) - len(run.Checkpoint) - len(run.Reason)
	if growth < 0 {
		growth = 0
	}
	base, err := agentAdd(run.StoredBytes, int64(growth), run.Limits.MaxStoredBytes)
	if err != nil {
		return domain.AgentRun{}, err
	}
	result, err := sizeAgentStep(&next, base, request, p.Payload, p.Key, p.Kind)
	if err != nil {
		return domain.AgentRun{}, err
	}
	// [06] CAS, checkpoint, counters and journal are one short transaction, never split around external IO.
	tag, err := tx.Exec(ctx, `UPDATE agent_runs SET state=$3,reason=$4,version=$5,last_seq=$6,checkpoint_text=$7,model_calls=$8,tool_calls=$9,tokens_reserved=$10,tokens_used=$11,stored_bytes=$12,updated_at=$13 WHERE id=$1 AND version=$2`, r.runID, p.ExpectedVersion, next.State, next.Reason, next.Version, next.LastSeq, string(next.Checkpoint), next.ModelCalls, next.ToolCalls, next.TokensReserved, next.TokensUsed, next.StoredBytes, next.UpdatedAt)
	if err != nil {
		return domain.AgentRun{}, err
	}
	if tag.RowsAffected() != 1 {
		return domain.AgentRun{}, ErrConflict
	}
	if err = insertAgentStep(ctx, tx, next, p.Key, hash, request, p.Kind, p.Payload, result); err != nil {
		return domain.AgentRun{}, err
	}
	return next, tx.Commit(ctx)
}
