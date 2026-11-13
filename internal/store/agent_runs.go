package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"trident/internal/domain"
)

// [01] Ownership always comes from the authenticated Session, never from caller input.
type CreateAgentRunParams struct {
	Key          string
	SnapshotPath string
	SnapshotHash string
	Goal         string
	Config       json.RawMessage
	Limits       domain.AgentLimits
	Deadline     time.Time
}

// [02] Tx accepts only fixed event kinds, validated deltas and CAS. Nil Checkpoint preserves it.
type AgentTransition struct {
	ExpectedVersion    int64
	Key                string
	Kind               domain.AgentStepKind
	Payload            json.RawMessage
	Checkpoint         json.RawMessage
	State              domain.AgentRunState
	Reason             string
	ModelDelta         int64
	ToolDelta          int64
	ReservedTokenDelta int64
	UsedTokenDelta     int64
}

const agentRunColumns = `id,owner_id,snapshot_path,snapshot_hash,goal,config_text,config_hash,state,reason,version,last_seq,checkpoint_text,model_calls,tool_calls,tokens_reserved,tokens_used,stored_bytes,max_model_calls,max_tool_calls,max_tokens,max_stored_bytes,deadline_at,created_at,updated_at`

func scanAgentRun(row pgx.Row) (domain.AgentRun, error) {
	var r domain.AgentRun
	var config, checkpoint string
	err := row.Scan(&r.ID, &r.OwnerID, &r.SnapshotPath, &r.SnapshotHash, &r.Goal, &config, &r.ConfigHash, &r.State, &r.Reason, &r.Version, &r.LastSeq, &checkpoint, &r.ModelCalls, &r.ToolCalls, &r.TokensReserved, &r.TokensUsed, &r.StoredBytes, &r.Limits.MaxModelCalls, &r.Limits.MaxToolCalls, &r.Limits.MaxTokens, &r.Limits.MaxStoredBytes, &r.Deadline, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrDenied
	}
	r.Config, r.Checkpoint = json.RawMessage(config), json.RawMessage(checkpoint)
	return r, err
}

func agentActor(ctx context.Context, tx pgx.Tx, ss Session) (actor, error) {
	a, err := authenticateTx(ctx, tx, ss)
	if err != nil {
		return a, err
	}
	if a.kind != "human" || (a.role != "admin" && a.role != "scheduler") {
		return a, ErrDenied
	}
	return a, nil
}

func ownedAgentRun(ctx context.Context, tx pgx.Tx, a actor, runID int64, lock bool) (domain.AgentRun, error) {
	query := `SELECT ` + agentRunColumns + ` FROM agent_runs WHERE id=$1 AND owner_id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	return scanAgentRun(tx.QueryRow(ctx, query, runID, a.id))
}

func rollbackAgentTx(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func normalizeAgentCreate(p CreateAgentRunParams) (CreateAgentRunParams, []byte, string, error) {
	if !agentKey(p.Key) || !agentText(p.SnapshotPath, 4096, true) || !agentText(p.Goal, 16384, true) || len(p.SnapshotHash) != 64 || p.Deadline.IsZero() {
		return p, nil, "", ErrDenied
	}
	if _, err := hex.DecodeString(p.SnapshotHash); err != nil {
		return p, nil, "", ErrDenied
	}
	p.SnapshotHash = strings.ToLower(p.SnapshotHash)
	p.Deadline = p.Deadline.UTC().Truncate(time.Microsecond)
	if p.Limits.MaxModelCalls < 0 || p.Limits.MaxModelCalls > 64 || p.Limits.MaxToolCalls < 0 || p.Limits.MaxToolCalls > 256 || p.Limits.MaxTokens < 0 || p.Limits.MaxTokens > 100_000_000 || p.Limits.MaxStoredBytes < 2*agentTerminalHeadroom || p.Limits.MaxStoredBytes > 64*1024*1024 {
		return p, nil, "", ErrBudget
	}
	var err error
	p.Config, err = canonicalAgentJSON(p.Config, agentConfigMaxBytes, false)
	if err != nil {
		return p, nil, "", err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return p, nil, "", err
	}
	return p, raw, agentHash(raw), nil
}

func (s *Store) CreateAgentRun(ctx context.Context, ss Session, params CreateAgentRunParams) (domain.AgentRun, error) {
	p, request, hash, err := normalizeAgentCreate(params)
	if err != nil {
		return domain.AgentRun{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AgentRun{}, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return domain.AgentRun{}, err
	}
	// [03] Serializes creation/replay per authenticated owner, without reusing operationTask/outbox.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, fmt.Sprintf("trident.agent.create/%d/%s", a.id, p.Key)); err != nil {
		return domain.AgentRun{}, err
	}
	var existingID int64
	var previous string
	err = tx.QueryRow(ctx, `SELECT id,creation_digest FROM agent_runs WHERE owner_id=$1 AND creation_key=$2`, a.id, p.Key).Scan(&existingID, &previous)
	if err == nil {
		if previous != hash {
			return domain.AgentRun{}, ErrConflict
		}
		run, e := replayAgentStep(ctx, tx, existingID, p.Key, hash)
		if e != nil {
			return domain.AgentRun{}, e
		}
		return run, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return domain.AgentRun{}, err
	}
	var live bool
	if err = tx.QueryRow(ctx, `SELECT $1::timestamptz>clock_timestamp()`, p.Deadline).Scan(&live); err != nil {
		return domain.AgentRun{}, err
	}
	if !live {
		return domain.AgentRun{}, ErrDenied
	}
	run := domain.AgentRun{OwnerID: a.id, SnapshotPath: p.SnapshotPath, SnapshotHash: p.SnapshotHash, Goal: p.Goal, Config: p.Config, ConfigHash: agentHash(p.Config), State: domain.AgentRunReady, Version: 1, LastSeq: 1, Checkpoint: json.RawMessage(`{}`), Limits: p.Limits, Deadline: p.Deadline}
	// Allocate only this new Run ID; no identities are reset and a rollback may leave a normal sequence gap.
	if err = tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('agent_runs','id')),clock_timestamp()`).Scan(&run.ID, &run.CreatedAt); err != nil {
		return domain.AgentRun{}, err
	}
	run.UpdatedAt = run.CreatedAt
	// Map encoding sorts keys just like canonicalAgentJSON used for subsequent steps.
	payload, _ := json.Marshal(map[string]string{"snapshot_hash": run.SnapshotHash, "config_hash": run.ConfigHash})
	// [04] INSERT may set initial storage directly; no invisible follow-up aggregate mutation is needed.
	base := int64(len(run.SnapshotPath) + len(run.SnapshotHash) + len(run.Goal) + len(run.Config) + len(run.ConfigHash) + len(run.Checkpoint) + len(p.Key) + len(hash))
	result, err := sizeAgentStep(&run, base, request, payload, p.Key, domain.AgentStepCreated)
	if err != nil {
		return domain.AgentRun{}, err
	}
	// [05] The first aggregate and its creation journal entry are committed together, with exact storage charge.
	if _, err = tx.Exec(ctx, `INSERT INTO agent_runs(id,owner_id,creation_key,creation_digest,snapshot_path,snapshot_hash,goal,config_text,config_hash,state,version,last_seq,stored_bytes,max_model_calls,max_tool_calls,max_tokens,max_stored_bytes,deadline_at,created_at,updated_at) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'ready',1,1,$10,$11,$12,$13,$14,$15,$16,$16)`, run.ID, a.id, p.Key, hash, p.SnapshotPath, p.SnapshotHash, p.Goal, string(p.Config), run.ConfigHash, run.StoredBytes, p.Limits.MaxModelCalls, p.Limits.MaxToolCalls, p.Limits.MaxTokens, p.Limits.MaxStoredBytes, p.Deadline, run.CreatedAt); err != nil {
		return domain.AgentRun{}, err
	}
	if err = insertAgentStep(ctx, tx, run, p.Key, hash, request, domain.AgentStepCreated, payload, result); err != nil {
		return domain.AgentRun{}, err
	}
	return run, tx.Commit(ctx)
}

func replayAgentStep(ctx context.Context, tx pgx.Tx, runID int64, key, hash string) (domain.AgentRun, error) {
	var oldHash, raw string
	err := tx.QueryRow(ctx, `SELECT request_digest,result_text FROM agent_run_steps WHERE run_id=$1 AND idempotency_key=$2`, runID, key).Scan(&oldHash, &raw)
	if err != nil {
		return domain.AgentRun{}, err
	}
	if oldHash != hash {
		return domain.AgentRun{}, ErrConflict
	}
	var run domain.AgentRun
	if err = json.Unmarshal([]byte(raw), &run); err != nil {
		return domain.AgentRun{}, fmt.Errorf("decode agent replay: %w", err)
	}
	return run, nil
}

// [06] Charges canonical request/payload, exact replay result and durable text metadata; no caller delta.
func sizeAgentStep(run *domain.AgentRun, base int64, request, payload []byte, key string, kind domain.AgentStepKind) ([]byte, error) {
	stepBytes := int64(len(request) + len(payload) + len(key) + len(kind) + 128 + 64)
	var result []byte
	for i := 0; i < 8; i++ {
		var err error
		result, err = json.Marshal(run)
		if err != nil {
			return nil, err
		}
		next, err := agentAdd(base, stepBytes+int64(len(result)), run.Limits.MaxStoredBytes)
		if err != nil {
			return nil, err
		}
		if next == run.StoredBytes {
			break
		}
		run.StoredBytes = next
	}
	if !agentTerminal(run.State) {
		// [07] Terminal result repeats checkpoint/config. Reserve enough for it even at their maximum sizes.
		headroom := int64(len(result) + 8192)
		if headroom < agentTerminalHeadroom {
			headroom = agentTerminalHeadroom
		}
		if run.StoredBytes > run.Limits.MaxStoredBytes-headroom {
			return nil, ErrBudget
		}
	}
	return result, nil
}

func insertAgentStep(ctx context.Context, tx pgx.Tx, run domain.AgentRun, key, hash string, request []byte, kind domain.AgentStepKind, payload, result []byte) error {
	_, err := tx.Exec(ctx, `INSERT INTO agent_run_steps(run_id,seq,version,idempotency_key,request_digest,request_text,kind,payload_text,payload_hash,result_text) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, run.ID, run.LastSeq, run.Version, key, hash, string(request), kind, string(payload), agentHash(payload), string(result))
	return err
}

func (s *Store) GetAgentRun(ctx context.Context, ss Session, runID int64) (domain.AgentRun, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.AgentRun{}, err
	}
	defer rollbackAgentTx(tx)
	a, err := agentActor(ctx, tx, ss)
	if err != nil {
		return domain.AgentRun{}, err
	}
	run, err := ownedAgentRun(ctx, tx, a, runID, false)
	if err != nil {
		return domain.AgentRun{}, err
	}
	return run, tx.Commit(ctx)
}

func readAgentSteps(ctx context.Context, tx pgx.Tx, runID, afterSeq int64, limit int) ([]domain.AgentStep, error) {
	if afterSeq < 0 || limit < 1 || limit > 1000 {
		return nil, ErrDenied
	}
	rows, err := tx.Query(ctx, `SELECT run_id,seq,version,idempotency_key,request_digest,kind,payload_text,payload_hash,created_at FROM agent_run_steps WHERE run_id=$1 AND seq>$2 ORDER BY seq LIMIT $3`, runID, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	steps := make([]domain.AgentStep, 0)
	for rows.Next() {
		var step domain.AgentStep
		var payload string
		if err = rows.Scan(&step.RunID, &step.Seq, &step.Version, &step.Key, &step.Digest, &step.Kind, &payload, &step.PayloadHash, &step.CreatedAt); err != nil {
			return nil, err
		}
		step.Payload = json.RawMessage(payload)
		steps = append(steps, step)
	}
	return steps, rows.Err()
}

func (s *Store) ListAgentRunSteps(ctx context.Context, ss Session, runID, afterSeq int64, limit int) ([]domain.AgentStep, error) {
	tx, err := s.pool.Begin(ctx)
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
	steps, err := readAgentSteps(ctx, tx, runID, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	return steps, tx.Commit(ctx)
}
