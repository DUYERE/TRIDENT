package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"trident/internal/domain"
)

// 观察面只读查询：控制台以 trident_readonly 等受限定账号连接，可见范围由
// 数据库权限兜底；这里不做应用层 actor 认证，也绝不返回凭据哈希。
// 这些方法只读，不写任何表。

func (s *Store) ListAgentRunsReadOnly(ctx context.Context, limit int) ([]domain.AgentRun, error) {
	if limit < 1 || limit > 200 {
		return nil, ErrDenied
	}
	rows, err := s.pool.Query(ctx, `SELECT `+agentRunColumns+` FROM agent_runs ORDER BY updated_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs := make([]domain.AgentRun, 0)
	for rows.Next() {
		run, scanErr := scanAgentRun(rows)
		if scanErr != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

func (s *Store) GetAgentRunReadOnly(ctx context.Context, runID int64) (domain.AgentRun, error) {
	if runID < 1 {
		return domain.AgentRun{}, ErrDenied
	}
	run, err := scanAgentRun(s.pool.QueryRow(ctx, `SELECT `+agentRunColumns+` FROM agent_runs WHERE id=$1`, runID))
	if err == pgx.ErrNoRows {
		return domain.AgentRun{}, ErrDenied
	}
	return run, err
}

func (s *Store) ListAgentStepsReadOnly(ctx context.Context, runID, afterSeq int64, limit int) ([]domain.AgentStep, error) {
	if runID < 1 || afterSeq < 0 || limit < 1 || limit > 1000 {
		return nil, ErrDenied
	}
	rows, err := s.pool.Query(ctx, `SELECT run_id,seq,version,idempotency_key,request_digest,kind,payload_text,payload_hash,created_at FROM agent_run_steps WHERE run_id=$1 AND seq>$2 ORDER BY seq LIMIT $3`, runID, afterSeq, limit)
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
