package store

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
)

// RecoverExpired 只执行数据库侧安全隔离；未确认副作用的预留绝不自动释放或重试。
func (s *Store) RecoverExpired(ctx context.Context, ss Session, key string, taskID, missionID int64) (int64, error) {
	raw, e := s.operation(ctx, ss, "mission.recover", key, []any{taskID, missionID}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "reconciler"); e != nil {
			return nil, e
		}
		if _, e := taskLock(ctx, tx, taskID, false); e != nil {
			return nil, e
		}
		var state string
		e := tx.QueryRow(ctx, `SELECT state FROM missions WHERE task_id=$1 AND id=$2 FOR UPDATE`, taskID, missionID).Scan(&state)
		if e != nil {
			return nil, e
		}
		if state != "running" {
			return nil, ErrConflict
		}
		var live bool
		e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM execution_leases WHERE task_id=$1 AND mission_id=$2 AND status='active' AND lease_until>clock_timestamp())`, taskID, missionID).Scan(&live)
		if e != nil {
			return nil, e
		}
		if live {
			return nil, ErrConflict
		}
		if _, e = tx.Exec(ctx, `UPDATE execution_leases SET status='expired',released_at=clock_timestamp() WHERE task_id=$1 AND mission_id=$2 AND status='active'`, taskID, missionID); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `UPDATE missions SET state='blocked',version=version+1 WHERE id=$1`, missionID); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `UPDATE intents SET state='blocked',version=version+1 WHERE id=(SELECT intent_id FROM missions WHERE id=$1)`, missionID); e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, taskID, "mission", missionID, "mission.recovery_blocked", map[string]any{"reason": "lease expired; side effects require review", "budget_retained": true}); e != nil {
			return nil, e
		}
		return missionID, nil
	})
	return resultID(raw, e)
}

// RetryReviewed 需要管理员明确确认旧执行已终止且重试安全；P0 本身不能证明真实进程已结束。
func (s *Store) RetryReviewed(ctx context.Context, ss Session, key string, taskID, missionID int64, reason string) (int64, error) {
	raw, e := s.operation(ctx, ss, "mission.retry_reviewed", key, []any{taskID, missionID, reason}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if a.kind != "human" || strings.TrimSpace(reason) == "" {
			return nil, ErrDenied
		}
		if _, e := taskLock(ctx, tx, taskID, true); e != nil {
			return nil, e
		}
		var state string
		var attempt, max int
		e := tx.QueryRow(ctx, `SELECT state,attempt_count,max_attempts FROM missions WHERE task_id=$1 AND id=$2 FOR UPDATE`, taskID, missionID).Scan(&state, &attempt, &max)
		if e != nil {
			return nil, e
		}
		if state != "blocked" || attempt >= max {
			return nil, ErrConflict
		}
		var currentScope bool
		if e = tx.QueryRow(ctx, `SELECT m.scope_version=t.current_scope_ver AND m.scope_hash=v.scope_hash AND v.status='active' FROM missions m JOIN tasks t ON t.id=m.task_id JOIN authorization_versions v ON v.authorization_id=t.authorization_id AND v.version=t.current_scope_ver WHERE m.task_id=$1 AND m.id=$2`, taskID, missionID).Scan(&currentScope); e != nil {
			return nil, e
		}
		if !currentScope {
			return nil, ErrDenied
		}
		// [02] 已结算的执行不能凭旧预留重试；必须另建 Mission 重新预留预算。
		var reserved bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM budget_reservations WHERE mission_id=$1 AND status='active' AND amount>consumed) AND NOT EXISTS(SELECT 1 FROM budget_reservations WHERE mission_id=$1 AND status<>'active')`, missionID).Scan(&reserved); e != nil {
			return nil, e
		}
		if !reserved {
			return nil, ErrBudget
		}
		var active bool
		e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM execution_leases WHERE mission_id=$1 AND status='active' AND lease_until>clock_timestamp())`, missionID).Scan(&active)
		if e != nil {
			return nil, e
		}
		if active {
			return nil, ErrConflict
		}
		if _, e = tx.Exec(ctx, `UPDATE execution_leases SET status='revoked',released_at=clock_timestamp() WHERE mission_id=$1 AND status='active'`, missionID); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `UPDATE missions SET state='retry_pending',version=version+1 WHERE id=$1`, missionID); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `UPDATE intents SET state='running',version=version+1 WHERE id=(SELECT intent_id FROM missions WHERE id=$1)`, missionID); e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, taskID, "mission", missionID, "mission.retry_reviewed", map[string]any{"reason": reason, "reviewer": a.id}); e != nil {
			return nil, e
		}
		return missionID, nil
	})
	return resultID(raw, e)
}

// SettleReviewed 只允许可信服务对已停止执行做已知消费结算，不接收任意消费覆盖值。
func (s *Store) SettleReviewed(ctx context.Context, ss Session, key string, taskID, missionID int64, reason string) error {
	_, e := s.operation(ctx, ss, "mission.settle_reviewed", key, []any{taskID, missionID, reason}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "reconciler"); e != nil {
			return nil, e
		}
		if strings.TrimSpace(reason) == "" {
			return nil, ErrDenied
		}
		if _, e := taskLock(ctx, tx, taskID, false); e != nil {
			return nil, e
		}
		var state string
		e := tx.QueryRow(ctx, `SELECT state FROM missions WHERE task_id=$1 AND id=$2 FOR UPDATE`, taskID, missionID).Scan(&state)
		if e != nil {
			return nil, e
		}
		if state == "pending" || state == "running" || state == "retry_pending" {
			return nil, ErrConflict
		}
		if e = settle(ctx, tx, missionID); e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, taskID, "mission", missionID, "budget.settled_reviewed", map[string]any{"reason": reason}); e != nil {
			return nil, e
		}
		return missionID, nil
	})
	return e
}
