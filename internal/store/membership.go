package store

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
)

// [01] 任务权限在幂等回执前校验；停止任务的历史回执仍可读取，但撤销成员不能读取。
func taskActorLock(ctx context.Context, tx pgx.Tx, a actor, taskID int64, needActive bool) (int64, error) {
	auth, e := taskLock(ctx, tx, taskID, needActive)
	if e != nil {
		return 0, e
	}
	if a.role == "admin" && a.kind == "human" {
		return auth, nil
	}
	var granted bool
	e = tx.QueryRow(ctx, `SELECT status='active' AND role=$3 FROM task_members WHERE task_id=$1 AND principal_id=$2 FOR SHARE`, taskID, a.id, a.role).Scan(&granted)
	if e == pgx.ErrNoRows {
		return 0, ErrDenied
	}
	if e != nil {
		return 0, e
	}
	if !granted {
		return 0, ErrDenied
	}
	return auth, nil
}

// [02] 显式列出任务型操作，避免把授权合同ID或其他全局资源ID误当Task。
func operationTask(op string, request any) int64 {
	if r, ok := request.(workerRequest); ok {
		return r.Lease.TaskID
	}
	if r, ok := request.(MissionRequest); ok {
		return r.TaskID
	}
	switch op {
	case "asset.register", "asset.review", "intent.create", "budget.allocate", "mission.claim", "fact.validate", "intent.link_dependency", "mission.recover", "mission.retry_reviewed", "mission.settle_reviewed", "member.grant", "member.revoke", "tool.approve":
		if r, ok := request.([]any); ok && len(r) > 0 {
			if id, ok := r[0].(int64); ok {
				return id
			}
		}
	}
	return 0
}
func (s *Store) GrantTaskMember(ctx context.Context, ss Session, key string, taskID, principalID int64, role, reason string) (int64, error) {
	raw, e := s.operation(ctx, ss, "member.grant", key, []any{taskID, principalID, role, reason}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if a.kind != "human" || strings.TrimSpace(reason) == "" {
			return nil, ErrDenied
		}
		var currentRole, status string
		e := tx.QueryRow(ctx, `SELECT role,status FROM principals WHERE id=$1`, principalID).Scan(&currentRole, &status)
		if e != nil {
			return nil, e
		}
		if role != currentRole || status != "active" {
			return nil, ErrDenied
		}
		_, e = tx.Exec(ctx, `INSERT INTO task_members(task_id,principal_id,role,status,granted_by,reason) VALUES($1,$2,$3,'active',$4,$5) ON CONFLICT(task_id,principal_id) DO UPDATE SET role=EXCLUDED.role,status='active',granted_by=EXCLUDED.granted_by,reason=EXCLUDED.reason,updated_at=clock_timestamp()`, taskID, principalID, role, a.id, reason)
		if e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, taskID, "task", taskID, "task.member_granted", map[string]any{"principal_id": principalID, "role": role, "reason": reason}); e != nil {
			return nil, e
		}
		return principalID, nil
	})
	return resultID(raw, e)
}
func (s *Store) RevokeTaskMember(ctx context.Context, ss Session, key string, taskID, principalID int64, reason string) error {
	_, e := s.operation(ctx, ss, "member.revoke", key, []any{taskID, principalID, reason}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if a.kind != "human" || strings.TrimSpace(reason) == "" {
			return nil, ErrDenied
		}
		tag, e := tx.Exec(ctx, `UPDATE task_members SET status='revoked',reason=$3,updated_at=clock_timestamp() WHERE task_id=$1 AND principal_id=$2`, taskID, principalID, reason)
		if e != nil {
			return nil, e
		}
		if tag.RowsAffected() != 1 {
			return nil, ErrDenied
		}
		// [03] 与同Task执行共享合同/Task锁；先阻断原Mission，再撤销租约，绝不自动退款。
		_, e = tx.Exec(ctx, `UPDATE missions SET state='blocked',version=version+1 WHERE task_id=$1 AND state='running' AND id IN(SELECT mission_id FROM execution_leases WHERE task_id=$1 AND holder=$2 AND status='active')`, taskID, principalID)
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `UPDATE intents SET state='blocked',version=version+1 WHERE task_id=$1 AND state='running' AND id IN(SELECT m.intent_id FROM missions m JOIN execution_leases l ON l.mission_id=m.id WHERE l.task_id=$1 AND l.holder=$2 AND l.status='active')`, taskID, principalID)
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `UPDATE execution_leases SET status='revoked',released_at=clock_timestamp() WHERE task_id=$1 AND holder=$2 AND status='active'`, taskID, principalID)
		if e != nil {
			return nil, e
		}
		if e = invalidateRequests(ctx, tx, taskID, principalID); e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, taskID, "task", taskID, "task.member_revoked", map[string]any{"principal_id": principalID, "reason": reason, "budget_retained": true}); e != nil {
			return nil, e
		}
		return principalID, nil
	})
	return e
}

// [04] 消费过的准入是历史记录，不得因撤销抹掉；未消费请求与审批同步失效。
func invalidateRequests(ctx context.Context, tx pgx.Tx, taskID, requesterID int64) error {
	if _, e := tx.Exec(ctx, `UPDATE tool_calls SET status='revoked' WHERE task_id=$1 AND status='pending' AND ($2::bigint=0 OR requester_id=$2)`, taskID, requesterID); e != nil {
		return e
	}
	_, e := tx.Exec(ctx, `UPDATE approvals SET status='revoked' WHERE task_id=$1 AND status IN ('pending','approved') AND ($2::bigint=0 OR requester_id=$2)`, taskID, requesterID)
	return e
}
