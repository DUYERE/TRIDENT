package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"trident/internal/domain"
)

type ToolRequestInput struct {
	ToolName      string          `json:"tool_name"`
	ToolVersion   string          `json:"tool_version"`
	Target        string          `json:"target"`
	Protocol      string          `json:"protocol"`
	Port          uint16          `json:"port"`
	Action        string          `json:"action"`
	Arguments     json.RawMessage `json:"arguments"`
	PolicyVersion string          `json:"policy_version"`
}
type ToolRequest struct {
	ID         int64  `json:"id"`
	ApprovalID int64  `json:"approval_id"`
	Digest     string `json:"request_digest"`
}
type Admission struct {
	ID          int64  `json:"id"`
	ToolCallID  int64  `json:"tool_call_id"`
	Digest      string `json:"request_digest"`
	OfflineOnly bool   `json:"offline_only"`
}

func executionRequest(ctx context.Context, tx pgx.Tx, a actor, l Lease, input ToolRequestInput) (domain.ExecutionRequest, error) {
	r := domain.ExecutionRequest{TaskID: l.TaskID, MissionID: l.MissionID, LeaseID: l.ID, FencingToken: l.Token, RuntimeID: l.RuntimeID, RequesterID: a.id, ToolName: input.ToolName, ToolVersion: input.ToolVersion, Target: input.Target, Protocol: input.Protocol, Port: input.Port, Action: input.Action, Arguments: input.Arguments, PolicyVersion: input.PolicyVersion}
	var snapshot []byte
	e := tx.QueryRow(ctx, `SELECT m.authorization_id,m.scope_version,m.scope_hash,m.scope_snapshot FROM missions m WHERE m.task_id=$1 AND m.id=$2`, l.TaskID, l.MissionID).Scan(&r.AuthorizationID, &r.ScopeVersion, &r.ScopeHash, &snapshot)
	if e != nil {
		return r, e
	}
	var scope domain.Scope
	if e = json.Unmarshal(snapshot, &scope); e != nil {
		return r, e
	}
	if e = scope.AllowsURL(r.Target, r.Action); e != nil {
		return r, ErrDenied
	}
	return r, nil
}

// [01] 只创建离线包装器请求，目标URL仅作授权登记，不产生任何网络动作。
func (s *Store) RequestTool(ctx context.Context, ss Session, key string, l Lease, input ToolRequestInput, approvalTTL time.Duration) (ToolRequest, error) {
	raw, e := s.operation(ctx, ss, "tool.request", key, workerRequest{l, []any{input, int64(approvalTTL)}}, func(tx pgx.Tx, a actor) (any, error) {
		if approvalTTL < time.Millisecond || approvalTTL > 5*time.Minute || approvalTTL%time.Millisecond != 0 {
			return nil, ErrDenied
		}
		r, e := executionRequest(ctx, tx, a, l, input)
		if e != nil {
			return nil, e
		}
		snapshot, hash, e := r.Canonical()
		if e != nil {
			return nil, e
		}
		// [02] 存储必须来自规范化对象，不能把原始参数与规范摘要混用。
		if e = json.Unmarshal(snapshot, &r); e != nil {
			return nil, e
		}
		var out ToolRequest
		out.Digest = hash
		e = tx.QueryRow(ctx, `INSERT INTO tool_calls(task_id,mission_id,lease_id,fencing_token,runtime_id,requester_id,authorization_id,scope_version,scope_hash,tool_name,tool_version,target,protocol,port,action,arguments,policy_version,request_digest,request_snapshot,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,'pending') RETURNING id`, r.TaskID, r.MissionID, r.LeaseID, r.FencingToken, r.RuntimeID, r.RequesterID, r.AuthorizationID, r.ScopeVersion, r.ScopeHash, r.ToolName, r.ToolVersion, r.Target, r.Protocol, r.Port, r.Action, r.Arguments, r.PolicyVersion, hash, string(snapshot)).Scan(&out.ID)
		if e != nil {
			return nil, e
		}
		e = tx.QueryRow(ctx, `INSERT INTO approvals(task_id,mission_id,tool_call_id,lease_id,fencing_token,requester_id,request_digest,status,expires_at) SELECT $1,$2,$3,$4,$5,$6,$7,'pending',LEAST(clock_timestamp()+$8*interval '1 millisecond',l.lease_until,m.deadline_at) FROM execution_leases l JOIN missions m ON m.id=l.mission_id WHERE l.id=$4 RETURNING id`, l.TaskID, l.MissionID, out.ID, l.ID, l.Token, a.id, hash, approvalTTL.Milliseconds()).Scan(&out.ApprovalID)
		if e != nil {
			return nil, e
		}
		if e = validateLease(ctx, tx, a, l); e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, l.TaskID, "tool_call", out.ID, "approval.requested", out); e != nil {
			return nil, e
		}
		return out, nil
	})
	if e != nil {
		return ToolRequest{}, e
	}
	var out ToolRequest
	e = json.Unmarshal(raw, &out)
	return out, e
}

type storedTool struct {
	request        domain.ExecutionRequest
	digest, status string
	requester      actor
	lease          Lease
}

func lockTool(ctx context.Context, tx pgx.Tx, taskID, missionID, toolID int64) (storedTool, error) {
	var st storedTool
	var raw []byte
	e := tx.QueryRow(ctx, `SELECT t.request_snapshot,t.request_digest,t.status,p.id,p.role,p.principal_type FROM tool_calls t JOIN principals p ON p.id=t.requester_id WHERE t.task_id=$1 AND t.mission_id=$2 AND t.id=$3 FOR UPDATE OF t`, taskID, missionID, toolID).Scan(&raw, &st.digest, &st.status, &st.requester.id, &st.requester.role, &st.requester.kind)
	if e != nil {
		return st, e
	}
	if e = json.Unmarshal(raw, &st.request); e != nil {
		return st, e
	}
	_, hash, e := st.request.Canonical()
	if e != nil || hash != st.digest {
		return st, ErrDenied
	}
	st.lease = Lease{ID: st.request.LeaseID, TaskID: st.request.TaskID, MissionID: st.request.MissionID, Token: st.request.FencingToken, RuntimeID: st.request.RuntimeID}
	return st, nil
}

// [03] 锁前只读绑定，按 Mission->Pool->Lease->ToolCall->Approval 顺序取得所有锁。
func toolLease(ctx context.Context, tx pgx.Tx, taskID, missionID, toolID int64) (Lease, actor, error) {
	var l Lease
	var a actor
	e := tx.QueryRow(ctx, `SELECT t.lease_id,t.task_id,t.mission_id,t.fencing_token,t.runtime_id,p.id,p.role,p.principal_type FROM tool_calls t JOIN principals p ON p.id=t.requester_id WHERE t.task_id=$1 AND t.mission_id=$2 AND t.id=$3 AND p.status='active'`, taskID, missionID, toolID).Scan(&l.ID, &l.TaskID, &l.MissionID, &l.Token, &l.RuntimeID, &a.id, &a.role, &a.kind)
	return l, a, e
}
func (s *Store) ApproveTool(ctx context.Context, ss Session, key string, taskID, missionID, toolID int64, expectedDigest, reason string) (int64, error) {
	raw, e := s.operation(ctx, ss, "tool.approve", key, []any{taskID, missionID, toolID, expectedDigest, reason}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if a.kind != "human" || strings.TrimSpace(reason) == "" {
			return nil, ErrDenied
		}
		if _, e := taskActorLock(ctx, tx, a, taskID, true); e != nil {
			return nil, e
		}
		l, requester, e := toolLease(ctx, tx, taskID, missionID, toolID)
		if e != nil {
			return nil, e
		}
		if requester.id == a.id {
			return nil, ErrDenied
		}
		if e = validateLease(ctx, tx, requester, l); e != nil {
			return nil, e
		}
		st, e := lockTool(ctx, tx, taskID, missionID, toolID)
		if e != nil {
			return nil, e
		}
		if st.status != "pending" || st.digest != expectedDigest {
			return nil, ErrConflict
		}
		var approvalID int64
		e = tx.QueryRow(ctx, `SELECT id FROM approvals WHERE task_id=$1 AND mission_id=$2 AND tool_call_id=$3 FOR UPDATE`, taskID, missionID, toolID).Scan(&approvalID)
		if e != nil {
			return nil, e
		}
		if e = validateLease(ctx, tx, requester, l); e != nil {
			return nil, e
		}
		tag, e := tx.Exec(ctx, `UPDATE approvals SET status='approved',approver_id=$2,reason=$3,decided_at=clock_timestamp() WHERE id=$1 AND status='pending' AND request_digest=$4 AND expires_at>clock_timestamp() AND requester_id<>$2`, approvalID, a.id, reason, expectedDigest)
		if e != nil {
			return nil, e
		}
		if tag.RowsAffected() != 1 {
			return nil, ErrConflict
		}
		if e = event(ctx, tx, a, taskID, "tool_call", toolID, "approval.approved", map[string]any{"approval_id": approvalID, "request_digest": expectedDigest}); e != nil {
			return nil, e
		}
		return approvalID, nil
	})
	return resultID(raw, e)
}

func (s *Store) AdmitTool(ctx context.Context, ss Session, key string, l Lease, toolID int64, expectedDigest string) (Admission, error) {
	raw, e := s.operation(ctx, ss, "tool.admit", key, workerRequest{l, []any{toolID, expectedDigest}}, func(tx pgx.Tx, a actor) (any, error) {
		st, e := lockTool(ctx, tx, l.TaskID, l.MissionID, toolID)
		if e != nil {
			return nil, e
		}
		if st.digest != expectedDigest || st.status != "pending" || st.requester.id != a.id || st.lease != l {
			return nil, ErrConflict
		}
		var approvalID int64
		e = tx.QueryRow(ctx, `SELECT id FROM approvals WHERE task_id=$1 AND mission_id=$2 AND tool_call_id=$3 FOR UPDATE`, l.TaskID, l.MissionID, toolID).Scan(&approvalID)
		if e != nil {
			return nil, e
		}
		// [04] 预算消费可能等锁，审批最终有效期必须在账本锁后再次验证。
		if e = consumeTx(ctx, tx, l.MissionID, "steps", 1); e != nil {
			return nil, e
		}
		if e = validateLease(ctx, tx, a, l); e != nil {
			return nil, e
		}
		var currentPolicy bool
		e = tx.QueryRow(ctx, `SELECT t.policy_version=$2 AND t.scope_version=k.current_scope_ver AND t.scope_hash=v.scope_hash AND t.authorization_id=k.authorization_id AND t.status='pending' FROM tool_calls t JOIN tasks k ON k.id=t.task_id JOIN authorization_versions v ON v.authorization_id=k.authorization_id AND v.version=k.current_scope_ver WHERE t.id=$1`, toolID, domain.OfflinePolicyVersion).Scan(&currentPolicy)
		if e != nil {
			return nil, e
		}
		if !currentPolicy {
			return nil, ErrDenied
		}
		tag, e := tx.Exec(ctx, `UPDATE approvals SET status='consumed',consumed_at=clock_timestamp() WHERE id=$1 AND status='approved' AND request_digest=$2 AND expires_at>clock_timestamp() AND approver_id IS NOT NULL AND EXISTS(SELECT 1 FROM principals p WHERE p.id=approvals.approver_id AND p.status='active' AND p.role='admin' AND p.principal_type='human')`, approvalID, expectedDigest)
		if e != nil {
			return nil, e
		}
		if tag.RowsAffected() != 1 {
			return nil, ErrConflict
		}
		var out Admission
		out.ToolCallID = toolID
		out.Digest = expectedDigest
		out.OfflineOnly = true
		e = tx.QueryRow(ctx, `INSERT INTO tool_admissions(task_id,mission_id,tool_call_id,approval_id,request_digest) VALUES($1,$2,$3,$4,$5) RETURNING id`, l.TaskID, l.MissionID, toolID, approvalID, expectedDigest).Scan(&out.ID)
		if e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `UPDATE tool_calls SET status='admitted',admitted_at=clock_timestamp() WHERE id=$1`, toolID); e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, l.TaskID, "tool_call", toolID, "tool.admitted_offline", out); e != nil {
			return nil, e
		}
		return out, nil
	})
	if e != nil {
		return Admission{}, e
	}
	var out Admission
	e = json.Unmarshal(raw, &out)
	return out, e
}
