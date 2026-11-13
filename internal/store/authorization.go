package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"trident/internal/domain"
)

type AuthorizationRequest struct {
	PrincipalID    int64        `json:"principal_id"`
	Scope          domain.Scope `json:"scope"`
	ValidFrom      time.Time    `json:"valid_from"`
	ExpiresAt      time.Time    `json:"expires_at"`
	ProofRef       string       `json:"proof_ref"`
	ProofHash      string       `json:"proof_hash"`
	SingleOperator bool         `json:"single_operator_mode"`
}

// CreateAuthorization 创建 draft；人工证明核验与激活是独立操作，不信任请求自报 verified。
func (s *Store) CreateAuthorization(ctx context.Context, ss Session, key string, r AuthorizationRequest) (int64, error) {
	raw, e := s.operation(ctx, ss, "authorization.create", key, r, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if a.kind != "human" {
			return nil, ErrDenied
		}
		canonical, hash, e := r.Scope.Canonical()
		if e != nil {
			return nil, e
		}
		if !r.ExpiresAt.After(r.ValidFrom) || r.PrincipalID == 0 || strings.TrimSpace(r.ProofRef) == "" || len(r.ProofHash) != 64 {
			return nil, ErrDenied
		}
		if r.SingleOperator && !s.singleOperator {
			return nil, ErrDenied
		}
		var active bool
		e = tx.QueryRow(ctx, `SELECT status='active' AND principal_type IN ('human','organization') FROM principals WHERE id=$1 FOR SHARE`, r.PrincipalID).Scan(&active)
		if e != nil {
			return nil, e
		}
		if !active {
			return nil, ErrDenied
		}
		var id int64
		e = tx.QueryRow(ctx, `INSERT INTO authorization_contracts(principal_id,valid_from,expires_at,single_operator_mode) VALUES($1,$2,$3,$4) RETURNING id`, r.PrincipalID, r.ValidFrom, r.ExpiresAt, r.SingleOperator).Scan(&id)
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO authorization_versions(authorization_id,version,scope_document,scope_hash,created_by) VALUES($1,1,$2,$3,$4)`, id, canonical, hash, a.id)
		if e != nil {
			return nil, e
		}
		// [01] 这里只记录提交的证明摘要，核验者须在激活步骤明确作出人工证明确认。
		payload := map[string]any{"scope_hash": hash, "proof_ref": r.ProofRef, "proof_hash": r.ProofHash, "single_operator_mode": r.SingleOperator}
		if e = authEvent(ctx, tx, a, id, "submitted", payload); e != nil {
			return nil, e
		}
		return id, nil
	})
	return resultID(raw, e)
}
func authEvent(ctx context.Context, tx pgx.Tx, a actor, id int64, name string, payload any) error {
	var previous string
	e := tx.QueryRow(ctx, `SELECT event_hash FROM authorization_events WHERE authorization_id=$1 ORDER BY id DESC LIMIT 1`, id).Scan(&previous)
	if e != nil && e != pgx.ErrNoRows {
		return e
	}
	raw, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	hash, e := digest(struct {
		AuthorizationID, ActorID int64
		Event, Previous          string
		Payload                  json.RawMessage
	}{id, a.id, name, previous, raw})
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO authorization_events(authorization_id,actor_id,event_type,payload,previous_event_hash,event_hash) VALUES($1,$2,$3,$4,$5,$6)`, id, a.id, name, raw, previous, hash)
	return e
}
func (s *Store) ActivateAuthorization(ctx context.Context, ss Session, key string, id int64, attestation string) (int64, error) {
	raw, e := s.operation(ctx, ss, "authorization.activate", key, []any{id, attestation}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if a.kind != "human" || strings.TrimSpace(attestation) == "" {
			return nil, ErrDenied
		}
		var owner int64
		var single, valid bool
		var status string
		e := tx.QueryRow(ctx, `SELECT principal_id,single_operator_mode,status,valid_from<=clock_timestamp() AND expires_at>clock_timestamp() FROM authorization_contracts WHERE id=$1 FOR UPDATE`, id).Scan(&owner, &single, &status, &valid)
		if e != nil {
			return nil, e
		}
		// [03] 必须在合同锁到手后独立检查时钟，锁前计算的布尔值不可作为最终许可。
		if e = tx.QueryRow(ctx, `SELECT valid_from<=clock_timestamp() AND expires_at>clock_timestamp() FROM authorization_contracts WHERE id=$1`, id).Scan(&valid); e != nil {
			return nil, e
		}
		if status != "draft" || !valid || (owner == a.id && (!single || !s.singleOperator)) {
			return nil, ErrDenied
		}
		var ownerActive bool
		e = tx.QueryRow(ctx, `SELECT status='active' FROM principals WHERE id=$1`, owner).Scan(&ownerActive)
		if e != nil {
			return nil, e
		}
		if !ownerActive {
			return nil, ErrDenied
		}
		var payloadRaw []byte
		e = tx.QueryRow(ctx, `SELECT payload FROM authorization_events WHERE authorization_id=$1 AND event_type='submitted' ORDER BY id DESC LIMIT 1`, id).Scan(&payloadRaw)
		if e != nil {
			return nil, e
		}
		var p struct {
			ProofRef  string `json:"proof_ref"`
			ProofHash string `json:"proof_hash"`
		}
		if e = json.Unmarshal(payloadRaw, &p); e != nil {
			return nil, e
		}
		var scopeRaw []byte
		var storedHash string
		e = tx.QueryRow(ctx, `SELECT scope_document,scope_hash FROM authorization_versions WHERE authorization_id=$1 AND version=1 AND status='active' FOR UPDATE`, id).Scan(&scopeRaw, &storedHash)
		if e != nil {
			return nil, e
		}
		var scope domain.Scope
		if e = json.Unmarshal(scopeRaw, &scope); e != nil {
			return nil, e
		}
		_, actualHash, e := scope.Canonical()
		if e != nil || actualHash != storedHash {
			return nil, ErrDenied
		}
		if e = tx.QueryRow(ctx, `SELECT valid_from<=clock_timestamp() AND expires_at>clock_timestamp() FROM authorization_contracts WHERE id=$1`, id).Scan(&valid); e != nil {
			return nil, e
		}
		if !valid {
			return nil, ErrDenied
		}
		_, e = tx.Exec(ctx, `INSERT INTO authorization_proofs(authorization_id,proof_type,storage_ref,content_hash,verified_by_principal_id,verification_status) VALUES($1,'manual_attestation',$2,$3,$4,'verified')`, id, p.ProofRef, p.ProofHash, a.id)
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `UPDATE authorization_contracts SET status='active',approved_by_principal_id=$2 WHERE id=$1`, id, a.id)
		if e != nil {
			return nil, e
		}
		if e = authEvent(ctx, tx, a, id, "activated", map[string]any{"attestation": attestation, "scope_hash": storedHash, "single_operator_mode": single}); e != nil {
			return nil, e
		}
		return id, nil
	})
	return resultID(raw, e)
}
func (s *Store) RevokeAuthorization(ctx context.Context, ss Session, key string, id int64, reason string) (int64, error) {
	raw, e := s.operation(ctx, ss, "authorization.revoke", key, []any{id, reason}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if strings.TrimSpace(reason) == "" {
			return nil, ErrDenied
		}
		var old string
		e := tx.QueryRow(ctx, `SELECT status FROM authorization_contracts WHERE id=$1 FOR UPDATE`, id).Scan(&old)
		if e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `UPDATE authorization_contracts SET status='revoked' WHERE id=$1`, id); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `UPDATE authorization_versions SET status='revoked' WHERE authorization_id=$1 AND status='active'`, id); e != nil {
			return nil, e
		}
		rows, e := tx.Query(ctx, `SELECT id FROM tasks WHERE authorization_id=$1 ORDER BY id FOR UPDATE`, id)
		if e != nil {
			return nil, e
		}
		var ids []int64
		for rows.Next() {
			var t int64
			if e = rows.Scan(&t); e != nil {
				rows.Close()
				return nil, e
			}
			ids = append(ids, t)
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return nil, e
		}
		for _, t := range ids {
			if e = invalidateRequests(ctx, tx, t, 0); e != nil {
				return nil, e
			}
			if _, e = tx.Exec(ctx, `UPDATE execution_leases SET status='revoked',released_at=clock_timestamp() WHERE task_id=$1 AND status='active'`, t); e != nil {
				return nil, e
			}
			if _, e = tx.Exec(ctx, `UPDATE missions SET state='stopped',version=version+1 WHERE task_id=$1 AND state IN ('pending','running','retry_pending')`, t); e != nil {
				return nil, e
			}
			if _, e = tx.Exec(ctx, `UPDATE intents SET state='stopped',version=version+1 WHERE task_id=$1 AND state IN ('open','running','blocked','parked')`, t); e != nil {
				return nil, e
			}
			if e = event(ctx, tx, a, t, "task", t, "authorization.revoked", map[string]any{"authorization_id": id, "reason": reason}); e != nil {
				return nil, e
			}
		}
		// [02] 撤销不等于消费为零：预算保留给独立 Reconciler 对账，不盲目退款。
		if e = authEvent(ctx, tx, a, id, "revoked", map[string]any{"reason": reason}); e != nil {
			return nil, e
		}
		return id, nil
	})
	return resultID(raw, e)
}
func (s *Store) CreateTask(ctx context.Context, ss Session, key string, authID int64, goal string, deadline time.Time) (int64, error) {
	raw, e := s.operation(ctx, ss, "task.create", key, []any{authID, goal, deadline}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if strings.TrimSpace(goal) == "" {
			return nil, ErrDenied
		}
		var valid bool
		var expires time.Time
		e := tx.QueryRow(ctx, `SELECT status='active' AND valid_from<=clock_timestamp() AND expires_at>clock_timestamp(),expires_at FROM authorization_contracts WHERE id=$1 FOR UPDATE`, authID).Scan(&valid, &expires)
		if e != nil {
			return nil, e
		}
		if e = tx.QueryRow(ctx, `SELECT status='active' AND valid_from<=clock_timestamp() AND expires_at>clock_timestamp() FROM authorization_contracts WHERE id=$1`, authID).Scan(&valid); e != nil {
			return nil, e
		}
		if !valid || deadline.After(expires) {
			return nil, ErrDenied
		}
		var ver int
		e = tx.QueryRow(ctx, `SELECT version FROM authorization_versions WHERE authorization_id=$1 AND status='active'`, authID).Scan(&ver)
		if e != nil {
			return nil, e
		}
		var id int64
		e = tx.QueryRow(ctx, `INSERT INTO tasks(authorization_id,current_scope_ver,goal,deadline_at) SELECT $1,$2,$3,$4 WHERE $4>clock_timestamp() RETURNING id`, authID, ver, goal, deadline).Scan(&id)
		if e != nil {
			return nil, e
		}
		if a.kind != "human" {
			return nil, ErrDenied
		}
		if _, e = tx.Exec(ctx, `INSERT INTO task_members(task_id,principal_id,role,status,granted_by,reason) VALUES($1,$2,'admin','active',$2,'task creator')`, id, a.id); e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, id, "task", id, "task.created", map[string]any{"goal": goal}); e != nil {
			return nil, e
		}
		return id, nil
	})
	return resultID(raw, e)
}
func (s *Store) RegisterAsset(ctx context.Context, ss Session, key string, taskID int64, url string) (int64, error) {
	raw, e := s.operation(ctx, ss, "asset.register", key, []any{taskID, url}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin", "scheduler"); e != nil {
			return nil, e
		}
		if _, e := taskLock(ctx, tx, taskID, true); e != nil {
			return nil, e
		}
		if strings.TrimSpace(url) == "" {
			return nil, ErrDenied
		}
		var id int64
		e := tx.QueryRow(ctx, `INSERT INTO assets(task_id,asset_key) VALUES($1,$2) RETURNING id`, taskID, url).Scan(&id)
		if e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, taskID, "asset", id, "asset.discovered", map[string]any{"scope_status": "pending_review"}); e != nil {
			return nil, e
		}
		return id, nil
	})
	return resultID(raw, e)
}
func (s *Store) ReviewAsset(ctx context.Context, ss Session, key string, taskID, assetID int64, action string) (int64, error) {
	raw, e := s.operation(ctx, ss, "asset.review", key, []any{taskID, assetID, action}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if _, e := taskLock(ctx, tx, taskID, true); e != nil {
			return nil, e
		}
		var url string
		e := tx.QueryRow(ctx, `SELECT asset_key FROM assets WHERE task_id=$1 AND id=$2 FOR UPDATE`, taskID, assetID).Scan(&url)
		if e != nil {
			return nil, e
		}
		var b []byte
		e = tx.QueryRow(ctx, `SELECT v.scope_document FROM tasks t JOIN authorization_versions v ON v.authorization_id=t.authorization_id AND v.version=t.current_scope_ver WHERE t.id=$1`, taskID).Scan(&b)
		if e != nil {
			return nil, e
		}
		var scope domain.Scope
		if e = json.Unmarshal(b, &scope); e != nil {
			return nil, e
		}
		if e = scope.AllowsURL(url, action); e != nil {
			return nil, fmt.Errorf("%w: asset not in registered scope", ErrDenied)
		}
		_, e = tx.Exec(ctx, `UPDATE assets SET scope_status='in_scope' WHERE task_id=$1 AND id=$2`, taskID, assetID)
		if e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, taskID, "asset", assetID, "asset.reviewed", map[string]any{"scope_status": "in_scope"}); e != nil {
			return nil, e
		}
		return assetID, nil
	})
	return resultID(raw, e)
}
