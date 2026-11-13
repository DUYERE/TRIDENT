package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"strings"
	"trident/internal/domain"
)

type ScopeProposal struct {
	AuthorizationID int64        `json:"authorization_id"`
	BaseVersion     int          `json:"base_version"`
	Scope           domain.Scope `json:"scope"`
	ProofRef        string       `json:"proof_ref"`
	ProofHash       string       `json:"proof_hash"`
}
type ScopeVersion struct {
	Version int    `json:"version"`
	Hash    string `json:"scope_hash"`
}

func (s *Store) ProposeScope(ctx context.Context, ss Session, key string, r ScopeProposal) (ScopeVersion, error) {
	raw, e := s.operation(ctx, ss, "scope.propose", key, r, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if a.kind != "human" || r.BaseVersion <= 0 || strings.TrimSpace(r.ProofRef) == "" {
			return nil, ErrDenied
		}
		proof, e := hex.DecodeString(r.ProofHash)
		if e != nil || len(proof) != 32 {
			return nil, ErrDenied
		}
		canonical, hash, e := r.Scope.Canonical()
		if e != nil {
			return nil, e
		}
		var status string
		e = tx.QueryRow(ctx, `SELECT status FROM authorization_contracts WHERE id=$1 FOR UPDATE`, r.AuthorizationID).Scan(&status)
		if e != nil {
			return nil, e
		}
		if status != "active" {
			return nil, ErrDenied
		}
		var current int
		e = tx.QueryRow(ctx, `SELECT version FROM authorization_versions WHERE authorization_id=$1 AND status='active'`, r.AuthorizationID).Scan(&current)
		if e != nil {
			return nil, e
		}
		if current != r.BaseVersion {
			return nil, ErrConflict
		}
		var next int
		e = tx.QueryRow(ctx, `SELECT COALESCE(max(version),0)+1 FROM authorization_versions WHERE authorization_id=$1`, r.AuthorizationID).Scan(&next)
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO authorization_versions(authorization_id,version,scope_document,scope_hash,status,created_by) VALUES($1,$2,$3,$4,'draft',$5)`, r.AuthorizationID, next, canonical, hash, a.id)
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO authorization_scope_proposals(authorization_id,version,base_version,scope_hash,proof_ref,proof_hash,submitted_by) VALUES($1,$2,$3,$4,$5,$6,$7)`, r.AuthorizationID, next, current, hash, r.ProofRef, r.ProofHash, a.id)
		if e != nil {
			return nil, e
		}
		if e = authEvent(ctx, tx, a, r.AuthorizationID, "scope_submitted", map[string]any{"version": next, "base_version": current, "scope_hash": hash, "proof_hash": r.ProofHash}); e != nil {
			return nil, e
		}
		return ScopeVersion{next, hash}, nil
	})
	if e != nil {
		return ScopeVersion{}, e
	}
	var out ScopeVersion
	e = json.Unmarshal(raw, &out)
	return out, e
}

// [01] 以合同为粒度原子切换；旧Mission快照永远不改写，预算保留给对账。
func (s *Store) ApproveScope(ctx context.Context, ss Session, key string, authID int64, version, expectedBase int, expectedHash, attestation string) (ScopeVersion, error) {
	raw, e := s.operation(ctx, ss, "scope.approve", key, []any{authID, version, expectedBase, expectedHash, attestation}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if a.kind != "human" || strings.TrimSpace(attestation) == "" {
			return nil, ErrDenied
		}
		var owner int64
		var status string
		var single bool
		e := tx.QueryRow(ctx, `SELECT principal_id,status,single_operator_mode FROM authorization_contracts WHERE id=$1 FOR UPDATE`, authID).Scan(&owner, &status, &single)
		if e != nil {
			return nil, e
		}
		if status != "active" || (owner == a.id && (!single || !s.singleOperator)) {
			return nil, ErrDenied
		}
		rows, e := tx.Query(ctx, `SELECT id FROM tasks WHERE authorization_id=$1 ORDER BY id FOR UPDATE`, authID)
		if e != nil {
			return nil, e
		}
		var tasks []int64
		for rows.Next() {
			var id int64
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return nil, e
			}
			tasks = append(tasks, id)
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return nil, e
		}
		var current int
		e = tx.QueryRow(ctx, `SELECT version FROM authorization_versions WHERE authorization_id=$1 AND status='active'`, authID).Scan(&current)
		if e != nil {
			return nil, e
		}
		if current != expectedBase {
			return nil, ErrConflict
		}
		var rawScope []byte
		var hash, proofRef, proofHash string
		var base int
		e = tx.QueryRow(ctx, `SELECT v.scope_document,v.scope_hash,p.base_version,p.proof_ref,p.proof_hash FROM authorization_versions v JOIN authorization_scope_proposals p USING(authorization_id,version) WHERE v.authorization_id=$1 AND v.version=$2 AND v.status='draft' FOR UPDATE OF v`, authID, version).Scan(&rawScope, &hash, &base, &proofRef, &proofHash)
		if e != nil {
			return nil, e
		}
		if base != expectedBase || hash != expectedHash {
			return nil, ErrConflict
		}
		var scope domain.Scope
		if e = json.Unmarshal(rawScope, &scope); e != nil {
			return nil, e
		}
		_, actual, e := scope.Canonical()
		if e != nil || actual != hash {
			return nil, ErrDenied
		}
		var valid bool
		e = tx.QueryRow(ctx, `SELECT c.status='active' AND c.valid_from<=clock_timestamp() AND c.expires_at>clock_timestamp() AND p.status='active' FROM authorization_contracts c JOIN principals p ON p.id=c.principal_id WHERE c.id=$1`, authID).Scan(&valid)
		if e != nil {
			return nil, e
		}
		if !valid {
			return nil, ErrDenied
		}
		if _, e = tx.Exec(ctx, `UPDATE authorization_versions SET status='superseded' WHERE authorization_id=$1 AND version=$2`, authID, current); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `UPDATE authorization_versions SET status='active' WHERE authorization_id=$1 AND version=$2`, authID, version); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO authorization_proofs(authorization_id,proof_type,storage_ref,content_hash,verified_by_principal_id,verification_status) VALUES($1,'manual_attestation',$2,$3,$4,'verified')`, authID, proofRef, proofHash, a.id); e != nil {
			return nil, e
		}
		for _, task := range tasks {
			if _, e = tx.Exec(ctx, `UPDATE missions SET state='stopped',version=version+1 WHERE task_id=$1 AND state IN ('pending','running','retry_pending')`, task); e != nil {
				return nil, e
			}
			if _, e = tx.Exec(ctx, `UPDATE execution_leases SET status='revoked',released_at=clock_timestamp() WHERE task_id=$1 AND status='active'`, task); e != nil {
				return nil, e
			}
			if _, e = tx.Exec(ctx, `UPDATE intents SET state='stopped',version=version+1 WHERE task_id=$1 AND state IN ('open','running','blocked','parked')`, task); e != nil {
				return nil, e
			}
			if e = invalidateRequests(ctx, tx, task, 0); e != nil {
				return nil, e
			}
			if _, e = tx.Exec(ctx, `UPDATE assets SET scope_status='pending_review' WHERE task_id=$1 AND scope_status='in_scope'`, task); e != nil {
				return nil, e
			}
			if _, e = tx.Exec(ctx, `UPDATE tasks SET current_scope_ver=$2,version=version+1 WHERE id=$1`, task, version); e != nil {
				return nil, e
			}
			if e = event(ctx, tx, a, task, "task", task, "scope.version_changed", map[string]any{"authorization_id": authID, "previous_version": current, "version": version, "scope_hash": hash, "budget_retained": true}); e != nil {
				return nil, e
			}
		}
		if e = authEvent(ctx, tx, a, authID, "scope_changed", map[string]any{"previous_version": current, "version": version, "scope_hash": hash, "proof_hash": proofHash, "attestation": attestation}); e != nil {
			return nil, e
		}
		return ScopeVersion{version, hash}, nil
	})
	if e != nil {
		return ScopeVersion{}, e
	}
	var out ScopeVersion
	e = json.Unmarshal(raw, &out)
	return out, e
}
