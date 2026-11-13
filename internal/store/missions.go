package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"trident/internal/domain"
)

type MissionRequest struct {
	TaskID   int64            `json:"task_id"`
	IntentID int64            `json:"intent_id"`
	AssetID  int64            `json:"asset_id"`
	Angle    string           `json:"angle"`
	Deadline time.Time        `json:"deadline"`
	Budgets  map[string]int64 `json:"budgets"`
}

func (s *Store) CreateIntent(ctx context.Context, ss Session, key string, taskID, assetID int64, title string) (int64, error) {
	raw, e := s.operation(ctx, ss, "intent.create", key, []any{taskID, assetID, title}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin", "scheduler"); e != nil {
			return nil, e
		}
		if _, e := taskLock(ctx, tx, taskID, true); e != nil {
			return nil, e
		}
		if strings.TrimSpace(title) == "" {
			return nil, ErrDenied
		}
		id, e := node(ctx, tx, taskID, "intent")
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO intents(id,task_id,target_asset_id,title) VALUES($1,$2,$3,$4)`, id, taskID, assetID, title)
		if e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, taskID, "intent", id, "intent.created", map[string]any{"title": title}); e != nil {
			return nil, e
		}
		return id, nil
	})
	return resultID(raw, e)
}
func (s *Store) SetBudget(ctx context.Context, ss Session, key string, taskID int64, kind string, amount int64) (int64, error) {
	raw, e := s.operation(ctx, ss, "budget.allocate", key, []any{taskID, kind, amount}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if _, e := taskLock(ctx, tx, taskID, true); e != nil {
			return nil, e
		}
		if amount < 0 {
			return nil, ErrBudget
		}
		var id int64
		e := tx.QueryRow(ctx, `INSERT INTO budget_ledgers(task_id,kind,allocated) VALUES($1,$2,$3) ON CONFLICT(task_id,kind) DO UPDATE SET allocated=EXCLUDED.allocated WHERE budget_ledgers.reserved+budget_ledgers.consumed<=EXCLUDED.allocated RETURNING id`, taskID, kind, amount).Scan(&id)
		if e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, taskID, "budget", id, "budget.allocated", map[string]any{"amount": amount, "kind": kind}); e != nil {
			return nil, e
		}
		return id, nil
	})
	return resultID(raw, e)
}
func (s *Store) SetPool(ctx context.Context, ss Session, key, name string, capacity int) (int64, error) {
	raw, e := s.operation(ctx, ss, "pool.configure", key, []any{name, capacity}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if capacity < 0 || strings.TrimSpace(name) == "" {
			return nil, ErrDenied
		}
		if _, e := tx.Exec(ctx, `INSERT INTO resource_pools(resource_key,capacity) VALUES($1,$2) ON CONFLICT(resource_key) DO NOTHING`, name, capacity); e != nil {
			return nil, e
		}
		var old int
		if e := tx.QueryRow(ctx, `SELECT capacity FROM resource_pools WHERE resource_key=$1 FOR UPDATE`, name).Scan(&old); e != nil {
			return nil, e
		}
		var active int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM execution_leases WHERE resource_key=$1 AND status='active' AND lease_until>clock_timestamp()`, name).Scan(&active); e != nil {
			return nil, e
		}
		if capacity < active {
			return nil, ErrConflict
		}
		_, e := tx.Exec(ctx, `UPDATE resource_pools SET capacity=$2 WHERE resource_key=$1`, name, capacity)
		return int64(capacity), e
	})
	return resultID(raw, e)
}
func (s *Store) CreateMission(ctx context.Context, ss Session, key string, r MissionRequest) (int64, error) {
	raw, e := s.operation(ctx, ss, "mission.create", key, r, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin", "scheduler"); e != nil {
			return nil, e
		}
		if _, e := taskLock(ctx, tx, r.TaskID, true); e != nil {
			return nil, e
		}
		if strings.TrimSpace(r.Angle) == "" || len(r.Budgets) == 0 {
			return nil, ErrDenied
		}
		var intentState, assetStatus string
		var assetID int64
		e := tx.QueryRow(ctx, `SELECT i.state,i.target_asset_id,a.scope_status FROM intents i JOIN assets a ON a.task_id=i.task_id AND a.id=i.target_asset_id WHERE i.task_id=$1 AND i.id=$2 FOR UPDATE OF i`, r.TaskID, r.IntentID).Scan(&intentState, &assetID, &assetStatus)
		if e != nil {
			return nil, e
		}
		if intentState != "open" || assetStatus != "in_scope" || assetID != r.AssetID {
			return nil, ErrDenied
		}
		var missing bool
		e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM intent_fact_deps d JOIN facts f ON f.task_id=d.task_id AND f.id=d.fact_id WHERE d.intent_id=$1 AND f.validation<>'validated')`, r.IntentID).Scan(&missing)
		if e != nil {
			return nil, e
		}
		if missing {
			return nil, ErrDenied
		}
		var authID int64
		var ver int
		var hash string
		var snapshot []byte
		var taskDeadline time.Time
		e = tx.QueryRow(ctx, `SELECT t.authorization_id,t.current_scope_ver,v.scope_hash,v.scope_document,t.deadline_at FROM tasks t JOIN authorization_versions v ON v.authorization_id=t.authorization_id AND v.version=t.current_scope_ver WHERE t.id=$1`, r.TaskID).Scan(&authID, &ver, &hash, &snapshot, &taskDeadline)
		if e != nil {
			return nil, e
		}
		if r.Deadline.After(taskDeadline) {
			return nil, ErrDenied
		}
		var live bool
		e = tx.QueryRow(ctx, `SELECT $1::timestamptz>clock_timestamp()`, r.Deadline).Scan(&live)
		if e != nil {
			return nil, e
		}
		if !live {
			return nil, ErrDenied
		}
		id, e := node(ctx, tx, r.TaskID, "mission")
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO missions(id,task_id,intent_id,target_asset_id,authorization_id,scope_version,scope_hash,scope_snapshot,angle,deadline_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, r.TaskID, r.IntentID, r.AssetID, authID, ver, hash, snapshot, r.Angle, r.Deadline)
		if e != nil {
			return nil, e
		}
		// [01] 按 kind 排序锁账本；所有维度的预留与 Mission 同事务，全成或全退。
		rows, e := tx.Query(ctx, `SELECT id,kind FROM budget_ledgers WHERE task_id=$1 ORDER BY kind FOR UPDATE`, r.TaskID)
		if e != nil {
			return nil, e
		}
		type ledger struct {
			id   int64
			kind string
		}
		var ledgers []ledger
		for rows.Next() {
			var l ledger
			if e = rows.Scan(&l.id, &l.kind); e != nil {
				rows.Close()
				return nil, e
			}
			ledgers = append(ledgers, l)
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return nil, e
		}
		matched := 0
		for _, l := range ledgers {
			amount, ok := r.Budgets[l.kind]
			if !ok {
				continue
			}
			if amount <= 0 {
				return nil, ErrBudget
			}
			tag, e := tx.Exec(ctx, `UPDATE budget_ledgers SET reserved=reserved+$2 WHERE id=$1 AND allocated-consumed-reserved >= $2`, l.id, amount)
			if e != nil {
				return nil, e
			}
			if tag.RowsAffected() != 1 {
				return nil, ErrBudget
			}
			_, e = tx.Exec(ctx, `INSERT INTO budget_reservations(task_id,mission_id,ledger_id,amount) VALUES($1,$2,$3,$4)`, r.TaskID, id, l.id, amount)
			if e != nil {
				return nil, e
			}
			matched++
		}
		if matched != len(r.Budgets) {
			return nil, ErrBudget
		}
		if _, e = tx.Exec(ctx, `UPDATE intents SET state='running',version=version+1 WHERE id=$1`, r.IntentID); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO edges(task_id,src_id,dst_id,rel) VALUES($1,$2,$3,'spawns')`, r.TaskID, r.IntentID, id); e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, r.TaskID, "mission", id, "mission.created", r); e != nil {
			return nil, e
		}
		return id, nil
	})
	return resultID(raw, e)
}
func (s *Store) Claim(ctx context.Context, ss Session, key string, taskID, missionID int64, pool, runtime string, ttl time.Duration) (Lease, error) {
	request := []any{taskID, missionID, pool, runtime, int64(ttl)}
	raw, e := s.operation(ctx, ss, "mission.claim", key, request, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "worker"); e != nil {
			return nil, e
		}
		if ttl < time.Millisecond || ttl > 5*time.Minute || ttl%time.Millisecond != 0 || strings.TrimSpace(runtime) == "" {
			return nil, ErrDenied
		}
		if _, e := taskLock(ctx, tx, taskID, true); e != nil {
			return nil, e
		}
		var state string
		var live bool
		var scopeVersion, current int
		e := tx.QueryRow(ctx, `SELECT m.state,m.deadline_at>clock_timestamp(),m.scope_version,t.current_scope_ver FROM missions m JOIN tasks t ON t.id=m.task_id WHERE m.task_id=$1 AND m.id=$2 FOR UPDATE OF m`, taskID, missionID).Scan(&state, &live, &scopeVersion, &current)
		if e != nil {
			return nil, e
		}
		if (state != "pending" && state != "retry_pending") || !live || scopeVersion != current {
			return nil, ErrConflict
		}
		var capacity int
		e = tx.QueryRow(ctx, `SELECT capacity FROM resource_pools WHERE resource_key=$1 FOR UPDATE`, pool).Scan(&capacity)
		if e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `UPDATE execution_leases SET status='expired',released_at=clock_timestamp() WHERE resource_key=$1 AND status='active' AND lease_until<=clock_timestamp()`, pool); e != nil {
			return nil, e
		}
		var count int
		e = tx.QueryRow(ctx, `SELECT count(*) FROM execution_leases WHERE resource_key=$1 AND status='active'`, pool).Scan(&count)
		if e != nil {
			return nil, e
		}
		if count >= capacity {
			return nil, ErrConflict
		}
		// [04] 取得池锁后再校验，防止锁等待跨过合同/任务/Mission 截止时间。
		if _, e = taskLock(ctx, tx, taskID, true); e != nil {
			return nil, e
		}
		var reserved bool
		e = tx.QueryRow(ctx, `SELECT m.deadline_at>clock_timestamp() AND EXISTS(SELECT 1 FROM budget_reservations r WHERE r.mission_id=m.id AND r.status='active' AND r.amount>r.consumed) AND NOT EXISTS(SELECT 1 FROM budget_reservations r WHERE r.mission_id=m.id AND r.status<>'active') FROM missions m WHERE m.id=$1`, missionID).Scan(&reserved)
		if e != nil {
			return nil, e
		}
		if !reserved {
			return nil, ErrBudget
		}
		l := Lease{TaskID: taskID, MissionID: missionID, RuntimeID: runtime}
		e = tx.QueryRow(ctx, `UPDATE resource_pools SET next_fencing_token=next_fencing_token+1 WHERE resource_key=$1 RETURNING next_fencing_token`, pool).Scan(&l.Token)
		if e != nil {
			return nil, e
		}
		e = tx.QueryRow(ctx, `INSERT INTO execution_leases(task_id,mission_id,resource_key,holder,runtime_id,fencing_token,lease_until) SELECT $1,$2,$3,$4,$5,$6,LEAST(clock_timestamp()+$7*interval '1 millisecond',deadline_at) FROM missions WHERE id=$2 RETURNING id`, taskID, missionID, pool, a.id, runtime, l.Token, ttl.Milliseconds()).Scan(&l.ID)
		if e != nil {
			return nil, e
		}
		tag, e := tx.Exec(ctx, `UPDATE missions SET state='running',version=version+1,attempt_count=attempt_count+1 WHERE id=$1 AND attempt_count<max_attempts`, missionID)
		if e != nil {
			return nil, e
		}
		if tag.RowsAffected() != 1 {
			return nil, ErrConflict
		}
		if e = event(ctx, tx, a, taskID, "mission", missionID, "mission.started", l); e != nil {
			return nil, e
		}
		return l, nil
	})
	if e != nil {
		return Lease{}, e
	}
	var l Lease
	e = json.Unmarshal(raw, &l)
	return l, e
}

type workerRequest struct {
	Lease Lease `json:"lease"`
	Body  any   `json:"body"`
}

func validateLease(ctx context.Context, tx pgx.Tx, a actor, l Lease) error {
	if e := allowed(a, "worker"); e != nil {
		return e
	}
	if _, e := taskActorLock(ctx, tx, a, l.TaskID, true); e != nil {
		return e
	}
	// [02] 与 Claim/SetPool 共用池锁；续租与缩容不能基于不同快照同时提交。
	var pool string
	if e := tx.QueryRow(ctx, `SELECT id FROM missions WHERE task_id=$1 AND id=$2 FOR UPDATE`, l.TaskID, l.MissionID).Scan(new(int64)); e != nil {
		return ErrStale
	}
	if e := tx.QueryRow(ctx, `SELECT resource_key FROM execution_leases WHERE task_id=$1 AND mission_id=$2 AND id=$3`, l.TaskID, l.MissionID, l.ID).Scan(&pool); e != nil {
		return ErrStale
	}
	if _, e := tx.Exec(ctx, `SELECT resource_key FROM resource_pools WHERE resource_key=$1 FOR UPDATE`, pool); e != nil {
		return e
	}
	var valid bool
	// [03] 只认执行对象自身租约，绝不与池的最新 token 相等比较，避免误杀合法并发者。
	e := tx.QueryRow(ctx, `SELECT m.state='running' AND m.deadline_at>clock_timestamp() AND m.scope_version=t.current_scope_ver AND m.scope_hash=v.scope_hash AND v.status='active' AND l.holder=$4 AND l.fencing_token=$5 AND l.runtime_id=$6 AND l.status='active' AND l.lease_until>clock_timestamp() FROM missions m JOIN tasks t ON t.id=m.task_id JOIN authorization_versions v ON v.authorization_id=m.authorization_id AND v.version=m.scope_version JOIN execution_leases l ON l.mission_id=m.id AND l.task_id=m.task_id WHERE m.task_id=$1 AND m.id=$2 AND l.id=$3 FOR UPDATE OF m,l`, l.TaskID, l.MissionID, l.ID, a.id, l.Token, l.RuntimeID).Scan(&valid)
	if e == pgx.ErrNoRows {
		return ErrStale
	}
	if e != nil {
		return e
	}
	if !valid {
		return ErrStale
	}
	// [05] Lease 行锁可能发生等待，获得全部锁后重新读取实际有效期。
	if _, e = taskLock(ctx, tx, l.TaskID, true); e != nil {
		return e
	}
	e = tx.QueryRow(ctx, `SELECT l.status='active' AND l.lease_until>clock_timestamp() AND m.state='running' AND m.deadline_at>clock_timestamp() FROM execution_leases l JOIN missions m ON m.id=l.mission_id WHERE l.id=$1`, l.ID).Scan(&valid)
	if e != nil {
		return e
	}
	if !valid {
		return ErrStale
	}
	return nil
}
func (s *Store) Heartbeat(ctx context.Context, ss Session, key string, l Lease, ttl time.Duration) error {
	_, e := s.operation(ctx, ss, "lease.heartbeat", key, workerRequest{l, ttl.Milliseconds()}, func(tx pgx.Tx, a actor) (any, error) {
		if ttl < time.Millisecond || ttl > 5*time.Minute || ttl%time.Millisecond != 0 {
			return nil, ErrDenied
		}
		_, e := tx.Exec(ctx, `UPDATE execution_leases SET heartbeat_at=clock_timestamp(),lease_until=LEAST(clock_timestamp()+$2*interval '1 millisecond',m.deadline_at) FROM missions m WHERE execution_leases.id=$1 AND m.id=execution_leases.mission_id`, l.ID, ttl.Milliseconds())
		return l.ID, e
	})
	return e
}
func (s *Store) RecordFact(ctx context.Context, ss Session, key string, l Lease, confidence string, content json.RawMessage) (int64, error) {
	raw, e := s.operation(ctx, ss, "fact.record", key, workerRequest{l, []any{confidence, content}}, func(tx pgx.Tx, a actor) (any, error) {
		if confidence != "observed" && confidence != "inferred" {
			return nil, ErrDenied
		}
		if !json.Valid(content) || len(content) > 65536 {
			return nil, ErrDenied
		}
		id, e := node(ctx, tx, l.TaskID, "fact")
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO facts(id,task_id,mission_id,actor_id,confidence,content) VALUES($1,$2,$3,$4,$5,$6)`, id, l.TaskID, l.MissionID, a.id, confidence, content)
		if e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO edges(task_id,src_id,dst_id,rel) VALUES($1,$2,$3,'yields')`, l.TaskID, l.MissionID, id); e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, l.TaskID, "fact", id, "fact.created", map[string]any{"confidence": confidence}); e != nil {
			return nil, e
		}
		return id, nil
	})
	return resultID(raw, e)
}
func (s *Store) Consume(ctx context.Context, ss Session, key string, l Lease, kind string, amount int64) error {
	_, e := s.operation(ctx, ss, "budget.consume", key, workerRequest{l, []any{kind, amount}}, func(tx pgx.Tx, a actor) (any, error) {
		if e := consumeTx(ctx, tx, l.MissionID, kind, amount); e != nil {
			return nil, e
		}
		if e := event(ctx, tx, a, l.TaskID, "mission", l.MissionID, "budget.consumed", map[string]any{"kind": kind, "amount": amount}); e != nil {
			return nil, e
		}
		return amount, nil
	})
	return e
}
func settle(ctx context.Context, tx pgx.Tx, missionID int64) error {
	rows, e := tx.Query(ctx, `SELECT b.id,r.id,r.amount-r.consumed FROM budget_ledgers b JOIN budget_reservations r ON r.ledger_id=b.id WHERE r.mission_id=$1 AND r.status='active' ORDER BY b.kind FOR UPDATE OF b,r`, missionID)
	if e != nil {
		return e
	}
	type item struct{ ledger, reservation, left int64 }
	var items []item
	for rows.Next() {
		var it item
		if e = rows.Scan(&it.ledger, &it.reservation, &it.left); e != nil {
			rows.Close()
			return e
		}
		items = append(items, it)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	for _, it := range items {
		if _, e = tx.Exec(ctx, `UPDATE budget_ledgers SET reserved=reserved-$2 WHERE id=$1`, it.ledger, it.left); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE budget_reservations SET status='settled' WHERE id=$1`, it.reservation); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) Finish(ctx context.Context, ss Session, key string, l Lease, state string) error {
	_, e := s.operation(ctx, ss, "mission.finish", key, workerRequest{l, state}, func(tx pgx.Tx, a actor) (any, error) {
		if e := domain.ValidateTransition("mission", "running", state); e != nil {
			return nil, e
		}
		if state == "retry_pending" || state == "running" {
			return nil, ErrDenied
		}
		if e := settle(ctx, tx, l.MissionID); e != nil {
			return nil, e
		}
		if _, e := tx.Exec(ctx, `UPDATE missions SET state=$2,version=version+1 WHERE id=$1`, l.MissionID, state); e != nil {
			return nil, e
		}
		intentState := "blocked"
		if state == "done" {
			intentState = "done"
		}
		if state == "exhausted" {
			intentState = "exhausted"
		}
		if state == "stopped" || state == "killed" {
			intentState = "stopped"
		}
		if _, e := tx.Exec(ctx, `UPDATE intents SET state=$2,version=version+1 WHERE id=(SELECT intent_id FROM missions WHERE id=$1)`, l.MissionID, intentState); e != nil {
			return nil, e
		}
		if _, e := tx.Exec(ctx, `UPDATE execution_leases SET status='released',released_at=clock_timestamp() WHERE id=$1`, l.ID); e != nil {
			return nil, e
		}
		if e := event(ctx, tx, a, l.TaskID, "mission", l.MissionID, "mission."+state, map[string]any{"state": state}); e != nil {
			return nil, e
		}
		return l.MissionID, nil
	})
	return e
}
