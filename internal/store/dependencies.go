package store

import (
	"context"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ValidateFact(ctx context.Context, ss Session, key string, taskID, factID int64) error {
	_, e := s.operation(ctx, ss, "fact.validate", key, []any{taskID, factID}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin"); e != nil {
			return nil, e
		}
		if _, e := taskLock(ctx, tx, taskID, true); e != nil {
			return nil, e
		}
		tag, e := tx.Exec(ctx, `UPDATE facts SET validation='validated' WHERE task_id=$1 AND id=$2`, taskID, factID)
		if e != nil {
			return nil, e
		}
		if tag.RowsAffected() != 1 {
			return nil, ErrDenied
		}
		if e = event(ctx, tx, a, taskID, "fact", factID, "fact.validated", map[string]any{"validation": "validated"}); e != nil {
			return nil, e
		}
		return factID, nil
	})
	return e
}
func (s *Store) LinkDependency(ctx context.Context, ss Session, key string, taskID, intentID, factID int64) error {
	_, e := s.operation(ctx, ss, "intent.link_dependency", key, []any{taskID, intentID, factID}, func(tx pgx.Tx, a actor) (any, error) {
		if e := allowed(a, "admin", "scheduler"); e != nil {
			return nil, e
		}
		if _, e := taskLock(ctx, tx, taskID, true); e != nil {
			return nil, e
		}
		var state string
		e := tx.QueryRow(ctx, `SELECT state FROM intents WHERE task_id=$1 AND id=$2 FOR UPDATE`, taskID, intentID).Scan(&state)
		if e != nil {
			return nil, e
		}
		if state != "open" {
			return nil, ErrConflict
		}
		// [01] Task 已锁定，路径检查和插边不会与另一事务同时产生依赖闭环。
		if _, e = tx.Exec(ctx, `INSERT INTO edges(task_id,src_id,dst_id,rel) VALUES($1,$2,$3,'derived_from') ON CONFLICT DO NOTHING`, taskID, factID, intentID); e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO intent_fact_deps(task_id,intent_id,fact_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, taskID, intentID, factID); e != nil {
			return nil, e
		}
		if e = event(ctx, tx, a, taskID, "intent", intentID, "intent.dependency_added", map[string]any{"fact_id": factID}); e != nil {
			return nil, e
		}
		return intentID, nil
	})
	return e
}
