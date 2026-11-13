package store

import (
	"context"
	"github.com/jackc/pgx/v5"
)

// [01] 必须由持有合同/Task/Mission锁的调用方使用，不能另起独立事务。
func consumeTx(ctx context.Context, tx pgx.Tx, missionID int64, kind string, amount int64) error {
	if amount <= 0 {
		return ErrBudget
	}
	var ledgerID, reservationID int64
	e := tx.QueryRow(ctx, `SELECT b.id,r.id FROM budget_ledgers b JOIN budget_reservations r ON r.ledger_id=b.id WHERE r.mission_id=$1 AND b.kind=$2 AND r.status='active' FOR UPDATE OF b,r`, missionID, kind).Scan(&ledgerID, &reservationID)
	if e == pgx.ErrNoRows {
		return ErrBudget
	}
	if e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `UPDATE budget_reservations SET consumed=consumed+$2 WHERE id=$1 AND amount-consumed>=$2`, reservationID, amount)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return ErrBudget
	}
	_, e = tx.Exec(ctx, `UPDATE budget_ledgers SET reserved=reserved-$2,consumed=consumed+$2 WHERE id=$1`, ledgerID, amount)
	return e
}
