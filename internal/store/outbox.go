package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// [01] OutboxEvent 只承载通知；消费者不能把通知重投当作再次执行工具的授权。
type OutboxEvent struct {
	ID               int64
	TaskID           int64
	AggregateKind    string
	AggregateID      int64
	AggregateVersion int64
	EventType        string
	Payload          json.RawMessage
	ClaimGeneration  int64
}

// [02] 限制单次数据库工作量、租约时长及重试等待；时间精度与 PostgreSQL 的微秒一致。
const (
	outboxMaxClaimLimit      = 1000
	outboxMaxClaimTTL        = 5 * time.Minute
	outboxMaxRetryDelay      = 24 * time.Hour
	outboxMaxDispatcherBytes = 128
	outboxMaxReasonBytes     = 1024
	outboxMaxAttempts        = 1<<31 - 1
)

// [03] 只发现当前可领取的聚合队首所属 Task，不扫描/锁定全部历史 Task，也不截断任务覆盖。
// [04] 此查询不锁事件；先按 Auth/Task 全局顺序加锁，再在领取 SQL 中重新检查资格。
const outboxClaimTasksSQL = `
SELECT DISTINCT t.authorization_id, e.task_id
FROM outbox_events AS e
JOIN tasks AS t ON t.id = e.task_id
WHERE e.published_at IS NULL
  AND e.dead_lettered_at IS NULL
  AND e.available_at <= clock_timestamp()
  AND (e.locked_until IS NULL OR e.locked_until <= clock_timestamp())
  AND ($1::boolean OR EXISTS (
      SELECT 1 FROM task_members AS member
      WHERE member.task_id = e.task_id AND member.principal_id = $2
        AND member.role = 'reconciler' AND member.status = 'active'
  ))
  AND NOT EXISTS (
      SELECT 1 FROM outbox_events AS previous
      WHERE previous.task_id = e.task_id
        AND previous.aggregate_kind = e.aggregate_kind
        AND previous.aggregate_id = e.aggregate_id
        AND previous.aggregate_version < e.aggregate_version
        AND previous.published_at IS NULL
  )
ORDER BY t.authorization_id, e.task_id`

// [05] 前序检查故意不排除死信、未到期及正在领取的事件；SKIP LOCKED 不能越过聚合队首。
const outboxClaimSQL = `
WITH heads AS (
    SELECT e.id
    FROM outbox_events AS e
    WHERE e.published_at IS NULL
      AND e.dead_lettered_at IS NULL
      AND e.available_at <= clock_timestamp()
      AND (e.locked_until IS NULL OR e.locked_until <= clock_timestamp())
      AND e.task_id = ANY($6::bigint[])
      AND ($4::boolean OR EXISTS (
          SELECT 1 FROM task_members AS member
          WHERE member.task_id = e.task_id AND member.principal_id = $5
            AND member.role = 'reconciler' AND member.status = 'active'
      ))
      AND NOT EXISTS (
          SELECT 1 FROM outbox_events AS previous
          WHERE previous.task_id = e.task_id
            AND previous.aggregate_kind = e.aggregate_kind
            AND previous.aggregate_id = e.aggregate_id
            AND previous.aggregate_version < e.aggregate_version
            AND previous.published_at IS NULL
      )
    ORDER BY e.id
    LIMIT $1
    FOR UPDATE OF e SKIP LOCKED
)
UPDATE outbox_events AS e
SET locked_by = $2,
    claimed_by_principal_id = $5,
    locked_until = clock_timestamp() + $3::bigint * interval '1 microsecond',
    claim_generation = e.claim_generation + 1,
    attempts = e.attempts + 1
FROM heads
WHERE e.id = heads.id
RETURNING e.id, e.task_id, e.aggregate_kind, e.aggregate_id,
          e.aggregate_version, e.event_type, e.payload, e.claim_generation`

// [06] 回执同时绑定数据库身份和公开 dispatcher；同名 dispatcher 不能代另一身份确认或失败。
const outboxAckSQL = `
UPDATE outbox_events
SET published_at = clock_timestamp(), locked_by = NULL, locked_until = NULL,
    claimed_by_principal_id = NULL
WHERE id = $1 AND claim_generation = $2 AND locked_by = $3
  AND claimed_by_principal_id = $4
  AND locked_until > clock_timestamp()
  AND published_at IS NULL AND dead_lettered_at IS NULL`

const outboxFailSQL = `
UPDATE outbox_events
SET locked_by = NULL,
    locked_until = NULL,
    claimed_by_principal_id = NULL,
    available_at = clock_timestamp() + $6::bigint * interval '1 microsecond',
    last_error = $4,
    dead_lettered_at = CASE WHEN attempts >= $5 THEN clock_timestamp() ELSE NULL END
WHERE id = $1 AND claim_generation = $2 AND locked_by = $3
  AND claimed_by_principal_id = $7
  AND locked_until > clock_timestamp()
  AND published_at IS NULL AND dead_lettered_at IS NULL`

const outboxReplaySQL = `
UPDATE outbox_events
SET published_at = NULL, dead_lettered_at = NULL,
    available_at = clock_timestamp(), locked_by = NULL, locked_until = NULL,
    claimed_by_principal_id = NULL,
    claim_generation = claim_generation + 1, attempts = 0, last_error = NULL
WHERE id = $1
RETURNING task_id, aggregate_kind, aggregate_id, aggregate_version, claim_generation`

// [07] ClaimEvents 仅允许管理员及对账服务领取；提交成功前不暴露领取结果，也不发送网络请求。
func (s *Store) ClaimEvents(ctx context.Context, ss Session, dispatcher string, limit int, ttl time.Duration) ([]OutboxEvent, error) {
	if err := validateOutboxClaim(dispatcher, limit, ttl); err != nil {
		return nil, err
	}
	tx, a, err := s.beginOutboxTx(ctx, ss, "admin", "reconciler")
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())

	taskIDs, err := lockOutboxClaimTasks(ctx, tx, a)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, outboxClaimSQL, limit, dispatcher, ttl.Microseconds(),
		a.role == "admin" && a.kind == "human", a.id, taskIDs)
	if err != nil {
		return nil, err
	}
	events := make([]OutboxEvent, 0, limit)
	for rows.Next() {
		var e OutboxEvent
		if err = rows.Scan(&e.ID, &e.TaskID, &e.AggregateKind, &e.AggregateID,
			&e.AggregateVersion, &e.EventType, &e.Payload, &e.ClaimGeneration); err != nil {
			rows.Close()
			return nil, err
		}
		events = append(events, e)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	// [05] UPDATE RETURNING 不保证顺序，返回值按领取候选的 ID 顺序稳定排列。
	sort.Slice(events, func(i, j int) bool { return events[i].ID < events[j].ID })
	return events, nil
}

// [06] AckEvent 使用 owner、generation 和真实数据库时钟做 CAS；重复或陈旧回执返回 ErrConflict。
func (s *Store) AckEvent(ctx context.Context, ss Session, id, generation int64, dispatcher string) error {
	if err := validateOutboxReceipt(id, generation, dispatcher); err != nil {
		return err
	}
	tx, a, err := s.beginOutboxTx(ctx, ss, "admin", "reconciler")
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if err = lockOutboxEventTask(ctx, tx, a, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, outboxAckSQL, id, generation, dispatcher, a.id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return tx.Commit(ctx)
}

// [07] FailEvent 的 attempts 来自领取次数；到达上限才进入死信，否则延迟重试并释放领取。
func (s *Store) FailEvent(ctx context.Context, ss Session, id, generation int64, dispatcher, message string, maxAttempts int, delay time.Duration) error {
	if err := validateOutboxFailure(id, generation, dispatcher, maxAttempts, delay); err != nil {
		return err
	}
	tx, a, err := s.beginOutboxTx(ctx, ss, "admin", "reconciler")
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if err = lockOutboxEventTask(ctx, tx, a, id); err != nil {
		return err
	}

	tag, err := tx.Exec(ctx, outboxFailSQL,
		id, generation, dispatcher, outboxErrorSummary(message), maxAttempts, delay.Microseconds(), a.id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return tx.Commit(ctx)
}

// [08] ReplayEvent 仅管理员可用，可重投已发布或死信通知，也可撤销正在处理的领取。
// [09] 只修改原通知的投递字段；不调用 event、不修改 payload/业务版本、不创建任务或工具执行。
func (s *Store) ReplayEvent(ctx context.Context, ss Session, id int64, reason string) error {
	if err := validateOutboxReplay(id, reason); err != nil {
		return err
	}
	tx, a, err := s.beginOutboxTx(ctx, ss, "admin")
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if err = lockOutboxEventTask(ctx, tx, a, id); err != nil {
		return err
	}

	var e OutboxEvent
	err = tx.QueryRow(ctx, outboxReplaySQL, id).
		Scan(&e.TaskID, &e.AggregateKind, &e.AggregateID, &e.AggregateVersion, &e.ClaimGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	// [10] 审计与重投必须同事务提交；reason 应为人工说明，禁止填写凭据或原始网络错误。
	detail, err := json.Marshal(struct {
		EventID          int64  `json:"event_id"`
		Reason           string `json:"reason"`
		AggregateKind    string `json:"aggregate_kind"`
		AggregateID      int64  `json:"aggregate_id"`
		AggregateVersion int64  `json:"aggregate_version"`
		ClaimGeneration  int64  `json:"claim_generation"`
		NotificationOnly bool   `json:"notification_only"`
	}{id, strings.TrimSpace(reason), e.AggregateKind, e.AggregateID, e.AggregateVersion, e.ClaimGeneration, true})
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO activities(task_id, actor_id, kind, detail)
VALUES ($1, $2, 'outbox.replayed', $3)`, e.TaskID, a.id, detail); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// [11] 领取前只锁有候选事件的 Task；同合同多任务及跨合同批次均遵守 Auth/Task 顺序。
func lockOutboxClaimTasks(ctx context.Context, tx pgx.Tx, a actor) ([]int64, error) {
	rows, err := tx.Query(ctx, outboxClaimTasksSQL, a.role == "admin" && a.kind == "human", a.id)
	if err != nil {
		return nil, err
	}
	var candidates []int64
	for rows.Next() {
		var authID, taskID int64
		if err = rows.Scan(&authID, &taskID); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, taskID)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}

	taskIDs := make([]int64, 0, len(candidates))
	for _, taskID := range candidates {
		if _, err = taskActorLock(ctx, tx, a, taskID, false); err != nil {
			// [12] 发现候选后可能已撤销成员；排除它而不影响其他已授权 Task 的领取。
			if errors.Is(err, ErrDenied) {
				continue
			}
			return nil, err
		}
		taskIDs = append(taskIDs, taskID)
	}
	return taskIDs, nil
}

// [13] 非锁读仅定位真实 Task；必须先锁 Auth/Task/成员，再取事件锁，禁止反向加锁。
func lockOutboxEventTask(ctx context.Context, tx pgx.Tx, a actor, id int64) error {
	var taskID int64
	err := tx.QueryRow(ctx, `SELECT task_id FROM outbox_events WHERE id = $1`, id).Scan(&taskID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if _, err = taskActorLock(ctx, tx, a, taskID, false); err != nil {
		return err
	}
	return lockOutboxEvent(ctx, tx, id)
}

// [14] 全局管理员只接受人工身份，禁止历史 service/admin 凭据绕过任务成员权限。
func allowedOutboxActor(a actor, roles ...string) error {
	if a.role == "admin" && a.kind != "human" {
		return ErrDenied
	}
	return allowed(a, roles...)
}

// [15] 每笔投递事务重新鉴权；不借用 operation，避免幂等结果缓存绕过实时领取状态校验。
func (s *Store) beginOutboxTx(ctx context.Context, ss Session, roles ...string) (pgx.Tx, actor, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, actor{}, err
	}
	a, err := authenticateTx(ctx, tx, ss)
	if err == nil {
		err = allowedOutboxActor(a, roles...)
	}
	if err != nil {
		tx.Rollback(context.Background())
		return nil, actor{}, err
	}
	return tx, a, nil
}

// [12] 先取得行锁再检查时钟，避免等待行锁期间租约已过期却仍被旧回执确认。
func lockOutboxEvent(ctx context.Context, tx pgx.Tx, id int64) error {
	var lockedID int64
	err := tx.QueryRow(ctx, `SELECT id FROM outbox_events WHERE id = $1 FOR UPDATE`, id).Scan(&lockedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	return err
}

func validateOutboxDispatcher(dispatcher string) error {
	if len(dispatcher) == 0 || len(dispatcher) > outboxMaxDispatcherBytes || !utf8.ValidString(dispatcher) {
		return fmt.Errorf("%w: invalid outbox dispatcher", ErrConflict)
	}
	for _, r := range dispatcher {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%w: invalid outbox dispatcher", ErrConflict)
		}
	}
	return nil
}

func validateOutboxClaim(dispatcher string, limit int, ttl time.Duration) error {
	if err := validateOutboxDispatcher(dispatcher); err != nil {
		return err
	}
	if limit < 1 || limit > outboxMaxClaimLimit {
		return fmt.Errorf("%w: outbox claim limit must be between 1 and 1000", ErrConflict)
	}
	if ttl < time.Microsecond || ttl > outboxMaxClaimTTL || ttl%time.Microsecond != 0 {
		return fmt.Errorf("%w: outbox claim TTL must be 1 microsecond to 5 minutes at microsecond precision", ErrConflict)
	}
	return nil
}

func validateOutboxReceipt(id, generation int64, dispatcher string) error {
	if id <= 0 || generation <= 0 {
		return fmt.Errorf("%w: invalid outbox event ID or generation", ErrConflict)
	}
	return validateOutboxDispatcher(dispatcher)
}

func validateOutboxFailure(id, generation int64, dispatcher string, maxAttempts int, delay time.Duration) error {
	if err := validateOutboxReceipt(id, generation, dispatcher); err != nil {
		return err
	}
	if maxAttempts < 1 || maxAttempts > outboxMaxAttempts {
		return fmt.Errorf("%w: outbox max attempts must fit a positive PostgreSQL integer", ErrConflict)
	}
	if delay < 0 || delay > outboxMaxRetryDelay || delay%time.Microsecond != 0 {
		return fmt.Errorf("%w: outbox retry delay must be 0 to 24 hours at microsecond precision", ErrConflict)
	}
	return nil
}

func validateOutboxReplay(id int64, reason string) error {
	if id <= 0 || len(reason) == 0 || len(reason) > outboxMaxReasonBytes || !utf8.ValidString(reason) {
		return fmt.Errorf("%w: invalid outbox replay ID or reason", ErrConflict)
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: outbox replay requires a reason", ErrConflict)
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: outbox replay reason contains control characters", ErrConflict)
		}
	}
	return nil
}

// [13] 任意错误可能携带未知格式的凭据，故完整隐去原文，仅保存固定格式的有界长度摘要。
// [14] 不复制、扫描或散列不受限的 message；即使超大或含非法 UTF-8，数据库也不接收其原文。
func outboxErrorSummary(message string) string {
	return fmt.Sprintf("delivery failed (diagnostic redacted; original_bytes=%d)", len(message))
}
