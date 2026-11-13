package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

func TestOutboxValidateDispatcher(t *testing.T) {
	// [01] dispatcher 是有界公开实例标识，不接受空白、控制字符或非法 UTF-8。
	for _, value := range []string{
		"dispatcher-1", "host:dispatcher/01", "投递器-一", strings.Repeat("a", outboxMaxDispatcherBytes),
	} {
		if err := validateOutboxDispatcher(value); err != nil {
			t.Errorf("valid dispatcher rejected: %v", err)
		}
	}
	for _, value := range []string{
		"", " ", " worker", "worker ", "worker two", "worker\t1", "worker\n1", "worker\x001",
		"worker1", "worker　1", string([]byte{0xff}), strings.Repeat("a", outboxMaxDispatcherBytes+1),
	} {
		if err := validateOutboxDispatcher(value); !errors.Is(err, ErrConflict) {
			t.Errorf("invalid dispatcher error = %v, want ErrConflict", err)
		}
	}
}

func TestOutboxValidateClaim(t *testing.T) {
	// [02] 微秒下限避免正的 duration 被截断成零，边界上限防止过大批次和超长锁。
	tests := []struct {
		name       string
		dispatcher string
		limit      int
		ttl        time.Duration
		valid      bool
	}{
		{"minimum", "worker", 1, time.Microsecond, true},
		{"typical", "worker", 32, 30 * time.Second, true},
		{"maximum", "worker", outboxMaxClaimLimit, outboxMaxClaimTTL, true},
		{"empty dispatcher", "", 1, time.Second, false},
		{"zero limit", "worker", 0, time.Second, false},
		{"negative limit", "worker", -1, time.Second, false},
		{"excessive limit", "worker", outboxMaxClaimLimit + 1, time.Second, false},
		{"zero TTL", "worker", 1, 0, false},
		{"negative TTL", "worker", 1, -time.Second, false},
		{"submicrosecond TTL", "worker", 1, time.Microsecond - 1, false},
		{"fractional microsecond TTL", "worker", 1, time.Second + time.Nanosecond, false},
		{"excessive TTL", "worker", 1, outboxMaxClaimTTL + time.Microsecond, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOutboxClaim(tt.dispatcher, tt.limit, tt.ttl)
			if tt.valid {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrConflict) {
				t.Fatalf("error = %v, want ErrConflict", err)
			}
		})
	}
}

func TestOutboxValidateReceipt(t *testing.T) {
	if err := validateOutboxReceipt(1, 1, "worker"); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		id, generation int64
		dispatcher     string
	}{
		{0, 1, "worker"}, {-1, 1, "worker"}, {1, 0, "worker"}, {1, -1, "worker"}, {1, 1, ""},
	} {
		if err := validateOutboxReceipt(tt.id, tt.generation, tt.dispatcher); !errors.Is(err, ErrConflict) {
			t.Errorf("error = %v, want ErrConflict", err)
		}
	}
}

func TestOutboxValidateFailure(t *testing.T) {
	// [03] attempts 与数据库 INT 范围一致；零等待可以立即重试，负等待及亚微秒精度拒绝。
	tests := []struct {
		name        string
		id          int64
		generation  int64
		dispatcher  string
		maxAttempts int
		delay       time.Duration
		valid       bool
	}{
		{"minimum", 1, 1, "worker", 1, 0, true},
		{"typical", 1, 2, "worker", 5, time.Second, true},
		{"maximum", 1, 1, "worker", outboxMaxAttempts, outboxMaxRetryDelay, true},
		{"invalid ID", 0, 1, "worker", 5, time.Second, false},
		{"invalid generation", 1, 0, "worker", 5, time.Second, false},
		{"invalid dispatcher", 1, 1, "", 5, time.Second, false},
		{"zero attempts", 1, 1, "worker", 0, time.Second, false},
		{"negative attempts", 1, 1, "worker", -1, time.Second, false},
		{"negative delay", 1, 1, "worker", 5, -time.Second, false},
		{"submicrosecond delay", 1, 1, "worker", 5, time.Nanosecond, false},
		{"fractional microsecond delay", 1, 1, "worker", 5, time.Second + time.Nanosecond, false},
		{"excessive delay", 1, 1, "worker", 5, outboxMaxRetryDelay + time.Microsecond, false},
	}
	// [04] 运行在 64 位平台时额外检查超出 PostgreSQL INT 的输入，仍保持测试可在 32 位编译。
	tooMany := int64(outboxMaxAttempts) + 1
	if int64(int(tooMany)) == tooMany {
		tests = append(tests, struct {
			name        string
			id          int64
			generation  int64
			dispatcher  string
			maxAttempts int
			delay       time.Duration
			valid       bool
		}{"excessive attempts", 1, 1, "worker", int(tooMany), time.Second, false})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOutboxFailure(tt.id, tt.generation, tt.dispatcher, tt.maxAttempts, tt.delay)
			if tt.valid {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrConflict) {
				t.Fatalf("error = %v, want ErrConflict", err)
			}
		})
	}
}

func TestOutboxValidateReplay(t *testing.T) {
	// [05] 人工重投原因必须非空、有界、合法 UTF-8 且无控制字符，禁止写入任意大审计字段。
	for _, reason := range []string{"修复投递端后重新通知", " manual retry ", strings.Repeat("a", outboxMaxReasonBytes)} {
		if err := validateOutboxReplay(1, reason); err != nil {
			t.Errorf("valid replay reason rejected: %v", err)
		}
	}
	for _, reason := range []string{
		"", " \t\n", "　", "reason\x00", "reason\nsecond line", "reason",
		string([]byte{0xff}), strings.Repeat("a", outboxMaxReasonBytes+1),
	} {
		if err := validateOutboxReplay(1, reason); !errors.Is(err, ErrConflict) {
			t.Errorf("invalid replay reason error = %v, want ErrConflict", err)
		}
	}
	for _, id := range []int64{0, -1} {
		if err := validateOutboxReplay(id, "manual retry"); !errors.Is(err, ErrConflict) {
			t.Errorf("invalid replay ID error = %v, want ErrConflict", err)
		}
	}
}

func TestOutboxErrorSummaryDoesNotPersistCredentials(t *testing.T) {
	// [06] 不猜测凭据格式：URL、Header、DSN、未知 token 及超长错误的原文全部不落库。
	for _, input := range []string{
		"", "connection reset", "Authorization: Bearer secret-access-token",
		"postgres://user:secret-password@example.invalid/database",
		"Cookie: session=secret-cookie", "unknown-format-sensitive-value",
		"first line\r\nforged log entry\x00", string([]byte{0xff, 0xfe}),
		strings.Repeat("sensitive", 1<<17),
	} {
		got := outboxErrorSummary(input)
		if len(got) > 128 || !utf8.ValidString(got) || strings.ContainsAny(got, "\r\n\x00") {
			t.Fatalf("summary must be bounded and safe, got %q", got)
		}
		if input != "" && strings.Contains(got, input) {
			t.Fatal("summary contains original diagnostic")
		}
		if !strings.HasPrefix(got, "delivery failed (diagnostic redacted; original_bytes=") {
			t.Fatalf("unexpected summary format: %q", got)
		}
	}
	if got := outboxErrorSummary("secret"); got != "delivery failed (diagnostic redacted; original_bytes=6)" {
		t.Fatalf("unexpected summary: %q", got)
	}
}

func TestOutboxInvalidArgumentsDoNotTouchDatabase(t *testing.T) {
	// [07] 使用空 Store 验证公开入口先做参数检查，不连接 PostgreSQL、不需要测试服务。
	var s Store
	ctx := context.Background()
	ss := Session{}
	tests := []struct {
		name string
		call func() error
	}{
		{"claim dispatcher", func() error { _, err := s.ClaimEvents(ctx, ss, "", 1, time.Second); return err }},
		{"claim limit", func() error { _, err := s.ClaimEvents(ctx, ss, "worker", 0, time.Second); return err }},
		{"claim TTL", func() error { _, err := s.ClaimEvents(ctx, ss, "worker", 1, 0); return err }},
		{"ack ID", func() error { return s.AckEvent(ctx, ss, 0, 1, "worker") }},
		{"ack generation", func() error { return s.AckEvent(ctx, ss, 1, 0, "worker") }},
		{"ack dispatcher", func() error { return s.AckEvent(ctx, ss, 1, 1, "") }},
		{"fail attempts", func() error { return s.FailEvent(ctx, ss, 1, 1, "worker", "ignored", 0, time.Second) }},
		{"fail delay", func() error { return s.FailEvent(ctx, ss, 1, 1, "worker", "ignored", 3, -time.Second) }},
		{"fail claim", func() error { return s.FailEvent(ctx, ss, 1, 0, "worker", "ignored", 3, time.Second) }},
		{"replay ID", func() error { return s.ReplayEvent(ctx, ss, 0, "manual retry") }},
		{"replay reason", func() error { return s.ReplayEvent(ctx, ss, 1, " ") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, ErrConflict) {
				t.Fatalf("error = %v, want ErrConflict", err)
			}
		})
	}
}

func TestOutboxEventPayloadPreserved(t *testing.T) {
	// [08] 通知结构使用 RawMessage 保留 JSON 对象，而非把 payload 二次编码成字符串。
	e := OutboxEvent{
		ID: 1, TaskID: 2, AggregateKind: "mission", AggregateID: 3,
		AggregateVersion: 4, EventType: "mission.done", Payload: json.RawMessage(`{"state":"done"}`),
		ClaimGeneration: 5,
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["Payload"]) != `{"state":"done"}` {
		t.Fatalf("payload = %s, want JSON object", got["Payload"])
	}
}

func TestOutboxAllowedActor(t *testing.T) {
	// [09] 全局越权仅限人工管理员；服务管理员不能通过任何投递入口。
	for _, tt := range []struct {
		name  string
		actor actor
		roles []string
		allow bool
	}{
		{"human admin claim", actor{1, "admin", "human"}, []string{"admin", "reconciler"}, true},
		{"human admin replay", actor{1, "admin", "human"}, []string{"admin"}, true},
		{"service admin claim", actor{1, "admin", "service"}, []string{"admin", "reconciler"}, false},
		{"service admin replay", actor{1, "admin", "service"}, []string{"admin"}, false},
		{"organization admin", actor{1, "admin", "organization"}, []string{"admin"}, false},
		{"service reconciler", actor{2, "reconciler", "service"}, []string{"admin", "reconciler"}, true},
		{"reconciler cannot replay", actor{2, "reconciler", "service"}, []string{"admin"}, false},
		{"worker cannot claim", actor{3, "worker", "service"}, []string{"admin", "reconciler"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := allowedOutboxActor(tt.actor, tt.roles...)
			if tt.allow && err != nil {
				t.Fatal(err)
			}
			if !tt.allow && !errors.Is(err, ErrDenied) {
				t.Fatalf("error = %v, want ErrDenied", err)
			}
		})
	}
}

func TestOutboxClaimSQLTaskIsolation(t *testing.T) {
	// [10] 权限与已锁任务集合必须在 LIMIT 前过滤，不能领取后才在 Go 中丢弃越权事件。
	for _, tt := range []struct {
		name, query, admin, principal string
	}{
		{"candidate tasks", outboxClaimTasksSQL, "$1::boolean OR EXISTS", "member.principal_id = $2"},
		{"claim", outboxClaimSQL, "$4::boolean OR EXISTS", "member.principal_id = $5"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			order := strings.Index(tt.query, "ORDER BY")
			for _, clause := range []string{
				"e.published_at IS NULL", "e.dead_lettered_at IS NULL", "e.available_at <= clock_timestamp()",
				"e.locked_until IS NULL OR e.locked_until <= clock_timestamp()", tt.admin,
				"FROM task_members AS member", "member.task_id = e.task_id", tt.principal,
				"member.role = 'reconciler'", "member.status = 'active'",
				"previous.task_id = e.task_id", "previous.aggregate_kind = e.aggregate_kind",
				"previous.aggregate_id = e.aggregate_id", "previous.aggregate_version < e.aggregate_version",
				"previous.published_at IS NULL",
			} {
				if at := strings.Index(tt.query, clause); at < 0 || order < 0 || at >= order {
					t.Errorf("missing qualification before ordering: %s", clause)
				}
			}
			for _, unsafe := range []string{"previous.dead_lettered_at", "previous.available_at", "previous.locked_until"} {
				if strings.Contains(tt.query, unsafe) {
					t.Errorf("aggregate head may be bypassed: %s", unsafe)
				}
			}
		})
	}
	if !strings.Contains(outboxClaimTasksSQL, "SELECT DISTINCT t.authorization_id, e.task_id") ||
		!strings.Contains(outboxClaimTasksSQL, "ORDER BY t.authorization_id, e.task_id") {
		t.Fatal("candidate tasks must be deduplicated and globally sorted by Auth/Task")
	}
	if strings.Contains(outboxClaimTasksSQL, "LIMIT") || strings.Contains(outboxClaimTasksSQL, "FOR UPDATE") {
		t.Fatal("task discovery must not truncate coverage or lock events before Task locks")
	}
	limit := strings.Index(outboxClaimSQL, "LIMIT $1")
	lockedTasks := strings.Index(outboxClaimSQL, "AND e.task_id = ANY($6::bigint[])")
	if limit < 0 || lockedTasks < 0 || lockedTasks >= limit ||
		!strings.Contains(outboxClaimSQL, "claimed_by_principal_id = $5") ||
		!strings.Contains(outboxClaimSQL, "FOR UPDATE OF e SKIP LOCKED") {
		t.Fatal("claim must bind the principal and only lock pre-authorized tasks before LIMIT")
	}
}

func TestOutboxReceiptSQLPrincipalCAS(t *testing.T) {
	// [11] dispatcher 相同但 principal 不同的回执也必须失败；释放领取后清除两种 owner。
	for _, tt := range []struct{ name, query, owner string }{
		{"ack", outboxAckSQL, "AND claimed_by_principal_id = $4"},
		{"fail", outboxFailSQL, "AND claimed_by_principal_id = $7"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, clause := range []string{
				"WHERE id = $1 AND claim_generation = $2 AND locked_by = $3", tt.owner,
				"AND locked_until > clock_timestamp()", "published_at IS NULL AND dead_lettered_at IS NULL",
				"claimed_by_principal_id = NULL", "locked_by = NULL", "locked_until = NULL",
			} {
				if !strings.Contains(tt.query, clause) {
					t.Errorf("missing receipt protection: %s", clause)
				}
			}
		})
	}
	for _, clause := range []string{
		"claimed_by_principal_id = NULL", "locked_by = NULL", "locked_until = NULL",
		"claim_generation = claim_generation + 1", "attempts = 0", "last_error = NULL",
	} {
		if !strings.Contains(outboxReplaySQL, clause) {
			t.Errorf("replay must revoke the old receipt: missing %s", clause)
		}
	}
}

// [12] 仅模拟此文件所需的 pgx 调用；不创建连接、不读取任何 DSN 或运行迁移。
// 未实现的方法由嵌入接口保持 fail-closed，意外数据库操作会直接使测试失败。
type outboxTestStep struct {
	method string
	query  string
	args   []any
	values []any
	rows   [][]any
	err    error
}

type outboxTestTx struct {
	pgx.Tx
	t        *testing.T
	steps    []outboxTestStep
	rowsOpen bool
}

func (tx *outboxTestTx) next(method, query string, args []any) outboxTestStep {
	tx.t.Helper()
	if tx.rowsOpen {
		tx.t.Fatal("candidate rows must be closed before issuing lock queries")
	}
	if len(tx.steps) == 0 {
		tx.t.Fatalf("unexpected %s: %s", method, query)
	}
	step := tx.steps[0]
	tx.steps = tx.steps[1:]
	if step.method != method || !strings.Contains(query, step.query) || !reflect.DeepEqual(args, step.args) {
		tx.t.Fatalf("got %s %q args %v; want %s containing %q args %v", method, query, args, step.method, step.query, step.args)
	}
	return step
}

func (tx *outboxTestTx) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	step := tx.next("row", query, args)
	return outboxTestRow{t: tx.t, values: step.values, err: step.err}
}

func (tx *outboxTestTx) Query(_ context.Context, query string, args ...any) (pgx.Rows, error) {
	step := tx.next("rows", query, args)
	if step.err != nil {
		return nil, step.err
	}
	tx.rowsOpen = true
	return &outboxTestRows{tx: tx, values: step.rows, index: -1}, nil
}

type outboxTestRow struct {
	t      *testing.T
	values []any
	err    error
}

func (row outboxTestRow) Scan(dest ...any) error {
	row.t.Helper()
	if row.err != nil {
		return row.err
	}
	if len(dest) != len(row.values) {
		row.t.Fatalf("scan has %d destinations, want %d", len(dest), len(row.values))
	}
	for i, value := range row.values {
		target, source := reflect.ValueOf(dest[i]), reflect.ValueOf(value)
		if target.Kind() != reflect.Ptr || target.IsNil() || !source.IsValid() || !source.Type().AssignableTo(target.Elem().Type()) {
			row.t.Fatalf("scan value %T cannot populate %T", value, dest[i])
		}
		target.Elem().Set(source)
	}
	return nil
}

type outboxTestRows struct {
	pgx.Rows
	tx     *outboxTestTx
	values [][]any
	index  int
	closed bool
}

func (rows *outboxTestRows) Next() bool {
	if rows.closed {
		return false
	}
	rows.index++
	if rows.index >= len(rows.values) {
		rows.Close()
		return false
	}
	return true
}

func (rows *outboxTestRows) Scan(dest ...any) error {
	return (outboxTestRow{t: rows.tx.t, values: rows.values[rows.index]}).Scan(dest...)
}

func (rows *outboxTestRows) Close() {
	rows.closed = true
	rows.tx.rowsOpen = false
}

func (rows *outboxTestRows) Err() error { return nil }

func outboxTestTaskLockSteps(a actor, authID, taskID int64, memberErr error, granted bool) []outboxTestStep {
	// [13] stopped Task/失效 Scope 仍可投递历史通知，needActive=false 不能误要求业务继续运行。
	steps := []outboxTestStep{
		{method: "row", query: "SELECT authorization_id FROM tasks", args: []any{taskID}, values: []any{authID}},
		{method: "row", query: "FROM authorization_contracts WHERE id=$1 FOR UPDATE", args: []any{authID}, values: []any{"revoked", false}},
		{method: "row", query: "FOR UPDATE OF t,v", args: []any{taskID}, values: []any{"stopped", "revoked", false}},
	}
	if a.role != "admin" || a.kind != "human" {
		steps = append(steps, outboxTestStep{
			method: "row", query: "FROM task_members WHERE task_id=$1 AND principal_id=$2 FOR SHARE",
			args: []any{taskID, a.id, a.role}, values: []any{granted}, err: memberErr,
		})
	}
	return steps
}

func outboxTestAssertDone(t *testing.T, tx *outboxTestTx) {
	t.Helper()
	if len(tx.steps) != 0 || tx.rowsOpen {
		t.Fatalf("unconsumed steps = %d, rows still open = %v", len(tx.steps), tx.rowsOpen)
	}
}

func TestOutboxLockClaimTasks(t *testing.T) {
	// [14] task ID 大小不代表合同锁顺序；同合同先锁较小 Task，再进入下一个合同。
	for _, tt := range []struct {
		name      string
		actor     actor
		denied    bool
		memberErr error
		want      []int64
	}{
		{"admin", actor{1, "admin", "human"}, false, nil, []int64{30, 40, 10}},
		{"reconciler", actor{2, "reconciler", "service"}, false, nil, []int64{30, 40, 10}},
		{"revoked after discovery", actor{2, "reconciler", "service"}, true, nil, []int64{30, 10}},
		{"missing after discovery", actor{2, "reconciler", "service"}, true, pgx.ErrNoRows, []int64{30, 10}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tx := &outboxTestTx{t: t, steps: []outboxTestStep{{
				method: "rows", query: outboxClaimTasksSQL,
				args: []any{tt.actor.role == "admin" && tt.actor.kind == "human", tt.actor.id},
				rows: [][]any{{int64(2), int64(30)}, {int64(2), int64(40)}, {int64(3), int64(10)}},
			}}}
			tx.steps = append(tx.steps, outboxTestTaskLockSteps(tt.actor, 2, 30, nil, true)...)
			tx.steps = append(tx.steps, outboxTestTaskLockSteps(tt.actor, 2, 40, tt.memberErr, !tt.denied)...)
			tx.steps = append(tx.steps, outboxTestTaskLockSteps(tt.actor, 3, 10, nil, true)...)
			got, err := lockOutboxClaimTasks(context.Background(), tx, tt.actor)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("locked tasks = %v, error = %v; want %v", got, err, tt.want)
			}
			outboxTestAssertDone(t, tx)
		})
	}
}

func TestOutboxLockClaimTasksErrors(t *testing.T) {
	a := actor{2, "reconciler", "service"}
	dbErr := errors.New("test query failure")
	t.Run("discovery error", func(t *testing.T) {
		tx := &outboxTestTx{t: t, steps: []outboxTestStep{{method: "rows", query: outboxClaimTasksSQL, args: []any{false, a.id}, err: dbErr}}}
		if _, err := lockOutboxClaimTasks(context.Background(), tx, a); !errors.Is(err, dbErr) {
			t.Fatalf("error = %v, want query failure", err)
		}
		outboxTestAssertDone(t, tx)
	})
	t.Run("empty candidates", func(t *testing.T) {
		tx := &outboxTestTx{t: t, steps: []outboxTestStep{{method: "rows", query: outboxClaimTasksSQL, args: []any{false, a.id}}}}
		got, err := lockOutboxClaimTasks(context.Background(), tx, a)
		if err != nil || got == nil || len(got) != 0 {
			t.Fatalf("locked tasks = %v, error = %v; want non-nil empty list", got, err)
		}
		outboxTestAssertDone(t, tx)
	})
	t.Run("membership query error is not denial", func(t *testing.T) {
		tx := &outboxTestTx{t: t, steps: []outboxTestStep{{
			method: "rows", query: outboxClaimTasksSQL, args: []any{false, a.id}, rows: [][]any{{int64(2), int64(30)}},
		}}}
		tx.steps = append(tx.steps, outboxTestTaskLockSteps(a, 2, 30, dbErr, true)...)
		if _, err := lockOutboxClaimTasks(context.Background(), tx, a); !errors.Is(err, dbErr) {
			t.Fatalf("error = %v, want query failure", err)
		}
		outboxTestAssertDone(t, tx)
	})
}

func TestOutboxLockEventTask(t *testing.T) {
	// [15] Ack/Fail/Replay 共用非锁定位 -> Auth/Task/member -> event 的严格顺序。
	for _, tt := range []struct {
		name      string
		actor     actor
		lookupErr error
		memberErr error
		granted   bool
		eventErr  error
		wantErr   error
	}{
		{"human admin", actor{1, "admin", "human"}, nil, nil, true, nil, nil},
		{"active member", actor{2, "reconciler", "service"}, nil, nil, true, nil, nil},
		{"revoked member", actor{2, "reconciler", "service"}, nil, nil, false, nil, ErrDenied},
		{"missing member", actor{2, "reconciler", "service"}, nil, pgx.ErrNoRows, false, nil, ErrDenied},
		{"missing event", actor{2, "reconciler", "service"}, pgx.ErrNoRows, nil, true, nil, ErrConflict},
		{"event gone before lock", actor{2, "reconciler", "service"}, nil, nil, true, pgx.ErrNoRows, ErrConflict},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tx := &outboxTestTx{t: t, steps: []outboxTestStep{{
				method: "row", query: "SELECT task_id FROM outbox_events WHERE id = $1",
				args: []any{int64(90)}, values: []any{int64(30)}, err: tt.lookupErr,
			}}}
			if tt.lookupErr == nil {
				tx.steps = append(tx.steps, outboxTestTaskLockSteps(tt.actor, 2, 30, tt.memberErr, tt.granted)...)
				if tt.memberErr == nil && tt.granted {
					tx.steps = append(tx.steps, outboxTestStep{
						method: "row", query: "SELECT id FROM outbox_events WHERE id = $1 FOR UPDATE",
						args: []any{int64(90)}, values: []any{int64(90)}, err: tt.eventErr,
					})
				}
			}
			if err := lockOutboxEventTask(context.Background(), tx, tt.actor, 90); !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			outboxTestAssertDone(t, tx)
		})
	}
}
