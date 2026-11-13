// Package store 实现首批 P0 的受控事务；不是可供 Agent 直连的数据库 API。
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"trident/db"
)

var (
	ErrDenied   = errors.New("operation denied")
	ErrConflict = errors.New("state or idempotency conflict")
	ErrBudget   = errors.New("insufficient reserved budget")
	ErrStale    = errors.New("stale execution lease")
)

type Store struct {
	pool           *pgxpool.Pool
	singleOperator bool
}

// Session 不导出认证凭据字段，调用方只能通过 Authenticate 获得身份上下文。
type Session struct{ hash string }
type Principal struct {
	ID      int64  `json:"id"`
	Subject string `json:"subject"`
	Role    string `json:"role"`
	Token   string `json:"token,omitempty"`
}
type Lease struct {
	ID        int64  `json:"id"`
	TaskID    int64  `json:"task_id"`
	MissionID int64  `json:"mission_id"`
	Token     int64  `json:"fencing_token"`
	RuntimeID string `json:"runtime_id"`
}
type actor struct {
	id         int64
	role, kind string
}

func Open(ctx context.Context, dsn string, singleOperator bool) (*Store, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration")
	}
	config.MaxConns = 128
	config.MinConns = 0
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	p, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, fmt.Errorf("database unavailable: %w", err)
	}
	if err = db.Check(ctx, p); err != nil {
		p.Close()
		return nil, fmt.Errorf("schema gate: %w", err)
	}
	return &Store{pool: p, singleOperator: singleOperator}, nil
}
func (s *Store) Close() { s.pool.Close() }
func digest(v any) (string, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func credential() (string, string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", "", e
	}
	t := hex.EncodeToString(b)
	h, _ := digest(t)
	return t, h, nil
}
func authenticateTx(ctx context.Context, tx pgx.Tx, session Session) (actor, error) {
	var a actor
	// [01] 每笔事务重新验证数据库身份，凭据撤销不依赖本地 Session 缓存。
	e := tx.QueryRow(ctx, `SELECT id,role,principal_type FROM principals WHERE credential_hash=$1 AND status='active' FOR SHARE`, session.hash).Scan(&a.id, &a.role, &a.kind)
	if errors.Is(e, pgx.ErrNoRows) {
		return a, ErrDenied
	}
	return a, e
}
func (s *Store) Authenticate(ctx context.Context, token string) (Session, error) {
	if len(token) != 64 {
		return Session{}, ErrDenied
	}
	h, _ := digest(token)
	ss := Session{hash: h}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return Session{}, e
	}
	defer tx.Rollback(context.Background())
	if _, e = authenticateTx(ctx, tx, ss); e != nil {
		return Session{}, e
	}
	return ss, tx.Commit(ctx)
}
func allowed(a actor, roles ...string) error {
	for _, r := range roles {
		if a.role == r {
			return nil
		}
	}
	return ErrDenied
}

// Bootstrap 是显式本地管理操作，要求独占新库；应用启动绝不自动 seed 管理员。
func (s *Store) Bootstrap(ctx context.Context, subject string) (Principal, error) {
	if strings.TrimSpace(subject) == "" {
		return Principal{}, ErrDenied
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return Principal{}, e
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(84732001)`); e != nil {
		return Principal{}, e
	}
	var count int
	e = tx.QueryRow(ctx, `SELECT count(*) FROM principals`).Scan(&count)
	if e != nil {
		return Principal{}, e
	}
	if count != 0 {
		return Principal{}, ErrDenied
	}
	t, h, e := credential()
	if e != nil {
		return Principal{}, e
	}
	p := Principal{Subject: subject, Role: "admin", Token: t}
	e = tx.QueryRow(ctx, `INSERT INTO principals(subject,principal_type,role,credential_hash) VALUES($1,'human','admin',$2) RETURNING id`, subject, h).Scan(&p.ID)
	if e != nil {
		return Principal{}, e
	}
	return p, tx.Commit(ctx)
}
func (s *Store) AddPrincipal(ctx context.Context, ss Session, subject, kind, role string) (Principal, error) {
	if strings.TrimSpace(subject) == "" || (kind != "human" && kind != "service") {
		return Principal{}, ErrDenied
	}
	if role != "admin" && role != "scheduler" && role != "worker" && role != "reconciler" {
		return Principal{}, ErrDenied
	}
	if kind == "service" && role == "admin" {
		return Principal{}, ErrDenied
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return Principal{}, e
	}
	defer tx.Rollback(context.Background())
	a, e := authenticateTx(ctx, tx, ss)
	if e != nil {
		return Principal{}, e
	}
	if e = allowed(a, "admin"); e != nil {
		return Principal{}, e
	}
	t, h, e := credential()
	if e != nil {
		return Principal{}, e
	}
	p := Principal{Subject: subject, Role: role, Token: t}
	e = tx.QueryRow(ctx, `INSERT INTO principals(subject,principal_type,role,credential_hash) VALUES($1,$2,$3,$4) RETURNING id`, subject, kind, role, h).Scan(&p.ID)
	if e != nil {
		return Principal{}, e
	}
	return p, tx.Commit(ctx)
}

// operation 将幂等结果与业务变更原子提交；相同键但摘要不同，不能复用授权结果。
func (s *Store) operation(ctx context.Context, ss Session, op, key string, request any, fn func(pgx.Tx, actor) (any, error)) (json.RawMessage, error) {
	if strings.TrimSpace(key) == "" || len(key) > 200 {
		return nil, ErrConflict
	}
	h, e := digest(request)
	if e != nil {
		return nil, e
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(context.Background())
	a, e := authenticateTx(ctx, tx, ss)
	if e != nil {
		return nil, e
	}
	lockKey := fmt.Sprintf("%d/%s/%s", a.id, op, key)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); e != nil {
		return nil, e
	}
	if taskID := operationTask(op, request); taskID > 0 {
		if _, e = taskActorLock(ctx, tx, a, taskID, false); e != nil {
			return nil, e
		}
	}
	var oldHash string
	var old json.RawMessage
	e = tx.QueryRow(ctx, `SELECT request_hash,result FROM operation_results WHERE actor_id=$1 AND operation=$2 AND idempotency_key=$3`, a.id, op, key).Scan(&oldHash, &old)
	if e == nil {
		if oldHash != h {
			return nil, ErrConflict
		}
		return old, tx.Commit(ctx)
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	// [02] Worker 所有新增副作用都在同一事务中通过服务端 Fencing 校验。
	if wr, ok := request.(workerRequest); ok {
		if e = validateLease(ctx, tx, a, wr.Lease); e != nil {
			return nil, e
		}
	}
	result, e := fn(tx, a)
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(result)
	if e != nil {
		return nil, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO operation_results(actor_id,operation,idempotency_key,request_hash,result) VALUES($1,$2,$3,$4,$5)`, a.id, op, key, h, raw)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return raw, nil
}
func resultID(raw json.RawMessage, e error) (int64, error) {
	if e != nil {
		return 0, e
	}
	var id int64
	e = json.Unmarshal(raw, &id)
	return id, e
}
func event(ctx context.Context, tx pgx.Tx, a actor, taskID int64, kind string, id int64, name string, payload any) error {
	raw, e := json.Marshal(payload)
	if e != nil {
		return e
	}
	var version int64
	e = tx.QueryRow(ctx, `INSERT INTO aggregate_versions(task_id,kind,aggregate_id,version) VALUES($1,$2,$3,1) ON CONFLICT(task_id,kind,aggregate_id) DO UPDATE SET version=aggregate_versions.version+1 RETURNING version`, taskID, kind, id).Scan(&version)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO activities(task_id,actor_id,kind,detail) VALUES($1,$2,$3,$4)`, taskID, a.id, name, raw); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO outbox_events(task_id,aggregate_kind,aggregate_id,aggregate_version,event_type,payload) VALUES($1,$2,$3,$4,$5,$6)`, taskID, kind, id, version, name, raw)
	return e
}

// taskLock 统一按 Authorization -> Task 加锁，取得锁后使用真实数据库时钟检查。
func taskLock(ctx context.Context, tx pgx.Tx, taskID int64, needActive bool) (int64, error) {
	var authID int64
	if e := tx.QueryRow(ctx, `SELECT authorization_id FROM tasks WHERE id=$1`, taskID).Scan(&authID); e != nil {
		return 0, e
	}
	var status string
	var valid bool
	e := tx.QueryRow(ctx, `SELECT status,valid_from<=clock_timestamp() AND expires_at>clock_timestamp() FROM authorization_contracts WHERE id=$1 FOR UPDATE`, authID).Scan(&status, &valid)
	if e != nil {
		return 0, e
	}
	var taskStatus, versionStatus string
	var live bool
	e = tx.QueryRow(ctx, `SELECT t.status,v.status,t.deadline_at>clock_timestamp() FROM tasks t JOIN authorization_versions v ON v.authorization_id=t.authorization_id AND v.version=t.current_scope_ver WHERE t.id=$1 FOR UPDATE OF t,v`, taskID).Scan(&taskStatus, &versionStatus, &live)
	if e != nil {
		return 0, e
	}
	// [03] FOR UPDATE 可能等待旧锁，时间表达式必须在所有锁取得后另发语句重算。
	if needActive {
		e = tx.QueryRow(ctx, `SELECT c.status='active' AND c.valid_from<=clock_timestamp() AND c.expires_at>clock_timestamp() AND t.status='running' AND t.deadline_at>clock_timestamp() AND v.status='active' AND owner.status='active' AND approver.status='active' FROM tasks t JOIN authorization_contracts c ON c.id=t.authorization_id JOIN authorization_versions v ON v.authorization_id=c.id AND v.version=t.current_scope_ver JOIN principals owner ON owner.id=c.principal_id JOIN principals approver ON approver.id=c.approved_by_principal_id WHERE t.id=$1`, taskID).Scan(&valid)
		if e != nil {
			return 0, e
		}
		if !valid {
			return 0, ErrDenied
		}
	}
	return authID, nil
}
func node(ctx context.Context, tx pgx.Tx, taskID int64, kind string) (int64, error) {
	var id int64
	e := tx.QueryRow(ctx, `INSERT INTO nodes(task_id,kind) VALUES($1,$2) RETURNING id`, taskID, kind).Scan(&id)
	return id, e
}
