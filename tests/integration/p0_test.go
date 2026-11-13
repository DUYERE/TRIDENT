//go:build integration

// Package integration 仅连接显式指定的独立测试库；缺少配置为失败，不静默跳过。
package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"trident/db"
	"trident/internal/domain"
	"trident/internal/store"
)

var sequence atomic.Int64

func unique(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), sequence.Add(1))
}

type fixture struct {
	s                         *store.Store
	p                         *pgxpool.Pool
	admin, worker, reconciler store.Session
	auth, task, asset         int64
	workerID, reconcilerID    int64
}

func setup(t *testing.T) *fixture {
	t.Helper()
	dsn := os.Getenv("TRIDENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TRIDENT_TEST_DATABASE_URL required: real PostgreSQL integration tests do not skip")
	}
	ctx := context.Background()
	p, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(p.Close)
	if e = db.Migrate(ctx, p, "integration-test"); e != nil {
		t.Fatal(e)
	}
	if e = db.Check(ctx, p); e != nil {
		t.Fatal(e)
	}
	s, e := store.Open(ctx, dsn, false)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	token := os.Getenv("TRIDENT_TEST_ADMIN_TOKEN")
	if token == "" {
		p, e := s.Bootstrap(ctx, "test-root")
		if e != nil {
			t.Fatal("bootstrap requires an empty dedicated test DB or TRIDENT_TEST_ADMIN_TOKEN:", e)
		}
		token = p.Token
		if e = os.Setenv("TRIDENT_TEST_ADMIN_TOKEN", token); e != nil {
			t.Fatal(e)
		}
	}
	admin, e := s.Authenticate(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	owner, e := s.AddPrincipal(ctx, admin, unique("owner"), "human", "scheduler")
	if e != nil {
		t.Fatal(e)
	}
	worker, e := s.AddPrincipal(ctx, admin, unique("worker"), "service", "worker")
	if e != nil {
		t.Fatal(e)
	}
	recon, e := s.AddPrincipal(ctx, admin, unique("reconciler"), "service", "reconciler")
	if e != nil {
		t.Fatal(e)
	}
	ws, e := s.Authenticate(ctx, worker.Token)
	if e != nil {
		t.Fatal(e)
	}
	rs, e := s.Authenticate(ctx, recon.Token)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256([]byte("synthetic offline authorization proof"))
	now := time.Now().UTC()
	scope := domain.Scope{Domains: []string{"example.invalid"}, IPRanges: []string{"192.0.2.0/24"}, Ports: []uint16{443}, Protocols: []string{"https"}, AllowedActions: []string{"observe"}, ForbiddenActions: []string{"destructive"}, MaxRPS: 2, MaxConcurrency: 4, DataPolicy: "synthetic-only", StopConditions: []string{"deadline", "revocation"}}
	auth, e := s.CreateAuthorization(ctx, admin, unique("auth"), store.AuthorizationRequest{PrincipalID: owner.ID, Scope: scope, ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), ProofRef: "manual:integration", ProofHash: hex.EncodeToString(h[:])})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ActivateAuthorization(ctx, admin, unique("activate"), auth, "Verified synthetic fixture for offline transaction tests"); e != nil {
		t.Fatal(e)
	}
	task, e := s.CreateTask(ctx, admin, unique("task"), auth, "offline fixture", now.Add(30*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.GrantTaskMember(ctx, admin, unique("grant-worker"), task, worker.ID, "worker", "explicit fixture worker"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.GrantTaskMember(ctx, admin, unique("grant-reconciler"), task, recon.ID, "reconciler", "explicit fixture reconciler"); e != nil {
		t.Fatal(e)
	}
	asset, e := s.RegisterAsset(ctx, admin, unique("asset"), task, "https://example.invalid/")
	if e != nil {
		t.Fatal(e)
	}
	var state string
	if e = p.QueryRow(ctx, `SELECT scope_status FROM assets WHERE id=$1`, asset).Scan(&state); e != nil || state != "pending_review" {
		t.Fatalf("asset default=%s err=%v", state, e)
	}
	if _, e = s.ReviewAsset(ctx, admin, unique("review"), task, asset, "observe"); e != nil {
		t.Fatal(e)
	}
	return &fixture{s: s, p: p, admin: admin, worker: ws, reconciler: rs, auth: auth, task: task, asset: asset, workerID: worker.ID, reconcilerID: recon.ID}
}
func (f *fixture) mission(t *testing.T, amount int64) int64 {
	t.Helper()
	ctx := context.Background()
	i, e := f.s.CreateIntent(ctx, f.admin, unique("intent"), f.task, f.asset, "synthetic test intent")
	if e != nil {
		t.Fatal(e)
	}
	m, e := f.s.CreateMission(ctx, f.admin, unique("mission"), store.MissionRequest{TaskID: f.task, IntentID: i, AssetID: f.asset, Angle: "offline", Deadline: time.Now().Add(10 * time.Minute), Budgets: map[string]int64{"steps": amount}})
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func (f *fixture) budget(t *testing.T, n int64) {
	t.Helper()
	if _, e := f.s.SetBudget(context.Background(), f.admin, unique("budget"), f.task, "steps", n); e != nil {
		t.Fatal(e)
	}
}
func (f *fixture) pool(t *testing.T, cap int) string {
	t.Helper()
	name := unique("pool")
	if _, e := f.s.SetPool(context.Background(), f.admin, unique("pool-config"), name, cap); e != nil {
		t.Fatal(e)
	}
	return name
}
func (f *fixture) claim(t *testing.T, m int64, pool string, ttl time.Duration) store.Lease {
	t.Helper()
	l, e := f.s.Claim(context.Background(), f.worker, unique("claim"), f.task, m, pool, unique("runtime"), ttl)
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func scalar(t *testing.T, p *pgxpool.Pool, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if e := p.QueryRow(context.Background(), q, args...).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}

func TestOfflineLifecycleIdempotency(t *testing.T) {
	f := setup(t)
	f.budget(t, 10)
	m := f.mission(t, 4)
	l := f.claim(t, m, f.pool(t, 2), time.Minute)
	ctx := context.Background()
	if e := f.s.Consume(ctx, f.worker, "consume-once", l, "steps", 2); e != nil {
		t.Fatal(e)
	}
	if e := f.s.Consume(ctx, f.worker, "consume-once", l, "steps", 2); e != nil {
		t.Fatal(e)
	}
	if e := f.s.Consume(ctx, f.worker, "consume-once", l, "steps", 3); !errors.Is(e, store.ErrConflict) {
		t.Fatalf("digest mismatch=%v", e)
	}
	fact, e := f.s.RecordFact(ctx, f.worker, "fact-once", l, "observed", json.RawMessage(`{"synthetic":true}`))
	if e != nil {
		t.Fatal(e)
	}
	again, e := f.s.RecordFact(ctx, f.worker, "fact-once", l, "observed", json.RawMessage(`{"synthetic":true}`))
	if e != nil || again != fact {
		t.Fatalf("fact duplicated: %d %d %v", fact, again, e)
	}
	if e = f.s.Finish(ctx, f.worker, "finish-once", l, "done"); e != nil {
		t.Fatal(e)
	}
	if e = f.s.Finish(ctx, f.worker, "finish-once", l, "done"); e != nil {
		t.Fatal(e)
	}
	if got := scalar(t, f.p, `SELECT consumed FROM budget_ledgers WHERE task_id=$1`, f.task); got != 2 {
		t.Fatalf("consumed=%d", got)
	}
	if got := scalar(t, f.p, `SELECT reserved FROM budget_ledgers WHERE task_id=$1`, f.task); got != 0 {
		t.Fatalf("reserved=%d", got)
	}
	if _, e = f.s.RecordFact(ctx, f.worker, unique("late"), l, "observed", json.RawMessage(`{}`)); e == nil {
		t.Fatal("terminal worker wrote result")
	}
}
func TestOneHundredConcurrentClaims(t *testing.T) {
	f := setup(t)
	f.budget(t, 10)
	m := f.mission(t, 4)
	pool := f.pool(t, 100)
	ctx := context.Background()
	var winners atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	// [01] 所有 goroutine 同步起跑，Store 允许128连接；每个调用独立事务。
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, e := f.s.Claim(ctx, f.worker, fmt.Sprintf("claim-%d", i), f.task, m, pool, fmt.Sprintf("runtime-%d", i), time.Minute)
			if e == nil {
				winners.Add(1)
			} else if !errors.Is(e, store.ErrConflict) {
				t.Errorf("claim error: %v", e)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners=%d", winners.Load())
	}
	if n := scalar(t, f.p, `SELECT count(*) FROM execution_leases WHERE mission_id=$1 AND status='active'`, m); n != 1 {
		t.Fatalf("leases=%d", n)
	}
}
func TestConcurrentBudgetReservations(t *testing.T) {
	f := setup(t)
	f.budget(t, 10)
	ctx := context.Background()
	var intents []int64
	for i := 0; i < 20; i++ {
		id, e := f.s.CreateIntent(ctx, f.admin, unique("intent"), f.task, f.asset, "budget race")
		if e != nil {
			t.Fatal(e)
		}
		intents = append(intents, id)
	}
	var winners atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, id := range intents {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			<-start
			_, e := f.s.CreateMission(ctx, f.admin, fmt.Sprintf("reserve-%d", id), store.MissionRequest{TaskID: f.task, IntentID: id, AssetID: f.asset, Angle: "offline", Deadline: time.Now().Add(time.Minute), Budgets: map[string]int64{"steps": 3}})
			if e == nil {
				winners.Add(1)
			} else if !errors.Is(e, store.ErrBudget) {
				t.Errorf("reserve: %v", e)
			}
		}(id)
	}
	close(start)
	wg.Wait()
	if winners.Load() != 3 {
		t.Fatalf("reservation winners=%d", winners.Load())
	}
	if n := scalar(t, f.p, `SELECT reserved FROM budget_ledgers WHERE task_id=$1`, f.task); n != 9 {
		t.Fatalf("reserved=%d", n)
	}
}
func TestFencingAndMultiCapacityPool(t *testing.T) {
	f := setup(t)
	f.budget(t, 20)
	pool := f.pool(t, 2)
	m1 := f.mission(t, 4)
	m2 := f.mission(t, 4)
	a := f.claim(t, m1, pool, time.Minute)
	b := f.claim(t, m2, pool, time.Minute)
	ctx := context.Background()
	if b.Token <= a.Token {
		t.Fatal("token not monotonic")
	}
	if e := f.s.Consume(ctx, f.worker, unique("a-before"), a, "steps", 1); e != nil {
		t.Fatal("new peer token killed valid lease:", e)
	}
	// [03] 显式注入过期，避免100ms实时时限将合法并发测试变成调度时延测试。
	if _, e := f.p.Exec(ctx, `UPDATE execution_leases SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, a.ID); e != nil {
		t.Fatal(e)
	}
	if e := f.s.Heartbeat(ctx, f.worker, unique("old-heartbeat"), a, time.Minute); e == nil {
		t.Fatal("expired worker renewed")
	}
	if _, e := f.s.RecoverExpired(ctx, f.reconciler, unique("recover"), f.task, m1); e != nil {
		t.Fatal(e)
	}
	if got := scalar(t, f.p, `SELECT reserved FROM budget_ledgers WHERE task_id=$1`, f.task); got != 7 {
		t.Fatalf("uncertain budget prematurely released=%d", got)
	}
	if _, e := f.s.RetryReviewed(ctx, f.admin, unique("review-retry"), f.task, m1, "offline execution confirmed stopped; idempotent retry safe"); e != nil {
		t.Fatal(e)
	}
	c := f.claim(t, m1, pool, time.Minute)
	if c.Token <= b.Token {
		t.Fatal("replacement token not increased")
	}
	if _, e := f.s.RecordFact(ctx, f.worker, unique("stale-fact"), a, "observed", json.RawMessage(`{}`)); e == nil {
		t.Fatal("old worker wrote authoritative result")
	}
	if e := f.s.Consume(ctx, f.worker, unique("stale-consume"), a, "steps", 1); e == nil {
		t.Fatal("old worker consumed budget")
	}
	if e := f.s.Consume(ctx, f.worker, unique("b-live"), b, "steps", 1); e != nil {
		t.Fatal("unrelated live lease rejected:", e)
	}
	if e := f.s.Consume(ctx, f.worker, unique("c-live"), c, "steps", 1); e != nil {
		t.Fatal(e)
	}
}
func TestRevocationAndReconciliation(t *testing.T) {
	f := setup(t)
	f.budget(t, 10)
	m := f.mission(t, 4)
	l := f.claim(t, m, f.pool(t, 1), time.Minute)
	ctx := context.Background()
	if e := f.s.Consume(ctx, f.worker, unique("consume"), l, "steps", 1); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.RevokeAuthorization(ctx, f.admin, unique("revoke"), f.auth, "fixture stop"); e != nil {
		t.Fatal(e)
	}
	if e := f.s.Consume(ctx, f.worker, unique("denied"), l, "steps", 1); e == nil {
		t.Fatal("revoked execution allowed")
	}
	if _, e := f.s.CreateTask(ctx, f.admin, unique("bad-task"), f.auth, "revoked", time.Now().Add(time.Minute)); e == nil {
		t.Fatal("revoked task created")
	}
	if n := scalar(t, f.p, `SELECT reserved FROM budget_ledgers WHERE task_id=$1`, f.task); n != 3 {
		t.Fatal("revocation lost unknown reservation")
	}
	if e := f.s.SettleReviewed(ctx, f.reconciler, "settle-review", f.task, m, "offline execution stopped and all usage accounted"); e != nil {
		t.Fatal(e)
	}
	if e := f.s.SettleReviewed(ctx, f.reconciler, "settle-review", f.task, m, "offline execution stopped and all usage accounted"); e != nil {
		t.Fatal(e)
	}
	if n := scalar(t, f.p, `SELECT reserved FROM budget_ledgers WHERE task_id=$1`, f.task); n != 0 {
		t.Fatalf("reserved=%d", n)
	}
	if n := scalar(t, f.p, `SELECT consumed FROM budget_ledgers WHERE task_id=$1`, f.task); n != 1 {
		t.Fatalf("consumed=%d", n)
	}
}
func TestDatabaseIntegrityAndAtomicOutbox(t *testing.T) {
	f := setup(t)
	g := setup(t)
	f.budget(t, 10)
	m := f.mission(t, 2)
	ctx := context.Background()
	if _, e := f.p.Exec(ctx, `INSERT INTO edges(task_id,src_id,dst_id,rel) VALUES($1,$2,$3,'spawns')`, g.task, m, m+1); e == nil {
		t.Fatal("cross task edge allowed")
	}
	if _, e := f.p.Exec(ctx, `UPDATE authorization_versions SET scope_hash=repeat('a',64) WHERE authorization_id=$1`, f.auth); e == nil {
		t.Fatal("scope mutable")
	}
	if _, e := f.p.Exec(ctx, `UPDATE missions SET state='done',version=version+1 WHERE id=$1`, m); e == nil {
		t.Fatal("illegal pending -> done")
	}
	if _, e := f.p.Exec(ctx, `INSERT INTO nodes(task_id,kind) VALUES($1,'fact')`, f.task); e == nil {
		t.Fatal("orphan node allowed")
	}
	if _, e := f.p.Exec(ctx, `DELETE FROM tasks WHERE id=$1`, f.task); e == nil {
		t.Fatal("audit retention bypassed")
	}
	before := scalar(t, f.p, `SELECT count(*) FROM intents WHERE task_id=$1`, f.task)
	// [02] 在专属测试库注入 Outbox 失败，证明业务不能绕过事件提交。
	if _, e := f.p.Exec(ctx, `ALTER TABLE outbox_events ADD CONSTRAINT injected_failure CHECK(event_type<>'intent.created') NOT VALID`); e != nil {
		t.Fatal(e)
	}
	_, e := f.s.CreateIntent(ctx, f.admin, unique("outbox-fail"), f.task, f.asset, "must rollback")
	if _, cleanup := f.p.Exec(ctx, `ALTER TABLE outbox_events DROP CONSTRAINT injected_failure`); cleanup != nil {
		t.Fatal(cleanup)
	}
	if e == nil {
		t.Fatal("business commit despite outbox failure")
	}
	if after := scalar(t, f.p, `SELECT count(*) FROM intents WHERE task_id=$1`, f.task); after != before {
		t.Fatalf("business leaked after rollback: %d -> %d", before, after)
	}
}
func TestSettledMissionCannotRetryWithoutReservation(t *testing.T) {
	f := setup(t)
	f.budget(t, 10)
	m := f.mission(t, 3)
	l := f.claim(t, m, f.pool(t, 1), time.Minute)
	ctx := context.Background()
	if e := f.s.Finish(ctx, f.worker, unique("blocked-finish"), l, "blocked"); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.RetryReviewed(ctx, f.admin, unique("retry-settled"), f.task, m, "offline retry reviewed"); !errors.Is(e, store.ErrBudget) {
		t.Fatalf("settled retry=%v", e)
	}
	if n := scalar(t, f.p, `SELECT reserved FROM budget_ledgers WHERE task_id=$1`, f.task); n != 0 {
		t.Fatalf("reserved=%d", n)
	}
}

func TestClaimRechecksDeadlineAfterPoolLock(t *testing.T) {
	f := setup(t)
	f.budget(t, 10)
	m := f.mission(t, 2)
	pool := f.pool(t, 1)
	ctx := context.Background()
	if _, e := f.p.Exec(ctx, `UPDATE missions SET deadline_at=clock_timestamp()+interval '250 milliseconds' WHERE id=$1`, m); e != nil {
		t.Fatal(e)
	}
	blocker, e := f.p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer blocker.Rollback(ctx)
	if _, e = blocker.Exec(ctx, `SELECT resource_key FROM resource_pools WHERE resource_key=$1 FOR UPDATE`, pool); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.s.Claim(ctx, f.worker, unique("delayed-claim"), f.task, m, pool, "delayed-runtime", time.Minute)
		done <- err
	}()
	time.Sleep(350 * time.Millisecond)
	if e = blocker.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e == nil {
		t.Fatal("deadline passed during pool wait but claim succeeded")
	}
	if n := scalar(t, f.p, `SELECT count(*) FROM execution_leases WHERE mission_id=$1`, m); n != 0 {
		t.Fatalf("expired lease inserted=%d", n)
	}
}

func TestAuthorizationAndScopeDenials(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, e := f.s.Authenticate(ctx, "forged-token"); e == nil {
		t.Fatal("forged identity allowed")
	}
	if _, e := f.s.AddPrincipal(ctx, f.worker, "rogue", "human", "admin"); e == nil {
		t.Fatal("worker escalated")
	}
	asset, e := f.s.RegisterAsset(ctx, f.admin, unique("outside"), f.task, "https://outside.invalid/")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.ReviewAsset(ctx, f.admin, unique("review-outside"), f.task, asset, "observe"); e == nil {
		t.Fatal("out of scope asset approved")
	}
	f.budget(t, 10)
	intent, e := f.s.CreateIntent(ctx, f.admin, unique("pending-intent"), f.task, asset, "pending asset")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.CreateMission(ctx, f.admin, unique("pending-mission"), store.MissionRequest{TaskID: f.task, IntentID: intent, AssetID: asset, Angle: "offline", Deadline: time.Now().Add(time.Minute), Budgets: map[string]int64{"steps": 1}}); e == nil {
		t.Fatal("pending asset executable")
	}
	if _, e = f.p.Exec(ctx, `UPDATE authorization_contracts SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.auth); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.CreateTask(ctx, f.admin, unique("expired-task"), f.auth, "expired", time.Now().Add(time.Minute)); e == nil {
		t.Fatal("expired authorization allowed")
	}
}
