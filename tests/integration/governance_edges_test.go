//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trident/internal/store"
)

func TestOutboxTaskIsolationAndPrincipalOwnership(t *testing.T) {
	f := setup(t)
	g := setup(t)
	drainEvents(t, f)
	ctx := context.Background()
	id := appendFixtureEvent(t, f, 300, 1)
	other := appendFixtureEvent(t, g, 301, 1)
	events, e := f.s.ClaimEvents(ctx, f.reconciler, "shared-name", 100, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	own, ok := findEvent(events, id)
	if !ok {
		t.Fatal("member could not claim own event")
	}
	if _, ok = findEvent(events, other); ok {
		t.Fatal("claimed another task event")
	}
	if e = g.s.AckEvent(ctx, g.reconciler, id, own.ClaimGeneration, "shared-name"); !errors.Is(e, store.ErrDenied) {
		t.Fatalf("nonmember ACK=%v", e)
	}
	if _, e = f.s.GrantTaskMember(ctx, f.admin, unique("grant-second-recon"), f.task, g.reconcilerID, "reconciler", "second service"); e != nil {
		t.Fatal(e)
	}
	if e = g.s.AckEvent(ctx, g.reconciler, id, own.ClaimGeneration, "shared-name"); !errors.Is(e, store.ErrConflict) {
		t.Fatalf("different principal stole ACK=%v", e)
	}
	if e = f.s.RevokeTaskMember(ctx, f.admin, unique("revoke-recon"), f.task, f.reconcilerID, "revoke receipt permission"); e != nil {
		t.Fatal(e)
	}
	if e = f.s.AckEvent(ctx, f.reconciler, id, own.ClaimGeneration, "shared-name"); !errors.Is(e, store.ErrDenied) {
		t.Fatalf("revoked ACK=%v", e)
	}
	if e = f.s.ReplayEvent(ctx, f.admin, id, "release revoked service notification claim"); e != nil {
		t.Fatal(e)
	}
	drainEvents(t, f)
}

func TestGrantedSchedulerCannotCrossTasks(t *testing.T) {
	f := setup(t)
	g := setup(t)
	ctx := context.Background()
	p, e := f.s.AddPrincipal(ctx, f.admin, unique("task-scheduler"), "service", "scheduler")
	if e != nil {
		t.Fatal(e)
	}
	ss, e := f.s.Authenticate(ctx, p.Token)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.GrantTaskMember(ctx, f.admin, unique("grant-scheduler"), f.task, p.ID, "worker", "role mismatch"); !errors.Is(e, store.ErrDenied) {
		t.Fatalf("mismatched role=%v", e)
	}
	if _, e = f.s.GrantTaskMember(ctx, f.admin, unique("grant-scheduler"), f.task, p.ID, "scheduler", "explicit scheduler"); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.CreateIntent(ctx, ss, unique("valid-scheduled-intent"), f.task, f.asset, "member may schedule"); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.CreateIntent(ctx, ss, unique("cross-task-intent"), g.task, g.asset, "must not schedule"); !errors.Is(e, store.ErrDenied) {
		t.Fatalf("scheduler cross task=%v", e)
	}
	if _, e = f.s.RecoverExpired(ctx, g.reconciler, unique("cross-task-recover"), f.task, 12345); !errors.Is(e, store.ErrDenied) {
		t.Fatalf("reconciler cross task=%v", e)
	}
}

func TestScopeCutoverMultipleTasksConcurrentBaseline(t *testing.T) {
	f := setup(t)
	f.budget(t, 20)
	m := f.mission(t, 4)
	l := f.claim(t, m, f.pool(t, 1), time.Minute)
	ctx := context.Background()
	second, e := f.s.CreateTask(ctx, f.admin, unique("same-contract-task"), f.auth, "second task same contract", time.Now().Add(5*time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	v1, e := f.s.ProposeScope(ctx, f.admin, unique("scope-a"), proposal(t, f))
	if e != nil {
		t.Fatal(e)
	}
	v2, e := f.s.ProposeScope(ctx, f.admin, unique("scope-b"), proposal(t, f))
	if e != nil {
		t.Fatal(e)
	}
	var wins atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, v := range []store.ScopeVersion{v1, v2} {
		wg.Add(1)
		go func(v store.ScopeVersion) {
			defer wg.Done()
			<-start
			_, err := f.s.ApproveScope(ctx, f.admin, unique("scope-race"), f.auth, v.Version, 1, v.Hash, "concurrent scope approval")
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, store.ErrConflict) {
				t.Errorf("scope approval=%v", err)
			}
		}(v)
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("scope winners=%d", wins.Load())
	}
	active := scalar(t, f.p, `SELECT version FROM authorization_versions WHERE authorization_id=$1 AND status='active'`, f.auth)
	if n := scalar(t, f.p, `SELECT count(*) FROM tasks WHERE id IN($1,$2) AND current_scope_ver=$3`, f.task, second, active); n != 2 {
		t.Fatal("contract tasks cut over inconsistently")
	}
	if e = f.s.Heartbeat(ctx, f.worker, unique("old-scope-heartbeat"), l, time.Minute); e == nil {
		t.Fatal("old scope lease alive")
	}
	if n := scalar(t, f.p, `SELECT count(*) FROM execution_leases WHERE mission_id=$1 AND status='revoked'`, m); n != 1 {
		t.Fatal("old scope lease not revoked")
	}
}

func TestRequestCanonicalNumbersSurviveDatabaseRoundTrip(t *testing.T) {
	f := setup(t)
	f.budget(t, 20)
	m := f.mission(t, 5)
	l := f.claim(t, m, f.pool(t, 1), time.Minute)
	ctx := context.Background()
	input := offlineInput()
	input.Arguments = json.RawMessage(`{"big":123456789012345678901234567890,"exp":1e3,"fraction":1.00}`)
	r, e := f.s.RequestTool(ctx, f.worker, unique("number-request"), l, input, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.ApproveTool(ctx, f.admin, unique("number-approve"), f.task, m, r.ID, r.Digest, "numeric lexical form retained"); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.AdmitTool(ctx, f.worker, unique("number-admit"), l, r.ID, r.Digest); e != nil {
		t.Fatal("canonical digest changed after DB roundtrip:", e)
	}
}

func TestToolRequestCrossMissionBindingAndTokenReplacement(t *testing.T) {
	f := setup(t)
	f.budget(t, 20)
	pool := f.pool(t, 2)
	m := f.mission(t, 5)
	other := f.mission(t, 5)
	l := f.claim(t, m, pool, time.Minute)
	r := requestAndApprove(t, f, l)
	second := f.claim(t, other, pool, time.Minute)
	ctx := context.Background()
	if _, e := f.s.AdmitTool(ctx, f.worker, unique("cross-mission"), second, r.ID, r.Digest); e == nil {
		t.Fatal("approval crossed mission")
	}
	if _, e := f.p.Exec(ctx, `INSERT INTO approvals(task_id,mission_id,tool_call_id,lease_id,fencing_token,requester_id,request_digest,status,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,'pending',clock_timestamp()+interval '1 minute')`, f.task, other, r.ID, second.ID, second.Token, f.workerID, r.Digest); e == nil {
		t.Fatal("database allowed mixed mission approval")
	}
	if _, e := f.p.Exec(ctx, `UPDATE execution_leases SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, l.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.RecoverExpired(ctx, f.reconciler, unique("recover-for-new-token"), f.task, m); e != nil {
		t.Fatal(e)
	}
	if _, e := f.s.RetryReviewed(ctx, f.admin, unique("safe-token-retry"), f.task, m, "offline execution known stopped"); e != nil {
		t.Fatal(e)
	}
	replacement := f.claim(t, m, pool, time.Minute)
	if _, e := f.s.AdmitTool(ctx, f.worker, unique("replacement-old-approval"), replacement, r.ID, r.Digest); e == nil {
		t.Fatal("new token reused old approval")
	}
	if n := scalar(t, f.p, `SELECT consumed FROM budget_ledgers WHERE task_id=$1`, f.task); n != 0 {
		t.Fatalf("rejected bindings charged=%d", n)
	}
}
