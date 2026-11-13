//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trident/internal/domain"
	"trident/internal/store"
)

func offlineInput() store.ToolRequestInput {
	return store.ToolRequestInput{ToolName: domain.OfflineToolName, ToolVersion: domain.OfflineToolVersion, Target: "https://example.invalid/", Protocol: "https", Port: 443, Action: "observe", Arguments: json.RawMessage(`{"synthetic":true}`), PolicyVersion: domain.OfflinePolicyVersion}
}
func requestAndApprove(t *testing.T, f *fixture, l store.Lease) store.ToolRequest {
	t.Helper()
	ctx := context.Background()
	r, e := f.s.RequestTool(ctx, f.worker, unique("request"), l, offlineInput(), time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.ApproveTool(ctx, f.admin, unique("approve"), f.task, l.MissionID, r.ID, r.Digest, "verified offline request"); e != nil {
		t.Fatal(e)
	}
	return r
}
func TestTaskMembershipDefaultDenyAndRevocation(t *testing.T) {
	f := setup(t)
	f.budget(t, 20)
	m := f.mission(t, 5)
	pool := f.pool(t, 2)
	ctx := context.Background()
	outsider, e := f.s.AddPrincipal(ctx, f.admin, unique("other-worker"), "service", "worker")
	if e != nil {
		t.Fatal(e)
	}
	os, e := f.s.Authenticate(ctx, outsider.Token)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Claim(ctx, os, unique("outsider"), f.task, m, pool, "outsider", time.Minute); !errors.Is(e, store.ErrDenied) {
		t.Fatalf("ungranted worker claim=%v", e)
	}
	scheduler, e := f.s.AddPrincipal(ctx, f.admin, unique("scheduler"), "service", "scheduler")
	if e != nil {
		t.Fatal(e)
	}
	sc, e := f.s.Authenticate(ctx, scheduler.Token)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.CreateIntent(ctx, sc, unique("no-member"), f.task, f.asset, "not a member"); !errors.Is(e, store.ErrDenied) {
		t.Fatalf("scheduler bypass=%v", e)
	}
	if _, e = f.s.CreateTask(ctx, sc, unique("create-task-bypass"), f.auth, "no delegate", time.Now().Add(time.Minute)); !errors.Is(e, store.ErrDenied) {
		t.Fatalf("scheduler self grants task=%v", e)
	}
	l := f.claim(t, m, pool, time.Minute)
	r := requestAndApprove(t, f, l)
	key := unique("historical-fact")
	if _, e = f.s.RecordFact(ctx, f.worker, key, l, "observed", json.RawMessage(`{"synthetic":true}`)); e != nil {
		t.Fatal(e)
	}
	if e = f.s.RevokeTaskMember(ctx, f.admin, unique("revoke-worker"), f.task, f.workerID, "testing revoke"); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.RecordFact(ctx, f.worker, key, l, "observed", json.RawMessage(`{"synthetic":true}`)); !errors.Is(e, store.ErrDenied) {
		t.Fatalf("revoked member cached result=%v", e)
	}
	if _, e = f.s.AdmitTool(ctx, f.worker, unique("denied-admit"), l, r.ID, r.Digest); e == nil {
		t.Fatal("revoked member admitted")
	}
	if _, e = f.s.GrantTaskMember(ctx, f.admin, unique("regrant"), f.task, f.workerID, "worker", "explicit regrant"); e != nil {
		t.Fatal(e)
	}
	if e = f.s.Heartbeat(ctx, f.worker, unique("old-lease"), l, time.Minute); e == nil {
		t.Fatal("regrant resurrected old lease")
	}
	if n := scalar(t, f.p, `SELECT reserved FROM budget_ledgers WHERE task_id=$1`, f.task); n != 5 {
		t.Fatalf("revoke released budget=%d", n)
	}
	if n := scalar(t, f.p, `SELECT count(*) FROM approvals WHERE id=$1 AND status='revoked'`, r.ApprovalID); n != 1 {
		t.Fatal("approval not revoked")
	}
}
func TestToolApprovalConcurrentSingleConsumption(t *testing.T) {
	f := setup(t)
	f.budget(t, 20)
	m := f.mission(t, 8)
	l := f.claim(t, m, f.pool(t, 1), time.Minute)
	r := requestAndApprove(t, f, l)
	ctx := context.Background()
	var wins atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, e := f.s.AdmitTool(ctx, f.worker, fmt.Sprintf("admission-%d", i), l, r.ID, r.Digest)
			if e == nil {
				wins.Add(1)
			} else if !errors.Is(e, store.ErrConflict) {
				t.Errorf("admit=%v", e)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("admissions=%d", wins.Load())
	}
	if n := scalar(t, f.p, `SELECT count(*) FROM tool_admissions WHERE tool_call_id=$1`, r.ID); n != 1 {
		t.Fatalf("records=%d", n)
	}
	if n := scalar(t, f.p, `SELECT consumed FROM budget_ledgers WHERE task_id=$1`, f.task); n != 1 {
		t.Fatalf("charged steps=%d", n)
	}
}
func TestToolApprovalBindingImmutabilityAndIdempotency(t *testing.T) {
	f := setup(t)
	f.budget(t, 20)
	m := f.mission(t, 5)
	l := f.claim(t, m, f.pool(t, 1), time.Minute)
	ctx := context.Background()
	input := offlineInput()
	key := unique("request-same")
	r, e := f.s.RequestTool(ctx, f.worker, key, l, input, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	input.Arguments = json.RawMessage(`{"synthetic":false}`)
	if _, e = f.s.RequestTool(ctx, f.worker, key, l, input, time.Minute); !errors.Is(e, store.ErrConflict) {
		t.Fatalf("changed args reuse=%v", e)
	}
	if _, e = f.s.ApproveTool(ctx, f.worker, unique("self"), f.task, m, r.ID, r.Digest, "self"); !errors.Is(e, store.ErrDenied) {
		t.Fatalf("service self approval=%v", e)
	}
	if _, e = f.s.ApproveTool(ctx, f.admin, unique("wrong-digest"), f.task, m, r.ID, "bad-digest", "wrong"); !errors.Is(e, store.ErrConflict) {
		t.Fatalf("digest mismatch=%v", e)
	}
	if _, e = f.s.ApproveTool(ctx, f.admin, unique("approve"), f.task, m, r.ID, r.Digest, "approved offline"); e != nil {
		t.Fatal(e)
	}
	if _, e = f.p.Exec(ctx, `UPDATE tool_calls SET target='https://outside.invalid/' WHERE id=$1`, r.ID); e == nil {
		t.Fatal("mutable request")
	}
	if _, e = f.p.Exec(ctx, `UPDATE approvals SET request_digest=repeat('b',64) WHERE id=$1`, r.ApprovalID); e == nil {
		t.Fatal("mutable approval digest")
	}
	admissionKey := unique("admit-once")
	a, e := f.s.AdmitTool(ctx, f.worker, admissionKey, l, r.ID, r.Digest)
	if e != nil {
		t.Fatal(e)
	}
	b, e := f.s.AdmitTool(ctx, f.worker, admissionKey, l, r.ID, r.Digest)
	if e != nil || a.ID != b.ID || !b.OfflineOnly {
		t.Fatalf("duplicate=%+v %+v %v", a, b, e)
	}
	if n := scalar(t, f.p, `SELECT consumed FROM budget_ledgers WHERE task_id=$1`, f.task); n != 1 {
		t.Fatalf("duplicate charge=%d", n)
	}
}
func TestToolAdmissionOutboxFailureRollsBack(t *testing.T) {
	f := setup(t)
	f.budget(t, 20)
	m := f.mission(t, 5)
	l := f.claim(t, m, f.pool(t, 1), time.Minute)
	r := requestAndApprove(t, f, l)
	ctx := context.Background()
	if _, e := f.p.Exec(ctx, `ALTER TABLE outbox_events ADD CONSTRAINT injected_admission_failure CHECK(event_type<>'tool.admitted_offline') NOT VALID`); e != nil {
		t.Fatal(e)
	}
	_, e := f.s.AdmitTool(ctx, f.worker, unique("fail-admit"), l, r.ID, r.Digest)
	if _, cleanup := f.p.Exec(ctx, `ALTER TABLE outbox_events DROP CONSTRAINT injected_admission_failure`); cleanup != nil {
		t.Fatal(cleanup)
	}
	if e == nil {
		t.Fatal("admission ignored event failure")
	}
	if n := scalar(t, f.p, `SELECT consumed FROM budget_ledgers WHERE task_id=$1`, f.task); n != 0 {
		t.Fatalf("charged on rollback=%d", n)
	}
	if n := scalar(t, f.p, `SELECT count(*) FROM approvals WHERE id=$1 AND status='approved'`, r.ApprovalID); n != 1 {
		t.Fatal("approval consumed on rollback")
	}
	if n := scalar(t, f.p, `SELECT count(*) FROM tool_admissions WHERE tool_call_id=$1`, r.ID); n != 0 {
		t.Fatal("admission leaked")
	}
	if _, e = f.s.AdmitTool(ctx, f.worker, unique("retry-after-rollback"), l, r.ID, r.Digest); e != nil {
		t.Fatal(e)
	}
}
func proposal(t *testing.T, f *fixture) store.ScopeProposal {
	t.Helper()
	var raw []byte
	if e := f.p.QueryRow(context.Background(), `SELECT scope_document FROM authorization_versions WHERE authorization_id=$1 AND version=1`, f.auth).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var scope domain.Scope
	if e := json.Unmarshal(raw, &scope); e != nil {
		t.Fatal(e)
	}
	scope.MaxRPS = 3
	h := sha256.Sum256([]byte("new scope proof"))
	return store.ScopeProposal{AuthorizationID: f.auth, BaseVersion: 1, Scope: scope, ProofRef: "manual:scope-test", ProofHash: hex.EncodeToString(h[:])}
}
func TestScopeApprovalCutoverAndStaleBaseline(t *testing.T) {
	f := setup(t)
	f.budget(t, 20)
	m := f.mission(t, 6)
	l := f.claim(t, m, f.pool(t, 1), time.Minute)
	r := requestAndApprove(t, f, l)
	ctx := context.Background()
	p := proposal(t, f)
	v, e := f.s.ProposeScope(ctx, f.admin, unique("proposal"), p)
	if e != nil {
		t.Fatal(e)
	}
	other, e := f.s.ProposeScope(ctx, f.admin, unique("proposal-other"), p)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.s.Consume(ctx, f.worker, unique("draft-does-not-stop"), l, "steps", 1); e != nil {
		t.Fatal("draft altered execution:", e)
	}
	if _, e = f.s.ApproveScope(ctx, f.admin, unique("bad-scope-hash"), f.auth, v.Version, 1, "wrong", "wrong"); !errors.Is(e, store.ErrConflict) {
		t.Fatalf("bad hash=%v", e)
	}
	if _, e = f.s.ApproveScope(ctx, f.admin, unique("activate-scope"), f.auth, v.Version, 1, v.Hash, "new scope verified"); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.ApproveScope(ctx, f.admin, unique("stale-base"), f.auth, other.Version, 1, other.Hash, "stale"); !errors.Is(e, store.ErrConflict) {
		t.Fatalf("stale proposal=%v", e)
	}
	if n := scalar(t, f.p, `SELECT current_scope_ver FROM tasks WHERE id=$1`, f.task); n != int64(v.Version) {
		t.Fatal("task scope not switched")
	}
	if e = f.s.Consume(ctx, f.worker, unique("old-scope"), l, "steps", 1); e == nil {
		t.Fatal("old scope worker executed")
	}
	if _, e = f.s.AdmitTool(ctx, f.worker, unique("old-approval"), l, r.ID, r.Digest); e == nil {
		t.Fatal("old approval admitted")
	}
	if n := scalar(t, f.p, `SELECT reserved FROM budget_ledgers WHERE task_id=$1`, f.task); n != 5 {
		t.Fatalf("cutover lost budget=%d", n)
	}
	if n := scalar(t, f.p, `SELECT count(*) FROM assets WHERE id=$1 AND scope_status='pending_review'`, f.asset); n != 1 {
		t.Fatal("asset not pending review")
	}
	if n := scalar(t, f.p, `SELECT scope_version FROM missions WHERE id=$1`, m); n != 1 {
		t.Fatal("mission snapshot rewritten")
	}
	if _, e = f.p.Exec(ctx, `UPDATE authorization_scope_proposals SET proof_ref='changed' WHERE authorization_id=$1 AND version=$2`, f.auth, v.Version); e == nil {
		t.Fatal("proposal proof mutable")
	}
}
func TestToolApprovalExpiryAfterLedgerLock(t *testing.T) {
	f := setup(t)
	f.budget(t, 10)
	m := f.mission(t, 5)
	l := f.claim(t, m, f.pool(t, 1), time.Minute)
	ctx := context.Background()
	r, e := f.s.RequestTool(ctx, f.worker, unique("short-approval"), l, offlineInput(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.ApproveTool(ctx, f.admin, unique("approve-short"), f.task, m, r.ID, r.Digest, "short offline approval"); e != nil {
		t.Fatal(e)
	}
	tx, e := f.p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT id FROM budget_ledgers WHERE task_id=$1 FOR UPDATE`, f.task); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, err := f.s.AdmitTool(ctx, f.worker, unique("wait-ledger"), l, r.ID, r.Digest); done <- err }()
	time.Sleep(1100 * time.Millisecond)
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e == nil {
		t.Fatal("expired approval admitted after ledger wait")
	}
	if n := scalar(t, f.p, `SELECT consumed FROM budget_ledgers WHERE task_id=$1`, f.task); n != 0 {
		t.Fatalf("expired charge=%d", n)
	}
}
