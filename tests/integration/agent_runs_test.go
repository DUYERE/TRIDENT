//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"trident/db"
	"trident/internal/domain"
	"trident/internal/store"
)

type agentRunFixture struct {
	s       *store.Store
	p       *pgxpool.Pool
	admin   store.Session
	owner   store.Session
	other   store.Session
	service store.Session
	ownerID int64
}

// [01] Only the explicitly authorized loopback test DB is accepted. Every fixture owns its temporary schema.
// Nothing resets/deletes an existing DB, shared principal, identity sequence or legacy migration history.
// The Linux race container opts into the dedicated compose service alias; it is the same trident_test DB.
func setupAgentRuns(t *testing.T) *agentRunFixture {
	t.Helper()
	dsn := os.Getenv("TRIDENT_TEST_DATABASE_URL")
	cfg, err := pgxpool.ParseConfig(dsn)
	if dsn == "" || err != nil {
		t.Fatal("TRIDENT_TEST_DATABASE_URL must explicitly select the local trident_test DB")
	}
	loopback := cfg.ConnConfig.Host == "127.0.0.1" && cfg.ConnConfig.Port == 55432
	composeAlias := os.Getenv("TRIDENT_TEST_DATABASE_NETWORK") == "isolated-compose" &&
		cfg.ConnConfig.Host == "postgres" && cfg.ConnConfig.Port == 5432
	if (!loopback && !composeAlias) || cfg.ConnConfig.Database != "trident_test" {
		t.Fatal("agent Run tests permit only trident_test on loopback or the dedicated compose alias")
	}
	ctx := context.Background()
	admin, err := pgxpool.NewWithConfig(ctx, cfg.Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := strings.ReplaceAll(unique("agent_runs"), "-", "_")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, `CREATE SCHEMA `+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, e := admin.Exec(context.Background(), `DROP SCHEMA `+quoted+` CASCADE`); e != nil {
			t.Errorf("cleanup owned temporary schema: %v", e)
		}
	})
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if err = db.Migrate(ctx, p, "agent-run-fixture"); err != nil {
		t.Fatal(err)
	}
	// Preserve credentials outside the DSN and only append the owned search_path runtime parameter.
	connString := dsn
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, e := url.Parse(dsn)
		if e != nil {
			t.Fatal("invalid test database URL")
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		connString = u.String()
	} else {
		connString += " search_path=" + schema
	}
	s, err := store.Open(ctx, connString, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	root, err := s.Bootstrap(ctx, "agent-run-test-root")
	if err != nil {
		t.Fatal(err)
	}
	adminSession, err := s.Authenticate(ctx, root.Token)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := s.AddPrincipal(ctx, adminSession, "agent-run-owner", "human", "scheduler")
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.AddPrincipal(ctx, adminSession, "agent-run-other", "human", "admin")
	if err != nil {
		t.Fatal(err)
	}
	service, err := s.AddPrincipal(ctx, adminSession, "agent-run-service", "service", "scheduler")
	if err != nil {
		t.Fatal(err)
	}
	ownerSession, err := s.Authenticate(ctx, owner.Token)
	if err != nil {
		t.Fatal(err)
	}
	otherSession, err := s.Authenticate(ctx, other.Token)
	if err != nil {
		t.Fatal(err)
	}
	serviceSession, err := s.Authenticate(ctx, service.Token)
	if err != nil {
		t.Fatal(err)
	}
	return &agentRunFixture{s: s, p: p, admin: adminSession, owner: ownerSession, other: otherSession, service: serviceSession, ownerID: owner.ID}
}

func agentRunParams() store.CreateAgentRunParams {
	return store.CreateAgentRunParams{Key: "create", SnapshotPath: "snapshots/synthetic.json", SnapshotHash: strings.Repeat("a", 64), Goal: "inspect synthetic local snapshot", Config: json.RawMessage(`{"mode":"offline","number":9007199254740993}`), Limits: domain.AgentLimits{MaxModelCalls: 3, MaxToolCalls: 2, MaxTokens: 1000, MaxStoredBytes: 1024 * 1024}, Deadline: time.Now().UTC().Add(time.Hour)}
}

func agentMustCreate(t *testing.T, f *agentRunFixture, p store.CreateAgentRunParams) domain.AgentRun {
	t.Helper()
	r, err := f.s.CreateAgentRun(context.Background(), f.owner, p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func agentMustRunner(t *testing.T, f *agentRunFixture, runID int64) *store.AgentRunner {
	t.Helper()
	r, err := f.s.AcquireAgentRunner(context.Background(), f.owner, runID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Errorf("close runner: %v", err)
		}
	})
	return r
}

func agentMustTx(t *testing.T, r *store.AgentRunner, p store.AgentTransition) domain.AgentRun {
	t.Helper()
	run, err := r.Tx(context.Background(), p)
	if err != nil {
		t.Fatalf("transition %s: %v", p.Kind, err)
	}
	return run
}

func TestAgentRunsOwnershipRevocationAndReplay(t *testing.T) {
	f := setupAgentRuns(t)
	ctx := context.Background()
	params := agentRunParams()
	run := agentMustCreate(t, f, params)
	if run.OwnerID != f.ownerID || run.Version != 1 || run.LastSeq != 1 || run.State != domain.AgentRunReady {
		t.Fatal("creation binding/cursor mismatch")
	}
	if _, err := f.s.CreateAgentRun(ctx, f.service, params); !errors.Is(err, store.ErrDenied) {
		t.Fatal("service scheduler created Run")
	}
	for _, ss := range []store.Session{f.admin, f.other, f.service} {
		if _, err := f.s.GetAgentRun(ctx, ss, run.ID); !errors.Is(err, store.ErrDenied) {
			t.Fatal("non-owner could read Run")
		}
		if _, err := f.s.ListAgentRunSteps(ctx, ss, run.ID, 0, 100); !errors.Is(err, store.ErrDenied) {
			t.Fatal("non-owner could read steps")
		}
		if r, err := f.s.AcquireAgentRunner(ctx, ss, run.ID); !errors.Is(err, store.ErrDenied) {
			if r != nil {
				r.Close()
			}
			t.Fatal("non-owner acquired runner")
		}
	}
	runner := agentMustRunner(t, f, run.ID)
	start := store.AgentTransition{ExpectedVersion: 1, Key: "start", Kind: domain.AgentStepStarted, Payload: json.RawMessage(`{"z":1,"a":2}`)}
	started := agentMustTx(t, runner, start)
	if started.State != domain.AgentRunRunning || started.Version != 2 {
		t.Fatal("start mismatch")
	}
	// [02] Canonical request formatting replays the original snapshot, not the latest Run.
	start.Payload = json.RawMessage(` { "a":2, "z":1 } `)
	again := agentMustTx(t, runner, start)
	if again.Version != started.Version || again.StoredBytes != started.StoredBytes {
		t.Fatal("replay mutated Run")
	}
	createdAgain, err := f.s.CreateAgentRun(ctx, f.owner, params)
	if err != nil || createdAgain.Version != 1 || createdAgain.ID != run.ID {
		t.Fatal("create replay did not return original result")
	}
	changed := start
	changed.Payload = json.RawMessage(`{"a":3,"z":1}`)
	if _, err = runner.Tx(ctx, changed); !errors.Is(err, store.ErrConflict) {
		t.Fatal("changed request reused idempotency key")
	}
	params.Goal += " changed"
	if _, err = f.s.CreateAgentRun(ctx, f.owner, params); !errors.Is(err, store.ErrConflict) {
		t.Fatal("changed create digest replayed")
	}
	if _, err = f.p.Exec(ctx, `UPDATE principals SET status='revoked' WHERE id=$1`, f.ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Tx(ctx, start); !errors.Is(err, store.ErrDenied) {
		t.Fatal("revoked owner replay bypassed authentication")
	}
	if _, err = runner.Get(ctx); !errors.Is(err, store.ErrDenied) {
		t.Fatal("revoked runner read succeeded")
	}
	if _, err = runner.ListSteps(ctx, 0, 100); !errors.Is(err, store.ErrDenied) {
		t.Fatal("revoked runner steps succeeded")
	}
	params.Goal = run.Goal
	if _, err = f.s.CreateAgentRun(ctx, f.owner, params); !errors.Is(err, store.ErrDenied) {
		t.Fatal("revoked create replay bypassed authentication")
	}
}

func TestAgentRunsRunnerSessionLockAndCAS(t *testing.T) {
	f := setupAgentRuns(t)
	ctx := context.Background()
	run := agentMustCreate(t, f, agentRunParams())
	runner := agentMustRunner(t, f, run.ID)
	if second, err := f.s.AcquireAgentRunner(ctx, f.owner, run.ID); !errors.Is(err, store.ErrConflict) {
		if second != nil {
			second.Close()
		}
		t.Fatal("simultaneous runner acquired session lock")
	}
	// Acquiring a runner must not implicitly start/resume it.
	got, err := runner.Get(ctx)
	if err != nil || got.State != domain.AgentRunReady || got.Version != 1 {
		t.Fatal("acquire unexpectedly changed state")
	}
	agentMustTx(t, runner, store.AgentTransition{ExpectedVersion: 1, Key: "start", Kind: domain.AgentStepStarted})
	if _, err = runner.Tx(ctx, store.AgentTransition{ExpectedVersion: 1, Key: "stale", Kind: domain.AgentStepCheckpoint}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("stale version committed")
	}
	steps, err := runner.ListSteps(ctx, 0, 100)
	if err != nil || len(steps) != 2 {
		t.Fatal("failed CAS appended step")
	}
	if err = runner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Get(ctx); !errors.Is(err, store.ErrStale) {
		t.Fatal("closed runner still usable")
	}
	replacement := agentMustRunner(t, f, run.ID)
	got, err = replacement.Get(ctx)
	if err != nil || got.Version != 2 {
		t.Fatal("lock release lost durable state")
	}
	// [03] The dedicated connection does not pin an open transaction across external IO.
	var idleTx int
	if err = f.p.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND state='idle in transaction' AND query LIKE '%agent_runs%'`).Scan(&idleTx); err != nil || idleTx != 0 {
		t.Fatalf("runner leaked open transaction: %d %v", idleTx, err)
	}
}

func TestAgentRunsAtomicBudgetsUnknownAndJournal(t *testing.T) {
	f := setupAgentRuns(t)
	ctx := context.Background()
	p := agentRunParams()
	p.Limits.MaxModelCalls = 2
	run := agentMustCreate(t, f, p)
	r := agentMustRunner(t, f, run.ID)
	agentMustTx(t, r, store.AgentTransition{ExpectedVersion: 1, Key: "start", Kind: domain.AgentStepStarted})
	prepared := agentMustTx(t, r, store.AgentTransition{ExpectedVersion: 2, Key: "prepare", Kind: domain.AgentStepModelPrepared, ModelDelta: 1, ReservedTokenDelta: 600, Checkpoint: json.RawMessage(`{"pending_model":"one"}`)})
	if prepared.ModelCalls != 1 || prepared.TokensReserved != 600 || string(prepared.Checkpoint) != `{"pending_model":"one"}` {
		t.Fatal("prepare/checkpoint not atomic")
	}
	if _, err := r.Tx(ctx, store.AgentTransition{ExpectedVersion: 3, Key: "bad-settle", Kind: domain.AgentStepModelCompleted, ReservedTokenDelta: -599, UsedTokenDelta: 100}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("partial/unbound reservation release accepted")
	}
	unknown := agentMustTx(t, r, store.AgentTransition{ExpectedVersion: 3, Key: "unknown", Kind: domain.AgentStepUnknown, Reason: "transport result unknown"})
	if unknown.TokensReserved != 600 {
		t.Fatal("unknown refunded reservation")
	}
	if _, err := r.Tx(ctx, store.AgentTransition{ExpectedVersion: 4, Key: "bypass-resume", Kind: domain.AgentStepModelPrepared, ModelDelta: 1, ReservedTokenDelta: 100}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("unknown bypassed explicit resume")
	}
	agentMustTx(t, r, store.AgentTransition{ExpectedVersion: 4, Key: "resume", Kind: domain.AgentStepResumed})
	if _, err := r.Tx(ctx, store.AgentTransition{ExpectedVersion: 5, Key: "over-budget", Kind: domain.AgentStepModelPrepared, ModelDelta: 1, ReservedTokenDelta: 401, Checkpoint: json.RawMessage(`{"should_not_commit":true}`)}); !errors.Is(err, store.ErrBudget) {
		t.Fatal("reserved+used cap bypassed")
	}
	prepared2 := agentMustTx(t, r, store.AgentTransition{ExpectedVersion: 5, Key: "prepare2", Kind: domain.AgentStepModelPrepared, ModelDelta: 1, ReservedTokenDelta: 400})
	if prepared2.TokensReserved != 1000 || prepared2.ModelCalls != 2 {
		t.Fatal("failed reservation changed counter")
	}
	if _, err := r.Tx(ctx, store.AgentTransition{ExpectedVersion: 6, Key: "steal-unknown-reserve", Kind: domain.AgentStepModelCompleted, ReservedTokenDelta: -1000, UsedTokenDelta: 10}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("new call released old unknown reserve")
	}
	settled := agentMustTx(t, r, store.AgentTransition{ExpectedVersion: 6, Key: "settle2", Kind: domain.AgentStepModelCompleted, ReservedTokenDelta: -400, UsedTokenDelta: 100})
	if settled.TokensReserved != 600 || settled.TokensUsed != 100 {
		t.Fatal("known settlement refunded unknown call")
	}
	if _, err := r.Tx(ctx, store.AgentTransition{ExpectedVersion: 7, Key: "double-settle", Kind: domain.AgentStepModelCompleted, ReservedTokenDelta: -400, UsedTokenDelta: 100}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("double settlement accepted")
	}
	if _, err := r.Tx(ctx, store.AgentTransition{ExpectedVersion: 7, Key: "model-limit", Kind: domain.AgentStepModelPrepared, ModelDelta: 1, ReservedTokenDelta: 1}); !errors.Is(err, store.ErrBudget) {
		t.Fatal("model hardcap bypassed")
	}
	done := agentMustTx(t, r, store.AgentTransition{ExpectedVersion: 7, Key: "budget-exhausted", Kind: domain.AgentStepBudgetExhausted, Reason: "model calls exhausted"})
	if done.State != domain.AgentRunBudgetExhausted || done.TokensReserved != 600 {
		t.Fatal("terminal released uncertain budget")
	}
	if _, err := r.Tx(ctx, store.AgentTransition{ExpectedVersion: 8, Key: "restart", Kind: domain.AgentStepResumed}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("terminal resurrected")
	}
	steps, err := r.ListSteps(ctx, 0, 100)
	if err != nil || int64(len(steps)) != done.Version {
		t.Fatal("step/cursor gap after rollback")
	}
	for i, step := range steps {
		if step.Seq != int64(i+1) || step.Version != step.Seq {
			t.Fatal("append cursor mismatch")
		}
		h := sha256.Sum256(step.Payload)
		if hex.EncodeToString(h[:]) != step.PayloadHash {
			t.Fatal("canonical payload hash mismatch")
		}
	}
}

func TestAgentRunsAccountingOnlyTerminal(t *testing.T) {
	f := setupAgentRuns(t)
	ctx := context.Background()
	p := agentRunParams()
	p.Limits.MaxModelCalls = 2
	run := agentMustCreate(t, f, p)
	r := agentMustRunner(t, f, run.ID)
	agentMustTx(t, r, store.AgentTransition{ExpectedVersion: 1, Key: "start", Kind: domain.AgentStepStarted})
	prepared := agentMustTx(t, r, store.AgentTransition{ExpectedVersion: 2, Key: "prepare", Kind: domain.AgentStepModelPrepared, ModelDelta: 1, ReservedTokenDelta: 600, Checkpoint: json.RawMessage(`{"version":1,"messages":[],"pending_model":{"reservation":600}}`)})

	accounting := func(mutate func(*domain.AgentAccounting)) json.RawMessage {
		a := domain.AgentAccounting{
			Reason:        domain.AgentAccountingResponseBytes,
			Response:      domain.AgentAccountingSummary{SHA256: strings.Repeat("b", 64), Bytes: 4096, Stop: "complete"},
			ReportedUsage: domain.AgentAccountingUsage{Known: true, InputTokens: 100, OutputTokens: 30},
		}
		if mutate != nil {
			mutate(&a)
		}
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	invalid := []struct {
		name     string
		payload  json.RawMessage
		replace  json.RawMessage
		reserved int64
		used     int64
	}{
		{"retained", accounting(func(a *domain.AgentAccounting) { a.Response.Retained = true }), nil, -600, 130},
		{"usage", accounting(func(a *domain.AgentAccounting) { a.ReportedUsage.OutputTokens = 31 }), nil, -600, 130},
		{"checkpoint", accounting(nil), json.RawMessage(`{"replacement":true}`), -600, 130},
	}
	for _, tc := range invalid {
		if _, err := r.Tx(ctx, store.AgentTransition{ExpectedVersion: 3, Key: "bad-" + tc.name, Kind: domain.AgentStepModelCompleted, Payload: tc.payload, Checkpoint: tc.replace, State: domain.AgentRunBudgetExhausted, ReservedTokenDelta: tc.reserved, UsedTokenDelta: tc.used}); !errors.Is(err, store.ErrDenied) {
			t.Fatalf("%s accepted: %v", tc.name, err)
		}
	}
	got, err := r.Get(ctx)
	if err != nil || got.Version != 3 || got.TokensReserved != 600 || string(got.Checkpoint) != string(prepared.Checkpoint) {
		t.Fatalf("rejected accounting changed Run: %+v %v", got, err)
	}
	settled := agentMustTx(t, r, store.AgentTransition{ExpectedVersion: 3, Key: "account", Kind: domain.AgentStepModelCompleted, Payload: accounting(nil), State: domain.AgentRunBudgetExhausted, ReservedTokenDelta: -600, UsedTokenDelta: 130})
	if settled.State != domain.AgentRunBudgetExhausted || settled.TokensReserved != 0 || settled.TokensUsed != 130 || string(settled.Checkpoint) != string(prepared.Checkpoint) {
		t.Fatalf("accounting settlement mismatch: %+v", settled)
	}
	steps, err := r.ListSteps(ctx, 0, 100)
	if err != nil || len(steps) != 4 {
		t.Fatalf("steps=%d err=%v", len(steps), err)
	}
	last := steps[len(steps)-1]
	var stored domain.AgentAccounting
	if last.Kind != domain.AgentStepModelCompleted || json.Unmarshal(last.Payload, &stored) != nil || stored.Reason != domain.AgentAccountingResponseBytes || stored.Response.Retained || len(stored.Response.SHA256) != 64 {
		t.Fatalf("stored accounting kind=%s payload=%s", last.Kind, last.Payload)
	}
	if _, err = r.Tx(ctx, store.AgentTransition{ExpectedVersion: settled.Version, Key: "resume", Kind: domain.AgentStepResumed}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("accounting terminal resurrected")
	}
}

func TestAgentRunsStorageAndImmutability(t *testing.T) {
	f := setupAgentRuns(t)
	ctx := context.Background()
	p := agentRunParams()
	p.Limits.MaxStoredBytes = 128 * 1024
	run := agentMustCreate(t, f, p)
	r := agentMustRunner(t, f, run.ID)
	agentMustTx(t, r, store.AgentTransition{ExpectedVersion: 1, Key: "start", Kind: domain.AgentStepStarted})
	large, _ := json.Marshal(map[string]string{"text": strings.Repeat("x", 64*1024)})
	if _, err := r.Tx(ctx, store.AgentTransition{ExpectedVersion: 2, Key: "oversize", Kind: domain.AgentStepCheckpoint, Payload: large}); !errors.Is(err, store.ErrBudget) {
		t.Fatal("ordinary step consumed terminal reserve")
	}
	got, err := r.Get(ctx)
	if err != nil || got.Version != 2 || string(got.Checkpoint) != `{}` {
		t.Fatal("rejected storage write partially committed")
	}
	terminal := agentMustTx(t, r, store.AgentTransition{ExpectedVersion: 2, Key: "terminal", Kind: domain.AgentStepBudgetExhausted, Reason: "stored bytes exhausted"})
	if terminal.StoredBytes > terminal.Limits.MaxStoredBytes {
		t.Fatal("terminal bypassed hardcap")
	}
	for _, sql := range []string{
		`UPDATE agent_run_steps SET payload_text='{}' WHERE run_id=$1`,
		`DELETE FROM agent_run_steps WHERE run_id=$1`,
		`UPDATE agent_runs SET owner_id=owner_id+1 WHERE id=$1`,
		`UPDATE agent_runs SET goal='changed' WHERE id=$1`,
		`DELETE FROM agent_runs WHERE id=$1`,
	} {
		if _, err := f.p.Exec(ctx, sql, run.ID); err == nil {
			t.Fatalf("immutable journal/binding changed: %s", sql)
		}
	}
	// [04] A direct aggregate-only write cannot commit without the matching append entry.
	p.Key = "atomicity"
	another := agentMustCreate(t, f, p)
	if _, err := f.p.Exec(ctx, `UPDATE agent_runs SET version=version+1,last_seq=last_seq+1,state='running' WHERE id=$1`, another.ID); err == nil {
		t.Fatal("aggregate-only update committed without step")
	}
	if _, err := f.p.Exec(ctx, `UPDATE agent_runs SET max_tokens=max_tokens+1 WHERE id=$1`, another.ID); err == nil {
		t.Fatal("immutable limits changed")
	}
}

func TestAgentRunsUpgradePreservesLegacy(t *testing.T) {
	// [05] Build exactly migrations001-003 in an owned nested schema, then apply only the new forward migration.
	f := setupAgentRuns(t)
	ctx := context.Background()
	name := strings.ReplaceAll(unique("agent_upgrade"), "-", "_")
	ident := pgx.Identifier{name}.Sanitize()
	if _, err := f.p.Exec(ctx, `CREATE SCHEMA `+ident); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.p.Exec(context.Background(), `DROP SCHEMA `+ident+` CASCADE`); err != nil {
			t.Errorf("cleanup own upgrade schema: %v", err)
		}
	})
	cfg := f.p.Config().Copy()
	cfg.ConnConfig.RuntimeParams["search_path"] = name
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	if _, err = p.Exec(ctx, `CREATE TABLE schema_migrations(version text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),applied_by text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	_, source, _, _ := runtime.Caller(0)
	for _, file := range []string{"001_core.sql", "002_integrity.sql", "003_p0_governance.sql"} {
		raw, e := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "db", "migrations", file))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = p.Exec(ctx, string(raw)); e != nil {
			t.Fatal(e)
		}
		h := sha256.Sum256(raw)
		if _, e = p.Exec(ctx, `INSERT INTO schema_migrations(version,checksum,applied_by) VALUES($1,$2,'agent-upgrade-fixture')`, file, hex.EncodeToString(h[:])); e != nil {
			t.Fatal(e)
		}
	}
	if _, err = p.Exec(ctx, `INSERT INTO principals(subject,principal_type,role,credential_hash) VALUES('legacy-unchanged','human','scheduler',repeat('b',64))`); err != nil {
		t.Fatal(err)
	}
	var before string
	if err = p.QueryRow(ctx, `SELECT row_to_json(p)::text FROM principals p WHERE subject='legacy-unchanged'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = db.Check(ctx, p); err == nil {
		t.Fatal("schema gate accepted missing Run migration")
	}
	if err = db.Migrate(ctx, p, "agent-forward-upgrade"); err != nil {
		t.Fatal(err)
	}
	if err = db.Migrate(ctx, p, "agent-forward-upgrade-repeat"); err != nil {
		t.Fatal(err)
	}
	if err = db.Check(ctx, p); err != nil {
		t.Fatal(err)
	}
	var after string
	if err = p.QueryRow(ctx, `SELECT row_to_json(p)::text FROM principals p WHERE subject='legacy-unchanged'`).Scan(&after); err != nil || after != before {
		t.Fatal("Run upgrade modified legacy identity")
	}
	var n int
	if err = p.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version='004_agent_runs.sql'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("new migration not registered exactly once")
	}
	if err = p.QueryRow(ctx, `SELECT count(*) FROM agent_runs`).Scan(&n); err != nil || n != 0 {
		t.Fatal("upgrade fabricated Runs")
	}
}
