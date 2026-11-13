//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"trident/db"
)

// [01] 独立临时Schema模拟已有P0.1库；只销毁本测试自己创建的Schema。
func TestP01UpgradePreservesHistoryAndFencesUnassignedWorkers(t *testing.T) {
	dsn := os.Getenv("TRIDENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TRIDENT_TEST_DATABASE_URL required")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	name := strings.ReplaceAll(unique("upgrade"), "-", "_")
	ident := pgx.Identifier{name}.Sanitize()
	if _, e = admin.Exec(ctx, `CREATE SCHEMA `+ident); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if _, err := admin.Exec(ctx, `DROP SCHEMA `+ident+` CASCADE`); err != nil {
			t.Errorf("cleanup own schema: %v", err)
		}
	}()
	config, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	config.ConnConfig.RuntimeParams["search_path"] = name
	p, e := pgxpool.NewWithConfig(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	_, source, _, _ := runtime.Caller(0)
	migrations := filepath.Join(filepath.Dir(source), "..", "..", "db", "migrations")
	if _, e = p.Exec(ctx, `CREATE TABLE schema_migrations(version text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),applied_by text NOT NULL)`); e != nil {
		t.Fatal(e)
	}
	for _, file := range []string{"001_core.sql", "002_integrity.sql"} {
		raw, err := os.ReadFile(filepath.Join(migrations, file))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = p.Exec(ctx, string(raw)); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(raw)
		if _, err = p.Exec(ctx, `INSERT INTO schema_migrations(version,checksum,applied_by) VALUES($1,$2,'upgrade-fixture')`, file, hex.EncodeToString(h[:])); err != nil {
			t.Fatal(err)
		}
	}
	tx, e := p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	sql := `
 INSERT INTO principals(id,subject,principal_type,role,credential_hash) OVERRIDING SYSTEM VALUE VALUES(1,'old-worker','service','worker',repeat('a',64));
 INSERT INTO authorization_contracts(id,principal_id,status,valid_from,expires_at) OVERRIDING SYSTEM VALUE VALUES(1,1,'active',clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour');
 INSERT INTO authorization_versions(authorization_id,version,scope_document,scope_hash,created_by) VALUES(1,1,'{}',repeat('b',64),1);
 INSERT INTO tasks(id,authorization_id,current_scope_ver,goal,deadline_at) OVERRIDING SYSTEM VALUE VALUES(1,1,1,'old task',clock_timestamp()+interval '1 hour');
 INSERT INTO assets(id,task_id,asset_key,scope_status) OVERRIDING SYSTEM VALUE VALUES(1,1,'https://example.invalid/','in_scope');
 INSERT INTO nodes(id,task_id,kind) OVERRIDING SYSTEM VALUE VALUES(1,1,'intent'),(2,1,'mission');
 INSERT INTO intents(id,task_id,target_asset_id,title,state) VALUES(1,1,1,'old intent','running');
 INSERT INTO missions(id,task_id,intent_id,target_asset_id,authorization_id,scope_version,scope_hash,scope_snapshot,angle,state,deadline_at) VALUES(2,1,1,1,1,1,repeat('b',64),'{}','old','running',clock_timestamp()+interval '1 hour');
 INSERT INTO resource_pools(resource_key,capacity,next_fencing_token) VALUES('old',1,1);
 INSERT INTO execution_leases(task_id,mission_id,resource_key,holder,runtime_id,fencing_token,lease_until) VALUES(1,2,'old',1,'old-runtime',1,clock_timestamp()+interval '1 hour');
 INSERT INTO budget_ledgers(task_id,kind,allocated,reserved,consumed) VALUES(1,'steps',10,3,1);
 INSERT INTO budget_reservations(task_id,mission_id,ledger_id,amount,consumed) VALUES(1,2,1,4,1);`
	if _, e = tx.Exec(ctx, sql); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = db.Migrate(ctx, p, "upgrade-test"); e != nil {
		t.Fatal(e)
	}
	if e = db.Migrate(ctx, p, "upgrade-repeat"); e != nil {
		t.Fatal(e)
	}
	if e = db.Check(ctx, p); e != nil {
		t.Fatal(e)
	}
	if n := scalar(t, p, `SELECT count(*) FROM execution_leases WHERE status='revoked'`); n != 1 {
		t.Fatal("old lease not fenced")
	}
	if n := scalar(t, p, `SELECT count(*) FROM missions WHERE state='blocked' AND scope_version=1 AND scope_hash=repeat('b',64) AND scope_snapshot='{}'`); n != 1 {
		t.Fatal("old mission history changed")
	}
	if n := scalar(t, p, `SELECT reserved FROM budget_ledgers WHERE task_id=1`); n != 3 {
		t.Fatal("upgrade released uncertain budget")
	}
	if n := scalar(t, p, `SELECT count(*) FROM task_members`); n != 0 {
		t.Fatal("upgrade silently granted access")
	}
	if n := scalar(t, p, `SELECT count(*) FROM outbox_events WHERE event_type='p0.membership_upgrade_isolated'`); n != 1 {
		t.Fatal("upgrade audit missing or repeated")
	}
}
