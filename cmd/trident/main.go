// TRIDENT CLI：离线授权治理与本地源码快照，不提供网络测试能力。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"trident/db"
	"trident/internal/domain"
	"trident/internal/store"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "TRIDENT:", e)
		os.Exit(1)
	}
}

const productVersion = "TRIDENT 0.2.0-p0.2 + r1-core + r2-sca-declarations-v2 + r2-maven-effective-tree-v1 + r2-endpoint-inventory-v3 + r2-source-sink-flow-v12 + r2-finding-evidence + r2-readonly-web-console + r2-agent-analysis-tools + r2-cyclonedx-sbom + r2-sarif-reachability + r3-isolated-patch-v2 + r3-repair-policy-gvisor (read-only Agent Core; OpenAI Chat Completions; live-model acceptance pending)"

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: trident version | project <import|inspect|list|read|search> | sca <inspect|sbom|tree|resolve> | audit <endpoints|dataflow|findings|sarif|reachability> | web | patch <propose|verify|repair> | agent <run|status|steps|resume|export> | migrate | check | bootstrap <subject> | demo-offline")
	}
	command := os.Args[1]
	if command == "version" {
		fmt.Println(productVersion)
		return nil
	}
	// [01] 本地项目工具不连接数据库，不调用模型，也不执行项目代码。
	if command == "project" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		ctx, timeout := context.WithTimeout(ctx, 2*time.Minute)
		defer timeout()
		return runProject(ctx, os.Args[2:], os.Stdout)
	}
	if command == "sca" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		ctx, timeout := context.WithTimeout(ctx, 2*time.Minute)
		defer timeout()
		return runSCA(ctx, os.Args[2:], os.Stdout)
	}
	if command == "audit" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		ctx, timeout := context.WithTimeout(ctx, 2*time.Minute)
		defer timeout()
		return runAudit(ctx, os.Args[2:], os.Stdout)
	}
	if command == "web" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		return runWeb(ctx, os.Args[2:], os.Stdout)
	}
	if command == "patch" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		return runPatch(ctx, os.Args[2:], os.Stdout)
	}
	if command == "agent" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		return runAgent(ctx, os.Args[2:], os.Stdout)
	}
	dsn := os.Getenv("TRIDENT_DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("TRIDENT_DATABASE_URL is required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 2*time.Minute)
	defer timeout()
	if command == "migrate" || command == "check" {
		p, e := pgxpool.New(ctx, dsn)
		if e != nil {
			return fmt.Errorf("invalid database configuration")
		}
		defer p.Close()
		if command == "check" {
			if e = db.Check(ctx, p); e != nil {
				return e
			}
			fmt.Println("schema verified; no changes made")
			return nil
		}
		actor := os.Getenv("TRIDENT_MIGRATION_ACTOR")
		if actor == "" {
			return fmt.Errorf("TRIDENT_MIGRATION_ACTOR is required for explicit migration")
		}
		if e = db.Migrate(ctx, p, actor); e != nil {
			return e
		}
		fmt.Println("migrations applied and checksums verified")
		return nil
	}
	s, e := store.Open(ctx, dsn, false)
	if e != nil {
		return e
	}
	defer s.Close()
	if command == "bootstrap" {
		if len(os.Args) != 3 {
			return fmt.Errorf("bootstrap requires a subject")
		}
		p, e := s.Bootstrap(ctx, os.Args[2])
		if e != nil {
			return e
		}
		// [01] 凭据仅在显式初始化时输出一次，不记录到日志；调用者应重定向到受保护文件。
		return json.NewEncoder(os.Stdout).Encode(p)
	}
	if command != "demo-offline" {
		return fmt.Errorf("unknown command %q", command)
	}
	if os.Getenv("TRIDENT_CONFIRM_TEST_DATABASE") != "yes" {
		return fmt.Errorf("demo creates persistent test records; set TRIDENT_CONFIRM_TEST_DATABASE=yes for a dedicated test database")
	}
	ss, e := s.Authenticate(ctx, os.Getenv("TRIDENT_TOKEN"))
	if e != nil {
		return e
	}
	return demo(ctx, s, ss)
}
func demo(ctx context.Context, s *store.Store, admin store.Session) error {
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	owner, e := s.AddPrincipal(ctx, admin, "demo-owner-"+suffix, "human", "scheduler")
	if e != nil {
		return e
	}
	worker, e := s.AddPrincipal(ctx, admin, "demo-worker-"+suffix, "service", "worker")
	if e != nil {
		return e
	}
	ws, e := s.Authenticate(ctx, worker.Token)
	if e != nil {
		return e
	}
	h := sha256.Sum256([]byte("local offline demonstration; no external target authorization"))
	scope := domain.Scope{Domains: []string{"example.invalid"}, Ports: []uint16{443}, Protocols: []string{"https"}, AllowedActions: []string{"observe"}, ForbiddenActions: []string{"destructive"}, MaxRPS: 1, MaxConcurrency: 1, DataPolicy: "synthetic-only", StopConditions: []string{"deadline", "revocation"}}
	now := time.Now().UTC()
	auth, e := s.CreateAuthorization(ctx, admin, suffix+"-auth", store.AuthorizationRequest{PrincipalID: owner.ID, Scope: scope, ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), ProofRef: "manual:offline-demo", ProofHash: hex.EncodeToString(h[:])})
	if e != nil {
		return e
	}
	if _, e = s.ActivateAuthorization(ctx, admin, suffix+"-activate", auth, "Confirmed synthetic offline task; no target network execution"); e != nil {
		return e
	}
	task, e := s.CreateTask(ctx, admin, suffix+"-task", auth, "offline transaction demonstration", now.Add(30*time.Minute))
	if e != nil {
		return e
	}
	if _, e = s.GrantTaskMember(ctx, admin, suffix+"-grant-worker", task, worker.ID, "worker", "offline demo worker"); e != nil {
		return e
	}
	asset, e := s.RegisterAsset(ctx, admin, suffix+"-asset", task, "https://example.invalid/")
	if e != nil {
		return e
	}
	if _, e = s.ReviewAsset(ctx, admin, suffix+"-review", task, asset, "observe"); e != nil {
		return e
	}
	if _, e = s.SetBudget(ctx, admin, suffix+"-budget", task, "steps", 10); e != nil {
		return e
	}
	if _, e = s.SetPool(ctx, admin, suffix+"-pool", "offline-demo", 4); e != nil {
		return e
	}
	intent, e := s.CreateIntent(ctx, admin, suffix+"-intent", task, asset, "validate synthetic lifecycle")
	if e != nil {
		return e
	}
	mission, e := s.CreateMission(ctx, admin, suffix+"-mission", store.MissionRequest{TaskID: task, IntentID: intent, AssetID: asset, Angle: "offline", Deadline: now.Add(10 * time.Minute), Budgets: map[string]int64{"steps": 3}})
	if e != nil {
		return e
	}
	lease, e := s.Claim(ctx, ws, suffix+"-claim", task, mission, "offline-demo", "demo-"+suffix, time.Minute)
	if e != nil {
		return e
	}
	request, e := s.RequestTool(ctx, ws, suffix+"-request", lease, store.ToolRequestInput{ToolName: domain.OfflineToolName, ToolVersion: domain.OfflineToolVersion, Target: "https://example.invalid/", Protocol: "https", Port: 443, Action: "observe", Arguments: json.RawMessage(`{"synthetic":true}`), PolicyVersion: domain.OfflinePolicyVersion}, time.Minute)
	if e != nil {
		return e
	}
	if _, e = s.ApproveTool(ctx, admin, suffix+"-approve", task, mission, request.ID, request.Digest, "synthetic offline demonstration approved"); e != nil {
		return e
	}
	admission, e := s.AdmitTool(ctx, ws, suffix+"-admit", lease, request.ID, request.Digest)
	if e != nil {
		return e
	}
	fact, e := s.RecordFact(ctx, ws, suffix+"-fact", lease, "observed", json.RawMessage(`{"synthetic":true,"observation":"offline result; no target contacted"}`))
	if e != nil {
		return e
	}
	if e = s.Finish(ctx, ws, suffix+"-finish", lease, "done"); e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"product": "TRIDENT", "phase": "P0.2", "tool_call_id": request.ID, "admission_id": admission.ID, "task_id": task, "mission_id": mission, "fact_id": fact, "network_execution": false, "state": "done"})
}
