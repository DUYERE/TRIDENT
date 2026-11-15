package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"trident/internal/agent"
	"trident/internal/domain"
	openaiadapter "trident/internal/model/openai"
	"trident/internal/project"
	"trident/internal/store"
	"trident/internal/tools"
)

// [01] Agent 命令需要数据库身份；源码读取与模型外发分别显式确认。
func runAgent(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: trident agent run|status|steps|resume|export")
	}
	command := args[0]
	if command != "run" && command != "status" && command != "steps" && command != "resume" && command != "export" {
		return fmt.Errorf("unknown agent command %q", command)
	}
	f := flag.NewFlagSet("agent "+command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var runID, after int64
	var limit int
	var key, snapshot, hash, goal, endpoint, modelName, outputParam, apiKeyEnv, advisoryPath string
	var exportPath string
	var exportMaxBytes, retentionDays int64
	var includeExpired bool
	var allowEgress, loopback, ackUnknown bool
	var timeout, outputTokens, maxModels, maxTools, maxTokens int64
	apiKeyEnv = "TRIDENT_MODEL_API_KEY"
	if command == "run" {
		f.StringVar(&key, "key", "", "unique create idempotency key")
		f.StringVar(&snapshot, "snapshot", "", "existing trusted snapshot directory")
		f.StringVar(&hash, "snapshot-hash", "", "trusted snapshot hash")
		f.StringVar(&goal, "goal", "", "analysis goal (also disclosed to approved model)")
		f.StringVar(&advisoryPath, "advisories", "", "optional absolute local advisory catalog for read-only analysis tools")
		f.StringVar(&endpoint, "endpoint", "", "explicit API base URL")
		f.StringVar(&modelName, "model", "", "explicit model identifier")
		f.StringVar(&outputParam, "output-parameter", "max_completion_tokens", "max_completion_tokens or legacy max_tokens")
		f.BoolVar(&allowEgress, "approve-egress", false, "approve entire pinned snapshot+goal to this endpoint/model for this Run")
		f.BoolVar(&loopback, "allow-loopback-http", false, "allow numeric loopback HTTP protocol test service")
		f.Int64Var(&timeout, "model-timeout-seconds", 60, "per model request timeout (1..120)")
		f.Int64Var(&outputTokens, "max-output-tokens", 4096, "output token ceiling per request")
		f.Int64Var(&maxModels, "max-model-calls", 8, "model attempts")
		f.Int64Var(&maxTools, "max-tool-calls", 24, "tool attempts")
		f.Int64Var(&maxTokens, "max-tokens", 131072, "reserved/reported token allowance; not a billing guarantee")
	} else {
		f.Int64Var(&runID, "id", 0, "Run ID")
	}
	if command == "export" {
		f.StringVar(&exportPath, "out", "", "new JSON export file outside the snapshot")
		f.Int64Var(&exportMaxBytes, "max-bytes", 1<<20, "export size ceiling (1 KiB..8 MiB)")
		f.Int64Var(&retentionDays, "retention-days", 30, "evidence retention window (1..3650 days)")
		f.BoolVar(&includeExpired, "include-expired", false, "explicitly export evidence older than the retention window")
	}
	if command == "steps" {
		f.Int64Var(&after, "after", 0, "last sequence already seen")
		f.IntVar(&limit, "limit", 50, "page size")
	}
	if command == "resume" {
		f.BoolVar(&ackUnknown, "acknowledge-unknown", false, "confirm prior runner stopped and possible previously billed request")
	}
	if command == "run" || command == "resume" {
		f.StringVar(&apiKeyEnv, "api-key-env", "TRIDENT_MODEL_API_KEY", "host environment variable containing model key (never persisted)")
	}
	if e := f.Parse(args[1:]); e != nil {
		return fmt.Errorf("invalid agent arguments: %w", e)
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected agent positional arguments")
	}
	if command != "run" && runID <= 0 {
		return fmt.Errorf("positive --id required")
	}
	var config agent.Config
	if command == "run" {
		if key == "" || snapshot == "" || hash == "" || goal == "" {
			return fmt.Errorf("run requires --key --snapshot --snapshot-hash --goal")
		}
		deadline := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
		config = agent.Config{Version: agent.Version, Endpoint: endpoint, Model: modelName, OutputParameter: outputParam, TimeoutSeconds: timeout, MaxOutputTokens: outputTokens, MaxRequestBytes: 2 << 20, MaxResponseBytes: 512 << 10, AllowLoopbackHTTP: loopback, EgressAllowed: allowEgress, EgressExpiresAt: deadline}
		if advisoryPath != "" {
			absolute, pathErr := filepath.Abs(advisoryPath)
			if pathErr != nil {
				return pathErr
			}
			config.AnalysisAdvisoryPath = absolute
		}
		if e := config.Validate(); e != nil {
			return e
		}
		if e := config.AllowRequest(time.Now()); e != nil {
			return fmt.Errorf("model egress not approved; explicit --approve-egress is required for the entire snapshot and goal")
		}
		var e error
		config.Endpoint, e = openaiadapter.NormalizeEndpoint(config.Endpoint, loopback)
		if e != nil {
			return e
		}
	}
	dsn := os.Getenv("TRIDENT_DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("TRIDENT_DATABASE_URL is required")
	}
	s, e := store.Open(ctx, dsn, false)
	if e != nil {
		return e
	}
	defer s.Close()
	ss, e := s.Authenticate(ctx, os.Getenv("TRIDENT_TOKEN"))
	if e != nil {
		return e
	}
	if command == "status" {
		r, e := s.GetAgentRun(ctx, ss, runID)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(r)
	}
	if command == "export" {
		return exportAgentRun(ctx, s, ss, runID, exportPath, exportMaxBytes, retentionDays, includeExpired, out)
	}
	if command == "steps" {
		r, e := s.ListAgentRunSteps(ctx, ss, runID, after, limit)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(r)
	}
	var run domain.AgentRun
	if command == "run" {
		absolute, e := filepath.Abs(snapshot)
		if e != nil {
			return e
		}
		checked, e := project.Open(ctx, absolute, hash)
		if e != nil {
			return e
		}
		_ = checked.Close()
		encoded, e := json.Marshal(config)
		if e != nil {
			return e
		}
		run, e = s.CreateAgentRun(ctx, ss, store.CreateAgentRunParams{Key: key, SnapshotPath: absolute, SnapshotHash: hash, Goal: goal, Config: encoded, Limits: domain.AgentLimits{MaxModelCalls: maxModels, MaxToolCalls: maxTools, MaxTokens: maxTokens, MaxStoredBytes: 32 << 20}, Deadline: config.EgressExpiresAt})
		if e != nil {
			return e
		}
	} else {
		run, e = s.GetAgentRun(ctx, ss, runID)
		if e != nil {
			return e
		}
		config, e = agent.DecodeConfig(run.Config)
		if e != nil {
			return e
		}
	}
	// [02] 只从明确指定环境变量取密钥；不使用 Claude/OpenAI 当前会话或 SDK 环境默认。
	apiKey := os.Getenv(apiKeyEnv)
	if apiKey == "" {
		return fmt.Errorf("model key missing from explicitly selected environment variable; Run %d preserved", run.ID)
	}
	client, e := openaiadapter.New(openaiadapter.Config{Endpoint: config.Endpoint, Model: config.Model, APIKey: apiKey, Timeout: time.Duration(config.TimeoutSeconds) * time.Second, MaxRequestBytes: config.MaxRequestBytes, MaxResponseBytes: config.MaxResponseBytes, OutputParameter: openaiadapter.OutputParameter(config.OutputParameter), AllowLoopbackHTTP: config.AllowLoopbackHTTP})
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	snapshotView, e := project.Open(ctx, run.SnapshotPath, run.SnapshotHash)
	if e != nil {
		return e
	}
	defer snapshotView.Close()
	registry := tools.NewWithAnalysis(snapshotView, tools.AnalysisOptions{AdvisoryPath: config.AnalysisAdvisoryPath})
	runner, e := s.AcquireAgentRunner(ctx, ss, run.ID)
	if e != nil {
		return e
	}
	defer runner.Close()
	result, e := agent.Execute(ctx, runner, client, registry, ackUnknown)
	if encodeErr := json.NewEncoder(out).Encode(result); encodeErr != nil {
		return encodeErr
	}
	// A budget stop is a terminal Run state, not a startup failure: report which
	// ceiling was hit and that no conclusion was produced.
	if errors.Is(e, store.ErrBudget) {
		if final, getErr := s.GetAgentRun(ctx, ss, run.ID); getErr == nil {
			return fmt.Errorf("Run %d 达到预算上限并停止（model %d/%d · tool %d/%d · tokens %d/%d）；budget_exhausted 不是分析结论，需要提高预算后用新的 --key 重跑",
				final.ID, final.ModelCalls, final.Limits.MaxModelCalls, final.ToolCalls, final.Limits.MaxToolCalls, final.TokensUsed, final.Limits.MaxTokens)
		}
	}
	return e
}

// exportAgentRun writes a bounded evidence export without deleting or mutating
// the append-only database record. Retention is an access policy here, not DB
// pruning; the agent tables are intentionally immutable.
func exportAgentRun(ctx context.Context, s *store.Store, ss store.Session, runID int64, exportPath string, maxBytes, retentionDays int64, includeExpired bool, out io.Writer) error {
	if exportPath == "" {
		return fmt.Errorf("agent export requires --out")
	}
	if maxBytes < 1024 || maxBytes > 8<<20 {
		return fmt.Errorf("export max-bytes must be between 1024 and 8388608")
	}
	if retentionDays < 1 || retentionDays > 3650 {
		return fmt.Errorf("retention-days must be between 1 and 3650")
	}
	run, err := s.GetAgentRun(ctx, ss, runID)
	if err != nil {
		return err
	}
	expired := time.Since(run.CreatedAt) > time.Duration(retentionDays)*24*time.Hour
	if expired && !includeExpired {
		return fmt.Errorf("run %d is older than the %d-day retention window; pass --include-expired to export it", runID, retentionDays)
	}
	absoluteOut, err := filepath.Abs(exportPath)
	if err != nil {
		return err
	}
	if insideSnapshot(run.SnapshotPath, absoluteOut) {
		return fmt.Errorf("export must be outside the pinned snapshot")
	}
	if info, statErr := os.Lstat(absoluteOut); statErr == nil || !os.IsNotExist(statErr) {
		if statErr == nil && info.Mode().IsRegular() {
			return fmt.Errorf("export output already exists; choose a new file")
		}
		return fmt.Errorf("export output must be a new regular file")
	}
	var steps []domain.AgentStep
	after := int64(0)
	for len(steps) <= 10_000 {
		page, pageErr := s.ListAgentRunSteps(ctx, ss, runID, after, 200)
		if pageErr != nil {
			return pageErr
		}
		steps = append(steps, page...)
		if len(page) < 200 {
			break
		}
		after = page[len(page)-1].Seq
	}
	if len(steps) > 10_000 {
		return fmt.Errorf("run %d exceeds the 10000-step export bound", runID)
	}
	envelope := map[string]any{
		"export_kind":       "agent_run_evidence",
		"schema_version":    1,
		"retention_days":    retentionDays,
		"retention_expired": expired,
		"runtime_status":    "not_run",
		"run":               run,
		"steps":             steps,
		"limitations": []string{
			"export_is_read_only: the append-only run and step records are not deleted or modified",
			"checkpoint_and_tool_payloads_are_included: review before sharing; credentials are never intentionally stored",
			"retention_is_access_policy_not_database_pruning",
		},
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if int64(len(encoded)) > maxBytes {
		return fmt.Errorf("export is %d bytes and exceeds --max-bytes %d", len(encoded), maxBytes)
	}
	file, err := os.OpenFile(absoluteOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(encoded); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"run_id": runID, "out": absoluteOut, "bytes": len(encoded), "steps": len(steps),
		"retention_days": retentionDays, "retention_expired": expired, "runtime_status": "not_run",
	})
}
