package domain

import (
	"encoding/json"
	"time"
)

// [01] AgentRunState describes only the local Run, not legacy Tasks or Missions.
type AgentRunState string

const (
	AgentRunReady           AgentRunState = "ready"
	AgentRunRunning         AgentRunState = "running"
	AgentRunPaused          AgentRunState = "paused"
	AgentRunUnknown         AgentRunState = "unknown"
	AgentRunCompleted       AgentRunState = "completed"
	AgentRunFailed          AgentRunState = "failed"
	AgentRunCancelled       AgentRunState = "cancelled"
	AgentRunBudgetExhausted AgentRunState = "budget_exhausted"
)

type AgentStepKind string

const (
	AgentStepCreated         AgentStepKind = "run.created"
	AgentStepStarted         AgentStepKind = "run.started"
	AgentStepModelPrepared   AgentStepKind = "model.prepared"
	AgentStepModelCompleted  AgentStepKind = "model.completed"
	AgentStepToolStarted     AgentStepKind = "tool.started"
	AgentStepToolCompleted   AgentStepKind = "tool.completed"
	AgentStepCheckpoint      AgentStepKind = "run.checkpoint"
	AgentStepPaused          AgentStepKind = "run.paused"
	AgentStepResumed         AgentStepKind = "run.resumed"
	AgentStepUnknown         AgentStepKind = "run.unknown"
	AgentStepCompleted       AgentStepKind = "run.completed"
	AgentStepFailed          AgentStepKind = "run.failed"
	AgentStepCancelled       AgentStepKind = "run.cancelled"
	AgentStepBudgetExhausted AgentStepKind = "run.budget_exhausted"
)

// [02] Limits are immutable per Run. Zero is a real zero allowance, not unlimited.
type AgentLimits struct {
	MaxModelCalls  int64 `json:"max_model_calls"`
	MaxToolCalls   int64 `json:"max_tool_calls"`
	MaxTokens      int64 `json:"max_tokens"`
	MaxStoredBytes int64 `json:"max_stored_bytes"`
}

// [03] Config and Checkpoint are bounded canonical JSON objects; no credentials belong here.
type AgentRun struct {
	ID             int64           `json:"id"`
	OwnerID        int64           `json:"owner_id"`
	SnapshotPath   string          `json:"snapshot_path"`
	SnapshotHash   string          `json:"snapshot_hash"`
	Goal           string          `json:"goal"`
	Config         json.RawMessage `json:"config"`
	ConfigHash     string          `json:"config_hash"`
	State          AgentRunState   `json:"state"`
	Reason         string          `json:"reason"`
	Version        int64           `json:"version"`
	LastSeq        int64           `json:"last_seq"`
	Checkpoint     json.RawMessage `json:"checkpoint"`
	ModelCalls     int64           `json:"model_calls"`
	ToolCalls      int64           `json:"tool_calls"`
	TokensReserved int64           `json:"tokens_reserved"`
	TokensUsed     int64           `json:"tokens_used"`
	StoredBytes    int64           `json:"stored_bytes"`
	Limits         AgentLimits     `json:"limits"`
	Deadline       time.Time       `json:"deadline"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// [04] AgentAccounting is the bounded terminal diagnostic for a known model
// response that was received but deliberately not retained because of a local
// byte limit. It never contains the response body or tool arguments; the
// response digest and provider-reported usage are journaled instead.
type AgentAccounting struct {
	Reason        string                 `json:"reason"`
	Response      AgentAccountingSummary `json:"response"`
	ReportedUsage AgentAccountingUsage   `json:"reported_usage"`
}

// AgentAccountingSummary identifies the omitted response without storing it.
type AgentAccountingSummary struct {
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
	Stop     string `json:"stop"`
	Retained bool   `json:"retained"`
}

// AgentAccountingUsage preserves actual provider usage; unknown is never zero.
type AgentAccountingUsage struct {
	Known        bool  `json:"known"`
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

// Fixed local limits that may force an accounting-only terminal.
const (
	AgentAccountingResponseBytes = "response_byte_limit"
	AgentAccountingCheckpoint    = "checkpoint_limit"
	AgentAccountingStoredBytes   = "stored_byte_limit"
	AgentAccountingMaxBytes      = 4096
)

// [05] A step and its resulting Run snapshot commit atomically and are append-only.
type AgentStep struct {
	RunID       int64           `json:"run_id"`
	Seq         int64           `json:"seq"`
	Version     int64           `json:"version"`
	Key         string          `json:"key"`
	Digest      string          `json:"digest"`
	Kind        AgentStepKind   `json:"kind"`
	Payload     json.RawMessage `json:"payload"`
	PayloadHash string          `json:"payload_hash"`
	CreatedAt   time.Time       `json:"created_at"`
}
