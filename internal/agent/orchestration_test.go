package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trident/internal/domain"
	"trident/internal/model"
	"trident/internal/tools"
)

// Orchestration extensions: the terminal envelope gains optional intents /
// goal_proved / facts / candidates, all subject to the same observed-evidence
// coverage rule as hypotheses. Manual runs without these fields are unchanged.

func TestValidateFinalOrchestrationExtensions(t *testing.T) {
	m, registry, snapshot := loopFixture(t)
	run := m.run
	observed := readFixtureEvidence(t, registry, snapshot.Hash())
	observedLine := []tools.Evidence{observed}

	valid := map[string]any{
		"summary":     "orchestration round done",
		"hypotheses":  []any{},
		"limitations": []string{"static only"},
		"facts": []any{map[string]any{
			"summary": "fixture function observed", "confidence": "observed",
			"evidence": evidenceRefs(snapshot.Hash(), observed),
		}},
		"candidates": []any{map[string]any{
			"title": "suspicious helper", "severity": "medium", "note": "name-based",
			"evidence": evidenceRefs(snapshot.Hash(), observed),
		}},
		"intents":     []any{map[string]any{"summary": "audit the controller layer", "parent_ids": []any{1}}},
		"goal_proved": []any{"goal-1"},
	}
	raw, _ := json.Marshal(valid)
	if _, err := validateFinal(string(raw), observedLine, run.SnapshotHash); err != nil {
		t.Fatalf("valid orchestration envelope rejected: %v", err)
	}
	// Legacy manual-run envelope without the new fields still validates.
	if _, err := validateFinal(`{"summary":"s","hypotheses":[],"limitations":[]}`, nil, run.SnapshotHash); err != nil {
		t.Fatalf("legacy envelope rejected: %v", err)
	}
	negative := []struct{ name, body string }{
		{"bad_confidence", `{"summary":"s","hypotheses":[],"limitations":[],"facts":[{"summary":"x","confidence":"guessed","evidence":[]}]}`},
		{"fact_without_evidence", `{"summary":"s","hypotheses":[],"limitations":[],"facts":[{"summary":"x","confidence":"observed","evidence":[]}]}`},
		{"unobserved_fact", `{"summary":"s","hypotheses":[],"limitations":[],"facts":[{"summary":"x","confidence":"observed","evidence":[{"snapshot_hash":"HASH","path":"nope.go","sha256":"00","start_line":1,"end_line":1}]}]}`},
		{"candidate_without_evidence", `{"summary":"s","hypotheses":[],"limitations":[],"candidates":[{"title":"x","evidence":[]}]}`},
		{"too_many_intents", `{"summary":"s","hypotheses":[],"limitations":[],"intents":[{"summary":"1"},{"summary":"2"},{"summary":"3"},{"summary":"4"},{"summary":"5"}]}`},
	}
	for _, item := range negative {
		body := strings.ReplaceAll(item.body, "HASH", run.SnapshotHash)
		if _, err := validateFinal(body, observedLine, run.SnapshotHash); err == nil {
			t.Fatalf("%s: expected rejection", item.name)
		}
	}
}

// goal_proved must reference a registered goal node id. Free-form victory
// sentences used to pass because only non-emptiness and length were checked;
// they now fail as a protocol error before the orchestrator can mark anything
// met.
func TestValidateFinalPlannerAcceptsGraphEvidence(t *testing.T) {
	m, _, _ := loopFixture(t)
	body := `{"summary":"s","hypotheses":[{"statement":"graph observation","evidence":[{"snapshot_hash":"other","path":"x.jsp","sha256":"00","start_line":1,"end_line":1}]}],"limitations":[]}`
	if _, err := validateFinal(body, nil, m.run.SnapshotHash); err == nil {
		t.Fatal("manual run must reject evidence it did not observe")
	}
	if _, err := validateFinalWithPolicy(body, nil, m.run.SnapshotHash, true); err != nil {
		t.Fatalf("planner must accept evidence already pinned on the graph: %v", err)
	}
}

func TestValidateFinalAcceptsQuotedParentID(t *testing.T) {
	m, _, _ := loopFixture(t)
	body := `{"summary":"s","hypotheses":[],"limitations":[],"intents":[{"summary":"x","parent_ids":["13"]}]}`
	if _, err := validateFinal(body, nil, m.run.SnapshotHash); err != nil {
		t.Fatalf("quoted parent id rejected: %v", err)
	}
}

func TestValidateFinalGoalProvedRequiresGoalReference(t *testing.T) {
	m, _, _ := loopFixture(t)
	hash := m.run.SnapshotHash
	cases := []struct {
		name    string
		goals   string
		wantErr bool
	}{
		{"registered_reference", `["goal-12"]`, false},
		{"freeform_sentence", `["目标已达成"]`, true},
		{"bare_number", `["1"]`, true},
		{"zero_id", `["goal-0"]`, true},
		{"negative_id", `["goal--1"]`, true},
		{"mixed_valid_and_freeform", `["goal-1","全部完成"]`, true},
	}
	for _, item := range cases {
		body := `{"summary":"s","hypotheses":[],"limitations":[],"goal_proved":` + item.goals + `}`
		_, err := validateFinal(body, nil, hash)
		if item.wantErr && err == nil {
			t.Fatalf("%s: expected rejection, got nil", item.name)
		}
		if !item.wantErr && err != nil {
			t.Fatalf("%s: expected acceptance, got %v", item.name, err)
		}
	}
}

func evidenceRefs(hash string, observed tools.Evidence) []any {
	return []any{map[string]any{
		"snapshot_hash": hash, "path": observed.Path, "sha256": observed.SHA256,
		"start_line": observed.StartLine, "end_line": observed.EndLine,
	}}
}

// readFixtureEvidence performs one real read_source call so the test evidence
// matches what a tool result actually returns (path, sha256, line range) — the
// same path the loop's evidence ledger takes.
func readFixtureEvidence(t *testing.T, registry *tools.Registry, hash string) tools.Evidence {
	t.Helper()
	result, err := registry.Execute(context.Background(), "read_source", json.RawMessage(`{"path":"app.go","start_line":2,"limit":1}`))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := tools.ExtractEvidence("read_source", result)
	if err != nil || len(evidence) == 0 {
		t.Fatalf("read_source evidence extraction failed: %v", err)
	}
	return evidence[0]
}

func TestSettlementRoundWritesBackInBudget(t *testing.T) {
	m, registry, snapshot := loopFixture(t)
	m.run.Limits.MaxModelCalls = 2
	cfg := Config{Version: Version, Endpoint: "https://model.invalid/v1/chat/completions", Model: "scripted", OutputParameter: "max_tokens", TimeoutSeconds: 3, MaxOutputTokens: 1024, MaxRequestBytes: 64 << 10, MaxResponseBytes: 32 << 10, EgressAllowed: true, EgressExpiresAt: time.Now().Add(time.Hour), SettlementEnabled: true}
	raw, _ := json.Marshal(cfg)
	m.run.Config = raw
	observed := readFixtureEvidence(t, registry, snapshot.Hash())
	final := map[string]any{
		"summary": "settled", "hypotheses": []any{}, "limitations": []string{"static only"},
		"facts": []any{map[string]any{
			"summary": "fixture function observed", "confidence": "observed",
			"evidence": evidenceRefs(snapshot.Hash(), observed),
		}},
	}
	finalRaw, _ := json.Marshal(final)
	client := &scriptedClient{t: t, complete: func(n int, request model.Request) (model.Response, error) {
		switch n {
		case 1:
			if len(request.Tools) == 0 {
				t.Fatal("first dispatch must offer tools")
			}
			return model.Response{Stop: model.StopTools, Message: model.Message{Role: "assistant", Calls: []model.ToolCall{{ID: "read1", Name: "read_source", Arguments: json.RawMessage(`{"path":"app.go","start_line":2,"limit":1}`)}}}, Usage: model.Usage{Known: true, InputTokens: 10, OutputTokens: 10}}, nil
		case 2:
			// The settlement round must not offer tools, and the sentinel
			// message must be present so the model writes back instead of
			// being cut off.
			if len(request.Tools) != 0 {
				t.Fatalf("settlement dispatch must offer no tools, got %d", len(request.Tools))
			}
			found := false
			for _, message := range request.Messages {
				if message.Role == "user" && strings.HasPrefix(message.Content, settlementMarker) {
					found = true
				}
			}
			if !found {
				t.Fatal("settlement sentinel message missing")
			}
			return model.Response{Stop: model.StopComplete, Message: model.Message{Role: "assistant", Content: string(finalRaw)}, Usage: model.Usage{Known: true, InputTokens: 20, OutputTokens: 20}}, nil
		default:
			t.Fatalf("unexpected dispatch %d", n)
			return model.Response{}, nil
		}
	}}
	finalRun, err := Execute(t.Context(), m, client, registry, false)
	if err != nil {
		t.Fatalf("settlement run failed: %v", err)
	}
	if finalRun.State != domain.AgentRunCompleted {
		t.Fatalf("settlement run must complete, got %s", finalRun.State)
	}
	var cp loopCheckpoint
	if err := json.Unmarshal(finalRun.Checkpoint, &cp); err != nil {
		t.Fatal(err)
	}
	if !settlementDone(cp) {
		t.Fatal("checkpoint lost the settlement sentinel")
	}
	if finalRun.ModelCalls != 2 {
		t.Fatalf("settlement must stay in budget, model calls = %d", finalRun.ModelCalls)
	}
}

func TestSettlementDisabledKeepsLegacyStop(t *testing.T) {
	m, registry, _ := loopFixture(t)
	m.run.Limits.MaxModelCalls = 1
	client := &scriptedClient{t: t, complete: func(n int, request model.Request) (model.Response, error) {
		return model.Response{Stop: model.StopTools, Message: model.Message{Role: "assistant", Calls: []model.ToolCall{{ID: "read1", Name: "read_source", Arguments: json.RawMessage(`{"path":"app.go","start_line":2,"limit":1}`)}}}, Usage: model.Usage{Known: true, InputTokens: 10, OutputTokens: 10}}, nil
	}}
	finalRun, err := Execute(t.Context(), m, client, registry, false)
	if err == nil {
		t.Fatal("budget exhaustion without settlement must surface an error path")
	}
	if finalRun.State != domain.AgentRunBudgetExhausted {
		t.Fatalf("legacy behavior must be budget_exhausted, got %s", finalRun.State)
	}
}
