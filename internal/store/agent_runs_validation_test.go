package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"trident/internal/domain"
)

func unitAgentRun() domain.AgentRun {
	return domain.AgentRun{ID: 1, OwnerID: 2, State: domain.AgentRunRunning, Version: 2, LastSeq: 2, Config: json.RawMessage(`{}`), Checkpoint: json.RawMessage(`{"pending":true}`), Limits: domain.AgentLimits{MaxModelCalls: 3, MaxToolCalls: 3, MaxTokens: 1000, MaxStoredBytes: 1024 * 1024}}
}

func TestAgentCanonicalJSON(t *testing.T) {
	a, err := canonicalAgentJSON(json.RawMessage(` { "z":9007199254740993,"a":{"b":1.0}} `), 1024, false)
	if err != nil || string(a) != `{"a":{"b":1.0},"z":9007199254740993}` {
		t.Fatalf("canonical=%s err=%v", a, err)
	}
	b, err := canonicalAgentJSON(a, 1024, false)
	if err != nil || !bytes.Equal(a, b) || agentHash(a) != agentHash(b) {
		t.Fatal("canonicalization not stable")
	}
	for _, raw := range []string{`{"a":1,"a":2}`, `{"nested":{"x":1,"x":2}}`, `{} {}`, `[]`, `null`, `{"nul":"\u0000"}`, "{\"x\":\"\xff\"}", `{"x":` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40) + `}`} {
		if _, err = canonicalAgentJSON(json.RawMessage(raw), 1024, false); !errors.Is(err, ErrDenied) {
			t.Fatalf("accepted invalid JSON %q: %v", raw, err)
		}
	}
	if _, err = canonicalAgentJSON(json.RawMessage(`{"a":"<<<<"}`), 20, false); !errors.Is(err, ErrDenied) {
		t.Fatal("escaped canonical expansion escaped size limit")
	}
}

func TestAgentCreateCanonicalAndLimits(t *testing.T) {
	p := CreateAgentRunParams{Key: "create", SnapshotPath: "snapshot.json", SnapshotHash: strings.Repeat("A", 64), Goal: "local test", Config: json.RawMessage(`{"z":1,"a":2}`), Deadline: time.Now().Add(time.Hour), Limits: domain.AgentLimits{MaxStoredBytes: 128 * 1024}}
	n, _, hash, err := normalizeAgentCreate(p)
	if err != nil || n.SnapshotHash != strings.Repeat("a", 64) || string(n.Config) != `{"a":2,"z":1}` {
		t.Fatalf("normalization failed: %v", err)
	}
	p.Config = json.RawMessage(` { "a":2, "z":1 } `)
	_, _, same, err := normalizeAgentCreate(p)
	if err != nil || hash != same {
		t.Fatal("equivalent create changed digest")
	}
	p.Limits.MaxStoredBytes--
	if _, _, _, err = normalizeAgentCreate(p); !errors.Is(err, ErrBudget) {
		t.Fatal("missing bounded terminal reserve accepted")
	}
}

func TestAgentCASFixedKindsAndState(t *testing.T) {
	r := unitAgentRun()
	tests := []struct {
		name string
		p    AgentTransition
	}{
		{"stale", AgentTransition{ExpectedVersion: 1, Kind: domain.AgentStepCheckpoint}},
		{"unknown kind", AgentTransition{ExpectedVersion: 2, Kind: "run.set_anything"}},
		{"checkpoint state bypass", AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepCheckpoint, State: domain.AgentRunCompleted}},
		{"checkpoint budget bypass", AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepCheckpoint, ModelDelta: 1}},
		{"refund bypass", AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepPaused, ReservedTokenDelta: -1}},
		{"tool skipped", AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepToolStarted}},
		{"model skipped", AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepModelPrepared, ReservedTokenDelta: 10}},
		{"model negative usage", AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepModelCompleted, ReservedTokenDelta: -10, UsedTokenDelta: -1}},
		{"model min overflow", AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepModelCompleted, ReservedTokenDelta: math.MinInt64}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := applyAgentTransition(r, test.p); err == nil {
				t.Fatal("unsafe transition accepted")
			}
		})
	}
	r.State = domain.AgentRunUnknown
	if _, err := applyAgentTransition(r, AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepCheckpoint}); err == nil {
		t.Fatal("unknown advanced without explicit resume")
	}
	n, err := applyAgentTransition(r, AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepResumed})
	if err != nil || n.State != domain.AgentRunRunning || n.Version != 3 || !bytes.Equal(n.Checkpoint, r.Checkpoint) {
		t.Fatal("resume/nil checkpoint semantics failed")
	}
	for _, state := range []domain.AgentRunState{domain.AgentRunCompleted, domain.AgentRunFailed, domain.AgentRunCancelled, domain.AgentRunBudgetExhausted} {
		r.State = state
		if _, err := applyAgentTransition(r, AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepResumed}); !errors.Is(err, ErrConflict) {
			t.Fatalf("terminal %s mutable", state)
		}
	}
}

func TestAgentBudgetReservationAndUnknown(t *testing.T) {
	r := unitAgentRun()
	n, err := applyAgentTransition(r, AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepModelPrepared, ModelDelta: 1, ReservedTokenDelta: 1000})
	if err != nil || n.TokensReserved != 1000 || n.ModelCalls != 1 {
		t.Fatal("reservation not atomic")
	}
	if _, err = applyAgentTransition(n, AgentTransition{ExpectedVersion: 3, Kind: domain.AgentStepModelPrepared, ModelDelta: 1, ReservedTokenDelta: 1}); !errors.Is(err, ErrBudget) {
		t.Fatal("token hardcap not enforced")
	}
	settled, err := applyAgentTransition(n, AgentTransition{ExpectedVersion: 3, Kind: domain.AgentStepModelCompleted, ReservedTokenDelta: -1000, UsedTokenDelta: 123})
	if err != nil || settled.TokensUsed != 123 || settled.TokensReserved != 0 {
		t.Fatal("known settlement incorrect")
	}
	overrun, err := applyAgentTransition(n, AgentTransition{ExpectedVersion: 3, Kind: domain.AgentStepModelCompleted, ReservedTokenDelta: -1000, UsedTokenDelta: 1200})
	if err != nil || overrun.TokensUsed != 1200 || overrun.TokensReserved != 0 {
		t.Fatal("actual known overrun not persisted")
	}
	if _, err = applyAgentTransition(overrun, AgentTransition{ExpectedVersion: 4, Kind: domain.AgentStepModelPrepared, ModelDelta: 1, ReservedTokenDelta: 1}); !errors.Is(err, ErrBudget) {
		t.Fatal("known overrun allowed subsequent model request")
	}
	missing, err := applyAgentTransition(n, AgentTransition{ExpectedVersion: 3, Kind: domain.AgentStepModelCompleted})
	if err != nil || missing.TokensReserved != 1000 {
		t.Fatal("missing usage refunded")
	}
	unknown, err := applyAgentTransition(n, AgentTransition{ExpectedVersion: 3, Kind: domain.AgentStepUnknown})
	if err != nil || unknown.TokensReserved != 1000 {
		t.Fatal("unknown result refunded")
	}
	resumed, err := applyAgentTransition(unknown, AgentTransition{ExpectedVersion: 4, Kind: domain.AgentStepResumed})
	if err != nil || resumed.TokensReserved != 1000 {
		t.Fatal("resume released unknown tokens")
	}
	for _, tc := range []struct{ current, delta, cap int64 }{{math.MaxInt64, 1, math.MaxInt64}, {0, math.MinInt64, 100}, {10, -11, 100}, {10, 91, 100}} {
		if _, err := agentAdd(tc.current, tc.delta, tc.cap); !errors.Is(err, ErrBudget) {
			t.Fatalf("arithmetic bypass: %+v", tc)
		}
	}
}

func accountingPayload(t *testing.T, mutate func(*domain.AgentAccounting)) json.RawMessage {
	t.Helper()
	a := domain.AgentAccounting{
		Reason:        domain.AgentAccountingResponseBytes,
		Response:      domain.AgentAccountingSummary{SHA256: strings.Repeat("a", 64), Bytes: 2048, Stop: "complete"},
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

func TestAgentAccountingOnlyTerminal(t *testing.T) {
	r := unitAgentRun()
	r.State = domain.AgentRunRunning
	r.TokensReserved = 600
	valid := AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepModelCompleted, Payload: accountingPayload(t, nil), State: domain.AgentRunBudgetExhausted, ReservedTokenDelta: -600, UsedTokenDelta: 130}
	n, err := applyAgentTransition(r, valid)
	if err != nil || n.State != domain.AgentRunBudgetExhausted || n.TokensReserved != 0 || n.TokensUsed != 130 || !bytes.Equal(n.Checkpoint, r.Checkpoint) {
		t.Fatalf("accounting terminal not applied: %+v %v", n, err)
	}
	unknownUsage := accountingPayload(t, func(a *domain.AgentAccounting) { a.ReportedUsage = domain.AgentAccountingUsage{} })
	cases := []struct {
		name string
		p    AgentTransition
	}{
		{"retained", AgentTransition{Kind: domain.AgentStepModelCompleted, Payload: accountingPayload(t, func(a *domain.AgentAccounting) { a.Response.Retained = true }), State: domain.AgentRunBudgetExhausted, ReservedTokenDelta: -600, UsedTokenDelta: 130}},
		{"reason", AgentTransition{Kind: domain.AgentStepModelCompleted, Payload: accountingPayload(t, func(a *domain.AgentAccounting) { a.Reason = "other" }), State: domain.AgentRunBudgetExhausted, ReservedTokenDelta: -600, UsedTokenDelta: 130}},
		{"digest", AgentTransition{Kind: domain.AgentStepModelCompleted, Payload: accountingPayload(t, func(a *domain.AgentAccounting) { a.Response.SHA256 = "bogus" }), State: domain.AgentRunBudgetExhausted, ReservedTokenDelta: -600, UsedTokenDelta: 130}},
		{"stop", AgentTransition{Kind: domain.AgentStepModelCompleted, Payload: accountingPayload(t, func(a *domain.AgentAccounting) { a.Response.Stop = "arbitrary" }), State: domain.AgentRunBudgetExhausted, ReservedTokenDelta: -600, UsedTokenDelta: 130}},
		{"usage mismatch", AgentTransition{Kind: domain.AgentStepModelCompleted, Payload: accountingPayload(t, nil), State: domain.AgentRunBudgetExhausted, ReservedTokenDelta: -600, UsedTokenDelta: 131}},
		{"unknown usage with delta", AgentTransition{Kind: domain.AgentStepModelCompleted, Payload: unknownUsage, State: domain.AgentRunBudgetExhausted, ReservedTokenDelta: -600, UsedTokenDelta: 130}},
		{"replacement checkpoint", AgentTransition{Kind: domain.AgentStepModelCompleted, Payload: accountingPayload(t, nil), Checkpoint: json.RawMessage(`{}`), State: domain.AgentRunBudgetExhausted, ReservedTokenDelta: -600, UsedTokenDelta: 130}},
		{"oversized", AgentTransition{Kind: domain.AgentStepModelCompleted, Payload: json.RawMessage(`{"reason":"response_byte_limit","pad":"` + strings.Repeat("x", domain.AgentAccountingMaxBytes) + `"}`), State: domain.AgentRunBudgetExhausted, ReservedTokenDelta: -600, UsedTokenDelta: 130}},
	}
	for _, tc := range cases {
		tc.p.ExpectedVersion = 2
		if _, err := applyAgentTransition(r, tc.p); !errors.Is(err, ErrDenied) {
			t.Fatalf("%s accepted: %v", tc.name, err)
		}
	}
	unknown := AgentTransition{ExpectedVersion: 2, Kind: domain.AgentStepModelCompleted, Payload: unknownUsage, State: domain.AgentRunBudgetExhausted}
	n, err = applyAgentTransition(r, unknown)
	if err != nil || n.State != domain.AgentRunBudgetExhausted || n.TokensReserved != 600 || n.TokensUsed != 0 {
		t.Fatalf("unknown usage accounting: %+v %v", n, err)
	}
}

func TestAgentStorageHardcapAndTerminalHeadroom(t *testing.T) {
	r := unitAgentRun()
	r.Limits.MaxStoredBytes = 128 * 1024
	r.StoredBytes = 64 * 1024
	if _, err := sizeAgentStep(&r, 64*1024, []byte(`{}`), []byte(`{}`), "key", domain.AgentStepCheckpoint); !errors.Is(err, ErrBudget) {
		t.Fatal("normal transition spent terminal headroom")
	}
	r.State = domain.AgentRunBudgetExhausted
	result, err := sizeAgentStep(&r, 64*1024, []byte(`{}`), []byte(`{}`), "terminal", domain.AgentStepBudgetExhausted)
	if err != nil || r.StoredBytes > r.Limits.MaxStoredBytes {
		t.Fatal("bounded terminal could not commit")
	}
	var saved domain.AgentRun
	if err = json.Unmarshal(result, &saved); err != nil || saved.StoredBytes != r.StoredBytes {
		t.Fatal("replay storage size not fixed point")
	}
	if _, err = sizeAgentStep(&r, r.Limits.MaxStoredBytes, []byte(`{}`), []byte(`{}`), "terminal", domain.AgentStepBudgetExhausted); !errors.Is(err, ErrBudget) {
		t.Fatal("terminal exceeded storage hardcap")
	}
}
