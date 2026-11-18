package store

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestOrchestrationConflictMapsToBusy(t *testing.T) {
	unique := &pgconn.PgError{Code: "23505", ConstraintName: orchestrationRunningIndex, Detail: "Key (owner_id)=(7) already exists."}
	busy := classifyOrchestrationConflict(unique)
	if !errors.Is(busy, ErrOrchestrationBusy) {
		t.Fatalf("unique violation on the running index must map to ErrOrchestrationBusy, got %v", busy)
	}
	if other := classifyOrchestrationConflict(&pgconn.PgError{Code: "23505", ConstraintName: "other_index"}); errors.Is(other, ErrOrchestrationBusy) {
		t.Fatal("an unrelated unique violation was misclassified as orchestration busy")
	}
	if err := classifyOrchestrationConflict(errors.New("boom")); !errors.Is(err, errors.New("boom")) && err == nil {
		t.Fatal("a plain error must pass through")
	}
	if classifyOrchestrationConflict(nil) != nil {
		t.Fatal("nil must stay nil")
	}
}

func TestOrchestrationNodePayloadDefaultsToEmptyObject(t *testing.T) {
	if got := normalizeNodePayload(nil); got != "{}" {
		t.Fatalf("nil payload must become an empty JSON object, got %q", got)
	}
	if got := normalizeNodePayload(json.RawMessage("  ")); got != "{}" {
		t.Fatalf("blank payload must become an empty JSON object, got %q", got)
	}
	raw := json.RawMessage(`{"kind":"x"}`)
	if got := normalizeNodePayload(raw); got != string(raw) {
		t.Fatalf("valid payload must pass through unchanged, got %q", got)
	}
}

func TestOrchestrationTaskConfigValidate(t *testing.T) {
	valid := OrchestrationTaskConfig{MaxModelCalls: 8, MaxToolCalls: 24, MaxTokens: 131072}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := []OrchestrationTaskConfig{
		{MaxModelCalls: 0, MaxToolCalls: 24, MaxTokens: 131072},
		{MaxModelCalls: 65, MaxToolCalls: 24, MaxTokens: 131072},
		{MaxModelCalls: 8, MaxToolCalls: 0, MaxTokens: 131072},
		{MaxModelCalls: 8, MaxToolCalls: 257, MaxTokens: 131072},
		{MaxModelCalls: 8, MaxToolCalls: 24, MaxTokens: 4095},
		{MaxModelCalls: 8, MaxToolCalls: 24, MaxTokens: 1_000_001},
	}
	for i, config := range cases {
		if err := config.Validate(); err == nil {
			t.Fatalf("case %d must be rejected: %+v", i, config)
		}
	}
}
