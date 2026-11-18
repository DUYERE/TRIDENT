package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trident/internal/domain"
)

func TestPriorContextIncludesLatestBoundedSummaries(t *testing.T) {
	cp := json.RawMessage(`{"messages":[{"role":"user","content":"old"},{"role":"assistant","content":"{\"summary\":\"LFI path is reachable\",\"hypotheses\":[{\"statement\":\"archive path controls include\"}],\"limitations\":[\"runtime not run\"]}"}]}`)
	runs := []domain.AgentRun{
		{ID: 1, Goal: "first", State: domain.AgentRunCompleted, CreatedAt: time.Unix(100, 0), Checkpoint: cp},
		{ID: 2, Goal: strings.Repeat("x", 1000), State: domain.AgentRunFailed, CreatedAt: time.Unix(200, 0), Reason: "model unavailable"},
		{ID: 3, Goal: "active", State: domain.AgentRunRunning, CreatedAt: time.Unix(300, 0)},
	}
	context := PriorContext(runs, 2048)
	if !strings.Contains(context, "Run 1") || !strings.Contains(context, "LFI path is reachable") || !strings.Contains(context, "Run 2") {
		t.Fatalf("prior context missing run summaries: %q", context)
	}
	if strings.Contains(context, "Run 3") || strings.Contains(context, strings.Repeat("x", 500)) {
		t.Fatalf("prior context included nonterminal or unbounded content: %q", context)
	}
	if len(context) > 2048 {
		t.Fatalf("prior context exceeds bound: %d", len(context))
	}
}

func TestLoadCheckpointForRepairPromptAndPriorContext(t *testing.T) {
	run := domain.AgentRun{Goal: "repair the case", State: domain.AgentRunReady}
	cp, err := loadCheckpointFor(run, repairSystemPrompt, "Run 1 completed: prior summary")
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Messages) != 3 || cp.Messages[0].Content != repairSystemPrompt || cp.Messages[2].Content == "" || !strings.Contains(cp.Messages[2].Content, "prior summary") {
		t.Fatalf("checkpoint messages: %+v", cp.Messages)
	}
	legacy, err := loadCheckpointFor(run, systemPrompt, "")
	if err != nil || len(legacy.Messages) != 2 {
		t.Fatalf("legacy checkpoint: %+v %v", legacy, err)
	}
}
