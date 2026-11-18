package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"trident/internal/domain"
	"trident/internal/model"
	"trident/internal/tools"
)

func largeToolContent(size int) string {
	return `{"entries":[` + strings.Repeat(`{"path":"src/main/java/example/App.java","sha256":"`+
		strings.Repeat("a", 64)+`"},`, size/100) + `]}`
}

func TestCompactedToolContentIsLabelledJSON(t *testing.T) {
	content := largeToolContent(4096)
	marker := compactedToolContent(content)
	var decoded map[string]any
	if err := json.Unmarshal([]byte(marker), &decoded); err != nil {
		t.Fatalf("marker is not valid JSON: %v", err)
	}
	if decoded["truncated"] != true || decoded["reason"] != "agent_checkpoint_budget" {
		t.Fatalf("marker fields: %+v", decoded)
	}
	if decoded["original_bytes"] != float64(len(content)) {
		t.Fatalf("original_bytes: %+v", decoded["original_bytes"])
	}
	preview, _ := decoded["preview"].(string)
	if len(preview) > compactPreviewBytes {
		t.Fatalf("preview too large: %d", len(preview))
	}
}

func TestCompactionKeepsPerToolSummary(t *testing.T) {
	content := `{"schema_version":1,"tool":"list_findings","snapshot_hash":"abc","total":42,"offset":0,"limit":10,"partial":false,"advisory_configured":true,"counts":{"findings_total":42},"items":[` +
		strings.TrimSuffix(strings.Repeat(`{"id":"CWE-89:/x:q"},`, 500), ",") + `]}`
	marker := compactedToolContentFor("list_findings", content)
	var decoded map[string]any
	if err := json.Unmarshal([]byte(marker), &decoded); err != nil {
		t.Fatalf("marker is not valid JSON: %v", err)
	}
	if decoded["tool"] != "list_findings" {
		t.Fatalf("tool field: %+v", decoded["tool"])
	}
	summary, ok := decoded["summary"].(map[string]any)
	if !ok || summary["total"] != float64(42) || summary["partial"] != false {
		t.Fatalf("summary: %+v", decoded["summary"])
	}
	preview, _ := decoded["preview"].(string)
	if len(preview) > 1536 {
		t.Fatalf("per-tool preview too large: %d", len(preview))
	}
	readMarker := compactedToolContentFor("read_source", `{"lines":[`+strings.Repeat(`{"number":1,"text":"abcdefgh"},`, 1000)+`]}`)
	var readDecoded map[string]any
	if err := json.Unmarshal([]byte(readMarker), &readDecoded); err != nil {
		t.Fatal(err)
	}
	readPreview, _ := readDecoded["preview"].(string)
	if len(readPreview) > 2064 || !strings.Contains(readPreview, "\n...\n") {
		t.Fatalf("read_source preview should retain head and tail: %d", len(readPreview))
	}
}

func TestCheckpointLimitDisabledByDefault(t *testing.T) {
	messages := []model.Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: "audit goal"},
	}
	for i := 0; i < 4; i++ {
		id := "call-" + string(rune('a'+i))
		messages = append(messages,
			model.Message{Role: "assistant", Content: "reading", Calls: []model.ToolCall{{ID: id, Name: "read_source", Arguments: json.RawMessage(`{"path":"a.go"}`)}}},
			model.Message{Role: "tool", CallID: id, Content: largeToolContent(20000)},
		)
	}
	exec := &execution{cp: loopCheckpoint{Version: checkpointVersion, Messages: messages}}
	before := exec.checkpointSize()
	if before <= 48<<10 {
		t.Fatalf("test history is too small: %d", before)
	}
	exec.compactCheckpoint()
	if exec.cp.Compactions != 0 {
		t.Fatalf("default execution must not compact or cap history; compactions=%d", exec.cp.Compactions)
	}
	if after := exec.checkpointSize(); after != before {
		t.Fatalf("default execution changed checkpoint size: before=%d after=%d", before, after)
	}
}

func TestLoadCheckpointAcceptsCheckpointAboveLegacyLimit(t *testing.T) {
	cp := loopCheckpoint{
		Version: checkpointVersion,
		Messages: []model.Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: "audit goal"},
			{Role: "assistant", Content: largeToolContent(60000)},
		},
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 48<<10 {
		t.Fatalf("test checkpoint was not above the legacy cap: %d", len(raw))
	}
	if _, err := loadCheckpoint(domain.AgentRun{Goal: "audit goal", Checkpoint: raw}); err != nil {
		t.Fatalf("load rejected a checkpoint above the old 48 KiB cap: %v", err)
	}
}

func TestCommitAcceptsCheckpointAboveLegacyLimit(t *testing.T) {
	runner := &memoryRunner{run: domain.AgentRun{
		ID: 1, State: domain.AgentRunRunning, Version: 1,
		Limits: domain.AgentLimits{MaxModelCalls: 8, MaxToolCalls: 8, MaxTokens: 1 << 20, MaxStoredBytes: 32 << 20},
	}}
	exec := &execution{runner: runner, run: runner.run, cp: loopCheckpoint{
		Version: checkpointVersion,
		Messages: []model.Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: "audit goal"},
			{Role: "assistant", Content: largeToolContent(60000)},
		},
	}}
	if err := exec.commit(context.Background(), domain.AgentStepCheckpoint, "large checkpoint", nil, 0, 0, 0, 0); err != nil {
		t.Fatalf("commit rejected a checkpoint above the old 48 KiB cap: %v", err)
	}
	if got := len(runner.run.Checkpoint); got <= 48<<10 {
		t.Fatalf("test checkpoint was not above the legacy cap: %d", got)
	}
}

func TestCompactCheckpointBoundsHistoryWithoutBreakingPairing(t *testing.T) {
	oldMax, oldTarget := maxCheckpointBytes, checkpointCompactTarget
	maxCheckpointBytes, checkpointCompactTarget = 48<<10, 40<<10
	defer func() { maxCheckpointBytes, checkpointCompactTarget = oldMax, oldTarget }()

	messages := []model.Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: "audit goal"},
	}
	for i := 0; i < 4; i++ {
		id := "call-" + string(rune('a'+i))
		messages = append(messages,
			model.Message{Role: "assistant", Content: "reading", Calls: []model.ToolCall{{ID: id, Name: "read_source", Arguments: json.RawMessage(`{"path":"a.go"}`)}}},
			model.Message{Role: "tool", CallID: id, Content: largeToolContent(20000)},
		)
	}
	newest := messages[len(messages)-1].Content
	exec := &execution{cp: loopCheckpoint{
		Version:  checkpointVersion,
		Messages: messages,
		Evidence: []tools.Evidence{{Path: "a.go", StartLine: 1, EndLine: 2}},
	}}
	if size := exec.checkpointSize(); size <= checkpointCompactTarget {
		t.Fatalf("test history is too small: %d", size)
	}
	exec.compactCheckpoint()
	size := exec.checkpointSize()
	if size > checkpointCompactTarget {
		t.Fatalf("compaction did not reach target: %d", size)
	}
	if len(exec.cp.Messages) != len(messages) {
		t.Fatalf("messages removed: %d != %d", len(exec.cp.Messages), len(messages))
	}
	for i := 0; i < 2; i++ {
		if exec.cp.Messages[i].Role != messages[i].Role || exec.cp.Messages[i].Content != messages[i].Content {
			t.Fatalf("preamble changed: %+v", exec.cp.Messages[i])
		}
	}
	if exec.cp.Messages[len(messages)-1].Content != newest {
		t.Fatal("newest tool result must stay intact")
	}
	compacted := 0
	for _, message := range exec.cp.Messages {
		if message.Role != "tool" || message.Content == newest {
			continue
		}
		compacted++
		var marker map[string]any
		if err := json.Unmarshal([]byte(message.Content), &marker); err != nil || marker["truncated"] != true {
			t.Fatalf("old tool result not compacted: %q (%v)", message.Content, err)
		}
	}
	if compacted < 2 {
		t.Fatalf("expected at least two compacted results, got %d", compacted)
	}
	if exec.cp.Compactions != compacted || exec.cp.CompactedBytes <= 0 {
		t.Fatalf("audit fields: compactions=%d compacted_bytes=%d", exec.cp.Compactions, exec.cp.CompactedBytes)
	}
	before := exec.cp.Compactions
	exec.compactCheckpoint()
	if exec.cp.Compactions != before {
		t.Fatal("compaction must be idempotent once under target")
	}
	encoded, err := json.Marshal(exec.cp)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded loopCheckpoint
	if err := json.Unmarshal(encoded, &reloaded); err != nil {
		t.Fatal(err)
	}
	if reloaded.Compactions != exec.cp.Compactions || reloaded.CompactedBytes != exec.cp.CompactedBytes {
		t.Fatalf("audit fields did not round-trip: %+v", reloaded)
	}
}
