package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf8"

	"trident/internal/domain"
)

const (
	agentConfigMaxBytes     = 16 * 1024
	agentCheckpointMaxBytes = 64 * 1024
	agentPayloadMaxBytes    = 256 * 1024
	// [01] Normal work cannot spend the final 64KiB needed for a bounded terminal diagnostic.
	agentTerminalHeadroom int64 = 64 * 1024
	// AgentStorageHeadroom exposes the same fixed reserve for the agent loop's
	// local pre-check; the store remains the exact accounting authority.
	AgentStorageHeadroom = agentTerminalHeadroom
)

func agentHash(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func agentText(s string, max int, nonempty bool) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0) && len(s) <= max && (!nonempty || strings.TrimSpace(s) != "")
}

func agentKey(key string) bool { return agentText(key, 200, true) }

// [02] Duplicate keys, invalid UTF-8, deep objects and trailing JSON are rejected before hashing.
func canonicalAgentJSON(raw json.RawMessage, max int, emptyDefault bool) (json.RawMessage, error) {
	if len(raw) == 0 && emptyDefault {
		raw = json.RawMessage(`{}`)
	}
	if len(raw) == 0 || len(raw) > max || !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: invalid or oversized agent JSON", ErrDenied)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := readAgentJSON(d, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid agent JSON: %v", ErrDenied, err)
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, fmt.Errorf("%w: agent JSON must be an object", ErrDenied)
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing agent JSON", ErrDenied)
	}
	out, err := json.Marshal(v)
	if err != nil || len(out) > max {
		return nil, fmt.Errorf("%w: canonical agent JSON exceeds limit", ErrDenied)
	}
	return out, nil
}

func readAgentJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, fmt.Errorf("JSON nesting limit")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	if s, ok := t.(string); ok && strings.ContainsRune(s, 0) {
		return nil, fmt.Errorf("NUL is not supported")
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch delim {
	case '{':
		m := make(map[string]any)
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return nil, e
			}
			key, ok := k.(string)
			if !ok || strings.ContainsRune(key, 0) {
				return nil, fmt.Errorf("invalid object key")
			}
			if _, exists := m[key]; exists {
				return nil, fmt.Errorf("duplicate object key")
			}
			value, e := readAgentJSON(d, depth+1)
			if e != nil {
				return nil, e
			}
			m[key] = value
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return nil, fmt.Errorf("unclosed object")
		}
		return m, nil
	case '[':
		items := make([]any, 0)
		for d.More() {
			value, e := readAgentJSON(d, depth+1)
			if e != nil {
				return nil, e
			}
			items = append(items, value)
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return nil, fmt.Errorf("unclosed array")
		}
		return items, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter")
	}
}

func agentTerminal(state domain.AgentRunState) bool {
	return state == domain.AgentRunCompleted || state == domain.AgentRunFailed || state == domain.AgentRunCancelled || state == domain.AgentRunBudgetExhausted
}

func agentAdd(current, delta, cap int64) (int64, error) {
	if (delta > 0 && current > math.MaxInt64-delta) || (delta < 0 && delta < -current) {
		return 0, ErrBudget
	}
	next := current + delta
	if next < 0 || next > cap {
		return 0, ErrBudget
	}
	return next, nil
}

// [03] Fixed event semantics prevent caller-supplied generic mutations from bypassing accounting.
func applyAgentTransition(run domain.AgentRun, p AgentTransition) (domain.AgentRun, error) {
	if run.Version != p.ExpectedVersion || run.Version == math.MaxInt64 || agentTerminal(run.State) {
		return domain.AgentRun{}, ErrConflict
	}
	if !agentText(p.Reason, 4096, false) {
		return domain.AgentRun{}, ErrDenied
	}
	target := run.State
	expected := domain.AgentRunState("")
	zero := p.ModelDelta == 0 && p.ToolDelta == 0 && p.ReservedTokenDelta == 0 && p.UsedTokenDelta == 0
	switch p.Kind {
	case domain.AgentStepStarted:
		if run.State != domain.AgentRunReady || !zero {
			return domain.AgentRun{}, ErrConflict
		}
		expected = domain.AgentRunRunning
	case domain.AgentStepResumed:
		if (run.State != domain.AgentRunPaused && run.State != domain.AgentRunUnknown) || !zero {
			return domain.AgentRun{}, ErrConflict
		}
		expected = domain.AgentRunRunning
	case domain.AgentStepPaused:
		if (run.State != domain.AgentRunReady && run.State != domain.AgentRunRunning) || !zero {
			return domain.AgentRun{}, ErrConflict
		}
		expected = domain.AgentRunPaused
	case domain.AgentStepUnknown:
		if run.State != domain.AgentRunRunning || !zero {
			return domain.AgentRun{}, ErrConflict
		}
		expected = domain.AgentRunUnknown
	case domain.AgentStepCompleted:
		if run.State != domain.AgentRunRunning || !zero {
			return domain.AgentRun{}, ErrConflict
		}
		expected = domain.AgentRunCompleted
	case domain.AgentStepFailed, domain.AgentStepCancelled, domain.AgentStepBudgetExhausted:
		if !zero {
			return domain.AgentRun{}, ErrConflict
		}
		switch p.Kind {
		case domain.AgentStepFailed:
			expected = domain.AgentRunFailed
		case domain.AgentStepCancelled:
			expected = domain.AgentRunCancelled
		default:
			expected = domain.AgentRunBudgetExhausted
		}
	case domain.AgentStepModelPrepared:
		if run.State != domain.AgentRunRunning || p.ModelDelta != 1 || p.ToolDelta != 0 || p.ReservedTokenDelta <= 0 || p.UsedTokenDelta != 0 {
			return domain.AgentRun{}, ErrConflict
		}
	case domain.AgentStepModelCompleted:
		if run.State != domain.AgentRunRunning || p.ModelDelta != 0 || p.ToolDelta != 0 || p.ReservedTokenDelta > 0 || p.ReservedTokenDelta == math.MinInt64 || p.UsedTokenDelta < 0 || (p.ReservedTokenDelta == 0 && p.UsedTokenDelta != 0) {
			return domain.AgentRun{}, ErrConflict
		}
		// [05] A bounded response-omission diagnostic may settle usage and stop atomically.
		// It consumes terminal headroom once; it cannot be used to dispatch more work.
		if p.State == domain.AgentRunBudgetExhausted {
			if !validAgentAccountingTerminal(p) {
				return domain.AgentRun{}, ErrDenied
			}
			expected = domain.AgentRunBudgetExhausted
		}
	case domain.AgentStepToolStarted:
		if run.State != domain.AgentRunRunning || p.ToolDelta != 1 || p.ModelDelta != 0 || p.ReservedTokenDelta != 0 || p.UsedTokenDelta != 0 {
			return domain.AgentRun{}, ErrConflict
		}
	case domain.AgentStepToolCompleted:
		if run.State != domain.AgentRunRunning || !zero {
			return domain.AgentRun{}, ErrConflict
		}
	case domain.AgentStepCheckpoint:
		if run.State != domain.AgentRunRunning || !zero {
			return domain.AgentRun{}, ErrConflict
		}
	default:
		return domain.AgentRun{}, ErrDenied
	}
	if expected != "" {
		target = expected
	}
	if p.State != "" && p.State != target {
		return domain.AgentRun{}, ErrConflict
	}
	var err error
	if run.ModelCalls, err = agentAdd(run.ModelCalls, p.ModelDelta, run.Limits.MaxModelCalls); err != nil {
		return domain.AgentRun{}, err
	}
	if run.ToolCalls, err = agentAdd(run.ToolCalls, p.ToolDelta, run.Limits.MaxToolCalls); err != nil {
		return domain.AgentRun{}, err
	}
	// [04] Actual known usage is evidence, not an estimate: retain overruns instead of hiding/refunding them.
	if run.TokensUsed, err = agentAdd(run.TokensUsed, p.UsedTokenDelta, math.MaxInt64); err != nil {
		return domain.AgentRun{}, err
	}
	if run.TokensReserved, err = agentAdd(run.TokensReserved, p.ReservedTokenDelta, run.Limits.MaxTokens); err != nil {
		return domain.AgentRun{}, err
	}
	if p.Kind == domain.AgentStepModelPrepared || p.Kind == domain.AgentStepToolStarted {
		if run.TokensUsed > run.Limits.MaxTokens || run.TokensReserved > run.Limits.MaxTokens-run.TokensUsed {
			return domain.AgentRun{}, ErrBudget
		}
	}
	run.State = target
	run.Reason = p.Reason
	run.Version++
	run.LastSeq++
	if p.Checkpoint != nil {
		run.Checkpoint = append(json.RawMessage(nil), p.Checkpoint...)
	}
	return run, nil
}

// [06] A known response may be omitted only as this bounded accounting-only
// terminal: a tiny digest diagnostic, no replacement checkpoint, and token
// deltas consistent with the reported usage. Unknown usage keeps its
// reservation instead of being refunded or recorded as zero cost.
func validAgentAccountingTerminal(p AgentTransition) bool {
	if p.Kind != domain.AgentStepModelCompleted || p.State != domain.AgentRunBudgetExhausted || p.Checkpoint != nil {
		return false
	}
	if len(p.Payload) == 0 || len(p.Payload) > domain.AgentAccountingMaxBytes {
		return false
	}
	var accounting domain.AgentAccounting
	decoder := json.NewDecoder(bytes.NewReader(p.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&accounting); err != nil {
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return false
	}
	switch accounting.Reason {
	case domain.AgentAccountingResponseBytes, domain.AgentAccountingCheckpoint, domain.AgentAccountingStoredBytes:
	default:
		return false
	}
	if accounting.Response.Retained || accounting.Response.Bytes < 1 || len(accounting.Response.SHA256) != 64 {
		return false
	}
	if _, err := hex.DecodeString(accounting.Response.SHA256); err != nil {
		return false
	}
	switch accounting.Response.Stop {
	case "complete", "tool_calls", "refusal", "length":
	default:
		return false
	}
	usage := accounting.ReportedUsage
	if usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.InputTokens > math.MaxInt64-usage.OutputTokens {
		return false
	}
	if !usage.Known {
		return usage.InputTokens == 0 && usage.OutputTokens == 0 && p.UsedTokenDelta == 0 && p.ReservedTokenDelta == 0
	}
	return p.UsedTokenDelta == usage.InputTokens+usage.OutputTokens
}
