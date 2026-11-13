package openai

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"unicode/utf8"

	"trident/internal/model"
)

// These wire types intentionally do not use SDK zero-value enum defaults or
// permissive scalar coercion. Unsupported protocols are rejected, never guessed.
type wireResponse struct {
	Object  string           `json:"object"`
	Choices []wireChoice     `json:"choices"`
	Usage   *json.RawMessage `json:"usage"`
}

type wireChoice struct {
	Index        *int64       `json:"index"`
	FinishReason string       `json:"finish_reason"`
	Message      *wireMessage `json:"message"`
}

type wireMessage struct {
	Role         string            `json:"role"`
	Content      *string           `json:"content"`
	Refusal      *string           `json:"refusal"`
	Calls        []wireCall        `json:"tool_calls"`
	FunctionCall json.RawMessage   `json:"function_call"`
	Audio        json.RawMessage   `json:"audio"`
	Annotations  []json.RawMessage `json:"annotations"`
	// DeepSeek and other compatible providers return reasoning_content next to
	// the final answer. It is opaque continuation data, not user-visible output.
	ReasoningContent *string         `json:"reasoning_content"`
	ReasoningDetails json.RawMessage `json:"reasoning_details"`
	Reasoning        json.RawMessage `json:"reasoning"`
}

type wireCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function *struct {
		Name      string  `json:"name"`
		Arguments *string `json:"arguments"`
	} `json:"function"`
	Custom json.RawMessage `json:"custom"`
}

func decodeResponse(raw []byte, req model.Request) (model.Response, error) {
	// [01] Strictly validate the original bounded JSON, not SDK-inferred defaults.
	fail := func() (model.Response, error) {
		return model.Response{}, safeError(model.ErrProtocol, "unsupported or malformed completion")
	}
	if err := validateJSON(raw); err != nil {
		return fail()
	}
	var wire wireResponse
	if err := json.Unmarshal(raw, &wire); err != nil || wire.Object != "chat.completion" || len(wire.Choices) != 1 {
		return fail()
	}
	choice := wire.Choices[0]
	if choice.Index == nil || *choice.Index != 0 || choice.Message == nil || choice.Message.Role != "assistant" {
		return fail()
	}
	msg := choice.Message
	if nonNull(msg.FunctionCall) || nonNull(msg.Audio) || len(msg.Annotations) != 0 || nonNull(msg.ReasoningDetails) || nonNull(msg.Reasoning) {
		return fail()
	}
	if msg.ReasoningContent != nil && !validText(*msg.ReasoningContent) {
		return fail()
	}
	result := model.Response{Message: model.Message{Role: "assistant"}}
	if msg.Content != nil {
		if !validText(*msg.Content) {
			return fail()
		}
		result.Message.Content = *msg.Content
	}
	// [02] Missing/null usage remains unknown, never an invented zero-cost call.
	if wire.Usage != nil && nonNull(*wire.Usage) {
		var usage struct {
			Input  *int64 `json:"prompt_tokens"`
			Output *int64 `json:"completion_tokens"`
			Total  *int64 `json:"total_tokens"`
		}
		if err := json.Unmarshal(*wire.Usage, &usage); err != nil {
			return fail()
		}
		if usage.Input != nil && *usage.Input < 0 || usage.Output != nil && *usage.Output < 0 || usage.Total != nil && *usage.Total < 0 {
			return fail()
		}
		if usage.Input != nil && usage.Output != nil {
			if *usage.Input > math.MaxInt64-*usage.Output || (usage.Total != nil && *usage.Total != *usage.Input+*usage.Output) {
				return fail()
			}
			result.Usage = model.Usage{Known: true, InputTokens: *usage.Input, OutputTokens: *usage.Output}
		}
	}
	switch choice.FinishReason {
	case "stop":
		result.Stop = model.StopComplete
	case "tool_calls":
		result.Stop = model.StopTools
	case "length":
		result.Stop = model.StopLength
	case "content_filter":
		// Filtering is refusal, not successful empty output or a transport error.
		result.Stop = model.StopRefusal
		result.Message.Content = ""
	default:
		return fail()
	}
	if msg.Refusal != nil && *msg.Refusal != "" {
		if !validText(*msg.Refusal) {
			return fail()
		}
		result.Stop = model.StopRefusal
		result.Message.Content = *msg.Refusal
	}
	if result.Stop == model.StopTools {
		if len(msg.Calls) == 0 {
			return fail()
		}
		allowed, seen := make(map[string]bool), make(map[string]bool)
		for _, tool := range req.Tools {
			allowed[tool.Name] = true
		}
		for _, message := range req.Messages {
			for _, call := range message.Calls {
				seen[call.ID] = true
			}
		}
		// [03] Function-only calls, explicit IDs, JSON object arguments. Execution
		// authorization/schema validation still belongs to the caller's registry.
		for _, call := range msg.Calls {
			if call.Type != "function" || nonNull(call.Custom) || !validID(call.ID) || seen[call.ID] || call.Function == nil || !validName(call.Function.Name) || !allowed[call.Function.Name] || call.Function.Arguments == nil {
				return fail()
			}
			args := json.RawMessage(*call.Function.Arguments)
			if _, err := objectJSON(args); err != nil {
				return fail()
			}
			seen[call.ID] = true
			result.Message.Calls = append(result.Message.Calls, model.ToolCall{ID: call.ID, Name: call.Function.Name, Arguments: args})
		}
	} else if len(msg.Calls) != 0 {
		if result.Stop != model.StopLength {
			return fail()
		}
		// Truncated tool calls must never be turned into executable tool output.
		for _, call := range msg.Calls {
			if call.Type != "function" || nonNull(call.Custom) {
				return fail()
			}
		}
	} else if result.Stop == model.StopComplete && msg.Content == nil {
		return fail()
	}
	return result, nil
}

func nonNull(raw json.RawMessage) bool {
	return len(raw) != 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func objectJSON(raw []byte) (map[string]any, error) {
	if err := validateJSON(raw); err != nil {
		return nil, err
	}
	var object map[string]any
	// Standard decoding keeps numeric schema keywords as JSON numbers. The SDK
	// parameter encoder serializes json.Number as a string, which strict
	// OpenAI-compatible providers reject (e.g. maxLength/minimum/maximum).
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, safeError(model.ErrProtocol, "expected JSON object")
	}
	return object, nil
}

func validateJSON(raw []byte) error {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return safeError(model.ErrProtocol, "invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	// [04] Reject duplicate keys (at every depth) instead of last-value wins.
	if err := uniqueValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return safeError(model.ErrProtocol, "trailing JSON")
	}
	return nil
}

func uniqueValue(decoder *json.Decoder, depth int) error {
	if depth > 128 {
		return safeError(model.ErrProtocol, "JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return safeError(model.ErrProtocol, "invalid JSON")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	keys := make(map[string]bool)
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || keys[name] {
				return safeError(model.ErrProtocol, "duplicate or invalid JSON key")
			}
			keys[name] = true
		}
		if err := uniqueValue(decoder, depth+1); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return safeError(model.ErrProtocol, "invalid JSON")
	}
	return nil
}
