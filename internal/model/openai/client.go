// Package openai implements exactly one non-streaming Chat Completions request.
// Constructing a client never probes a provider or makes a network request.
package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	sdk "github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/shared"

	"trident/internal/model"
)

type OutputParameter string

const (
	OutputMaxCompletionTokens OutputParameter = "max_completion_tokens"
	OutputMaxTokens           OutputParameter = "max_tokens"
)

// Config is explicit provider configuration. Endpoint is the base URL, e.g.
// https://operator-selected.example/v1. No model, key, URL, or profile defaults
// are inferred from environment variables or provider discovery.
type Config struct {
	Endpoint          string
	Model             string
	APIKey            string
	Timeout           time.Duration
	MaxRequestBytes   int64
	MaxResponseBytes  int64
	OutputParameter   OutputParameter
	AllowLoopbackHTTP bool
}

type Client struct {
	service   sdk.ChatCompletionService
	transport *pinnedTransport
	config    Config
}

var _ model.Client = (*Client)(nil)

// New validates configuration only. Zero limits use fixed safe defaults;
// negative or unreasonably large limits are rejected rather than normalized.
func New(cfg Config) (*Client, error) {
	// [01] Reject implicit provider/profile selection and header injection.
	endpoint, err := NormalizeEndpoint(cfg.Endpoint, cfg.AllowLoopbackHTTP)
	if err != nil {
		return nil, err
	}
	if !validText(cfg.Model) || strings.TrimSpace(cfg.Model) != cfg.Model || cfg.Model == "" {
		return nil, configError("model is required")
	}
	if cfg.APIKey == "" || strings.IndexFunc(cfg.APIKey, func(r rune) bool { return r <= ' ' || r >= 127 }) >= 0 {
		return nil, configError("explicit API key is required")
	}
	if cfg.OutputParameter != OutputMaxCompletionTokens && cfg.OutputParameter != OutputMaxTokens {
		return nil, configError("explicit output parameter profile is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 120 * time.Second
	}
	if cfg.MaxRequestBytes == 0 {
		cfg.MaxRequestBytes = 2 << 20
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 512 << 10
	}
	if cfg.Timeout < 0 || cfg.MaxRequestBytes < 1 || cfg.MaxResponseBytes < 1 || cfg.MaxRequestBytes > 64<<20 || cfg.MaxResponseBytes > 64<<20 {
		return nil, configError("invalid timeout or byte limit")
	}
	cfg.Endpoint = endpoint
	target, _ := url.Parse(endpoint + "/chat/completions")
	transport := newTransport(target, cfg)
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// [02] Unlike sdk.NewClient, the official service constructor does NOT read
	// OPENAI_* environment variables (including OPENAI_CUSTOM_HEADERS).
	service := sdk.NewChatCompletionService(
		option.WithBaseURL(endpoint),
		option.WithAPIKey(cfg.APIKey),
		option.WithOrganization(""),
		option.WithProject(""),
		option.WithHTTPClient(httpClient),
		option.WithMaxRetries(0),
		option.WithRequestTimeout(cfg.Timeout),
	)
	return &Client{service: service, transport: transport, config: cfg}, nil
}

// Complete performs one SDK attempt. Tools are data only: execution, history,
// budgets, and further rounds remain exclusively the caller's responsibility.
func (c *Client) Complete(ctx context.Context, req model.Request) (model.Response, error) {
	if ctx == nil {
		return model.Response{}, safeError(model.ErrProtocol, "context is required")
	}
	if err := ctx.Err(); err != nil {
		return model.Response{}, safeError(err, "request interrupted")
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	params, err := c.parameters(req)
	if err != nil {
		return model.Response{}, err
	}
	// [03] Check actual SDK JSON before sending; transport rechecks the final body.
	body, err := json.Marshal(params)
	if err != nil {
		return model.Response{}, safeError(model.ErrProtocol, "request encoding failed")
	}
	if int64(len(body)) > c.config.MaxRequestBytes {
		return model.Response{}, safeError(model.ErrLimit, "request byte limit exceeded")
	}
	completion, err := c.service.New(ctx, params)
	if err != nil {
		return model.Response{}, sanitizeError(ctx, err)
	}
	if completion == nil {
		return model.Response{}, safeError(model.ErrProtocol, "missing completion")
	}
	return decodeResponse([]byte(completion.RawJSON()), req)
}

// CloseIdleConnections releases pooled connections without issuing a request.
func (c *Client) CloseIdleConnections() { c.transport.inner.CloseIdleConnections() }

func (c *Client) parameters(req model.Request) (sdk.ChatCompletionNewParams, error) {
	params := sdk.ChatCompletionNewParams{Model: c.config.Model}
	if req.MaxOutputTokens <= 0 || len(req.Messages) == 0 {
		return params, safeError(model.ErrProtocol, "messages and positive output limit are required")
	}
	if c.config.OutputParameter == OutputMaxTokens {
		params.MaxTokens = sdk.Int(req.MaxOutputTokens)
	} else {
		params.MaxCompletionTokens = sdk.Int(req.MaxOutputTokens)
	}
	// [04] Definitions are function-only JSON schemas; names cannot be duplicated.
	names := make(map[string]bool)
	for _, tool := range req.Tools {
		if !validName(tool.Name) || names[tool.Name] || !validText(tool.Description) {
			return params, safeError(model.ErrProtocol, "invalid tool definition")
		}
		schema, err := objectJSON(tool.Schema)
		if err != nil || schema["type"] != "object" {
			return params, safeError(model.ErrProtocol, "tool schema must be a JSON object schema")
		}
		names[tool.Name] = true
		params.Tools = append(params.Tools, sdk.ChatCompletionToolUnionParam{OfFunction: &sdk.ChatCompletionFunctionToolParam{
			Function: shared.FunctionDefinitionParam{Name: tool.Name, Description: sdk.String(tool.Description), Parameters: shared.FunctionParameters(schema)},
		}})
	}
	pending, seen := make(map[string]bool), make(map[string]bool)
	for _, msg := range req.Messages {
		if !validText(msg.Content) || (msg.Role != "assistant" && len(msg.Calls) != 0) || (msg.Role != "tool" && msg.CallID != "") || (len(pending) != 0 && msg.Role != "tool") {
			return params, safeError(model.ErrProtocol, "invalid message sequence")
		}
		var entry sdk.ChatCompletionMessageParamUnion
		switch msg.Role {
		case "system":
			entry = sdk.SystemMessage(msg.Content)
		case "user":
			entry = sdk.UserMessage(msg.Content)
		case "assistant":
			entry = sdk.AssistantMessage(msg.Content)
			for _, call := range msg.Calls {
				if !validID(call.ID) || seen[call.ID] || !validName(call.Name) {
					return params, safeError(model.ErrProtocol, "invalid historical tool call")
				}
				if _, err := objectJSON(call.Arguments); err != nil {
					return params, safeError(model.ErrProtocol, "invalid tool arguments")
				}
				seen[call.ID], pending[call.ID] = true, true
				entry.OfAssistant.ToolCalls = append(entry.OfAssistant.ToolCalls, sdk.ChatCompletionMessageToolCallUnionParam{OfFunction: &sdk.ChatCompletionMessageFunctionToolCallParam{
					ID:       call.ID,
					Function: sdk.ChatCompletionMessageFunctionToolCallFunctionParam{Name: call.Name, Arguments: string(call.Arguments)},
				}})
			}
		case "tool":
			if !pending[msg.CallID] {
				return params, safeError(model.ErrProtocol, "unmatched tool result")
			}
			delete(pending, msg.CallID)
			entry = sdk.ToolMessage(msg.Content, msg.CallID)
		default:
			return params, safeError(model.ErrProtocol, "unsupported message role")
		}
		params.Messages = append(params.Messages, entry)
	}
	if len(pending) != 0 {
		return params, safeError(model.ErrProtocol, "missing tool results")
	}
	return params, nil
}

func validText(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, '\x00') }

func validID(s string) bool {
	return len(s) > 0 && len(s) <= 256 && strings.IndexFunc(s, func(r rune) bool { return r <= ' ' || r >= 127 }) < 0
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// Errors wrap only fixed sentinels, never a provider/SDK/net error that could
// contain an API key, prompt, URL, response body, or filesystem information.
func safeError(kind error, message string) error { return fmt.Errorf("openai: %s: %w", message, kind) }
func configError(message string) error           { return safeError(model.ErrProtocol, message) }

func sanitizeError(ctx context.Context, err error) error {
	for _, sentinel := range []error{model.ErrLimit, model.ErrDenied, model.ErrRateLimit, model.ErrProtocol, model.ErrUnavailable} {
		if errors.Is(err, sentinel) {
			return safeError(sentinel, "request failed")
		}
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return sanitizeNetworkError(ctx, err)
	}
	// At this point the network succeeded through our pinned transport, so an
	// SDK decoding failure is a protocol failure, not a retryable transport error.
	return safeError(model.ErrProtocol, "invalid provider response")
}
