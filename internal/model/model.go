// Package model 定义供应商无关的单轮模型协议；不持有数据库或文件系统权限。
package model

import (
	"context"
	"encoding/json"
	"errors"
)

const ProtocolVersion = "trident-model-v1"

const (
	StopComplete = "complete"
	StopTools    = "tool_calls"
	StopRefusal  = "refusal"
	StopLength   = "length"
)

var (
	ErrProtocol    = errors.New("invalid model protocol")
	ErrRateLimit   = errors.New("model rate limited")
	ErrUnavailable = errors.New("model unavailable")
	ErrDenied      = errors.New("model request denied")
	ErrLimit       = errors.New("model request or response limit")
)

// [01] 消息仅允许system/user/assistant/tool，工具结果用CallID关联，不将源码提升为指令。
type Message struct {
	Role    string     `json:"role"`
	Content string     `json:"content"`
	Calls   []ToolCall `json:"calls,omitempty"`
	CallID  string     `json:"call_id,omitempty"`
}

type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
}

type Request struct {
	Messages        []Message `json:"messages"`
	Tools           []Tool    `json:"tools"`
	MaxOutputTokens int64     `json:"max_output_tokens"`
	// ReasoningEffort is passed only when the caller explicitly controls
	// provider thinking. "none" keeps a deterministic tool-shaped response from
	// spending the whole output budget on hidden reasoning.
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
}

type Usage struct {
	Known        bool  `json:"known"`
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

type Response struct {
	Message   Message `json:"message"`
	Stop      string  `json:"stop"`
	Usage     Usage   `json:"usage"`
	RequestID string  `json:"request_id,omitempty"`
}

// Client 一次调用一次尝试，不隐藏重试，不决定任何工具执行或外发许可。
type Client interface {
	Complete(context.Context, Request) (Response, error)
}
