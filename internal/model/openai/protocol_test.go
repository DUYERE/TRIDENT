package openai

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trident/internal/model"
)

func TestNormalizeEndpoint(t *testing.T) {
	for _, test := range []struct {
		input string
		allow bool
		want  string
	}{
		{"https://EXAMPLE.test/v1/", false, "https://example.test/v1"},
		{"https://example.test/", false, "https://example.test"},
		{"https://example.test", false, "https://example.test"},
		{"https://example.test:443/custom/api", false, "https://example.test:443/custom/api"},
		{"http://127.0.0.1:1234/v1", true, "http://127.0.0.1:1234/v1"},
		{"http://[::1]:1234/v1/", true, "http://[::1]:1234/v1"},
	} {
		got, err := NormalizeEndpoint(test.input, test.allow)
		if err != nil || got != test.want {
			t.Errorf("NormalizeEndpoint(%q) = %q, %v; want %q", test.input, got, err, test.want)
		}
	}
	for _, input := range []string{
		"", "example.test/v1", "ftp://example.test/v1", "https://u:password@example.test/v1", "https://example.test/v1?key=secret", "https://example.test/v1?", "https://example.test/v1#fragment", "https://example.test/v1#", "https://example.test/a/../v1", "https://example.test/a//v1", "https://example.test/%76%31", "https://example.test/%2e%2e/v1", "https://example.test/v1\\other", "https://example.test:0/v1", "https://example.test:65536/v1", "https://example.test:/v1", "https://example.test:bad/v1", "https://example.test/v1 ", "https://example.test/v1\n", "http://localhost:1234/v1", "http://127.0.0.1.evil.test/v1", "http://192.168.1.1/v1", "http://2130706433/v1", "http://[::]/v1", "https://[fe80::1%25en0]/v1",
	} {
		if _, err := NormalizeEndpoint(input, true); !errors.Is(err, model.ErrProtocol) {
			t.Errorf("unsafe endpoint accepted: %q (%v)", input, err)
		}
	}
	if _, err := NormalizeEndpoint("http://127.0.0.1:1234/v1", false); !errors.Is(err, model.ErrProtocol) {
		t.Fatal("loopback HTTP must require opt-in")
	}
}

func TestConfigExplicitAndDefaults(t *testing.T) {
	base := testConfig("https://explicit.test/v1")
	base.Timeout = 0
	client, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if client.config.Timeout != 120*time.Second || client.config.MaxRequestBytes != 2<<20 || client.config.MaxResponseBytes != 512<<10 {
		t.Fatal("unexpected safety defaults")
	}
	for name, mutate := range map[string]func(*Config){
		"endpoint":          func(c *Config) { c.Endpoint = "" },
		"model":             func(c *Config) { c.Model = "" },
		"model-space":       func(c *Config) { c.Model = " model " },
		"key":               func(c *Config) { c.APIKey = "" },
		"key-newline":       func(c *Config) { c.APIKey = "key\nsecret" },
		"profile":           func(c *Config) { c.OutputParameter = "" },
		"unknown-profile":   func(c *Config) { c.OutputParameter = "auto" },
		"negative-timeout":  func(c *Config) { c.Timeout = -time.Second },
		"negative-request":  func(c *Config) { c.MaxRequestBytes = -1 },
		"negative-response": func(c *Config) { c.MaxResponseBytes = -1 },
		"huge-request":      func(c *Config) { c.MaxRequestBytes = 1 << 62 },
		"huge-response":     func(c *Config) { c.MaxResponseBytes = 1 << 62 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if _, err := New(cfg); !errors.Is(err, model.ErrProtocol) {
				t.Fatalf("invalid config accepted: %v", err)
			}
		})
	}
}

func TestResponseStopsAndUsage(t *testing.T) {
	for _, test := range []struct {
		name  string
		body  string
		stop  string
		text  string
		known bool
	}{
		{"complete", completeJSON, model.StopComplete, "done", true},
		{"missing-usage", strings.Replace(completeJSON, `,"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}`, "", 1), model.StopComplete, "done", false},
		{"null-usage", strings.Replace(completeJSON, `{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}`, "null", 1), model.StopComplete, "done", false},
		{"partial-usage", strings.Replace(completeJSON, `{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}`, `{"prompt_tokens":11}`, 1), model.StopComplete, "done", false},
		{"zero-usage-known", strings.Replace(completeJSON, `{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}`, `{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}`, 1), model.StopComplete, "done", true},
		{"length", strings.Replace(completeJSON, `"finish_reason":"stop"`, `"finish_reason":"length"`, 1), model.StopLength, "done", true},
		{"reasoning-content", strings.Replace(completeJSON, `"refusal":null`, `"refusal":null,"reasoning_content":"opaque continuation"`, 1), model.StopComplete, "done", true},
		{"refusal", strings.Replace(completeJSON, `"refusal":null`, `"refusal":"cannot comply"`, 1), model.StopRefusal, "cannot comply", true},
		{"filter", strings.Replace(completeJSON, `"finish_reason":"stop"`, `"finish_reason":"content_filter"`, 1), model.StopRefusal, "", true},
		{"length-tool-partial", `{"object":"chat.completion","choices":[{"index":0,"finish_reason":"length","message":{"role":"assistant","content":null,"tool_calls":[{"type":"function","id":"partial","function":{"name":"read_source","arguments":"{"}}]}}]}`, model.StopLength, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { replyJSON(w, test.body) }, nil)
			got, err := client.Complete(context.Background(), testRequest())
			if err != nil || got.Stop != test.stop || got.Message.Content != test.text || got.Usage.Known != test.known || len(got.Message.Calls) != 0 {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}

func TestUnsupportedAndMalformedResponses(t *testing.T) {
	for name, body := range map[string]string{
		"responses-api":             `{"id":"resp_test","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"done"}]}]}`,
		"stream-chunk":              `{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"done"}}]}`,
		"invalid-json":              `{invalid sensitive-provider-body}`,
		"missing-object":            strings.Replace(completeJSON, `"object":"chat.completion",`, "", 1),
		"missing-finish":            strings.Replace(completeJSON, `"finish_reason":"stop",`, "", 1),
		"missing-role":              strings.Replace(completeJSON, `"role":"assistant",`, "", 1),
		"wrong-role":                strings.Replace(completeJSON, `"role":"assistant"`, `"role":"user"`, 1),
		"unknown-finish":            strings.Replace(completeJSON, `"finish_reason":"stop"`, `"finish_reason":"other"`, 1),
		"legacy-finish":             strings.Replace(completeJSON, `"finish_reason":"stop"`, `"finish_reason":"function_call"`, 1),
		"legacy-function":           strings.Replace(completeJSON, `"refusal":null`, `"refusal":null,"function_call":{"name":"read_source","arguments":"{}"}`, 1),
		"missing-index":             strings.Replace(completeJSON, `"index":0,`, "", 1),
		"wrong-index":               strings.Replace(completeJSON, `"index":0`, `"index":1`, 1),
		"null-content":              strings.Replace(completeJSON, `"content":"done"`, `"content":null`, 1),
		"numeric-content":           strings.Replace(completeJSON, `"content":"done"`, `"content":123`, 1),
		"array-content":             strings.Replace(completeJSON, `"content":"done"`, `"content":[{"type":"text","text":"done"}]`, 1),
		"tools-with-stop":           strings.Replace(toolResponse("call-A"), `"finish_reason":"tool_calls"`, `"finish_reason":"stop"`, 1),
		"tools-empty":               `{"object":"chat.completion","choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[]}}]}`,
		"custom-tool":               strings.Replace(toolResponse("call-A"), `"type":"function"`, `"type":"custom"`, 1),
		"tool-no-type":              strings.Replace(toolResponse("call-A"), `,"type":"function"`, "", 1),
		"tool-duplicate-id":         toolResponse("same", "same"),
		"tool-empty-id":             toolResponse(""),
		"unknown-tool":              strings.Replace(toolResponse("call-A"), "read_source", "unknown_tool", 1),
		"tool-invalid-arguments":    strings.Replace(toolResponse("call-A"), `"arguments":"{\"path\":\"a.go\"}"`, `"arguments":"{"`, 1),
		"tool-array-arguments":      strings.Replace(toolResponse("call-A"), `"arguments":"{\"path\":\"a.go\"}"`, `"arguments":"[]"`, 1),
		"tool-duplicate-argument":   strings.Replace(toolResponse("call-A"), `"arguments":"{\"path\":\"a.go\"}"`, `"arguments":"{\"path\":1,\"path\":2}"`, 1),
		"negative-usage":            strings.Replace(completeJSON, `"prompt_tokens":11`, `"prompt_tokens":-11`, 1),
		"float-usage":               strings.Replace(completeJSON, `"prompt_tokens":11`, `"prompt_tokens":1.5`, 1),
		"string-usage":              strings.Replace(completeJSON, `"prompt_tokens":11`, `"prompt_tokens":"11"`, 1),
		"inconsistent-usage":        strings.Replace(completeJSON, `"total_tokens":18`, `"total_tokens":17`, 1),
		"duplicate-key":             strings.Replace(completeJSON, `"content":"done"`, `"content":"first","content":"done"`, 1),
		"trailing-json":             completeJSON + `{}`,
		"numeric-reasoning-content": strings.Replace(completeJSON, `"refusal":null`, `"refusal":null,"reasoning_content":123`, 1),
		"vendor-reasoning-details":  strings.Replace(completeJSON, `"refusal":null`, `"refusal":null,"reasoning_details":[{"encrypted":"opaque"}]`, 1),
		"vendor-reasoning":          strings.Replace(completeJSON, `"refusal":null`, `"refusal":null,"reasoning":{"content":"opaque"}`, 1),
		"audio":                     strings.Replace(completeJSON, `"refusal":null`, `"refusal":null,"audio":{"id":"audio"}`, 1),
		"annotations":               strings.Replace(completeJSON, `"refusal":null`, `"refusal":null,"annotations":[{"type":"url_citation"}]`, 1),
		"multiple-choices":          `{"object":"chat.completion","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"one"}},{"index":1,"finish_reason":"stop","message":{"role":"assistant","content":"two"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { replyJSON(w, body) }, nil)
			req := testRequest()
			req.Tools = testTools()
			_, err := client.Complete(context.Background(), req)
			assertSafeError(t, err, model.ErrProtocol)
		})
	}
}

func TestInvalidRequestsNeverLeaveProcess(t *testing.T) {
	call := model.ToolCall{ID: "call-A", Name: "read_source", Arguments: json.RawMessage(`{"path":"a.go"}`)}
	for name, mutate := range map[string]func(*model.Request){
		"empty-messages": func(r *model.Request) { r.Messages = nil },
		"zero-output":    func(r *model.Request) { r.MaxOutputTokens = 0 },
		"developer-role": func(r *model.Request) { r.Messages[0].Role = "developer" },
		"unknown-role":   func(r *model.Request) { r.Messages[0].Role = "function" },
		"unmatched-result": func(r *model.Request) {
			r.Messages = append(r.Messages, model.Message{Role: "tool", CallID: "unknown", Content: "x"})
		},
		"user-call":    func(r *model.Request) { r.Messages[1].Calls = []model.ToolCall{call} },
		"user-call-id": func(r *model.Request) { r.Messages[1].CallID = "call-A" },
		"missing-results": func(r *model.Request) {
			r.Messages = append(r.Messages, model.Message{Role: "assistant", Calls: []model.ToolCall{call}})
		},
		"duplicate-results": func(r *model.Request) {
			r.Messages = append(r.Messages, model.Message{Role: "assistant", Calls: []model.ToolCall{call}}, model.Message{Role: "tool", CallID: "call-A", Content: "one"}, model.Message{Role: "tool", CallID: "call-A", Content: "two"})
		},
		"interrupted-results": func(r *model.Request) {
			r.Messages = append(r.Messages, model.Message{Role: "assistant", Calls: []model.ToolCall{call}}, model.Message{Role: "user", Content: "interrupt"})
		},
		"duplicate-tool":       func(r *model.Request) { r.Tools = append(r.Tools, r.Tools[0]) },
		"bad-tool-name":        func(r *model.Request) { r.Tools[0].Name = "bad/name" },
		"invalid-schema":       func(r *model.Request) { r.Tools[0].Schema = json.RawMessage(`{`) },
		"array-schema":         func(r *model.Request) { r.Tools[0].Schema = json.RawMessage(`[]`) },
		"non-object-schema":    func(r *model.Request) { r.Tools[0].Schema = json.RawMessage(`{"type":"string"}`) },
		"duplicate-schema-key": func(r *model.Request) { r.Tools[0].Schema = json.RawMessage(`{"type":"object","type":"object"}`) },
		"invalid-utf8":         func(r *model.Request) { r.Messages[1].Content = string([]byte{0xff}) },
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); replyJSON(w, completeJSON) }, nil)
			req := testRequest()
			req.Tools = testTools()
			mutate(&req)
			_, err := client.Complete(context.Background(), req)
			assertSafeError(t, err, model.ErrProtocol)
			if calls.Load() != 0 {
				t.Fatal("invalid request sent")
			}
		})
	}
}

func TestResponseContentTypeAndEncoding(t *testing.T) {
	for _, test := range []struct{ contentType, encoding string }{{"text/event-stream", ""}, {"text/html", ""}, {"application/json", "gzip"}} {
		client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", test.contentType)
			if test.encoding != "" {
				w.Header().Set("Content-Encoding", test.encoding)
			}
			_, _ = w.Write([]byte(completeJSON))
		}, nil)
		_, err := client.Complete(context.Background(), testRequest())
		assertSafeError(t, err, model.ErrProtocol)
	}
}
