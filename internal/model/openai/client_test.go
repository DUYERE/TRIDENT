package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/openai-go/v3/option"

	"trident/internal/model"
)

const completeJSON = `{"id":"test","object":"chat.completion","created":1,"model":"explicit-test-model","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"done","refusal":null}}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}`

func testRequest() model.Request {
	return model.Request{Messages: []model.Message{{Role: "system", Content: "audit instructions"}, {Role: "user", Content: "untrusted source"}}, MaxOutputTokens: 64}
}

func testTools() []model.Tool {
	return []model.Tool{{Name: "read_source", Description: "Read authorized source", Schema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}`)}}
}

func testConfig(endpoint string) Config {
	return Config{Endpoint: endpoint, Model: "explicit-test-model", APIKey: "test-explicit-key", Timeout: 2 * time.Second, OutputParameter: OutputMaxCompletionTokens, AllowLoopbackHTTP: true}
}

func testClient(t *testing.T, handler http.HandlerFunc, mutate func(*Config)) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cfg := testConfig(server.URL + "/v1")
	if mutate != nil {
		mutate(&cfg)
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client, server
}

func replyJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, body)
}

func assertSafeError(t *testing.T, err error, want error, forbidden ...string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v; want %v", err, want)
	}
	// [01] Also check wrapped errors: a sanitized outer string is insufficient.
	for e := err; e != nil; e = errors.Unwrap(e) {
		for _, secret := range append([]string{"test-explicit-key", "sensitive-provider-body", "untrusted source"}, forbidden...) {
			if secret != "" && strings.Contains(e.Error(), secret) {
				t.Fatalf("error leaked sensitive value: %v", e)
			}
		}
	}
}

func TestCompleteExplicitRequestAndAmbientIsolation(t *testing.T) {
	var ambientHits, calls atomic.Int32
	ambient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ambientHits.Add(1); w.WriteHeader(500) }))
	defer ambient.Close()
	for name, value := range map[string]string{
		"OPENAI_API_KEY": "ambient-key", "OPENAI_ADMIN_KEY": "ambient-admin", "OPENAI_BASE_URL": ambient.URL,
		"OPENAI_ORG_ID": "ambient-org", "OPENAI_PROJECT_ID": "ambient-project", "OPENAI_WEBHOOK_SECRET": "ambient-webhook",
		"OPENAI_CUSTOM_HEADERS": "Authorization: Bearer ambient-header\nOpenAI-Organization: ambient-org\nX-Ambient: secret",
		"HTTP_PROXY":            ambient.URL, "HTTPS_PROXY": ambient.URL, "ALL_PROXY": ambient.URL, "NO_PROXY": "",
		"http_proxy": ambient.URL, "https_proxy": ambient.URL, "all_proxy": ambient.URL, "no_proxy": "",
	} {
		t.Setenv(name, value)
	}
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.RequestURI() != "/v1/chat/completions" {
			t.Errorf("unexpected method/path: %s %s", r.Method, r.URL.RequestURI())
		}
		if r.Header.Get("Authorization") != "Bearer test-explicit-key" || r.Header.Get("OpenAI-Organization") != "" || r.Header.Get("OpenAI-Project") != "" || r.Header.Get("X-Ambient") != "" {
			t.Error("explicit auth/ambient isolation failed")
		}
		if r.Header.Get("Accept-Encoding") != "" || r.Header.Get("X-Stainless-Lang") != "" {
			t.Error("unexpected ambient SDK or compression header")
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if string(body["model"]) != `"explicit-test-model"` || string(body["max_completion_tokens"]) != "64" || body["max_tokens"] != nil || body["stream"] != nil {
			t.Errorf("unexpected completion profile: %s", body)
		}
		var messages []model.Message
		if err := json.Unmarshal(body["messages"], &messages); err != nil || len(messages) != 2 || messages[0].Role != "system" || messages[1].Content != "untrusted source" {
			t.Errorf("message mapping failed: %v", err)
		}
		replyJSON(w, completeJSON)
	}, nil)
	if client.transport.inner.Proxy != nil {
		t.Fatal("proxy must not be configured")
	}
	if calls.Load() != 0 {
		t.Fatal("constructor made a network request")
	}
	response, err := client.Complete(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if response.Stop != model.StopComplete || response.Message.Content != "done" || !response.Usage.Known || response.Usage.InputTokens != 11 || response.Usage.OutputTokens != 7 {
		t.Fatalf("unexpected response: %+v", response)
	}
	if calls.Load() != 1 || ambientHits.Load() != 0 {
		t.Fatalf("calls=%d ambient=%d", calls.Load(), ambientHits.Load())
	}
}

func TestLegacyOutputProfile(t *testing.T) {
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&body)
		if string(body["max_tokens"]) != "64" || body["max_completion_tokens"] != nil {
			t.Errorf("wrong profile: %s", body)
		}
		replyJSON(w, completeJSON)
	}, func(c *Config) { c.OutputParameter = OutputMaxTokens })
	if _, err := client.Complete(context.Background(), testRequest()); err != nil {
		t.Fatal(err)
	}
}

func TestToolsMultipleCallerControlledRounds(t *testing.T) {
	var calls atomic.Int32
	client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		round := calls.Add(1)
		var body struct {
			Messages []struct {
				Role       string `json:"role"`
				Content    string `json:"content"`
				ToolCallID string `json:"tool_call_id"`
				ToolCalls  []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"messages"`
			Tools []json.RawMessage `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body.Tools) != 1 || !strings.Contains(string(body.Tools[0]), `"type":"function"`) {
			t.Error("function definitions were not mapped")
		}
		switch round {
		case 1:
			replyJSON(w, toolResponse("call-A", "call-B"))
		case 2:
			if len(body.Messages) != 5 || len(body.Messages[2].ToolCalls) != 2 || body.Messages[2].ToolCalls[0].ID != "call-A" || body.Messages[2].ToolCalls[1].Function.Arguments != `{"path":"b.go"}` || body.Messages[3].ToolCallID != "call-B" || body.Messages[4].ToolCallID != "call-A" || body.Messages[3].Role != "tool" || body.Messages[3].Content != "source-B" {
				t.Error("tool call IDs/order/result roles were not preserved")
			}
			replyJSON(w, toolResponse("call-C"))
		case 3:
			if len(body.Messages) != 7 || body.Messages[5].ToolCalls[0].ID != "call-C" || body.Messages[6].ToolCallID != "call-C" {
				t.Error("second tool round was not preserved")
			}
			replyJSON(w, completeJSON)
		default:
			t.Error("adapter autonomously called provider")
		}
	}, nil)
	req := testRequest()
	req.Tools = testTools()
	first, err := client.Complete(context.Background(), req)
	if err != nil || first.Stop != model.StopTools || len(first.Message.Calls) != 2 || first.Message.Calls[1].ID != "call-B" || calls.Load() != 1 {
		t.Fatalf("first round: %+v %v", first, err)
	}
	req.Messages = append(req.Messages, first.Message, model.Message{Role: "tool", CallID: "call-B", Content: "source-B"}, model.Message{Role: "tool", CallID: "call-A", Content: "source-A"})
	second, err := client.Complete(context.Background(), req)
	if err != nil || second.Stop != model.StopTools || calls.Load() != 2 {
		t.Fatalf("second round: %+v %v", second, err)
	}
	req.Messages = append(req.Messages, second.Message, model.Message{Role: "tool", CallID: "call-C", Content: "source-C"})
	third, err := client.Complete(context.Background(), req)
	if err != nil || third.Stop != model.StopComplete || calls.Load() != 3 {
		t.Fatalf("third round: %+v %v", third, err)
	}
}

func toolResponse(ids ...string) string {
	calls := make([]map[string]any, 0, len(ids))
	for i, id := range ids {
		calls = append(calls, map[string]any{"id": id, "type": "function", "function": map[string]string{"name": "read_source", "arguments": fmt.Sprintf(`{"path":"%c.go"}`, 'a'+i)}})
	}
	raw, _ := json.Marshal(map[string]any{"object": "chat.completion", "choices": []any{map[string]any{"index": 0, "finish_reason": "tool_calls", "message": map[string]any{"role": "assistant", "content": nil, "tool_calls": calls}}}})
	return string(raw)
}

func TestRedirectsDeniedNoCredentialForwarding(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var destinationHits, originHits atomic.Int32
			destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { destinationHits.Add(1); replyJSON(w, completeJSON) }))
			defer destination.Close()
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				originHits.Add(1)
				w.Header().Set("Location", destination.URL+"/steal")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "sensitive-provider-body")
			}, nil)
			_, err := client.Complete(context.Background(), testRequest())
			assertSafeError(t, err, model.ErrDenied, destination.URL)
			if destinationHits.Load() != 0 || originHits.Load() != 1 {
				t.Fatalf("redirect followed/retried: origin=%d destination=%d", originHits.Load(), destinationHits.Load())
			}
		})
	}
}

func TestProviderErrorsNoRetryAndNoLeak(t *testing.T) {
	for _, test := range []struct {
		status int
		want   error
	}{{400, model.ErrProtocol}, {401, model.ErrDenied}, {403, model.ErrDenied}, {408, model.ErrUnavailable}, {429, model.ErrRateLimit}, {500, model.ErrUnavailable}, {503, model.ErrUnavailable}} {
		t.Run(fmt.Sprint(test.status), func(t *testing.T) {
			var calls atomic.Int32
			client, server := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Retry-After", "0")
				w.Header().Set("X-Should-Retry", "true")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, `{"error":{"message":"sensitive-provider-body test-explicit-key untrusted source"}}`)
			}, nil)
			_, err := client.Complete(context.Background(), testRequest())
			assertSafeError(t, err, test.want, server.URL)
			if calls.Load() != 1 {
				t.Fatalf("hidden retries: %d", calls.Load())
			}
		})
	}
}

func TestTimeoutAndCancellationNoRetry(t *testing.T) {
	for _, mode := range []string{"timeout", "cancel", "precanceled", "body-timeout"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			started := make(chan struct{}, 1)
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				started <- struct{}{}
				if mode == "body-timeout" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}, func(c *Config) { c.Timeout = 100 * time.Millisecond })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := error(context.DeadlineExceeded)
			if mode == "precanceled" {
				cancel()
				want = context.Canceled
			} else if mode == "cancel" {
				go func() { <-started; cancel() }()
				want = context.Canceled
			}
			_, err := client.Complete(ctx, testRequest())
			assertSafeError(t, err, want)
			expected := int32(1)
			if mode == "precanceled" {
				expected = 0
			}
			if calls.Load() != expected {
				t.Fatalf("calls=%d want=%d", calls.Load(), expected)
			}
		})
	}
}

func TestByteCapsActualBodies(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		chunked bool
	}{{"success-length", 200, false}, {"success-chunked", 200, true}, {"error-length", 429, false}, {"error-chunked", 500, true}} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if !test.chunked {
					w.Header().Set("Content-Length", "4096")
				}
				w.WriteHeader(test.status)
				if test.chunked {
					w.(http.Flusher).Flush()
				}
				_, _ = io.WriteString(w, strings.Repeat("s", 4096))
			}, func(c *Config) { c.MaxResponseBytes = 512 })
			_, err := client.Complete(context.Background(), testRequest())
			assertSafeError(t, err, model.ErrLimit)
			if calls.Load() != 1 {
				t.Fatal("oversize response retried")
			}
		})
	}
	t.Run("actual-request", func(t *testing.T) {
		var calls atomic.Int32
		client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); replyJSON(w, completeJSON) }, func(c *Config) { c.MaxRequestBytes = 512 })
		req := testRequest()
		req.Messages[1].Content = strings.Repeat("\"", 400) // JSON escaping exceeds raw input size.
		_, err := client.Complete(context.Background(), req)
		assertSafeError(t, err, model.ErrLimit)
		if calls.Load() != 0 {
			t.Fatal("oversize request left process")
		}
	})
	t.Run("exact-boundaries", func(t *testing.T) {
		client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { replyJSON(w, completeJSON) }, func(c *Config) { c.MaxResponseBytes = int64(len(completeJSON)) })
		params, err := client.parameters(testRequest())
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(params)
		client.config.MaxRequestBytes = int64(len(body))
		client.transport.maxRequest = int64(len(body))
		if _, err := client.Complete(context.Background(), testRequest()); err != nil {
			t.Fatalf("exact boundary rejected: %v", err)
		}
	})
}

func TestFinalTransportPinsAndMeasures(t *testing.T) {
	var calls atomic.Int32
	client, server := testClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); replyJSON(w, completeJSON) }, nil)
	for _, test := range []struct{ method, suffix string }{{"GET", "/v1/chat/completions"}, {"POST", "/v1/other"}, {"POST", "/v1/chat/completions?extra=1"}, {"POST", "/v1/chat/completions#fragment"}} {
		req, _ := http.NewRequest(test.method, server.URL+test.suffix, strings.NewReader(`{}`))
		_, err := client.transport.RoundTrip(req)
		assertSafeError(t, err, model.ErrDenied)
	}
	// [02] Tamper after SDK serialization: transport still checks the actual body.
	client.transport.maxRequest = 10
	req, _ := http.NewRequest("POST", server.URL+"/v1/chat/completions", strings.NewReader(strings.Repeat("x", 20)))
	req.ContentLength = 1
	_, err := client.transport.RoundTrip(req)
	assertSafeError(t, err, model.ErrLimit)
	// SDK request overrides must also fail at the final transport gate.
	client.service.Options = append(client.service.Options, option.WithBaseURL(server.URL+"/unapproved"))
	_, err = client.Complete(context.Background(), testRequest())
	assertSafeError(t, err, model.ErrDenied)
	if calls.Load() != 0 {
		t.Fatal("unapproved URL/method/body reached server")
	}
}
