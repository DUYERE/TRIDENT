package webui

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// The channel catalog is a compile-time offline snapshot, never fetched at
// runtime. Prices are public list prices captured for this build; the console
// labels them as a snapshot and the user can override any entry. Capabilities
// are declarative and not probe-verified.
type modelPreset struct {
	ModelID      string            `json:"model_id"`
	Name         string            `json:"name"`
	API          string            `json:"api"`
	Capabilities modelCapabilities `json:"capabilities"`
	Cost         *modelCost        `json:"cost"`
}

type channelSpec struct {
	Provider string   `json:"provider"`
	Name     string   `json:"name"`
	API      string   `json:"api"`
	BaseURL  string   `json:"base_url"`
	BaseURLs []string `json:"base_urls"`
	Featured bool     `json:"featured"`
	Models   []modelPreset
}

type channelView struct {
	Provider   string   `json:"provider"`
	Name       string   `json:"name"`
	API        string   `json:"api"`
	BaseURL    string   `json:"base_url"`
	BaseURLs   []string `json:"base_urls"`
	ModelCount int      `json:"model_count"`
	Featured   bool     `json:"featured"`
}

func preset(modelID, name, api string, contextWindow, maxOutput int64, reasoning, vision bool, input, output, cacheRead, cacheWrite float64) modelPreset {
	return modelPreset{
		ModelID: modelID, Name: name, API: api,
		Capabilities: modelCapabilities{ContextWindow: contextWindow, MaxOutput: maxOutput, Reasoning: reasoning, Vision: vision},
		Cost:         &modelCost{Input: input, Output: output, CacheRead: cacheRead, CacheWrite: cacheWrite},
	}
}

// builtinChannels is deliberately small and explicit. It exists to remove
// Base-URL/protocol typos for common providers, not to mirror every vendor.
func builtinChannels() []channelSpec {
	return []channelSpec{
		{
			Provider: "deepseek", Name: "DeepSeek", API: apiOpenAICompletions,
			BaseURL: "https://api.deepseek.com/v1", BaseURLs: []string{"https://api.deepseek.com/v1"}, Featured: true,
			Models: []modelPreset{
				preset("deepseek-chat", "DeepSeek Chat", apiOpenAICompletions, 131072, 65536, false, false, 0.28, 0.42, 0.028, 0),
				preset("deepseek-reasoner", "DeepSeek Reasoner", apiOpenAICompletions, 131072, 65536, true, false, 0.28, 0.42, 0.028, 0),
			},
		},
		{
			Provider: "openai", Name: "OpenAI", API: apiOpenAICompletions,
			BaseURL: "https://api.openai.com/v1", BaseURLs: []string{"https://api.openai.com/v1"}, Featured: true,
			Models: []modelPreset{
				preset("gpt-4.1", "GPT-4.1", apiOpenAICompletions, 1047576, 32768, false, true, 2, 8, 0.5, 0),
				preset("o4-mini", "o4-mini", apiOpenAICompletions, 200000, 100000, true, true, 1.1, 4.4, 0.275, 0),
			},
		},
		{
			Provider: "moonshotai", Name: "Moonshot AI", API: apiOpenAICompletions,
			BaseURL: "https://api.moonshot.ai/v1", BaseURLs: []string{"https://api.moonshot.ai/v1", "https://api.moonshot.cn/v1"}, Featured: true,
			Models: []modelPreset{
				preset("kimi-k2-0905-preview", "Kimi K2", apiOpenAICompletions, 262144, 32768, false, false, 0.6, 2.5, 0.15, 0),
				preset("moonshot-v1-128k", "Moonshot v1 128k", apiOpenAICompletions, 131072, 8192, false, false, 0.84, 0.84, 0, 0),
			},
		},
		{
			Provider: "zai", Name: "Z.AI", API: apiOpenAICompletions,
			BaseURL: "https://api.z.ai/api/coding/paas/v4", BaseURLs: []string{"https://api.z.ai/api/coding/paas/v4"}, Featured: true,
			Models: []modelPreset{
				preset("glm-4.6", "GLM-4.6", apiOpenAICompletions, 204800, 131072, true, false, 0.6, 2.2, 0.11, 0),
				preset("glm-4.5-air", "GLM-4.5 Air", apiOpenAICompletions, 131072, 98304, true, false, 0.2, 1.1, 0.03, 0),
			},
		},
		{
			Provider: "xai", Name: "xAI", API: apiOpenAICompletions,
			BaseURL: "https://api.x.ai/v1", BaseURLs: []string{"https://api.x.ai/v1"}, Featured: true,
			Models: []modelPreset{
				preset("grok-4", "Grok 4", apiOpenAICompletions, 256000, 32768, true, true, 3, 15, 0.75, 0),
				preset("grok-3-mini", "Grok 3 Mini", apiOpenAICompletions, 131072, 32768, true, false, 0.3, 0.5, 0.075, 0),
			},
		},
		{
			Provider: "qwen", Name: "Qwen (DashScope 兼容)", API: apiOpenAICompletions,
			BaseURL: "https://dashscope.aliyuncs.com/compatible-mode/v1",
			BaseURLs: []string{
				"https://dashscope.aliyuncs.com/compatible-mode/v1",
				"https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
			}, Featured: true,
			Models: []modelPreset{
				preset("qwen3-coder-plus", "Qwen3 Coder Plus", apiOpenAICompletions, 1048576, 65536, false, false, 4, 16, 0.4, 0),
				preset("qwen-max", "Qwen Max", apiOpenAICompletions, 32768, 8192, false, false, 1.6, 6.4, 0.16, 0),
			},
		},
		{
			Provider: "local", Name: "本地 / 自建（OpenAI 兼容）", API: apiOpenAICompletions,
			BaseURL: "http://127.0.0.1:11434/v1", BaseURLs: []string{"http://127.0.0.1:11434/v1"}, Featured: false,
			Models: []modelPreset{},
		},
	}
}
func channelViews(query string) []channelView {
	needle := strings.ToLower(strings.TrimSpace(query))
	views := make([]channelView, 0, 12)
	for _, channel := range builtinChannels() {
		if needle != "" && !channelMatches(channel, needle) {
			continue
		}
		views = append(views, channelView{
			Provider: channel.Provider, Name: channel.Name, API: channel.API,
			BaseURL: channel.BaseURL, BaseURLs: channel.BaseURLs,
			ModelCount: len(channel.Models), Featured: channel.Featured,
		})
	}
	sort.SliceStable(views, func(i, j int) bool {
		if views[i].Featured != views[j].Featured {
			return views[i].Featured
		}
		if views[i].Name != views[j].Name {
			return views[i].Name < views[j].Name
		}
		return views[i].Provider < views[j].Provider
	})
	return views
}

func channelMatches(channel channelSpec, needle string) bool {
	fields := []string{channel.Provider, channel.Name, channel.API, channel.BaseURL}
	fields = append(fields, channel.BaseURLs...)
	for _, model := range channel.Models {
		fields = append(fields, model.ModelID, model.Name)
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), needle) {
			return true
		}
	}
	return false
}

func channelByProvider(provider string) (channelSpec, bool) {
	for _, channel := range builtinChannels() {
		if channel.Provider == provider {
			return channel, true
		}
	}
	return channelSpec{}, false
}

type presetView struct {
	Provider     string            `json:"provider"`
	ProviderName string            `json:"provider_name"`
	ModelID      string            `json:"model_id"`
	Name         string            `json:"name"`
	API          string            `json:"api"`
	BaseURL      string            `json:"base_url"`
	Capabilities modelCapabilities `json:"capabilities"`
	Cost         *modelCost        `json:"cost"`
}

func presetViews(channel channelSpec) []presetView {
	views := make([]presetView, 0, len(channel.Models))
	for _, model := range channel.Models {
		views = append(views, presetView{
			Provider: channel.Provider, ProviderName: channel.Name,
			ModelID: model.ModelID, Name: model.Name, API: model.API,
			BaseURL: channel.BaseURL, Capabilities: model.Capabilities, Cost: model.Cost,
		})
	}
	return views
}

func (c *Console) handleModelChannels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion,
		"source":         "builtin-snapshot",
		"channels":       channelViews(r.URL.Query().Get("q")),
	})
}

func (c *Console) handleModelChannelModels(w http.ResponseWriter, r *http.Request) {
	channel, ok := channelByProvider(r.PathValue("provider"))
	if !ok {
		writeError(w, http.StatusNotFound, "channel_unknown", "内置目录中没有该渠道")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion,
		"source":         "builtin-snapshot",
		"provider":       channel.Provider,
		"name":           channel.Name,
		"api":            channel.API,
		"base_url":       channel.BaseURL,
		"base_urls":      channel.BaseURLs,
		"models":         presetViews(channel),
	})
}

// handleModelCatalogLookup fills capabilities and price by model ID. It never
// touches the endpoint: the caller keeps whatever Base URL it typed.
func (c *Console) handleModelCatalogLookup(w http.ResponseWriter, r *http.Request) {
	modelID := strings.TrimSpace(r.URL.Query().Get("model_id"))
	if modelID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "先填写模型 ID，再查内置目录")
		return
	}
	baseURL := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("base_url")))
	matches := []presetView{}
	for _, channel := range builtinChannels() {
		for _, model := range channel.Models {
			if !strings.EqualFold(model.ModelID, modelID) {
				continue
			}
			matches = append(matches, presetView{
				Provider: channel.Provider, ProviderName: channel.Name,
				ModelID: model.ModelID, Name: model.Name, API: model.API,
				BaseURL: channel.BaseURL, Capabilities: model.Capabilities, Cost: model.Cost,
			})
		}
	}
	if baseURL != "" {
		sort.SliceStable(matches, func(i, j int) bool {
			return baseURLAffinity(matches[i], baseURL) > baseURLAffinity(matches[j], baseURL)
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": SchemaVersion,
		"source":         "builtin-snapshot",
		"query":          map[string]string{"model_id": modelID, "base_url": baseURL},
		"matches":        matches,
	})
}

func baseURLAffinity(view presetView, baseURL string) int {
	if baseURL == "" {
		return 0
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return 0
	}
	if strings.Contains(strings.ToLower(view.BaseURL), parsed.Host) {
		return 2
	}
	return 0
}
