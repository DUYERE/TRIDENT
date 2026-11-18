package webui

import (
	"encoding/json"
	"strings"

	"trident/internal/domain"
)

// runUsage is a bounded, read-time estimate for one Run. It is derived from the
// provider usage already committed in model.completed steps; unknown usage is
// never converted into a zero cost.
type runUsage struct {
	ModelCalls    int      `json:"model_calls"`
	InputTokens   int64    `json:"input_tokens"`
	OutputTokens  int64    `json:"output_tokens"`
	Known         bool     `json:"usage_known"`
	EstimatedCost *float64 `json:"estimated_cost_usd,omitempty"`
	PricingSource string   `json:"pricing_source"`
	Currency      string   `json:"currency,omitempty"`
	Note          string   `json:"note,omitempty"`
	Truncated     bool     `json:"truncated"`
	RunTokensUsed int64    `json:"run_tokens_used"`
}

type stepModelUsage struct {
	Usage struct {
		Known        bool  `json:"known"`
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"usage"`
}

type runConfigRef struct {
	Endpoint string `json:"endpoint"`
	Model    string `json:"model"`
}

func (c *Console) runUsageOf(run domain.AgentRun, steps []domain.AgentStep) runUsage {
	usage := runUsage{PricingSource: "none", RunTokensUsed: run.TokensUsed}
	for _, step := range steps {
		if step.Kind != domain.AgentStepModelCompleted {
			continue
		}
		usage.ModelCalls++
		var payload stepModelUsage
		if err := json.Unmarshal(step.Payload, &payload); err != nil || !payload.Usage.Known {
			continue
		}
		if payload.Usage.InputTokens < 0 || payload.Usage.OutputTokens < 0 {
			continue
		}
		usage.Known = true
		usage.InputTokens += payload.Usage.InputTokens
		usage.OutputTokens += payload.Usage.OutputTokens
	}
	if len(steps) > 0 && steps[len(steps)-1].Seq < run.LastSeq {
		usage.Truncated = true
	}
	if !usage.Known {
		usage.Note = "provider 未报告可用的 token 用量；不折算为零成本"
		return usage
	}
	profile, ok := c.profileForRun(run)
	if !ok {
		usage.Note = "当前模型库中没有与该 Run 端点/模型匹配的条目，无法定价"
		return usage
	}
	if profile.Cost == nil {
		usage.Note = "该条目未声明价格；在模型库里填写输入/输出单价后可估算"
		return usage
	}
	cost := estimateCost(profile.Cost, usage.InputTokens, usage.OutputTokens)
	usage.EstimatedCost = &cost
	usage.PricingSource = "profile"
	usage.Currency = "USD"
	usage.Note = "按当前条目单价估算，不含缓存分项与阶梯价；与厂商账单可能有差异"
	if key, _ := c.profileKey(profile); key == "" {
		usage.Note += "；该条目当前没有可用密钥"
	}
	return usage
}

// estimateCost applies USD-per-million prices. Cache tokens are not part of the
// provider usage TRIDENT stores, so they cannot be charged here.
func estimateCost(cost *modelCost, inputTokens, outputTokens int64) float64 {
	total := float64(inputTokens)/1e6*cost.Input + float64(outputTokens)/1e6*cost.Output
	scale := 1e6
	return float64(int64(total*scale+0.5)) / scale
}

// profileForRun matches a Run's immutable config back to a current entry. A
// deleted or renamed entry yields no pricing rather than a guessed one.
func (c *Console) profileForRun(run domain.AgentRun) (modelProfile, bool) {
	var ref runConfigRef
	if err := json.Unmarshal(run.Config, &ref); err != nil {
		return modelProfile{}, false
	}
	endpoint := strings.TrimRight(strings.TrimSpace(ref.Endpoint), "/")
	file := c.modelsSnapshot()
	for _, profile := range file.Profiles {
		if strings.EqualFold(strings.TrimRight(profile.Endpoint, "/"), endpoint) &&
			strings.EqualFold(profile.Model, strings.TrimSpace(ref.Model)) {
			return profile, true
		}
	}
	return modelProfile{}, false
}
