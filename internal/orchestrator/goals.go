package orchestrator

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"trident/internal/domain"
)

// Goal construction for planner and worker sessions. The system prompt of an
// agent run is code-fixed and shared, so the role, discipline and output format
// ride in the goal text exactly like the reference implementation puts role
// dynamics in the user turn. Nothing here can widen the tool surface.

const plannerGoalHeader = `你是 TRIDENT 静态审计编排中的规划者。你本轮的唯一职责：读下面的态势 → 判定目标 → 只在确有未覆盖的新方向时产出审计意图。你不执行审计：本轮所有产物只能是终局 JSON 里的 intents / goal_proved。

规划纪律（必须遵守）：
- 硬底线：只要目标未全部判定达成、且当前没有任何 open 或 running 意图，本轮就【必须】产出至少一条向目标推进的意图；产出 0 条等于任务停摆。
- 0 条意图是正常结果，但必须有正当理由：①已有 open/running 意图覆盖了你想到的方向（换措辞重复是严重错误）；②下一步依赖在跑意图的产出。
- done/exhausted/blocked 的历史意图不重复原样派发；只有出现材料性新证据才重派，summary 写清与上次的差异。
- 串行链不要一次并行铺开：本轮只派前置已满足的那一步。
- 深度优先于覆盖度：发现高价值线索（未鉴权入口、参数直达危险 sink）优先派"往深走到底"的意图，不为拉平覆盖度铺广。
- 量化验收：goal_proved 之前必须核对下方态势的实测数据，禁止以"大体达成"提前盖章。
- 本轮禁止调用任何工具：态势已预取在下方，工具调用只会消耗预算并导致本轮无法产出终局 JSON。hypotheses 允许为空数组，不要为凑证据调用工具。
- 只输出已证实可达的方向；约束块是最高优先级，违反约束的方向绝不生成。
- 每轮 intents 最多 4 条；超出任务总预算的部分由引擎截断。

终局 JSON 格式（必须严格遵守，整条消息就是一个 JSON 对象，不要 Markdown，对象之外不得有任何字符；limitations 必须是最后一个字段，不要在它前面提前闭合对象）：
{"summary":"本轮判定的一句话总结","hypotheses":[],
 "intents":[{"summary":"一句话审计方向（对象+查什么+为什么可疑）","parent_ids":[],"asset_refs":[]}],
 "goal_proved":["goal-<id>"],"limitations":["..."]}`

const workerGoalHeader = `你是 TRIDENT 静态审计编排中的执行者。你领到【一条审计意图】，唯一职责：用只读工具完成这一条意图，把观察与候选发现写进终局 JSON，然后结束。不要自行开展意图之外的方向——值得深挖的线索写进 facts 交规划者。

写回纪律：
- facts：多个观察汇总成一条（summary 一句话 + evidence 源码证据），confidence=observed（直接读到）或 inferred（据代码推断）。只写本轮真实读到的：evidence 里的每条引用必须是本轮工具结果真实返回过的行，凭记忆编造会被整条拒绝。
- candidates：疑似问题（title + severity + evidence + note）。它们是【候选】不是确认漏洞；证据不足的嫌疑写 inferred fact，不要硬凑 candidate。
- 引擎发现（list_findings / trace_dataflow）与你的观察是两类：引用引擎发现时注明是静态证据；你的 candidates 只写你自己读码得出的判断。

终局 JSON 格式（必须严格遵守，整条消息就是一个 JSON 对象，不要 Markdown；limitations 必须是最后一个字段，不要在它前面提前闭合对象）：
{"summary":"一句话总结你审了什么、得到什么","hypotheses":[],
 "facts":[{"summary":"...","confidence":"observed|inferred","evidence":[{"snapshot_hash":"...","path":"...","sha256":"...","start_line":1,"end_line":1}]}],
 "candidates":[{"title":"...","severity":"high|medium|low","note":"...","evidence":[...]}],
 "limitations":["..."]}`

func constraintBlock(constraints []domain.OrchestrationConstraint) string {
	if len(constraints) == 0 {
		return ""
	}
	var allow, deny []string
	for _, c := range constraints {
		switch c.Kind {
		case "allow":
			allow = append(allow, "- "+c.Text)
		case "deny":
			deny = append(deny, "- "+c.Text)
		}
	}
	var b strings.Builder
	b.WriteString("\n\n【操作约束（最高优先级，凌驾于一切探索启发式；违反即不得进行）】：")
	if len(allow) > 0 {
		b.WriteString("\n允许的操作：\n" + strings.Join(allow, "\n"))
	}
	if len(deny) > 0 {
		b.WriteString("\n禁止的操作：\n" + strings.Join(deny, "\n"))
	}
	return b.String()
}

// renderGraphOverview folds the exploration graph into the goal text. It is the
// same data the detail API returns; nothing is invented here.
func renderGraphOverview(task domain.OrchestrationTask, nodes []domain.OrchestrationNode, edges []domain.OrchestrationEdge) string {
	view := map[string]any{
		"task":  map[string]any{"id": task.ID, "title": task.Title, "goal": task.Goal, "planner_rounds": task.PlannerRounds, "intents_spawned": task.IntentsSpawned, "max_intents": task.MaxIntents},
		"nodes": nodes,
		"edges": edges,
	}
	raw, err := json.Marshal(view)
	if err != nil {
		return ""
	}
	return "\n\n【当前探索图（完整态势，等同工具返回；按需引用节点 id）】：\n" + string(raw)
}

func buildPlannerGoal(task domain.OrchestrationTask, trigger string, nodes []domain.OrchestrationNode, edges []domain.OrchestrationEdge, constraints []domain.OrchestrationConstraint) string {
	var b strings.Builder
	b.WriteString(plannerGoalHeader)
	b.WriteString("\n\n任务目标：")
	b.WriteString(task.Goal)
	b.WriteString("\n\n【本轮触发的实际变动（先看这里，再决定是否补方向）】：")
	if strings.TrimSpace(trigger) == "" {
		b.WriteString("\n- 任务刚创建，这是第一轮规划：请根据目标与快照已知信息产出第一批意图。")
	} else {
		b.WriteString("\n- " + trigger)
	}
	b.WriteString(renderGraphOverview(task, nodes, edges))
	b.WriteString(constraintBlock(constraints))
	b.WriteString("\n\n立即输出终局 JSON。")
	return b.String()
}

func buildWorkerGoal(task domain.OrchestrationTask, intent domain.OrchestrationNode, nodes []domain.OrchestrationNode, edges []domain.OrchestrationEdge, constraints []domain.OrchestrationConstraint) string {
	var b strings.Builder
	b.WriteString(workerGoalHeader)
	b.WriteString("\n\n【你领到的意图（本次唯一任务：只做这一条，做完即停）】：\n")
	b.WriteString(intent.Summary)
	b.WriteString(fmt.Sprintf("\n意图节点 id：%d", intent.ID))
	if payload := intentAssetRefs(intent); len(payload) > 0 {
		b.WriteString("\n意图关联的引擎发现/资产引用：" + strings.Join(payload, "、"))
	}
	b.WriteString(renderGraphOverview(task, nodes, edges))
	b.WriteString(constraintBlock(constraints))
	b.WriteString("\n\n开始执行：只做这条意图，用只读工具查证，立即输出终局 JSON。")
	return b.String()
}

func intentAssetRefs(intent domain.OrchestrationNode) []string {
	var payload struct {
		AssetRefs []string `json:"asset_refs"`
	}
	if err := json.Unmarshal(intent.Payload, &payload); err != nil {
		return nil
	}
	sort.Strings(payload.AssetRefs)
	return payload.AssetRefs
}

func envValue(name string) string { return os.Getenv(name) }
