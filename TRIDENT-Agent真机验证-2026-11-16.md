# TRIDENT Agent 真机验证报告（2026-11-16）

仓库：`E:\pentest agent\TRIDENT`；控制台：`http://127.0.0.1:8791`；workspace：`.trident`；快照 hash `3de9c6c480c1b753a61aacb13f0938b65c92633f98c857da573e00f9337e5873`（market，256 文件 / 3,554,368 字节）。

## 结论

- **编排闭环通过**：planner 真实模型产出意图 → worker 真实模型调用只读工具 → worker 写回带证据事实/候选 → planner 次轮判定 `goal_proved` → 任务 `completed`，goal 节点 `met`。连续两次独立任务（task 24、25）均达到该终态。
- **单 Run 通过**：真实模型调用、工具回合、usage/token 计量、预算终止均已实测。
- **本轮修复 14 项**，其中 11 项代码/流程缺陷、3 项提示词/输出格式约束；每项均按 RED→GREEN 或真机复测验证。
- **模型余额限制**：`deepseek-flash` 可用（直接请求 200）；`deepseek-v4-pro` 返回 **HTTP 402 Insufficient Balance**。本报告所有闭环证据均在 `deepseek-flash` 上取得，符合“尽量用 flash、节省资金”的要求。
- **范围限制**：通过的是“机械检索型”目标（在单个 JSP 中检索 `${` 并给出行号），用于验证编排机制；**不等于**完整漏洞审计质量或漏洞确认能力。

## 凭据与环境（不记录密钥）

| 项 | 值 |
|---|---|
| 启动命令 | `web --workspace .trident --addr 127.0.0.1:8791 --enable-agent-chat --access-log <tmp>` |
| 控制台鉴权 | `X-Trident-Request: console` + `X-Trident-Token`；令牌仅存 `%TEMP%` 与 `console.json`，不写入报告 |
| Agent 主体 | 一次性 principal `agent-verify-20261116171409`（id 4767），`credential_hash = sha256(JSON 引号包裹的 token)` |
| 模型 profile | `deepseek-flash`（endpoint `https://api.deepseek.com/v1`，model `deepseek-flash`）；`agent-verify-pro`（v4-pro，余额不足） |
| 编排参数 | `max_planner_rounds=3`、`max_intents=1`、`max_workers=1`、`max_model_calls=8`、`max_tool_calls=8`、`max_tokens=300000`、`approve_egress=true` |
| 运行时状态 | `/api/agent/runtime` → `enabled=true, ready=true, active_run=0, active_task=0, model_ready=true` |

## 真机证据

### 1. 单 Run（真实模型 + 工具）

| Run | 配置 | 结果 |
|---|---|---|
| 53 | `max_tokens=4096` | `budget_exhausted`，0 次模型调用（预留机制拒绝） |
| 54 | `max_tokens=16384` | 1 次真实模型调用（input 2536 / output 78 tokens）+ `inspect_project` + `list_files` 两个工具回合；随后预算终止 |
| 57 / 58 | flash，读 pom.xml 目标 | `completed`，2-3 次模型调用、2-3 次工具调用；payload 为直出 envelope（字段 `summary/hypotheses/limitations/goal_proved`） |

`list_files` 在 Run 54 收到模型传入的 `prefix` 参数时返回 `invalid_arguments`（工具期望 `cursor`）；模型随后换参恢复，未单独修改工具 schema。这是模型参数错误，不是工具崩溃。

### 2. 编排闭环（成功）

**Task 24** `agent-search-flash`：目标“在 `src/main/webapp/WEB-INF/jsp/addckin.jsp` 中用 `search_source` 检索字符 `${`，列出至少一处命中的行号与原文片段作为证据”。

| 阶段 | Run | 状态 | 模型调用 | 工具调用 | tokens |
|---|---|---|---|---|---|
| planner r1 | 109 | completed | 1 | 0 | 3,836 |
| worker #55 | 110 | completed | 2 | 1 | 10,505 |
| planner r2 | 111 | completed | 1 | 0 | 7,002 |

图结果：`goal #54 = met`、`intent #55 = done`、`fact #56/#57 = done`、`finding_candidate #58 = open`；边 `54→55 spawns/derived_from`，`55→56/57/58 yields`。任务 `state=completed, reason=全部目标已判定达成`。

**Task 25** `agent-search-flash-repeat`：同一目标独立重跑。

| 阶段 | Run | 状态 | 模型调用 | 工具调用 | tokens |
|---|---|---|---|---|---|
| planner r1 | 112 | completed | 1 | 0 | 3,754 |
| worker #60 | 113 | completed | 3 | 2 | 19,563 |
| planner r2 | 114 | completed | 1 | 0 | 7,882 |

图结果：`goal #59 = met`、`intent #60 = done`、`fact #61–65 = done`、`finding_candidate #66 = open`；任务 `completed`，同样理由。**两次独立运行 2/2 成功。**

### 3. 失败到成功的关键节点（修复有效性证据）

| Task | 现象 | 根因 | 修复后 |
|---|---|---|---|
| 3 | 任务永久 `running`、nodes 为空 | `Start(r.Context())` 在 202 后取消请求 ctx，drive 首次读库失败静默返回 | 改用 `context.WithCancel(context.WithoutCancel(parent))`；run 109 起正常推进 |
| 4 | `failed`，SQLSTATE 22P02 | 节点空 `json.RawMessage` 直接写 jsonb | `normalizeNodePayload` 空/空白 → `{}` |
| 5 | `completed rounds=0 intents=0` | 小预算下 `IntentsSpawned+4 > MaxIntents` 首轮误判耗尽 | 改 `>=` 并在落图时按剩余预算截断 |
| 6/7 | run `completed` 但 engine 报“未产出终局 JSON” | `readFinal` 要求 `{"result":...}` 包装，实际 `run.completed` payload 是 envelope 本体 | `finalEnvelopeFromStep` 同时接受直出与 `result` 包装 |
| 8/9 | planner 3 轮 0 意图、预算耗尽/unknown | 通用 system prompt + 全套只读工具，planner 被驱使反复取证据 | planner 目标文本禁止调用工具；run 109/111 实测 **1 次模型调用、0 次工具**即产出 JSON |
| 10 | 首次产出 2 条意图 | 意图预算守卫修复生效 | planner→intent→worker 链路开始真实推进 |
| 11/14–23 | worker 反复 `budget_exhausted`/`unknown`，无 facts | 多种：输出 4096 tokens 被截断、worker 状态映射错误、hypotheses 未落图、意图预算提前终止 | 见修复清单；task 24/25 最终闭环 |
| 12 | 连续两次 `unknown`、0 tokens | `deepseek-v4-pro` 余额耗尽（HTTP 402） | 改用 `deepseek-flash`（直接请求 200） |
| 18 | worker 写回 3 facts + 1 candidate，planner 次轮仍失败 | planner 无工具、却引用图中证据，`validateFinal` 按“本轮观测”拒绝 | planner 会话允许引用图上已固定证据（`AllowUnobservedHypotheses`） |
| 19 | planner 次轮 JSON 多一个 `}` | 提示词示例把 `limitations` 放在 `intents` 前，模型提前闭合对象 | 示例改为 `limitations` 最后；任务 24/25 的 planner JSON 合法 |
| 22 | worker 写回 4 facts + candidate，任务却在 r1 结束 | 意图预算耗尽且无 open 意图时提前 break，未给 planner 证明轮 | 仅当图中**无**证据记录时才提前结束；有证据则继续证明轮 |
| 23 | worker 8 调用/10 工具后 `unknown`，无 facts | 模型自身未在预算内收尾（非代码缺陷） | 收窄为机械检索目标后 task 24/25 稳定完成 |

## 修复清单（14 项）

| # | 类型 | 症状 | 根因 | 修复 | 测试/证据 |
|---|---|---|---|---|---|
| 1 | 代码 | 202 后任务永久 running | 请求 ctx 取消传导到 drive | `context.WithCancel(context.WithoutCancel(parent))` | `TestStartDetachesFromRequestCancellation` |
| 2 | 代码 | 写节点 SQLSTATE 22P02 | 空 payload 写 jsonb | `normalizeNodePayload` → `{}` | `TestOrchestrationNodePayloadDefaultsToEmptyObject` |
| 3 | 代码 | 小意图预算首轮误判耗尽 | `+4` 预算守卫 | `>=` + 落图按剩余预算截断 | `TestDrivePlansWithSmallIntentBudget`、`TestDriveCapsPlannerIntentsAtTaskBudget` |
| 4 | 提示词 | planner JSON 示例含 `//` 注释，非法 JSON | 示例把说明写成注释 | 去注释，纪律移入文本 | `TestPlannerGoalJSONExampleIsValid` |
| 5 | 代码 | completed 但读不到 envelope | `readFinal` 只认 `{"result":...}` | `finalEnvelopeFromStep` 兼容直出/包装 | `TestFinalEnvelopeFromCompletedStep` |
| 6 | 提示词 | planner 反复调工具、不交 JSON | 通用 system prompt 驱使取证据 | planner 明确“禁止调用工具、hypotheses 可空” | run 109/111：1 call / 0 tool |
| 7 | 代码 | worker `unknown` 记为 done | 状态 switch 只处理 budget/failed/cancelled | `workerNodeState`：unknown→blocked | `TestWorkerNodeStateMapsUnknownToBlocked` |
| 8 | 代码 | worker `paused` 记为 done | 同上，paused 落入 default→done | paused→blocked | 同上测试补 `paused` 用例 |
| 9 | 代码 | worker 终局 JSON 被截断，run paused | 会话 `MaxOutputTokens=4096` | 提升到 8192（仍低于 Config 上限 16384） | task 24/25 worker completed |
| 10 | 代码 | planner `parent_ids:["13"]` 被整轮拒绝 | `ParentIDs []int64` 只接受数字 | `NodeRef` 接受数字、带引号、`goal-` 前缀 | `TestValidateFinalAcceptsQuotedParentID` |
| 11 | 代码 | planner 引用图中证据被拒 | 无工具会话无法产生“本轮观测” | 仅 planner 会话 `AllowUnobservedHypotheses` | `TestValidateFinalPlannerAcceptsGraphEvidence` |
| 12 | 代码 | worker hypotheses 不落图，goal 永远无证据 | 只处理 facts/candidates | hypotheses 带证据时写成 inferred fact | `TestDriveWritesHypothesesAsEvidenceFacts` |
| 13 | 代码 | 意图预算用尽后提前结束，proof 轮被跳过 | stop 条件只看 intents/open | 有证据记录时继续运行证明轮 | `TestDriveProofRoundRunsAfterIntentBudget` |
| 14 | 提示词 | planner 在 `limitations` 后多写一个 `}` | 示例字段顺序诱导提前闭合 | `limitations` 放最后并显式禁止提前闭合 | task 24/25 planner JSON 合法；失败样本 run 97 已定位 |

## 门禁（新鲜输出）

```
go build ./...   exit 0
go vet ./...     exit 0
go test -count=1 ./...  25 包 ok；internal/model 无测试文件；TEST_EXIT=0
```

`internal/agent`、`internal/orchestrator`、`internal/store` 均包含新增回归测试；`gofmt` 已执行。

## 模型余额与费用

- `deepseek-flash` 直接最小请求：`HTTP 200`，可正常返回。
- `deepseek-v4-pro` 直接最小请求：`HTTP 402`，`{"error":{"message":"Insufficient Balance ...","type":"insufficient_balance_error"}}`。
- `default` profile probe：`key_missing`（未配置独立密钥）。
- 成功任务 token 用量（flash）：task 24 `3,836 + 10,505 + 7,002 = 21,343`；task 25 `3,754 + 19,563 + 7,882 = 31,199`。失败重试的 token 用量未逐条折算金额，账单以 DeepSeek 控制台为准。

## 未覆盖 / 限制

- 只验证了“机械检索型”目标；未验证复杂审计目标（跨文件污点追踪、候选可信度、报告质量）。
- worker 仍可能在中途耗尽预算或 `unknown`（run 103/104/108 等）；这是模型收尾行为，不是引擎状态错误。窄目标可稳定完成，宽目标不保证。
- `list_files` 对模型传入的 `prefix` 返回 `invalid_arguments`，未改工具 schema；模型可自行改用 `cursor`。
- 未验证真实 docker/gVisor 执行（与本阶段无关，沿用历史结论）。
- `deepseek-v4-pro` 因余额不可用；`agent-verify-pro` profile 与复制出的 key 仍留在模型库，需清理或充值后复用。

## 当前运行状态与清理

- 控制台**仍在运行**（pid 见 `%TEMP%\trident-console.pid`；token 见 `%TEMP%\trident-console-token.txt`；stdout/stderr 见 `%TEMP%\trident-agent.out/.err`）。
- 测试数据保留以供复查：`orchestration_tasks` id 3–25 及 nodes/edges、`agent_runs` id 53–114 及 steps、principal 4767、profile `agent-verify-pro`。
- `console.json` 当前含 `agent_token` 与 `agent_chat_enabled`；停止控制台后应恢复为不含凭据的原始结构。
- 建议清理顺序：停控制台 → 备份/恢复 `console.json` → 删除 `orchestration_nodes`/`orchestration_edges` 再删 `orchestration_tasks` → 删除 `agent_runs`（先确认 steps 外键）→ 删除 principal 4767 → 从 `models.json`/`model_keys.json` 移除 `agent-verify-pro`。
