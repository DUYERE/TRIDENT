# 多 Agent 编排契约（orchestration）

- 日期：2026-11-15
- 状态：契约先行；实现随本切片落地。参考 CodeScan-Artex（SCA Audit）的三角色编排，按 TRIDENT 治理模型重构。
- 入口：`internal/orchestrator/`、`db/migrations/005_agent_orchestration.sql`、`POST /api/agent/orchestration*`、`#/tasks`。

## 1. 定位与边界

编排任务（orchestration task）是对当前快照的**多轮自主静态审计**：一个 Planner 反复唤醒并派发审计意图，多个 Worker 并发领意图用只读工具读码，结论写回一张可回溯的**探索图**。它与单 Run 对话（`/api/agent/chat`）并存：单 Run 是一次性问答式审阅；编排任务是目标驱动的多意图自主推进。

继承的硬边界（不放宽任何一条）：
- Agent 全部会话仍是 `agent_runs` 治理模型下的 Run：CAS 事务、`max_model_calls≤64`/`max_tool_calls≤256` 硬限、检查点 48 KiB 上限已于 2026-11-16 删除（默认不限，保留整体存储字节预算）、每次模型调度前重认证、`approve_egress` 语义不变。
- 工具面**零新增写工具**：Worker/Planner 只用既有 10 个只读快照/分析工具。不执行代码、不出网、无 Bash。
- 图写回权在**引擎**（服务端），不在 LLM：LLM 在终局 JSON 中声明结论与证据，引擎校验引用覆盖后才落图。静态三态语义不变：Agent 产出的一律是 `finding_candidate`（候选），不升级 `static_confirmed`；引擎发现仍是权威。`runtime_status` 恒 `not_run`。

## 2. 三角色

| 角色 | 实现形态 | 职责 |
|---|---|---|
| MainAgent | 控制台 `#/agent` 对话 + `POST /api/agent/orchestration/steer` | 观察（图总览）与操舵：加提示（hint）、直接注入高优意图、增删目标、登记 allow/deny 约束、停止任务。无独立 LLM 会话。 |
| Planner | 每个 planning 轮 = 一个 `agent_runs` 会话（goal 承载角色指令） | 唯一意图生成者。读预取态势（触发事件 + 图总览拼进 goal）→ 用 `goal_proved` 判目标 → 在终局 JSON 的 `intents[]` 产出 0..N 条新意图。产出 0 条是正常结果但须有正当理由；目标未达成且无 open/running 意图时必须派意图（防停摆）。 |
| Worker ×N | 每个意图 = 一个 `agent_runs` 会话（并发 ≤ 配置上限） | 领一条意图，用只读工具完成它，终局 JSON 写回 `facts[]`（observed/inferred）与 `candidates[]`（候选发现，必须带源码证据）。做完即停，不自行开新方向（线索写进 fact 交 Planner）。 |

## 3. 探索图（PostgreSQL，`agent_dsn` 同库）

```
orchestration_tasks     任务：title/goal/state/config/deadline
orchestration_nodes     节点：kind ∈ goal|intent|fact|finding_candidate|digest
                        intent.state ∈ open|running|done|exhausted|blocked|cancelled
                        fact.confidence ∈ observed|inferred
orchestration_edges     边：rel ∈ spawns|derived_from|yields（from=上游，to=下游）
orchestration_constraints 任务级操作约束：kind ∈ allow|deny
```

- 节点与边只增不改语义；intent 状态可由引擎推进（running→done/exhausted/blocked）。删除仅限显式停止任务后的级联。
- Planner/Worker 的态势不是工具调用，而是引擎预取后拼进 Run 的 goal 文本（图总览 + 触发事件），system prompt 保持既有唯一版本，checkpoint 校验不变。
- 引入 digest 的前提是图节点数超阈值（默认 >120）；否则全量态势进 goal。

## 4. 终局 JSON 扩展（FinalEnvelope v3，向后兼容）

`FinalEnvelope` 新增可选字段（既有单 Run 不带这些字段，行为与字节语义不变）：

```json
{
  "summary": "...",
  "hypotheses": [...],
  "limitations": [...],
  "intents": [{"summary":"...", "parent_ids":[1,2], "asset_refs":["/api/x"]}],
  "goal_proved": ["goal-1"],
  "facts": [{"summary":"...", "confidence":"observed", "evidence":[EvidenceRef]}],
  "candidates": [{"title":"...", "severity":"high", "evidence":[EvidenceRef], "note":"..."}]
}
```

- 证据引用走既有的 `observed evidence` 覆盖校验：facts/candidates 的每条引用必须真实读过，否则 Run 失败——与单 Run 的假设引用同一门槛。
- Planner 的 `intents` 每轮 ≤4 条；`goal_proved` 只能引用任务已登记目标，且引用必须是本次图中的 `goal-<节点id>`（`^goal-[1-9][0-9]{0,17}$`）。该任务还须至少有一个带非空 `evidence` 的 fact/finding_candidate 节点；不满足的声明被拒绝、不写节点状态，拒绝理由进入下一轮 trigger。
- Worker 的 `facts` 默认一条汇总；`candidates` 是候选不是确认漏洞，图上标注来源为 Agent 推断。

## 5. 引擎调度

- 事件：planner_done / worker_done / steer（hint/intent/goal/constraint）/ stop / deadline。事件驱动，无固定心跳（当前版本无空闲唤醒；planner 判定无新意图且无在跑 worker 时任务进入 `completed` 或按目标判定继续）。
- 并发：worker 上限默认 2（配置 1..4）；planner 轮串行。同一编排任务运行期间，控制台手动 Run（`chatActive`）互斥。跨进程互斥由数据库强制：`orchestration_tasks_one_running`（`db/migrations/006_orchestration_single_running.sql`）保证同一主体最多一个 `running` 任务；`Start` 在派发 goroutine 前同步抢占 `created→running`，第二个实例得到 409 `orchestration_busy` 而不是并行驱动。
- 任务级预算：`max_planner_rounds`（默认 6）、`max_intents`（默认 12）、`deadline`（默认 30 分钟）；会话级预算来自所选模型配置档案，单会话仍受 agent_runs 硬限。
- 意图状态推进：派发→running；完成→done；Run budget_exhausted→exhausted（Planner 可派接续）；Run failed→blocked；人停→cancelled。
- 结束条件：全部目标 met；**连续两轮**规划判空且无 open/running 意图（单轮判空不结束，给人工操舵留窗口）；或到达 planner 轮上限/意图上限/deadline 后无 running worker → `completed`（如实标注部分完成原因）；`stop` → `cancelled`。引擎每轮重读任务持久化计数器，意图预算终止依据是数据库值而非内存副本。

## 6. Settlement（预算内提前收尾）

`agent.Config` 新增 `SettlementEnabled`。当剩余模型调用恰好 1 次且尚未收尾时，loop 在预算内注入一条固定收尾 user 消息（哨兵 `[SETTLEMENT]` 防重复），要求模型不再调工具、立即按终局 JSON 写回已获得的结论。收尾轮不消耗额外预算、不改 store 语义；resume 后按哨兵文本识别已收尾。手动单 Run 默认关闭，编排会话默认开启。

## 7. API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/agent/orchestration` | 创建并启动任务（title/goal/profile/并发/轮数/意图上限/deadline，`approve_egress` 必选） |
| GET | `/api/agent/orchestration` | 任务列表（含状态/计数） |
| GET | `/api/agent/orchestration/detail?id=` | 图全量：任务 + 节点 + 边 + 约束 |
| POST | `/api/agent/orchestration/steer` | `kind=hint\|intent\|goal\|constraint`，写图并触发 Planner；仅接受 `created`/`running` 任务，终态任务返回 409 `orchestration_steer_rejected` |
| POST | `/api/agent/orchestration/stop` | 停止任务（在跑 worker 保留已提交步骤） |

错误码沿用控制台惯例：`agent_chat_busy`（编排与手动 Run 互斥）、`orchestration_busy`（数据库级单任务约束拒绝了启动）、`orchestration_steer_rejected`（终态任务不再接受操舵）、`orchestration_disabled`（写库会话未初始化）、`egress_not_approved`、`orchestration_budget_invalid`。

## 8. 限制与非目标

- 无空闲心跳唤醒（当前引擎事件全内联：planner 判空连续两轮才结束，已覆盖停摆语义；真实心跳唤醒需要后台定时器与外部事件源，属后续切片）、无 steer_work 运行中纠偏、无独立复核会话（候选发现的确认留给人 + 引擎三态）。
- 无资产图（引擎的 endpoints/findings 已是权威资产视图）；Worker 的 `asset_refs` 只是意图与引擎发现之间的软关联。
- 无冷节点压缩（节点数阈值默认不触达）；无跨任务图共享。
- LLM 输出的结构化字段由模型生成，引擎解析失败不阻塞任务：无效 intents/记录按无效处理并计入 limitation，不重试模型。
- 真实模型下的多轮收敛质量未验证；合成样本与 scripted provider 验收只证明机制正确，不证明审计效果。
