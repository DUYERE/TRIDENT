# R1 Agent Core 契约与设计决策

> 本地协议验收与一次获准的真实模型只读闭环均已完成，详见 `development-progress.md` 与 §6.1；设计承诺只有在实现和测试后才记为通过。不是完整 R2/R3，也不代表生产可利用性。

## 1. 边界与技术路线

1. 核心 Go；一个决策循环，不引入三角色、多 Worker 或自主子 Agent 网络。
2. 首个适配器使用官方 OpenAI Go SDK 的 Chat Completions 协议，明确配置模型/端点。兼容服务必须通过本契约，不假设 Responses、服务器工具或隐藏推理字段均通用。DeepSeek 等兼容服务返回的 `reasoning_content` 作为不透明延续数据接受但不落入最终答案；`reasoning_details`/`reasoning` 仍拒绝。工具 JSON Schema 的数值关键字必须以 JSON number 发送（SDK 会把 `json.Number` 编码成字符串，严格服务会拒绝）。
3. 工具为九个只读工具：快照 `inspect_project/list_files/read_source/search_source`，分析 `inspect_dependencies/match_advisories/query_endpoints/trace_dataflow/list_findings`。分析工具复用 `sca/audit/dataflow/findings`，只返回有界摘要和已实际读取的快照行引用。Agent 仍不执行 Shell/Maven/Java，不提供写源码、网络检索、补丁或修复能力。
4. 运行配置可绑定一个绝对的本地公告目录 `--advisories`；它是调用者配置，不是快照内容，不改变外发范围。未配置时 `match_advisories` 明确返回 `configured=false`。
5. 常规测试只用 Fake 与 loopback HTTP；本地测试服务不是实际 LLM，不可以据其输出宣称自主审计已验收。2026-11-13 用户单独批准了一次 DeepSeek `deepseek-flash`、仅合成样本、单次 Run 最多 10 次模型调用的只读验收，结果见 §6.1；该批准不扩展到其他快照、模型或未来调用。

## 2. 权限与外发

- Run 归已认证创建者所有；每次状态/步骤查询和事务都重新验证主体及所有权。无关 admin/worker/scheduler 不因全局角色访问他人 Run。旧 Mission 的离线 admission 不是 Run 授权。
- 本地读取、模型外发、修复写入、测试执行分离。本片后两项始终不可用。
- 外发默认拒绝；未来许可必须绑定整份快照 hash、规范端点、模型、有效期、目标/对话数据及额度。不存在仅批准部分文件却通过 inspect/list/search 泄漏其余路径的隐式行为。
- 默认排除敏感文件不等于充分脱敏；用户不得把任意源码输入误认为已获得外发批准。模型/仓库文本无法修改策略、工具集、身份或服务地址。
- 端点显式配置，HTTPS 正常校验；HTTP 仅显式 loopback 测试。禁自动重试、重定向、环境代理、环境端点覆盖、备用模型/服务发现。密钥由宿主环境指定读取，不保存到 Run/日志/工具输出。

## 3. PostgreSQL 权威协议与 Artifact

新增前向 004，001—003 保持原字节。Run 保存不可变输入配置/策略、状态/CAS版本、预算和恢复检查点；AgentStep 保存有序有大小界限的规范 JSON 原始文本及 SHA-256。协议内容暂直接存 PostgreSQL，不创建另一份可写 STATE 或 transcript 文件。快照本身是受 hash 认证的源码 Artifact；未来大日志/补丁再单独扩不可变 Artifact 存储。

原有 Task Activity/Outbox 强制 task_id，不制造假 Task 为 Run 借道。新 Run 的安全事务与事件同表记录，不先扩完整平台调度。

## 4. 调用事务与恢复

1. 一个 Run 仅一个驱动器：专用数据库连接持会话 advisory lock；短事务执行 owner/状态/期望版本及幂等检查。连接失效则旧驱动器停止，不将带锁连接放回池。
2. 模型调用前提交预留及 pending 请求；网络调用不跨 DB 事务；返回后原子提交用量、响应和检查点。
3. 已提交响应/工具结果恢复时复用，不重复执行。准备但未完成的只读工具可在同 hash 快照和同策略下重读，不二次计入尝试。
4. pending 模型请求没有已提交结果视为 unknown，保留预留并暂停。请求可能已被服务计费，不能自动退款或重发，不能宣称 exactly-once。明确恢复需用户承认可能重复费用及旧驱动器已停止；新请求是新尝试。
5. 不确定 DB 提交应以相同幂等键重新查询，不凭客户端报错决定新调用。鉴权在历史回执返回前重新执行；历史回执不是可复用执行票据。

## 5. 预算、协议与证据

- 限制模型尝试、工具步数、单次输出、累计 token 预留/报告、请求/响应/协议存储字节和绝对截止时间；耗尽仍须保存停止原因。无可信计数/价格配置时不宣称账单精确上限，未知用量不当零。
- 单个 Agent 工具结果最多 24 KiB；恢复检查点不再设 48 KiB 硬上限（2026-11-16 删除），只受整体持久化存储字节预算和请求/响应/协议存储字节限制；请求/响应过大明确失败，不静默截断。已知响应不能仅因上下文容量失败被冒称未知：有界 accounting-only 终态保留响应摘要、实际用量与未保留原因，停止而不是重复收费。服务错误信息只保存分类，不输出原始错误体/请求认证头。
- 工具参数拒绝未知/重复字段、尾随 JSON、null、不合类型、过深/过大内容。缺失/重复调用 ID 和不支持调用类型失败关闭；拒绝或截断响应中工具不执行。
- tool 文本始终是不可信数据；系统提示不代替确定性权限。输出继承快照 hash、文件 hash、行号和 partial，不声称 prompt injection 已完全解决。
- 最终结论为模型推断。引用须能在已保存 read/search 或分析工具实际读取的证据中核对；引用有效只证明出处一致，不证明漏洞成立。没有 AST、运行验证或补丁，不能产生“修复已验证”。
- 分析工具按文件/行读取快照后才登记引用；工具结果中的 `citations` 只包含已经通过 `snapshot.Read` 校验并写入证据账本的行。分析摘要本身不是源码证据，模型需要更多上下文时仍须调用 `read_source`。
- 运行检查点版本升为 v2（新增工具与引用契约）。v1 检查点不可恢复，不静默重放旧对话。

### 5.1 分析工具

| 工具 | 参数 | 返回与限制 |
|---|---|---|
| `inspect_dependencies` | `limit` 1–10、`offset` 0–100000 | POM 声明级依赖/模块，不是有效依赖树、classpath、SBOM 或可达性；无源码引用 |
| `match_advisories` | `limit`、`offset` | 仅精确版本公告匹配；未绑定公告目录时 `configured=false`；无源码引用 |
| `query_endpoints` | `q`、`limit`、`offset` | Spring MVC 注解级入口；每个入口附已读取的方法行引用 |
| `trace_dataflow` | `category`、`status`、`q`、`limit`、`offset` | 9 类 Source/Sink 静态 finding；`runtime_status=not_run`；最多两个实际读取的引用/条 |
| `list_findings` | `category`、`status`、`q`、`limit`、`offset` | 统一 Finding/Hypothesis，包括依赖候选；引用契约同上 |

所有分析工具单次结果仍受 24 KiB 循环上限约束；分页不复制分析缓存，不产生额外源码读取或网络访问。

### 5.2 检查点压缩（v2 扩展，默认关闭）

- 48 KiB 检查点硬上限与 40 KiB 软目标已于 2026-11-16 默认关闭：`maxCheckpointBytes=0`、`checkpointCompactTarget=0`，不再因上下文增长停止 Run，也不再自动截断历史工具结果。
- 压缩实现保留为可选/测试路径。启用时按固定顺序把较早的工具结果替换为合法 JSON 标记：`{"truncated":true,"reason":"agent_checkpoint_budget","original_bytes":N,"sha256":"...","preview":"..."}`；保留 system/user、所有 assistant `tool_calls` 与 tool 配对、证据账本以及最新两条工具结果。
- 启用时仍超过软目标则从较新的工具结果向旧压缩，但始终保留最新一条完整；若最新一条加其他状态仍超过硬上限，才最后压缩它。
- `compactions` 与 `compacted_bytes` 写入检查点作为审计字段；启用压缩并发生后，最终答案追加固定 limitation，提示历史工具结果被截断、引用旧上下文前应重新读取。压缩不改变证据账本，已实际读取的引用仍可校验。

### 5.3 Accounting-only 终态载荷

- 仅当模型响应已获得、但序列化响应/检查点/本地存储字节预算不足时使用；事件为 `model.completed`，目标状态为 `budget_exhausted`。
- payload 固定为 `{"reason":"response_byte_limit|stored_byte_limit","response":{"sha256":"<64hex>","bytes":N,"stop":"complete|tool_calls|refusal|length","retained":false},"reported_usage":{"known":bool,"input_tokens":N,"output_tokens":N}}`，上限 4096 字节。旧 Run 可能保留历史 `checkpoint_limit` 值，仅作兼容读取。
- 不写替换 checkpoint；usage 未知时 used/reserved delta 必须为 0 并保留预留，usage 已知时 used 必须等于 input+output，预留按 prepared 事件严格配对释放。
- 该终态不可恢复：不重放已获得的响应，不把未知用量记为零，也不冲抵更早的 unknown 预留。

## 6. 验收门槛

本地验收：Fake 单循环、官方 SDK loopback 协议、Run 所有者/幂等/CAS/并发/恢复/预算、004 迁移与历史回归、真实 CLI 本地服务和 Windows/Linux 测试。仅已获准的 `127.0.0.1:55432/trident_test` 可用于数据库写验收。

真实 R1 门槛仍需每次独立批准：具体模型/服务、合成样本外发范围及付费请求，然后证明真实模型自主选工具、识别入口并给带出处的假设。Fake 或本机脚本输出不得充当真实模型证据。

### 6.1 真实模型只读闭环记录（2026-11-13）

- 授权：用户明确提供 DeepSeek 官方 API key，指定 `deepseek-flash` 节省成本；沿用此前选择——仅外发 `tests/fixtures/java-maven` 合成样本、单次 Run 最多 10 次模型调用。
- 端点/模型：`https://api.deepseek.com/v1`、`deepseek-flash`；`--output-parameter max_tokens`；`--approve-egress`；密钥仅从 `TRIDENT_MODEL_API_KEY` 读取，不写入 Run/日志。
- 快照：`f6c6c4fa54c6775d24b7a6eee0a774b8d2374e0e2de8e3ec8328d5d2a2f2af00`（14 个合成文件）。
- 最终 Run 43：`completed`，3 次模型调用、4 次工具调用、18,394 tokens；工具顺序由模型自主选择：`inspect_project` → `trace_dataflow` → `query_endpoints` → `read_source`。
- 最终答案为一个 JSON envelope：2 条显式标注 `UNVERIFIED INFERENCE` 的假设；引用 `CustomerController.java:22-26/34-38/35` 与 `CustomerRepository.java:24/27-28`，全部通过证据账本校验；声明 `runtime_status=not_run` 与无 AST/未执行/未做依赖公告匹配等限制。
- 早期协议不兼容尝试：Run 37/38 因响应含 `reasoning_content`、工具 Schema 数值被编码为字符串被拒绝；Run 37 的模型响应可能已计费但未记账，最终以 DeepSeek 控制台为准。修复后 Run 41/42 分别因 60k token 预留与 48 KiB 检查点上限在总结前停止；Run 43 在收紧工具预算后完成。Run 41/42 的 tool/step 记录保留在 `trident_test` 数据库。
- Run 46（`deepseek-v4-pro`，同一合成快照与只读工具）：`completed`，3 次模型调用、4 次工具调用、21,956 tokens；模型自主选择 `trace_dataflow` → `query_endpoints` → `list_files` → `read_source`，输出 2 条 `UNVERIFIED INFERENCE` 假设，引用 `CustomerController.java:22-26/34-37` 与 `CustomerRepository.java:28`，全部通过证据账本校验。
- 该记录只证明两次真实模型的自主只读分析与出处引用能力，不证明漏洞可利用、覆盖完整或生产部署；不构成对其他模型/端点的验收。

### 6.2 压缩与证据导出（2026-11-13）

- 检查点压缩默认关闭；启用时按工具类型设置确定性预览长度：`read_source` 2048（保留头尾），搜索/列表/入口/依赖 1024，findings/dataflow/公告 1536，其他 512；标记始终是合法 JSON，并附带 `tool/original_bytes/sha256/preview` 与可用时的 `summary`（`total/offset/limit/partial/counts/coverage`）。
- 压缩不调用模型、不删除消息、不破坏 tool_call/result 配对；最新结果默认保持完整，只有硬上限仍超出时才压缩。
- `agent export --id --out` 只读导出 Run 与分页收集的全部 Step，默认 30 天保留窗口（`--retention-days` 1—3650），超期需显式 `--include-expired`；`--max-bytes` 默认 1 MiB、最大 8 MiB，超限失败关闭。导出不写数据库、不删除 append-only 记录。
- 数据库 agent 表保持 append-only；本片没有实现物理删除或自动清理，保留策略是访问控制而非 DB pruning。
