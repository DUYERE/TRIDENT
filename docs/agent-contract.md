# R1 Agent Core 契约与设计决策

> 本轮实现中。进度与实际验收见 `development-progress.md`；设计承诺只有在实现和测试后才记为通过。不是完整 R1 真实模型验收。

## 1. 边界与技术路线

1. 核心 Go；一个决策循环，不引入三角色、多 Worker 或自主子 Agent 网络。
2. 首个适配器使用官方 OpenAI Go SDK 的 Chat Completions 协议，明确配置模型/端点。兼容服务必须通过本契约，不假设 Responses、服务器工具或隐藏推理字段均通用。
3. 工具仅 `inspect_project/list_files/read_source/search_source`；复用既有快照工具。不执行 Shell/Maven/Java，不提供写源码、网络检索或补丁能力。
4. 用户本轮未授权真实模型调用或源码外发。测试只用 Fake 与 loopback HTTP；本地测试服务不是实际 LLM，不可以据其输出宣称自主审计已验收。

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
- 单个 Agent 工具结果最多 24 KiB，恢复检查点最多 48 KiB（下层 project 查询允许更大的 256 KiB，本层另设更小持久上下文上限）；请求/响应过大明确失败，不静默截断。已知响应不能仅因上下文容量失败被冒称未知：有界 accounting-only 终态保留响应摘要、实际用量与未保留原因，停止而不是重复收费。服务错误信息只保存分类，不输出原始错误体/请求认证头。
- 工具参数拒绝未知/重复字段、尾随 JSON、null、不合类型、过深/过大内容。缺失/重复调用 ID 和不支持调用类型失败关闭；拒绝或截断响应中工具不执行。
- tool 文本始终是不可信数据；系统提示不代替确定性权限。输出继承快照 hash、文件 hash、行号和 partial，不声称 prompt injection 已完全解决。
- 最终结论为模型推断。引用须能在已保存 read/search 的证据中核对；引用有效只证明出处一致，不证明漏洞成立。没有 AST、运行验证或补丁，不能产生“修复已验证”。

### 5.1 Accounting-only 终态载荷

- 仅当模型响应已获得、但序列化响应/检查点/本地存储字节预算不足时使用；事件为 `model.completed`，目标状态为 `budget_exhausted`。
- payload 固定为 `{"reason":"response_byte_limit|checkpoint_limit|stored_byte_limit","response":{"sha256":"<64hex>","bytes":N,"stop":"complete|tool_calls|refusal|length","retained":false},"reported_usage":{"known":bool,"input_tokens":N,"output_tokens":N}}`，上限 4096 字节。
- 不写替换 checkpoint；usage 未知时 used/reserved delta 必须为 0 并保留预留，usage 已知时 used 必须等于 input+output，预留按 prepared 事件严格配对释放。
- 该终态不可恢复：不重放已获得的响应，不把未知用量记为零，也不冲抵更早的 unknown 预留。

## 6. 验收门槛

本地验收：Fake 单循环、官方 SDK loopback 协议、Run 所有者/幂等/CAS/并发/恢复/预算、004 迁移与历史回归、真实 CLI 本地服务和 Windows/Linux 测试。仅已获准的 `127.0.0.1:55432/trident_test` 可用于数据库写验收。

真实 R1 门槛仍需独立批准：具体模型/服务、合成样本外发范围及付费请求，然后证明真实模型自主选工具、识别入口并给带出处的假设。Fake 或本机脚本输出不得充当真实模型证据。
