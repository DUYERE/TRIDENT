# 模型库与角色解析契约（v2）

本契约定义控制台的模型库（`models.json`）、内置渠道目录、连接探测与角色解析。目标是让「配一个端点」变成「选渠道 → 建条目 → 分配给角色」，同时不突破 TRIDENT 的既有边界：纯 Go、离线、密钥不回显；密钥可来自启动环境变量，也可由用户在控制台直接填写并保存在本机（0600）。

## 1. 目的与非目标

**目的**

- 用结构化数据描述模型能力与价格，供界面决策（是否接受图片、上下文长度提示）与成本估算使用。
- 用内置渠道目录消除「手填 Base URL / 记错协议」这类高频错误。
- 用固定角色槽位把「哪个会话用哪个端点」从隐式约定变成显式配置。
- 连接探测给出可执行的失败归因，而不是一句 HTTP 状态码。

**非目标**

- 不联网同步厂商目录。内置目录是编译期常量（离线快照），价格与能力可被用户覆盖。
- 不代理模型请求，不做配额/计费结算，不做集中密钥托管：密钥只在本机（内存 + `model_keys.json` 0600），不进入 Run 配置、不进入数据库。
- 不推断未声明的能力。缺省即「未声明」，界面显示为无能力标签，而不是猜测。
- 不做跨 Run 成本汇总（需要 input/output 分项落库，属后续切片）。

## 2. 数据模型（schema v2）

`models.json` 位于控制台 workspace，权限 0600，原子替换写入。

```json
{
  "schema_version": 2,
  "default": "deepseek-flash",
  "profiles": [
    {
      "id": "deepseek-flash",
      "label": "DeepSeek V4.1 Flash",
      "endpoint": "https://api.deepseek.com",
      "model": "deepseek-flash",
      "key_env": "TRIDENT_MODEL_API_KEY",
      "api": "openai-completions",
      "capabilities": {
        "context_window": 1000000,
        "max_output": 384000,
        "reasoning": true,
        "vision": true
      },
      "cost": { "input": 0.3, "output": 1.2, "cache_read": 0.006, "cache_write": 0 },
      "defaults": { "model_calls": 12, "tool_calls": 24, "tokens": 131072 }
    }
  ],
  "roles": {
    "main": "deepseek-flash",
    "planner": "follow-main",
    "worker": "follow-main"
  }
}
```

字段语义：

| 字段 | 类型 | 约束 | 说明 |
|---|---|---|---|
| `api` | 枚举 | 只接受 `openai-completions` | 线协议。控制台只实现 OpenAI Chat Completions 适配器；旧文件里的其他协议值保留用于展示，但聊天/编排会拒绝运行 |
| `capabilities.context_window` | int | 0–10,000,000 | 0 表示未声明 |
| `capabilities.max_output` | int | 0–1,000,000 | 0 表示未声明 |
| `capabilities.reasoning` | bool | — | 是否支持思考/推理 |
| `capabilities.vision` | bool | — | 是否接受图片输入 |
| `cost.*` | float | 0–10,000，最多 6 位小数 | 美元 / 百万 token；整组缺省表示未声明 |
| `roles.*` | string | 条目 ID 或 `follow-main` | 角色槽位 |
| `defaults.*` | int | 既有上下限 | 运行预算，语义不变 |

### 2.1 本机密钥（`model_keys.json`，schema 1）

```json
{ "schema_version": 1, "keys": { "deepseek-flash": "sk-..." } }
```

- 用户在「设置 → 模型」里直接粘贴 API Key，写入 workspace 的 `model_keys.json`，原子替换、0600（Windows 的 POSIX 位是 best-effort，由 NTFS ACL 决定）。
- **优先级**：本机保存 > 环境变量 `key_env`。清除本机密钥后自动回退到环境变量。
- 接口只返回 `key_present` 与 `key_source`（`stored` / `env` / `none`），永不回显密钥值；删除条目时一并删除其本机密钥。
- 密钥不进入 `models.json`、Run 的 `config`、数据库、日志或导出文件。

**迁移**：读取 schema 1 时按缺省值升级（`api=openai-completions`、能力全 0/false、`cost=nil`、`roles` 全 `follow-main`），写回时写 schema 2。未知字段仍然失败关闭（`DisallowUnknownFields`）。

**确定性**：条目按 ID 排序；`roles` 与 `resolved` 按键名排序；价格保留 6 位小数；同一输入序列化字节一致。

## 3. 角色槽位（适配 TRIDENT）

TRIDENT 只有三类真实模型消费方，不引入守门/评审/监督等本产品不存在的角色：

| 角色 | 名称 | 消费方 | 语义 |
|---|---|---|---|
| `main` | 主模型 | 控制台对话（手动 Run） | 会话默认端点；编排未单独配置时也作为回退 |
| `planner` | 规划者 | 编排引擎 Planner 轮 | 只做意图规划与目标判定，调用次数少、上下文长 |
| `worker` | 执行者 | 编排引擎 Worker 会话 | 并发领意图读码，工具调用多、输出短 |

- 除 `main` 外，角色值可为 `follow-main`，表示解析时取 `main` 的实际条目。
- `main` 不允许为 `follow-main`（无解引用目标）。
- 服务端返回 `resolved`：每个角色解析后的 `entry_id` / `entry_name` / `model` / `followed_main`。前端不重复推导。
- 删除保护：条目被任一角色**显式**引用时拒绝删除，返回引用角色列表；`follow-main` 不算显式引用。`main` 用 `default` 条目时，修改 `default` 等价于修改 `main`。
- 编排任务创建时分别解析 Planner/Worker 端点与密钥；任一缺失即拒绝启动并指出角色与变量名。

**为什么不做 reviewer/supervisor/commander/monitor**：TRIDENT 的发现三态来自确定性引擎（codescan/dataflow/sca），没有 LLM 复核、监督或指挥官会话。凭空增加角色会制造「配置了但不生效」的假象。

## 4. 内置渠道目录

编译期常量，随二进制发布，不联网。**只收录 OpenAI 兼容渠道**（DeepSeek / OpenAI Chat Completions / Moonshot / Z.AI / xAI / Qwen 兼容模式 / 本地自建），需要 Anthropic 或 Google 原生协议时应先在网关侧转换。字段：

```go
type channelSpec struct {
    Provider   string   // deepseek
    Name       string   // DeepSeek
    API        string   // openai-completions
    BaseURL    string   // https://api.deepseek.com
    BaseURLs   []string // 可选区域端点
    Featured   bool     // 常用渠道优先展示
    Models     []modelPreset
}
type modelPreset struct {
    ModelID string; Name string; API string
    Capabilities modelCapabilities
    Cost *modelCost
}
```

接口：

- `GET /api/agent/model-channels?q=` — 渠道列表（按 `featured`、`name` 排序；`q` 匹配名称/端点/模型 ID，限 200 条）。
- `GET /api/agent/model-channels/{provider}/models` — 该渠道的模型预设（含能力与价格）。
- `GET /api/agent/model-catalog/lookup?model_id=&base_url=` — 按模型 ID 查内置条目；返回 `matches`（可能多条，按 provider 排序），供「填充能力」使用。查不到返回空数组而不是 404。

目录中的价格是公开标价的离线快照，界面对此明示；用户可覆盖任一条目。

## 5. 连接探测

`POST /api/agent/models/probe`（既有路径），请求 `{"id": "..."}`，响应扩展：

```json
{
  "id": "deepseek-flash",
  "endpoint": "https://api.deepseek.com",
  "model": "deepseek-flash",
  "api": "openai-completions",
  "ok": true,
  "status": "ok",
  "models": ["deepseek-chat"],
  "latency_ms": 128,
  "probed_at": "2026-11-16T05:00:00Z"
}
```

失败时 `ok=false`，`status` 取值与归因：

| status | 触发 | 建议文案 |
|---|---|---|
| `key_missing` | 环境变量为空 | 在启动控制台的同一环境设置 `{key_env}` 后重启 |
| `auth` | 401/403 | 检查 Key 是否有效、是否属于该端点 |
| `not_found` | 404 | 检查 Base URL 路径（OpenAI 兼容通常以 /v1 结尾） |
| `upstream` | 429/5xx | 上游限流或不可用，稍后重试或换渠道 |
| `network` | 连接/超时 | 检查网络、代理与端点可达性 |
| `protocol` | 响应不是预期结构 | 协议选择与端点不匹配 |
| `empty` | 200 但无模型 | 端点没有可用模型 |

探测是只读的：不保存配置、不修改运行中的会话，密钥只在本次请求使用。OpenAI 兼容 `GET {base}/models` + `Authorization: Bearer`；跨主机重定向直接拒绝，不把密钥带去别的地址。

**探测结果不落库**：界面上的「未测试/可用/失败」是本次会话的瞬时状态，重载回到未测试。

## 6. 会话级覆盖（P2）

- 对话请求仍可显式传 `profile_id`，覆盖本次 Run 的端点；不传则解析角色 `main`。
- 覆盖不写回 `models.json`，不改变角色分配；界面显示「覆盖：{label}」与「跟随默认」入口。
- 覆盖选择只保存在浏览器本地（按项目隔离），刷新后保留、换项目不串。
- 编排任务创建窗口的选择同样支持覆盖 Planner/Worker，但只作用于该任务。

## 7. 成本估算（P2）

单 Run 估算，来自该 Run 已提交的 `model.completed` 步骤里的 provider usage：

```
cost = input_tokens/1e6*input + output_tokens/1e6*output
     + cache_read_tokens/1e6*cache_read   (provider 未报告缓存分项时按 0)
```

- 价格取该 Run 所用条目**当前**的 `cost`；条目已删除或价格未声明时输出 `null` 并注明原因，不写 0 冒充。
- 只统计 `usage.known=true` 的步骤；unknown 不折算成零成本。
- 响应附带 `usage_source: "steps"`、`pricing_source: "profile" | "none"`。
- 不做跨 Run 汇总（见 §1 非目标）。

## 8. API 变更

| 方法 | 路径 | 变更 |
|---|---|---|
| GET | `/api/agent/models` | 响应条目增加 `api`、`capabilities`、`cost`、`roles`；新增 `roles` 映射与 `resolved` |
| POST | `/api/agent/models` | 请求接受 `api`/`capabilities`/`cost`；未知字段仍拒绝 |
| POST | `/api/agent/models/remove` | 被角色显式引用时 409，`details.roles` 列出角色 |
| POST | `/api/agent/models/roles` | 新增：`{"role":"planner","target":"profile-id|follow-main"}`；设置 `main` 时同步维护兼容字段 `default` |
| GET | `/api/agent/model-channels` | 新增 |
| GET | `/api/agent/model-channels/{provider}/models` | 新增 |
| GET | `/api/agent/model-catalog/lookup` | 新增 |
| POST | `/api/agent/models/probe` | 响应增加 `ok/status/latency_ms/api`，`error` 保留兼容 |
| POST | `/api/agent/models/key` | 新增：`{"id":"...","key":"..."}` 保存本机密钥；`key` 为空表示清除。响应只含 `key_present` / `key_source` |

所有写接口在固定快照模式（`--workspace` 为空）下仍返回 `pinned_console`。写操作在有 Run 或编排任务运行时仍拒绝（现有 CAS 与互斥语义不变）。

## 9. 安全边界

- 密钥永不出现在响应、日志、`models.json` 与 Run 配置中；只暴露 `key_present` 与 `key_source`。
- `models.json` 与 `model_keys.json` 都以 0600 写入，先写临时文件再 rename，避免半截文件。
- 本机密钥优先于环境变量；清除后回退，不会出现「两条来源都不生效」的静默状态。
- 端点校验不变：https 任意主机；http 仅 loopback。
- 探测请求只读、有超时（10s）、有响应体上限（512KiB），不跟随重定向到其他主机（`CheckRedirect` 拒绝跨主机）。

## 10. 限制

- 内置目录是离线快照，可能与厂商最新模型/价格不一致；界面注明来源与可覆盖。
- 能力字段是声明式的，不通过实际调用验证（例如「支持图片」不做探测）。
- 只实现 OpenAI Chat Completions 一种线协议（第 4 节目录也只收录兼容渠道）；厂商私有签名、OAuth、AWS SigV4 等不支持。
- 角色仅 3 个，且与产品真实会话类型一一对应；新增角色必须先有真实消费方。
- 成本估算是按当前单价的近似值，不替代厂商账单；缓存计费与阶梯定价未建模。

## 11. 验收

- `go test ./internal/webui`：schema v1→v2 迁移、字段校验、角色解析（含 `follow-main` 与拒绝 `main` 自引用）、删除保护、目录查询、探测归因（用 `httptest` 模拟 401/404/500/坏 JSON）、成本估算（已知/未知 usage）、本机密钥的保存/优先级/清除/随条目删除、响应不回显密钥。
- `go test ./internal/orchestrator`：Planner/Worker 使用不同绑定；回退到共享绑定。
- `python scripts/test-web.py` 与 `powershell -File scripts/verify-offline.ps1` 全绿。
- 控制台实测：模型库表格显示能力与价格；抽屉三段式；角色分配三行；删除被引用条目返回 409 并列出角色；对话页可选择覆盖并回退。
