# Agent 运行时配置契约

启动参数（`--enable-agent-chat`、`--agent-token`、`--agent-dsn`）曾是一次性开关：漏传就要重启。本契约把它们搬进「设置 → Agent 与编排」，保存后立即生效，并持久化到工作区，下次启动无需重复传参。

## 1. 范围

| 项 | 存储键（`console.json`） | 说明 |
|---|---|---|
| 启用开关 | `agent_chat_enabled` | 同时控制对话与编排；关闭后不打开写库会话 |
| 会话库连接串 | `agent_dsn` | PostgreSQL DSN，含数据库凭据 |
| 主体令牌 | `agent_token` | 具备创建 Run 权限的主体令牌 |

- 启动参数仍然有效：显式 `--agent-*` 优先于持久化值（一次性覆盖），持久化值优先于环境变量 `TRIDENT_AGENT_DSN`。
- `console.json` 以 0600 写入，`.trident/` 已被 git 忽略。
- **不保存**模型端点/模型 ID：那属于 `models.json`（见 `model-library-contract.md`），每个角色单独解析。

## 2. API

### `GET /api/agent/runtime`

```json
{
  "schema_version": 1,
  "enabled": true,
  "ready": true,
  "dsn_stored": true,
  "dsn_target": "127.0.0.1:55432/trident_test",
  "token_stored": true,
  "active_run": 0,
  "active_task": 0,
  "model_ready": true
}
```

- `dsn_target` 只含 host 与 database，不含用户名、密码、query。
- `token_stored` 只是布尔；**任何响应都不返回令牌或 DSN 原文**。
- `ready` 表示 `enabled && 写库会话已打开`；`reason` 在未就绪时给出可执行说明。
- `model_ready` 表示主模型角色有可用密钥（本机或环境变量），仅作提示，不阻止启用。

### `POST /api/agent/runtime`

```json
{ "enabled": true, "dsn": "postgres://...", "token": "..." }
```

- 字段均可省略；省略表示沿用当前值。`clear_dsn` / `clear_token` 为显式清除，清除会同时把 `enabled` 置为 false。
- 顺序：**先校验后落盘**。启用时会真实 `store.Open` 并 `Authenticate`；新填写的令牌即使开关关闭也会校验，避免「已保存但已失效」。失败返回 400，旧配置保持不变。
- 有 Run 或编排任务运行中返回 409 `agent_busy`；运行中的会话不会热切换端点。
- 成功后立即重建写库会话与编排引擎（`orchestrator.New`），无需重启。
- 观测用只读库跟随同一 DSN 重建；失败只记录 `agent_dsn_error`，不阻塞保存。

错误码：`agent_dsn_missing`、`agent_dsn_invalid`、`agent_token_missing`、`agent_token_invalid`、`agent_busy`、`pinned_console`、`workspace_error`。

## 3. 启动流程

1. 读取 `console.json`，得到持久化的开关、DSN、令牌。
2. 显式启动参数覆盖对应项；`--agent-dsn` 为空时回退 `TRIDENT_AGENT_DSN`。
3. 开关为真且 DSN/令牌齐全时，打开写库会话、校验令牌、创建编排引擎；失败只降级为「已启用但未就绪」并记录原因，不阻塞控制台启动。
4. 观测库独立打开；打开失败只影响历史会话页。

## 4. 关闭语义

- 关闭开关：关闭写库会话与编排引擎，`chat.enabled=false`，原因写为「未启用」；观测库在 DSN 仍存在时保留，历史会话照常可读。
- 清除令牌：等价于关闭并清空令牌；清除连接：关闭并清空 DSN，同时关闭观测库。
- 关闭不会删除任何 Run、编排任务或图数据。

## 5. 安全边界

- 令牌与 DSN 只存本机（0600），不进入导出报告、日志、Run 配置或数据库。
- 响应只回布尔与掩码目标，不回显凭据；前端只有「已保存/未保存」。
- 令牌校验失败不落盘，不会把可用配置替换成坏配置。
- 仍受控制台自身的访问令牌保护；固定快照模式（无 `--workspace`）拒绝修改。

## 6. 限制

- 不做多租户隔离：令牌对应一个数据库主体，所有控制台用户共享。
- 不支持热切换正在运行的 Run/编排；必须等其结束或停止。
- 启用不代表能跑：还需要「设置 → 模型」里有主模型条目与可用密钥。
- 数据库凭据轮换后需在设置里更新并保存，旧连接会立即关闭。
- 固定快照模式（未以 `--workspace` 启动）下，设置页的运行时配置与分析路径均为只读；需要先以 `--workspace` 启动一次，此后所有配置都可在设置页随时修改，不需要再次重启。

## 7. 验证记录（2026-11-16）

- **离线门禁**：`agent_runtime_test.go` 覆盖凭据不回显、缺 DSN/坏 DSN 拒绝、关闭持久化、清除令牌自动停用、运行中 409；`agent_dsn_test.go` 新增 `TestUnconfiguredAgentHintsPointToSettings`，断言三个未配置端点（`threads` / `runs` / `steps`）的提示都指向设置页且不再建议加启动参数或重启。
- **在线闭环实测**（非自动化门禁）：本机 PostgreSQL 测试库上用一次性 `admin` 主体执行 `POST /api/agent/runtime {enabled:true,dsn,token}`，返回 `enabled=true / ready=true`，`GET /api/agent/runtime` 保持一致，`GET /api/agent/threads` 返回 200；随后 `POST {enabled:false,clear_token:true}` 停用。验证后删除一次性主体，`console.json` 与验证前字节一致，临时文件已清理。此实测只证明「保存即生效」，不证明模型调用或编排任务可成功执行。

## 8. 快速启用（quick setup，v1）

版本标识 `agent_runtime_quick_setup_v1`。手动填 DSN、去 `secrets/` 里翻 64 位令牌、理解 `principals`/role/hash 的成本过高；快速启用把本机已有的配置**自动发现并一次点击应用**，手动字段退到「高级」折叠区。它**不新增任何配置来源**，只是替用户读出已经存在的东西。

### `GET /api/agent/runtime/quick`

只读探测，不改变任何状态：

```json
{
  "schema_version": 1,
  "version": "agent_runtime_quick_setup_v1",
  "enabled": false,
  "ready": false,
  "dsn_found": true,
  "dsn_target": "127.0.0.1:55432/trident_test",
  "dsn_ok": true,
  "principal_found": true,
  "principal_role": "admin",
  "model_ready": false,
  "can_enable": true,
  "reason": ""
}
```

- `dsn_found`：有可用连接串候选；`dsn_target` 是掩码（host/db），与 §2 一致。
- `dsn_ok`：候选连接串真的打开了数据库并通过 schema gate。
- `principal_found` / `principal_role`：找到可 `Authenticate` 且满足创建 Run 权限（`status=active`、`principal_type=human`、`role ∈ {admin,scheduler}`）的主体。
- `model_ready`：主模型密钥是否可用。**它不阻塞启用**，只用于提示「启用后还需要配模型」。
- `can_enable = dsn_ok && principal_found`。为 false 时 `reason` 说明缺哪一项。
- 响应**永不回显** DSN、密码、令牌、subject 或文件路径。

### `POST /api/agent/runtime/quick`

无请求体。重新探测（不信任 GET 结果），再走 §2 完全相同的校验链（`store.Open` + `Authenticate` + 落盘 + 热替换），等价于替用户提交 `{enabled:true,dsn,token}`。成功返回 `agentRuntimeStatus`（§2）。失败不落盘、开关回滚。

错误码：`agent_quick_unavailable`（412，缺会话库或无可用主体）、`agent_busy`（409）、`pinned_console`（409）、以及 §2 的 `agent_dsn_invalid` / `agent_token_invalid` / `workspace_error`。

停用仍走 `POST /api/agent/runtime {enabled:false}`，不提供「一键停用」的隐式语义。

### 探测范围与顺序

1. DSN 候选：`console.json` 已存的 `agent_dsn` → 环境变量 `TRIDENT_DATABASE_URL`。没有则报告缺失，**不猜测、不拼装 compose 默认值**（连哪个库只有操作者知道）。
2. 主体候选：`console.json` 已存的 `agent_token` 优先，其次扫描 `<workspace>/secrets/` 与 `<workspace 父目录>/secrets/` 下的 `*.json`，只读取 `token` 字段（要求 64 位、无控制字符）。逐个 `Authenticate` 并用只读 `DescribePrincipal` 校验权限，取第一个满足条件的。
3. 每个候选都在**本机**验证；扫描不出结果就明确报「未找到」，不伪报可用。

### 明确不做

- **不启动数据库容器/服务**：连不上就报 `agent_quick_unavailable`，不会执行 `docker compose up` 之类的外部命令。
- **不自动创建主体**：不会调用 `bootstrap` 或写 `principals` 表；没有现成可用令牌就让用户去高级里填或先 bootstrap。
- **不自动启用**：仍要用户点一次按钮，因为启用会打开写库会话并允许后续调用模型。
- **不替代模型配置**：模型端点、主模型、API Key 仍属 `models.json` / `model_keys.json`。
- **不跳过校验**：POST 会重新真实连接与认证，探测结果只是预检。

### 限制

- 只在 `--workspace` 模式可用；固定快照模式拒绝。
- 扫描 `secrets/*.json` 时只认 `token` 字段，其他自定义凭据文件格式不识别。
- `DescribePrincipal` 是只读查询；主体在探测后、启用前被撤销时，POST 会失败且不落盘。
- 有 Run/编排运行时拒绝修改；不热切换。
