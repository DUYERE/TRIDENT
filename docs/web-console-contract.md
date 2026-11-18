# 只读 Web 分析控制台契约（R2 第十三片）

## 1. 定位与状态边界

`trident web` 为一个本地源码快照提供分析控制台。它复用 `project`、`sca`、`audit`、`authz`、`javaast`、`dataflow`、`findings` 的既有实现，不新增分析语义，也不改变任何 finding 的静态/运行时状态。

- 两种模式：**pinned**（`--snapshot` + `--snapshot-hash`，配置与快照都不可变）与 **workspace**（`--project` / `--workspace`，可在界面选择项目、切换已导入项目、修改路径配置并重新分析）。
- **可选的 Agent 控制平面**：默认关闭。只有同时给出 `--enable-agent-chat`、`--agent-dsn`、`--agent-token`（主体令牌）与模型绑定时，`#/agent` 才能创建 Run。此时控制台不再纯只读：它会调用模型、写入 Run 记录。每次运行都需要在界面显式勾选外发批准（`approve_egress`），服务端仍强制校验；同一进程一次只允许一个 Run。
- workspace 允许**空启动**：`trident web --workspace .trident` 不带 `--project` 时不加载任何快照，仅开放会话、配置、项目管理和目录浏览；其余分析路由统一返回 `409 no_project`，直到在「项目」页完成首次导入。
- workspace 模式仍不做：执行 Java/Maven/JUnit、调用模型、访问目标网络、创建 Run、审批或执行工具、写入原仓库目录。导入只读取源码，快照写入工作区 `snapshots/`，原目录永不被写入。
- 工作区新增的唯一可变状态是 `console.json`（路径配置与当前项目记录，不含密钥）与快照目录；分析结果仍只存在于进程内缓存。
- 不提供 Agent 控制 API；控制台只有只读查询、证据下载和工作区配置。**HTTP 分析控制台的存在不等于开放远程执行平面。**
- 页面上的 `runtime_status` 恒为 `not_run`；静态确认、`inconclusive` 和 `refuted` 的含义与 CLI 完全一致。未观察到的路径不是安全证明。

## 2. 启动与鉴权

```bash
# 一键模式：导入源码、计算摘要并启动；无需手工准备快照与 hash
trident web --project <source-dir> [--workspace <dir>] \
  [--advisories <file|dir>] [--path...] [--token <value>]

# 再次启动：工作区记住上次项目与配置，只需一个参数
trident web --workspace <dir>

# 固定快照模式（原有行为）
trident web --snapshot <dir> --snapshot-hash <sha256> [--advisories <file|dir>]
```

1. `--project` 未给 `--workspace` 时默认工作区为 `./.trident`；导入结果按摘要去重写入 `<workspace>/snapshots/<sha256>`，原目录只读。
2. `--snapshot` 仍必须提供外部可信摘要；`webui.New` 使用 `project.Open` 重新校验清单，失败即退出。
2.1. 工作区自动拾取 `<workspace>/advisories/` 目录与 `<workspace>/package-map.json`，因此公告与可达性映射不必每次作为参数传入；显式参数优先于工作区默认值。
2. `--addr` 只接受数值 loopback 地址或 `localhost`；通配地址、私网地址和外部域名一律拒绝。默认 `127.0.0.1:8787`。
3. 未提供 `--token` 时生成 48 位十六进制令牌并仅在启动终端打印一次。令牌不写入快照、日志或前端资源；workspace 的 `console.json` 同样不保存令牌。
4. `--token` 与 `--tokens` 互斥，同时提供即拒绝启动。
5. 浏览器登录使用 `POST /api/session`，成功返回 `Set-Cookie: trident_console=...; HttpOnly; SameSite=Strict; Path=/`，有效期 8 小时。脚本可使用 `X-Trident-Token` 请求头。同一客户端 host 连续 5 次令牌失败后锁定 30 秒（429 + `Retry-After`，成功登录清零）；这是对猜测次数的上限，不替代令牌强度。
6. 所有 `/api/` 与 `/export/` 请求必须携带令牌（Cookie 或 `X-Trident-Token`）与 `X-Trident-Request: console`。跨源页面无法在不触发 CORS 预检的情况下设置该头，服务端不授予任何 CORS 预检；配合 `SameSite=Strict` Cookie 构成 CSRF 防线。
7. 统一响应头：`Content-Security-Policy`（不含 `unsafe-inline`，脚本/样式全部为同源外部文件）、`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`、`Cross-Origin-Resource-Policy: same-origin`；API 与导出为 `Cache-Control: no-store`。

### 2.1 多用户令牌文件（P2-2）

`--tokens <file>` 将单令牌升级为可轮换的多用户令牌注册表。文件为 UTF-8 JSON 数组：

```json
[
  {"id": "alice", "role": "reviewer", "token_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
  {"id": "bob",   "role": "auditor",  "token_hash": "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"}
]
```

- `token_hash` 是令牌明文的 SHA-256 十六进制小写（64 字符）；**文件永不保存令牌明文**。生成方式：
  - POSIX：`printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1`
  - PowerShell：`$sha=[System.Security.Cryptography.SHA256]::Create();[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($TOKEN))).Replace('-','').ToLower()`
- 校验规则（启动失败即退出）：数组至少 1 项；`id`/`role` 为 1–64 字符且仅含 `A-Za-z0-9._-`；`id` 不得重复；`token_hash` 必须是 64 位十六进制且不得重复（同一令牌不能映射两个身份）；未知字段拒绝。
- 呈现令牌 → 计算 SHA-256 → 与注册表比对（命中后再做常数时间比较）。所有角色共享完全相同的只读权限；`role` 当前仅为审计身份标注与未来细粒度授权的预留接口，不是权限边界。
- **热重载与轮换**：每次授权请求检查令牌文件的 mtime+size 签名，变化即重新加载，无需重启。同一 `id` 换新 `token_hash` = 轮换（旧令牌下一个请求即 401，新令牌即生效）；删除条目 = 撤销。文件必须整体重写或原子替换（写临时文件后 rename）；就地部分写入导致解析失败时沿用最后已知良好注册表并向 stderr 告警，恢复合法内容后自动接管。重载遇到结构合法但为空数组的文件按“全部撤销”处理；仅启动时拒绝空数组以防误配置。
- 单令牌 `--token` 模式保持原语义（注册表内固定身份 `local`/`reviewer`）；`Token()` 仅在单令牌模式返回明文，多用户模式由 CLI 打印用户 id 列表而不打印任何令牌。

## 3. API

| 方法 | 路径 | 语义 |
|---|---|---|
| POST | `/api/session` | 用访问令牌换取 HttpOnly 会话 Cookie；仅接受 `{"token":"..."}`；每 host 5 次失败后 429 |
| GET | `/api/health` | 进程、快照摘要、分析是否已缓存；不触发分析 |
| GET | `/api/overview` | 快照清单、覆盖计数、类别分布、严重度分布（排除已反驳）、工具版本与限制；`code` 摘要在多语言分析未运行时返回 `available=false` / `reason=analysis_pending`，**不触发耗时分析** |
| GET | `/api/findings` | 支持 `status`、`category`、`severity`、`q`、`limit`、`offset` 的发现摘要；响应含分面 `severities`（随当前筛选联动，不随 severity 自身） |
| GET | `/api/finding?id=` | 单一发现完整证据、假设与限制 |
| GET | `/api/endpoints` | 支持 `q`、`limit`、`offset` 的 Java 注解级入口清单；另返回 `entries`/`entry_total`/`entry_coverage`/`entry_partial`/`entry_limitations`（Java 注解、codescan 声明路由、跨语言应用入口文件的统一证据），以及兼容字段 `application_entries`、`application_entries_partial`、`application_entry_limitations`；声明路由和文件候选均不当作已部署路由；ThinkPHP `\think\Route::rule($k,$val)` 等变量路径现在以 `path="<dynamic>"`、`path_status="dynamic_unresolved"`、`reason="route_path_not_literal"` 显式出现，不再从入口视图消失。`entry_partial` 只由 `file_limit`、`file_too_large`、`lex_rejected`、`statement_limit` 等入口相关缺口触发，`symbol_limit`/`call_limit`/`unresolved_limit` 不计入，`entry_limitations` 同步过滤这些符号层限制 |
| GET | `/api/dependencies` | Maven 声明级 SCA 报告（模块、依赖、公告匹配、覆盖） |
| GET | `/api/files` | 快照清单分页（`prefix`、`limit`、`cursor`） |
| GET | `/api/file` | 逐行读取（`path`、`start_line`、`limit`、`cursor`），完整校验 SHA-256 |
| GET | `/api/search` | 快照内区分大小写字面量检索（`q`、`prefix`、`limit`、`cursor`） |
| GET | `/api/report` | 下载与 `trident audit findings` 相同的统一证据 JSON |
| GET | `/api/sbom` | 下载与 `trident sca sbom` 相同的 CycloneDX 1.5 JSON |
| GET | `/api/metrics` | 只读运维指标（进程生命周期计数器，见 §6.1；令牌门禁） |
| GET | `/metrics` | Prometheus 文本格式 0.0.4 抓取端点（同一组计数器；令牌门禁，接受 `Authorization: Bearer`，豁免 console 头；指标名与 `docs/deployment.md` §2.2 告警规则对齐） |
| GET | `/api/tree` | 声明级依赖树（`sca.Tree`，与 CLI `sca tree` 同源） |
| GET | `/api/sarif` | 下载 SARIF 2.1.0（与 `audit sarif` 同源，GitHub code scanning 映射一致） |
| GET | `/api/reachability` | 有界可达性三态（需启动参数 `--package-map`；结果进程内缓存；未配置返回 412 + 启用指引） |
| GET | `/api/runtime-report` | 只读展示调用者提供的 `runtime http correlate --out` 报告（需启动参数 `--runtime-report`；≤64 MiB，JSON 校验失败 422；控制台不执行任何运行时验证） |
| GET | `/api/agent/steps` | 单个 Run 的 step 时间线（`run_id` 参数；limit ≤1000） |
| GET | `/api/agent/threads` | 按快照摘要过滤的会话列表（`hash` 缺省为当前项目），每个项目只看到自己的会话 |
| GET | `/api/agent/conversations` | 当前项目的会话列表（`hash=all` 查看全部；含活动 Run/Task） |
| GET | `/api/agent/conversations/detail?id=` | 单个会话的 Run、Task 与消息历史 |
| GET | `/api/agent/chat/state` | 对话能力状态：是否启用、模型与端点、密钥是否就绪、当前运行中的 Run、预算上限（无项目也可读） |
| GET | `/api/agent/models` | 模型库：配置档案列表（端点、模型、密钥变量名、密钥是否就绪、默认标记、每档预算） |
| POST | `/api/agent/models` | 新建/更新配置档案（`id`、`label`、`endpoint`、`model`、`key_env`、`defaults`）；**不接受密钥本身** |
| POST | `/api/agent/models/remove` | 删除档案（至少保留一个）；密钥在环境变量中不受影响 |
| POST | `/api/agent/models/roles` | 分配 `main`、`planner`、`worker` 角色；设置 `main` 时同步维护兼容字段 `default` |
| POST | `/api/agent/models/key` | 保存或清除本机模型密钥（`id`、`key`；空字符串表示清除）；响应只含 `key_present` / `key_source` |
| POST | `/api/agent/models/probe` | 探测单个档案的端点（`GET {endpoint}/models`，10s 超时、512 KiB 上限）；返回模型 ID 列表或错误 |
| POST | `/api/agent/chat` | 为当前项目快照创建并执行一个 Run（`goal`、`approve_egress`、可选 `profile_id`）；预算由所选配置档案的默认上限决定，页面不逐轮设置；未批准外发返回 412，已有 Run 在执行返回 409，同进程一次只允许一个 |
| GET | `/api/agent/model-channels` | 模型通道目录（内置通道与能力标签） |
| GET | `/api/agent/model-channels/{provider}/models` | 单个通道的模型列表 |
| GET | `/api/agent/model-catalog/lookup?model_id=` | 按模型 ID 查询能力、上下文窗口与价格；可选 `base_url` |
| GET | `/api/agent/runtime` | Agent 运行时状态与数据库配置（密钥只返回是否存在） |
| POST | `/api/agent/runtime` | 更新 Agent 会话库连接串与运行开关（无需重启） |
| GET | `/api/agent/runtime/quick` | 本机运行时一键启用状态 |
| POST | `/api/agent/runtime/quick` | 启用/停用本机运行时捷径 |
| POST | `/api/agent/orchestration` | 创建编排任务（planner/worker 角色、预算与目标） |
| GET | `/api/agent/orchestration` | 编排任务列表 |
| GET | `/api/agent/orchestration/detail?id=` | 单个编排任务、子 Run 与 step 明细 |
| POST | `/api/agent/orchestration/steer` | 向运行中的编排任务追加指令 |
| POST | `/api/agent/orchestration/stop?id=` | 停止编排任务及其子 Run |
| GET | `/api/authz` | 权限/越权控制清单：决策分布、逐入口决策、控制与过滤器链、覆盖与限制（`decision`、`q`、`limit`、`offset`） |
| GET | `/api/code-audit` | 多语言代码审计只读视图（`language`、`category`、`severity`、`q`、`limit`、`offset`）：规则集版本、分页发现、按语言/类别/严重度计数、语言覆盖、声明入口（≤200）、**符号索引 `symbols`/`calls`/`unresolved`（≤200）与 `symbol_languages`**、限制；新增 `file_partial`、`symbol_partial`、`finding_partial`、`rejected_files`（≤200，只含 `status=rejected`；文件摘要含 `scope=project|vendor|generated`）与 `rejected_scopes`；符号统计以 `coverage.symbols_found/calls_found/unresolved_found` 为全量；声明路由含 `path_status=declared|dynamic_unresolved`，变量路径以 `<dynamic>` 显式标记；**首次请求才触发分析并缓存结果**（进程内 + workspace `cache/code-audit/<snapshot>.<version>.json`，版本/快照不匹配将被忽略），后续请求命中缓存；`available=false` 时返回跳过原因且这些列表为空数组。不新增分析语义，`runtime_status` 恒为 `not_run` |
| GET | `/api/symbols` | 符号浏览器（`language`、`kind`、`q`、`limit`≤200、`offset`）：与 `/api/code-audit` 共用同一惰性分析和缓存，支持按语言、声明类型和名称/文件/容器关键词过滤；返回 `items`、`total`、`limit`、`offset`、`kinds`、`languages`、`partial`、`symbol_partial`；分析不可用时返回 `available=false` 和原因，不伪造结果 |
| GET | `/api/model` | Java 语义模型类型索引（`q`、`limit`、`offset`）；超过 2000 个 Java 文件或解析失败时 `enabled=false` 并给出原因。**额外返回已缓存的 `symbols`/`calls`/`unresolved`/`symbol_languages`/`symbol_partial`；`symbol_partial` 只反映符号轴，文件拒绝不影响它；未运行代码审计时返回 `symbol_reason=analysis_pending`，不主动启动分析，不伪造符号** |
| GET | `/api/model/type` | 单类型的声明、出向/入向调用边（`fqn`；边上限 200） |
| GET | `/api/config` | 当前模式、项目、路径配置、能力开关与分析状态；**不返回令牌** |
| POST | `/api/config` | 更新 `advisories_path`、`package_map_path`、`runtime_report`；校验失败返回 400 且不改动已存配置；成功后清空分析缓存（pinned 模式返回 409） |
| GET | `/api/projects` | 工作区项目注册表：当前摘要、已导入项目列表（来源、摘要、文件数、字节、导入时间） |
| POST | `/api/projects` | 导入并登记一个新项目，成功后切换并重新分析；返回登记条目 |
| POST | `/api/projects/select` | 切换到已导入项目（`hash`）；复用磁盘上的快照，不重新导入 |
| POST | `/api/projects/forget` | 从列表移除项目（`hash`）；**不删除快照文件**，当前项目拒绝移除（409 `project_active`） |
| GET | `/api/fs` | 目录选择器：只列子目录（`path`，缺省为用户主目录），不返回文件内容、不跟随符号链接、跳过隐藏目录、上限 500 项；Windows 额外返回盘符 `roots` |
| POST | `/api/analysis/rerun` | 丢弃缓存并立即重算，返回发现/入口/无控制入口/类型计数 |
| GET | `/export/report` | 下载确定性 HTML 审阅报告（见 §6；无时间戳、无外部资源） |
| GET | `/healthz` | 未认证探活（负载均衡/反向代理用），仅返回 `status/product/version`，不含分析或令牌状态 |

### 3.1 Agent 对话的启动参数

```bash
trident web --workspace .trident --agent-dsn "postgres://user:pw@127.0.0.1:5432/trident_test?sslmode=disable" \
  --enable-agent-chat --agent-token "$TRIDENT_AGENT_TOKEN" \
  --agent-endpoint https://api.deepseek.com/v1 --agent-model deepseek-v4-pro
```

- `--agent-token` 也可由 `TRIDENT_AGENT_TOKEN` 提供；令牌只用于进程内向数据库认证，不落盘、不返回给浏览器。
- 模型密钥有两个来源：启动环境变量，或在「设置 → 模型」里直接填写的本机密钥（`<workspace>/model_keys.json`，0600，经随机命名临时文件 + rename 写入）。本机密钥优先，清除后回退环境变量；两者都不回显，响应只有 `key_present` / `key_source`。`models.json` 只记录变量名。
- 端点必须是 https；http 仅允许 loopback（否则密钥会明文上路）。切换模型库不影响执行中的 Run：Run 创建时已固定端点、模型与预算。
- 关闭 `--enable-agent-chat` 时，`#/agent` 退化为只读时间线，不提供输入框。

`limit` 默认 50、最大 200；`offset` 最大 1,000,000；查询串与路径长度有上限。错误响应为 `{"schema_version":1,"code":"...","error":"..."}`：

- `401 unauthorized`：缺少/错误令牌；
- `403 missing_console_header`：缺少 `X-Trident-Request`；
- `400 invalid_request`：参数或游标非法；
- `404 not_found`：文件不在清单或 finding 不存在；
- `409 snapshot_integrity`：快照内容摘要不再匹配；
- `409 pinned_console`：当前以固定快照启动，不支持配置修改或项目导入；
- `409 no_project`：workspace 尚未导入任何项目，分析类路由不可用；
- `409 project_active`：试图移除正在分析的项目；
- `404 project_unknown`：项目不在工作区列表中；
- `413 limit`：超过快照工具预算；
- `500 analysis_failed`：分析失败（错误写入缓存，不逐请求重试）。

## 4. 分析缓存

1. 首次调用任一分析 API 时，在进程内运行 `sca.Inspect`、`audit.Inspect`、`findings.Analyze`、`authz.Analyze` 与 `javaast.Analyze` 各一次；成功后所有页面复用缓存。
1a. **多语言规则引擎是惰性分析**：`codescan.Analyze` 只在首次 `GET /api/code-audit` 时运行，结果（含跳过原因与失败）由 `codeMu` 独立缓存；概览、发现页和项目导入都不等它。原因：1084 个 PHP 文件的规则分析约 35 秒，把它放进同步首分析会让导入成功反馈一直转圈。受支持源码文件超过 1500 个时跳过并显示原因。
2. 缓存包含耗时和生成时间；失败作为终态缓存并返回 `analysis_failed`，下一进程启动才会重试，避免对固定快照重复消耗。
3. 分析期间的并发请求由互斥锁串行等待，只有一次实际分析。`POST /api/analysis/rerun`、`POST /api/config` 与 `POST /api/projects` 会清空缓存（含惰性可达性报告），下一次请求重新计算；pinned 模式下更换快照仍需重启。
4. `--advisories` 是调用者配置，不是快照内容；未提供时依赖页面与统一报告会明确显示未加载公告目录。

## 5. 审计访问日志（P2-2）

`--access-log <file>` 启用本地 JSONL 审计访问日志（追加写，`0600`，无轮转——轮转交给外部日志工具）。

- 记录范围：全部 `/api/` 与 `/export/` 请求，含未认证请求（`token_id` 为空字符串）；静态资源（`/`、`/assets/`）不记录。
- 行格式（每行一个 JSON 对象，UTC RFC3339 微秒时间）：

```json
{"time":"2026-11-14T09:00:00.123456Z","token_id":"alice","method":"GET","path":"/api/overview","status":200}
```

- 字段固定为 `time`/`token_id`/`method`/`path`/`status`；`path` 只记 URL 路径，不含查询串。
- **永不记录令牌明文或 Cookie 值**；`token_id` 是令牌文件中的身份标注（未认证为 `""`）。
- 写日志失败不阻断请求（best-effort，向 stderr 告警）；审计日志是访问痕迹而非安全边界，不得替代代理层审计。

## 6. 确定性报告导出（P2-2）

`GET /export/report` 返回 `text/html; charset=utf-8` 附件 `trident-report-<hash 前 12 位>.html`，用于团队审阅归档。

- **确定性**：同一快照 + 同一公告目录 + 同一二进制 → 输出字节一致。报告不含生成时间、分析耗时、进程启动时间或任何当前时刻；两次请求必须逐字节相同。
- **无外部资源**：不引用任何 `http://`/`https://` 资源、无外链脚本/样式/图片；样式为单个内联 `<style>`，全部动态文本经 HTML 转义。
- **内容**：快照信息（摘要、来源、清单/策略/工具版本、文件数与字节）、结论概要（状态计数与覆盖）、类别分布、逐发现明细（入口/组件/证据/假设/限制，按 finding ID 排序）、统一限制。`runtime_status` 恒为 `not_run` 原样保留。
- **不含**：访问者身份、令牌、访问日志或任何会话信息。报告与 `/api/report` JSON 同源，不新增分析语义。
- 非目标：PDF 导出、多快照对比、finding 状态流转（人工状态管理需要写入口，与只读边界冲突，明确不做）。

### 6.1 只读运维指标（P2-3 本地部分）

`GET /api/metrics` 返回 JSON 计数器快照（进程生命周期单调值；结构化日志为 §5 JSONL 审计日志与 stderr 告警）：

```json
{
  "product": "TRIDENT", "version": "...", "uptime_seconds": 0,
  "requests": {"total": 0, "unauthorized": 0, "forbidden": 0},
  "analysis": {"runs_total": 0, "cache_hits_total": 0, "failures_total": 0,
                "cached": false, "cached_ok": false, "last_duration_ms": 0, "last_error": ""}
}
```

- `requests` 只统计门禁层 `/api/` 与 `/export/` 请求（含拒绝）；`unauthorized`/`forbidden` 仅计中间件拒绝，handler 内部错误（如 `/api/session` 401）不计入。
- `analysis.runs_total` 为冷分析次数（含失败），`cache_hits_total` 为缓存命中次数，`cached`/`cached_ok` 反映终态缓存状态；`last_error` 为最后一次失败消息（与 API 错误同文，可能含快照内相对路径，不含令牌）。
- 端点受令牌 + console 头门禁；告警规则模板与采集方式见 [部署指南](deployment.md) §2.2。

## 7. 前端视图

| 路由 | 内容 |
|---|---|
| `#/projects` | 当前项目概览、目录选择器（浏览/上级/盘符）、手动路径导入、已导入项目列表（切换/移除）；无项目时为欢迎页 |
| `#/overview` | 快照摘要、11 个统计卡（含无控制入口、多语言审计与代码模型）、状态构成、覆盖门槛、10 类漏洞分布、限制 |
| `#/findings` | 状态/类别/关键字筛选、分页表格、证据抽屉（入口、数据流、证据、假设、限制）；零结果时明确说明本页只覆盖 Java/Spring、依赖与访问控制，并给出「代码审计」页入口 |
| `#/endpoints` | 方法、路径、控制器符号、权限决策、文件、参数绑定；按权限筛选；点击跳转源码 |
| `#/authz` | 决策分布（Java 端点）、按决策/关键字筛选的入口表、过滤器链、已识别控制与限制；多语言控制适配卡显示 PHP 请求脚本 / C# / Python / JS / Go 的文件级与脚本级词法证据 |
| `#/code` | 多语言代码审计：规则集版本 KPI、语言/类别/严重度/关键字筛选、发现表格（点击位置跳转源码）、可折叠 source→sink 证据流、7 语言覆盖、声明入口清单、限制与边界 |
| `#/model` | 类型检索与分页表；点击查看方法、字段与出向/入向调用边 |
| `#/settings` | 路径与分析：公告/package map/运行时报告配置、重新分析、导出与能力状态 |
| `#/settings/model` | 模型：端点与当前模型、端点模型列表（来自 `GET {endpoint}/models`）、设为当前、预算上限与检查点上限 |
| `#/agent` | Agent 对话：左栏是按快照隔离的会话列表（「全部项目」按钮传 `?hash=all` 取消过滤），右栏是消息流（模型正文、折叠的工具「过程」、最终结论与引用、终止原因），底部是目标输入、模型配置选择与逐轮外发批准；运行上限由所选条目的默认值决定（界面不再单列预算页）；未配置 `--agent-dsn` 时列出中文原因与启动示例，不显示空白页 |
| `#/dependencies` | 模块卡、依赖声明表、公告匹配、SCA 边界；导出 CycloneDX SBOM |
| `#/source` | 目录清单、路径前缀过滤、源码阅读、行号跳转、分页与字面量检索 |
| `#/about` | 构建/快照/工具链信息、只读 API 表、安全边界与限制 |

前端为无构建步骤的原生 HTML/CSS/JS，通过 `go:embed` 打包进单一二进制；无 npm、无 CDN、无外部字体或图片请求。样式只使用 CSSOM 设置动态宽度，CSP 不包含 `unsafe-inline`。

侧边栏可折叠为 64–68px 图标栏（状态存 `localStorage`），设置组可展开/收起；顶栏提供项目切换下拉，只列出工作区已导入项目。

无项目时前端停留在 `#/projects`，任何分析路由都会被重定向；顶栏导出按钮在无项目时禁用，底栏显示"未选择项目"。

## 8. 部署：TLS 反向代理与安全响应头

控制台只绑定 loopback；远程团队访问必须在**同一台主机**上加 TLS 终结反向代理（nginx/Caddy 等），把 `https://console.example` 反代到 `127.0.0.1:8787`。代理要求：

- 仅转发到数值 loopback 目标；强制 HTTPS，HTTP 请求 301 到 HTTPS；开启 HSTS。
- 不得剥离或覆盖应用安全响应头（CSP/`nosniff`/`DENY`/`no-referrer`/`CORP`/`no-store`）；可在其上追加头部，不可降低。
- 不得记录 `X-Trident-Token`、Cookie 或 Authorization 等请求头（nginx 默认不记录自定义头，保持默认；自定义日志格式不得加 `$http_x_trident_token`/`$http_cookie`）。
- 代理层访问日志可记录来源 IP 与时间，与应用层 JSONL 审计日志（无 IP、无令牌）互补。
- 反向代理不改变只读边界：控制台仍无写路由、无执行/修复入口；OIDC 仅以令牌文件 `role` 字段预留接口，不实现任何供应商。

## 9. 限制与非目标

- 只读控制台不改变 R2 分析能力：没有 Java AST、别名/指向分析、跨模块类型解析或运行时验证；新增的多语言规则引擎同样是受限词法前端，不做类型解析、跨过程污点或框架绑定。
- `/api/code-audit` 与 `#/code` 只展示 `audit code` 的静态结论，不提供规则编辑、执行、修复或运行时验证入口；规则外置只在 CLI 通过 `--rules` 生效。
- 控制台统一 finding 列表使用 `audit dataflow` v14 默认低噪声输出：无观察路径、通用 `unresolved_call` 边界与 MyBatis `#{}` 绑定不进入 finding 列表（记入 CLI 的 `coverage`）。发现数变少不等于项目更安全；需要 v1 语义或非入口 sink 锚点时分别使用 CLI 的 `--emit-unobserved` 与 `audit sinks`。
- 不提供多快照工作区、源码导入、任务管理、Agent 会话或工具审批。
- 不把入口注解当作已部署路由，不把公告精确版本命中当作可利用漏洞。
- `--advisories` 文件与快照摘要不绑定；更换公告目录不会自动刷新已有进程。
- 应用层只读不等于 OS 级不可变；持有令牌的本机用户仍可读取快照内全部允许文件。
- 不显示 Agent 会话不等于记录被删除：`--agent-dsn` 未配置时当前进程读不到会话库；会话默认按当前 `snapshot_hash` 过滤，切换项目后看不到其它项目的历史。两者都不是数据丢失。
- 「安全发现」页 0 条不是安全结论：该页是 Java/Spring + SCA + 访问控制的统一证据模型，非 Java 源码的规则发现在 `#/code`，且首次打开才会触发惰性分析。

## 10. 验收

1. `go test ./internal/webui ./cmd/trident -count=1`：令牌/头鉴权、Cookie 标志、CSP、资产目录拒绝、概览/发现/详情/入口/依赖/文件/检索/报告、路径遍历与缺失文件、并发缓存；多用户令牌文件（隔离、轮换、撤销、格式校验拒绝、互斥参数）、审计访问日志（字段、无令牌明文、未认证行）、导出确定性（两次字节一致、无外部 URL、无 ISO 时间戳）、`/healthz` 未认证探活与 `/api/metrics` 门禁计数器单调性。
2. `python scripts/test-web.py`：构建真实 CLI、导入合成快照、在随机 loopback 端口启动服务，验证登录与会话、全部只读 API、401/403/400/404 负例、报告下载、快照与样本字节级不变；`/healthz` 与 `/api/metrics` 字段与门禁断言；第二阶段以 `--tokens` + `--access-log` 启动第二个服务，验证多用户隔离（不同令牌不同 `token_id`）、轮换（旧令牌 401/新令牌 200）、`/export/report` 两次字节一致且无外部 URL/时间戳、JSONL 审计日志存在且不含令牌明文；全程不连接数据库、不调用模型、不执行 Java/Maven。
3. `python scripts/test-code-audit.py`：真实 Web 服务上验证**首次 `/api/overview` 不触发多语言分析**（`code.available=false` / `analysis_pending`）、`/api/code-audit`（发现总数、7 语言、运行时状态、语言筛选）、缓存后 `/api/overview.code` 与 CLI 报告对齐、未配置 Agent 库时的中文 412 提示。
4. 人工浏览器检查只用于视觉与交互，不作为安全验收的替代。

## 11. 实际结果

### 2026-11-13（初版单令牌控制台）

- `go build ./...`、`go test ./... -count=1`、`go vet ./...`：通过（含 `internal/webui` 7 项与 `cmd/trident` 2 项新测试）。
- `go test ./internal/webui -count=1 -v`：7 项通过（鉴权、资产与安全头、会话 Cookie、概览与发现、入口与依赖、文件/检索/报告、并发缓存）。
- `go test ./cmd/trident -run 'TestValidateLoopbackAddr|TestRunWebRejectsUnsafeArguments' -count=1 -v`：通过。
- `python scripts/test-web.py`：通过；仅 loopback、无需数据库/模型；快照与 fixture 前后 SHA-256 字节级一致。
- 回归：`test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py` 全部通过且分析计数不变；`test-local.py`（真实 PostgreSQL）、`test-agent.py`（loopback 非真实 LLM，Run 28/29）与 `test-linux.py`（`-race -tags=integration -p 1 ./...`）通过。
- 浏览器人工检查：登录页、概览、发现列表与证据抽屉、入口、依赖、源码阅读与检索、820px 响应式布局；无控制台错误。390px 移动截图因浏览器工具超时未采集，不据此声称移动端已验证。
- 未运行：真实外部模型、Java/Maven/JUnit、运行时漏洞验证、多用户并发压力测试、HTTPS/TLS 终止、操作系统级快照隔离。

### 2026-11-14（P2-2 多用户令牌、审计日志与确定性导出）

- `go build ./...`、`go vet ./internal/webui ./cmd/trident`、`go test ./internal/webui ./cmd/trident -count=1`：通过；`internal/webui` 新增 3 项测试（令牌文件轮换与审计日志、令牌文件格式校验拒绝、导出确定性）。
- `python scripts/test-web.py`：通过，第二阶段（`--tokens` + `--access-log`）验证多用户隔离（alice/bob/carol 各自 `token_id`）、轮换（alice 换新哈希后旧令牌 401、新令牌 200）、撤销（bob 删除即 401）、`/export/report` 两次请求跨用户字节一致且无 `http://`/`https://`/ISO 时间戳、JSONL 审计日志字段固定且不含任何令牌明文；快照与 fixture 字节不变。
- 未运行：真实 TLS 反向代理（nginx/Caddy）联调、OIDC 接入（仅预留 role 接口）、浏览器人工复核新按钮视觉（导出按钮复用既有下载管线与按钮样式）。

### 2026-11-14（P2-3 本地部分：/healthz、只读指标与告警模板）

- `go test ./internal/webui ./cmd/trident -count=1`：通过；新增 `metrics_test.go`（`/healthz` 未认证 JSON 探活、`/api/metrics` 401 门禁、请求/拒绝/分析冷热计数器单调性）。
- `python scripts/test-web.py`：通过，新增 [04] 断言（`/healthz` 字段、`/api/metrics` 401 与字段集、`cached/cached_ok/runs_total`）；八项 PASS 全绿，快照与 fixture 字节不变。
- 未运行：真实 Prometheus/Alertmanager 采集与告警触发（模板为文档形态）、生产备份演练与 RTO/RPO（需真实生产设施）、长时进程内存/句柄观测。

### 2026-11-15（P0-5 多语言代码审计视图）

- 新增 `GET /api/code-audit`（只读筛选/分页）、`/api/overview.code` 摘要与 `#/code` 页面；当时在首分析里同步跑一次有界 `codescan.Analyze`，超 1500 个受支持源码文件时跳过并显示原因，失败不影响其它页面。（**该同步设计在 2026-11-15 后续诊断中改为惰性**，见下一节；此处保留当时事实。）
- `python scripts/test-code-audit.py` 在真实 Web 服务上验证：发现总数与 CLI 报告一致（25 条）、7 语言覆盖、`runtime_status=not_run`、语言筛选只返回 PHP、`/api/overview.code.findings` 对齐；`python scripts/test-web.py` 9 项既有验收无回归。
- 浏览器实测（Edge，本机 loopback）：`#/code` 渲染 25 行发现、7 语言覆盖、24 条声明入口、12 条限制与规则集版本；语言筛选切到 PHP 后 5 行且全部为 PHP；证据流折叠显示 `$_GET → mysql_query` 与 4 个传播步骤；控制台除既有的 `/api/agent/threads` 412（未配置 Agent 库）外无新增错误。
- 未验证：真实多语言项目的页面规模表现；规则外置仍只在 CLI 通过 `--rules` 生效。

### 2026-11-15（真实 PHP 项目使用反馈与修复）

- **现象**：用户以 `trident.exe web --token ... --workspace .trident` 启动并导入 `D:\Code\PHP\www\www.test.com`（1084 文件 / 42 MB 快照）后，导入页一直转圈、不显示成功；「安全发现」页 0 条；重启后看不到之前项目的 Agent 对话。
- **实测根因**：导入本身成功（`.trident/projects.json` 已有条目），但 `importProject()` 把成功提示放在 `await ensureOverview(true)` 之后，而首分析里的 `codescan.Analyze` 对该快照耗时 **35.4 秒**（其余分析均 <0.5 秒）。「0 条」是因为统一证据模型只覆盖 Java/Spring/SCA/访问控制；同一快照的 `audit code` 实际有 **22 条**静态发现（21 PHP + 1 JS，`partial=true`，694/1084 文件被扫描）。Agent 会话不可见是因为启动没带 `--agent-dsn`，且 `handleAgentThreads` 默认按当前 `snapshot_hash` 过滤。
- **修复**：`codescan.Analyze` 移出同步首分析，改为 `codeMu` 保护的惰性缓存（首次 `/api/code-audit` 才运行，结果/跳过原因/失败都缓存）；概览 `code` 摘要未运行时为 `analysis_pending` 且不触发分析；导入成功立即 toast 并恢复按钮、不再等待首分析；findings 零结果提示明确指向 `#/code`；概览卡片改为「点击运行（非 Java 项目看这里）」；`#/code` 首次加载显示「可能需要数十秒」；Agent 会话支持 `?hash=all` 与「全部项目」按钮，未配置 DSN 时显示中文原因与启动示例。
- **实测结果（临时 8798 端口、pinned 同一快照）**：首次 `/api/overview` 0.06 s 且 `code.available=false`；`/api/code-audit` 35.68 s、22 条、`partial=true`；再次 `/api/overview` 0.00 s 且 `code.findings=22`；`/api/agent/threads` 412 带中文说明。Edge 浏览器实测 `#/findings` 提示与跳转按钮、`#/code` 22 行、`#/agent` 中文提示与「全部项目」按钮均正常，除预期 412 外无新增控制台错误。
- **回归**：`go test ./...`、`test-web.py`、`test-code-audit.py`（新增惰性/会话提示断言）、`test-java-mainline.py` 与离线全量门禁全绿。
- **边界**：22 条是静态证据不是已确认漏洞，其中多条位于 `extend/PHPExcel` 第三方库；`partial=true` 表示部分文件因字节/token 预算被拒绝。0 条与 22 条都不是安全结论。用户数据（`.trident`）全程只读，未修改其正在运行的进程。

### 2026-11-15（续）：发现页合并多语言发现与取消污染修复

- **用户二次反馈**：换新二进制后「安全发现」页仍 0 条——这是信息架构缺陷：多语言发现只在 `#/code`，用户的主视图永远是"零发现"。
- **修复一（发现页合并）**：`GET /api/findings` 与 `/api/finding?id=` 现在把惰性多语言报告经 `codescan.AsFindingsReport`（ID 前缀 `code:`）合并进结果；`findingSummary` 新增 `location`（无 endpoint/component 的发现取 sink 证据的 `file:line`）；前端行渲染与空状态、类别下拉同步。合并会触发惰性分析，发现页首次加载显示"正在合并…可能需要数十秒"。概览 `counts` 保持 Java 统一模型口径，多语言计数在 `code` 摘要与 `#/code` 页。
- **修复二（取消污染，本次真正根因）**：浏览器刷新/切页取消 HTTP 请求后，`codescan.Analyze` 返回 `context canceled`，旧实现把它作为**终态失败缓存**，报告被冻结为 0 条直到重启。修复：`codeAudit` 用 `context.WithoutCancel` + 10 分钟超时在后台继续跑完并缓存；`context.Canceled` 不缓存（可重试）；真实失败与耗时输出到 stderr。回归测试 `TestCodeAuditSurvivesRequestCancellation` 覆盖。
- **实测（pinned PHP 快照，新进程）**：取消场景——首请求 2 秒被客户端取消，重试请求 41.2 秒返回 22 条，第三次 0.01 秒缓存命中；干净场景 43.5 秒返回 22 条；Edge 浏览器发现页等待约 26 秒后渲染 `22 / 22 条 · 静态确认 22`，位置列显示 `public/.../ZeroClipboard.js:832` 与规则 ID。`test-web.py`、`test-code-audit.py`（新增 `/api/findings` 合并与详情断言）、`test-java-mainline.py`、`webui_test.go`（确认列表 1→2 条）、离线全量门禁全绿。
- **注意**：`java-maven` 合成样本的多语言发现为 0，故既有计数断言不变；`webui_test.go` 的确认列表断言由 1 条改为 2 条（dataflow + code），属语义变化的预期更新，已在本文与 `docs/development-progress.md` 记录。
- **注意**：`java-maven` 合成样本的多语言发现为 0，故既有计数断言不变；`webui_test.go` 的确认列表断言由 1 条改为 2 条（dataflow + code），属语义变化的预期更新，已在本文与 `docs/development-progress.md` 记录。

### 2026-11-15（续二）：Agent 会话库连接持久化，默认开启

- **需求**：用户不想每次启动都拼 `--agent-dsn`。实现为三层解析：`--agent-dsn` 显式参数 > workspace 持久化 `agent_dsn`（`console.json`，0600，git 已忽略）> 环境变量 `TRIDENT_AGENT_DSN`。设置页新增「Agent 会话库」输入框：保存前先真连库校验（失败 400 并保留旧值），成功即热替换观察库并持久化；「清除已保存的连接」恢复未配置态。保存 DSN 不再清空分析缓存（仅路径字段变化才重算）。
- **降级语义**：显式命令行 DSN 连接失败仍 fail-fast；持久化/环境 DSN 连接失败**不再阻止启动**——`/api/agent/threads` 返回 503 `agent_database_unreachable` 带中文原因，设置页显示失败详情，其余页面不受影响。修复 `handleConfigUpdate` 在仅保存 DSN 时丢弃 40 秒分析缓存的问题。
- **实测**：用户 workspace `console.json` 已写入真实 DSN；起临时实例（`--workspace .trident`，无任何 DSN 参数）后 `/api/agent/threads?hash=all` 返回 **52 条历史 Run**（含 Run 43/46 Spring 项目审计、Run 48 CodeScan-Artex）；Go 回归 `TestWorkspaceAgentDSN`（降级/校验拒绝/清除/热替换/持久化回读）、`TestExplicitAgentDSNFailureStopsStart`（显式失败仍 fail-fast）、`TestWorkspaceWithoutAgentDSNReportsPrecondition` 全绿；`test-web.py`、`test-code-audit.py`、`test-java-mainline.py`、`go test ./...`（23 包）与离线全量门禁通过。
- **安全边界**：`console.json` 含数据库凭据，仅限本机使用；不得提交（`.trident/` 已在 `.gitignore`）；导出报告与日志不含 DSN。`workspaceFile` 新增字段对旧二进制读取新文件不兼容（`DisallowUnknownFields`），升级需整组替换二进制。

### 2026-11-15（续三）：概览与发现页计数同步

- **用户反馈**：概览「安全发现 0」与发现页 22 条不一致。
- **修复**：`/api/overview` 在多语言报告已缓存时把它合并进同一套计数——`counts`、`severities` 与「发现构成」，类别归属用规则类目（`xss`/`sql`/…）映射到既有类别卡；报告未运行前，概览前端在后台触发惰性分析并在完成后**自动重渲染本页**（不阻塞首屏，无需手动刷新），多语言卡片显示「正在后台运行，完成后本页自动同步」。
- **实测**：Edge 打开概览首屏 counts=0，约 29 秒后台分析完成后页面自动变为 hero 22 / 安全发现 22（静态确认 22）；除既有的 Agent 未配置 412 外无新增控制台错误。Go 回归 `TestOverviewMergesCachedCodeFindings`（counts 3→4、SQL 类别 1→2）。
- **口径说明**：Java 统一模型发现与多语言规则发现现在共用「安全发现」一套计数；`/api/overview` 首屏在多语言分析运行前显示的是基础口径，前端会自动补齐。java-maven 样本多语言发现为 0，既有断言不变。

### 2026-11-15（续四）：顶栏美化

- **runtime 徽章**：`runtime_status = not_run` 裸英文徽章改为「🛡 静态证据 [not_run]」——盾牌图标 + 中文语义 + 等宽小字标签，暗/亮两套配色，悬停显示完整解释（未运行代码、未发请求、静态确认不等于可利用）。语义不变，可读性提升。
- **项目切换**：原生 `<select>`（option 无法定制）替换为自定义下拉：胶囊触发按钮（当前项目名 + 旋转箭头），展开为卡片列表——项目名、hash 短码、文件数/体积、当前项「当前」标记或「切换」动作，底部「管理项目」入口跳 `#/projects`；点击外部或 Esc 关闭，`aria-expanded`/`role=listbox` 语义保留，暗/亮两套配色。切换逻辑与既有 `selectProject` 流程一致。
- **验证**：`node --check`、`go build` 通过；Edge 实测暗/亮两主题的徽章与展开列表渲染正确（3 个项目、当前项标记、管理入口）；`test-web.py`、`webui/cmd` 单测无回归。服务已用新二进制重启并完成预热（22 条发现秒开）。

### 2026-11-15（续五）：构建版本展示精简

- **用户反馈**：「边界与关于」页底部的产品版本串把 24 个能力切片（工具名）拼成一行超长文本，冗余且重复。
- **修复**：`productVersion` 拆分为两部分——`productVersion = "0.2.0-p0.6"`（简洁构建号，控制台界面与侧边栏底部只显示它）与 `productCapabilities`（完整能力切片清单，仅在 `trident version` CLI 输出，第二行 `capabilities:`）。构建号主版本从停留在 `p0.2` 的旧值对齐为 `p0.6`（对应 P0-5 多语言代码审计与 P0-6 Java 主线两块能力），能力清单同步更新 `r2-source-sink-flow-v14` 与 `multi-language-code-audit`。
- **保留**：「分析工具链」卡片仍逐引擎列出完整 `tool_version`（findings/sca/audit/dataflow）——这是可复现性披露，与拼接串不同。
- **验证**：`trident version` 输出两行；Edge 实测「产品与构建」卡与侧边栏底部均为 `0.2.0-p0.6`；`cmd/trident`、`internal/webui` 单测无回归（无任何测试/文档断言旧拼接串）。

### 2026-11-15（续六）：Agent 与控制台分析融合

- **缺口**：Agent 的 `list_findings` 工具只集成 findings/sca/audit（Java 统一模型），看不到多语言代码审计发现——PHP 项目在 Agent 眼里就是"零发现"，与发现页割裂。

### 2026-11-15（续十一）：代码审计 v2 + Agent 配合度增强

**Agent 工具面**（`internal/tools`，Agent Run 与控制台共用）：
1. `list_findings`/`trace_dataflow` 新增 `language` 过滤（code: 发现取规则报告语言、Java 统一模型为 `java`）；`q` 匹配范围加入 `location`（`file:line`），Agent 可按文件名筛发现；分页上限 10 → 25；`counts` 增加 `language_<name>` 分布。
2. **category 过滤修复**：`code:` 发现此前只按 kind 映射匹配（`php.sql.query` 永远匹配不到 `category=sql`），现在按规则类别双匹配——`category=sql` 同时命中 `sql_injection` 与 `php.sql.query`。
3. **新工具 `list_rules`**：内置规则集摘要（id、语言、类别、CWE、严重度、模式计数），支持 `q`/`category`/`language` 过滤；明确披露规则是名字模式不是语义分析、不列调用者规则文件。
4. 工具定义总数 9 → 10（`TestDefinitionsFixedReadOnlyAndIndependent`、loop 工具数断言同步）。

**代码审计引擎 v2**（详见 code-audit-contract §10）：插值字符串感知（PHP 双引号/Python f-string/C# `$""`/JS-TS 反引号，`fromString` token 只能作 source/sanitizer）、同文件函数摘要（source/sink 包装、taint-through，一层、精确简单名、512/文件上限）、新增开放重定向与 XPath 共 8 条规则（内置 50 → 58）。`analysis_kind=multi_language_code_audit_v2`，`ruleset_version=trident-core-rules-2026-11-15-v2`。fixture 新增 11 条 v2 正例与负例，验收 36 条正例 + 负例零误报 + 字节确定性全绿（`test-code-audit.py` 11 组）。

### 2026-11-15（续十二）：多 Agent 编排（三角色 + 探索图）

参考 CodeScan-Artex 的三角色编排，按 TRIDENT 治理模型重构（契约见 [多 Agent 编排契约](agent-orchestration-contract.md)）：

- **新页面 `#/tasks` + API**：`POST /api/agent/orchestration`（创建并启动）、`GET /api/agent/orchestration`（列表）、`GET /api/agent/orchestration/detail?id=`（图全量）、`POST /api/agent/orchestration/steer`（hint/intent/goal/constraint 操舵，仅 `created`/`running` 任务接受）、`POST /api/agent/orchestration/stop`。编排与手动 Run 互斥（`orchestration_busy` / `agent_chat_busy`）；跨进程另有数据库级单 running 约束（migration 006）。
- **存储**：迁移 `005_agent_orchestration.sql`（orchestration_tasks/nodes/edges/constraints，复用 agent_dsn 同库）；Planner/Worker 会话仍是普通 `agent_runs`——预算、CAS、checkpoint、引用验证全部继承，工具面零新增写工具。
- **引擎**（`internal/orchestrator`）：事件顺序循环——Planner 轮读预取态势（触发事件 + 图总览拼进 goal）→ 终局 JSON 的 `intents/goal_proved` 由引擎解析写图 → 并发 Worker（默认 2）领意图 → 完成/写回 → 下一轮。图写回权在引擎：LLM 只在终局 JSON 声明，引用覆盖验证不过则 Run 失败，绝不落图。
- **FinalEnvelope v3**：可选 `intents`/`goal_proved`/`facts`/`candidates`（手动单 Run 不带，行为不变）；facts 必须带 observed/inferred 置信度与真实读过的引用。Agent 产出一律是 `finding_candidate`（候选），不升级引擎三态。
- **Settlement 收尾轮**：`agent.Config.SettlementEnabled`（编排会话开启）。剩余恰好 1 次模型调用时注入固定收尾消息（哨兵 `[SETTLEMENT]` 防重复），该轮禁发工具，模型把已获观察写回终局 JSON——防烂尾且不超预算。手动 Run 默认关闭。
- **诚实边界**：无心跳唤醒/steer_work 中途纠偏/独立复核会话（后续切片）；候选发现靠人+引擎三态确认；真实模型下的多轮收敛质量未验证，scripted 测试只证明机制。
- **修复**：`AnalysisOptions.CodeReport` 绑定控制台已缓存的 `codescan` 报告（`c.codeAudit` 缓存，Agent 复用而非重算 40 秒）；`analysisState` 把它经 `codescan.AsFindingsReport` 合并进 `list_findings`，`findingView` 新增 `location`（sink 证据 file:line），`trace_dataflow` 明确排除 `code:` 前缀发现（不冒充数据流证据），工具描述同步。发现详情抽屉新增「问 Agent」：预填带 finding ID 与位置的复核目标到 `#/agent` 的目标框（引用证据行、标注 UNVERIFIED INFERENCE 的提示词模板）。
- **回归**：`TestAnalysisToolsMergeCodeFindings`（合并/位置/计数/trace_dataflow 隔离）；`tools`、`webui`、`agent` 包全绿。

### 2026-11-16：模型库 v2（渠道目录 / 能力价格 / 角色槽位）

契约见 [模型库与角色解析契约](model-library-contract.md)。`models.json` 升级到 schema 2（读取 schema 1 自动按缺省升级，写回即 v2）：

- **渠道目录**：`GET /api/agent/model-channels`、`GET /api/agent/model-channels/{provider}/models`、`GET /api/agent/model-catalog/lookup?model_id=&base_url=`。目录是编译期离线快照（10 个渠道，含协议/端点/模型/能力/价格），不联网同步；界面明示「离线快照」，条目可覆盖。
- **条目字段**：新增 `api`（当前只接受 `openai-completions`：控制台只实现该适配器，其他协议在旧文件中保留展示但拒绝运行）、`capabilities{context_window,max_output,reasoning,vision}`、`cost{input,output,cache_read,cache_write}`（美元/百万 token，整组缺省表示未声明）。缺省不猜：能力为 0 显示「未声明」，价格为 nil 显示「价格未声明」。
- **角色槽位**：`roles{main,planner,worker}` + 服务端 `resolved`（含 `followed_main`）。`main` 不能 `follow-main`；`planner`/`worker` 默认跟随主模型。删除被角色显式引用的条目返回 409 `profile_in_use`，`details.roles` 列出角色。`POST /api/agent/models/roles` 改分配。
- **探测归因**：`POST /api/agent/models/probe` 增加 `ok/status/latency_ms/api`，`status` ∈ key_missing / auth / not_found / upstream / network / protocol / empty；统一 `GET {base}/models` + Bearer，拒绝跨主机重定向；结果仍是会话内瞬态，不落库。
- **成本估算**：`GET /api/agent/steps` 增加 `usage`（input/output tokens、estimated_cost_usd、pricing_source、note）。只统计 `model.completed` 步骤里 `usage.known=true` 的用量；条目缺失或未声明价格时输出 null 并说明原因，不写 0。未做跨 Run 汇总（需 input/output 分项落库）。
- **会话级覆盖**：对话页模型选择新增「跟随默认（主模型）」；显式选择作为本次 Run 覆盖，按项目存浏览器本地，不写回模型库。编排任务创建窗口的 profile 覆盖同时作用于 Planner/Worker。
- **边界**：目录价格是离线快照，可能与厂商现价不一致；能力声明不做探测验证；密钥可本机保存（0600，优先于环境变量），前端只见 `key_present` / `key_source`；无 AI 守门/LLM 复核角色（产品没有这些会话）。

### 2026-11-16（续二）：Agent 运行时配置（无需重启）

契约见 [Agent 运行时配置契约](agent-runtime-contract.md)。启动参数不再是唯一入口：

- **设置页新增「Agent 与编排」卡片**：启用开关、会话库连接串、主体令牌、清除按钮；保存后立即重建写库会话与编排引擎，无需重启。
- **API**：`GET/POST /api/agent/runtime`。启用前真实打开数据库并校验令牌，失败不落盘；有 Run/编排运行时 409。响应只返回 `dsn_target`（host/db 掩码）与 `token_stored` 布尔，永不回显凭据。
- **持久化**：`console.json` 新增 `agent_token`、`agent_chat_enabled`（0600）；启动参数仍优先于持久化值；`TRIDENT_AGENT_DSN` 作为 DSN 回退。
- **语义**：关闭开关会关闭写库会话与编排引擎，观测库在 DSN 保留时继续可读；清除令牌/连接会同时停用。已运行的 Run/编排不受影响，也不会热切换。
- **边界**：启用不等于可运行，仍需模型库中有主模型与密钥；固定快照模式拒绝修改；数据库凭据轮换需在设置里更新。

### 2026-11-16（续三）：消除残留的「必须重启」引导

- **提示统一**：所有「未配置」入口改为指向设置页并注明无需重启——`agent_database_missing`（`/api/agent/threads`、`/api/agent/conversations`、`/api/agent/steps`）、`orchestration_disabled`、公告未加载横幅、可达性未启用页、Agent 会话列表空态、API 清单说明。启动参数示例保留为「也可以」的次要路径，不再作为唯一解法。
- **固定快照模式**是唯一仍需重启一次的情形（要换成 `--workspace` 启动）；相关文案改为明确说明「启动一次后即可在设置页随时修改，之后无需再重启」，不把运行模式限制伪装成配置限制。
- **设置页 DOM 修复**：「分析配置」卡多一个 `</div>` 导致「仅重新分析」按钮与公告计数被挤出 `.form-row`；去掉提前闭合标签，按钮回到同一行。
- **回归**：`TestUnconfiguredAgentHintsPointToSettings` 锁定文案不再出现 `--agent-dsn`、`重启即可`、`start the console`；Playwright 重载后断言两个按钮同父节点，且当前页面无新增 CSP 内联样式报错。

### 2026-11-16（续四）：一键启用（quick setup v1）

契约见 [Agent 运行时配置契约](agent-runtime-contract.md) §8，版本 `agent_runtime_quick_setup_v1`。手动填 DSN、去 `secrets/` 翻 64 位令牌、理解 `principals`/role 的成本过高，因此：

- **设置页主操作改为「一键启用」**：卡片顶部显示三个检测状态（会话库已连接 / 主体令牌可用及 role / 主模型密钥可用），原开关、DSN、令牌、保存与清除按钮收进 `<details>`「高级设置」。已启用时主按钮变为「停用 Agent 与编排」。
- **API**：`GET /api/agent/runtime/quick` 只读探测；`POST /api/agent/runtime/quick` 无请求体，重新探测后走与手动表单**完全相同**的校验/落盘/热替换链（`applyAgentRuntimeRequest`）。停用仍走 `POST /api/agent/runtime {enabled:false}`。
- **探测范围**：DSN 取 `console.json` 已存值或 `TRIDENT_DATABASE_URL`；主体取已存令牌或 `<workspace>/secrets/`、`父目录/secrets/` 下 `*.json` 的 `token` 字段，逐个 `Authenticate` + 只读 `DescribePrincipal` 校验 `active / human / admin|scheduler`。不猜 DSN、不启容器、不建主体、不自动启用。
- **安全**：响应只回布尔、掩码目标与 role，永不回显 DSN/密码/令牌/subject/路径；探测错误用固定文案；POST 不信任 GET 结果，重新真实连接与认证，失败不落盘。
- **回归**：`agent_runtime_quick_test.go` 6 个用例（凭据不回显、无候选不误报、本机 secrets 扫描与优先序、不可用不落盘、pinned/busy 409、探测成功但真实 DSN 失败时不落盘）。

### 2026-11-17：C1–C7 前后端契约

- **`GET /api/code-audit`**：响应增加 `variables`（最多 200 条）、`string_constants`（最多 200 条，只含 SHA-256/长度，不含原文）；`coverage` 增加 `calls_resolved`、`variables_found`、`string_constants_found`；`routes[]` 增加 `source`、`target`，`path_status` 可为 `declared | dynamic_unresolved | convention_candidate`；ThinkPHP 动态路由在快照无 `urlconfig` 行时 `reason=database_urlconfig_absent`。缓存版本为 `p3.1`。
- **`GET /api/dependencies`**：`report.manifests[]`、`report.project.ecosystems[]`、`dependencies[].ecosystem/name/manifest`；`version_status` 为 `resolved | range | missing | unknown`。非 Maven 依赖使用 `name`，页面同时显示 `group_id:artifact_id` 与生态 chip。
- **`GET /api/authz`**：`language_adapters[]` 只保留**入口级**证据，每条含 `language/framework/file/line/symbol/control/requirement/decision/reason/entry_kind`，`decision` 为 `protected | public | unprotected | unknown`，`entry_kind` 为 `application_entry | request_script | route_declaration`。PHP 请求脚本另含 `scope=request_script`、`control_line`、`matched_controls`。未附着到入口的文件级观测移到顶层 `file_evidence[]`（`file_evidence_total` 为条数），不进入入口统计。新增 `language_counts[]`：固定 7 语言（java/php/csharp/python/javascript/typescript/go），每条含 `protected/public/unprotected/unknown/total/file_evidence`；`java` 行复用顶层 `counts`（Java 端点），非 Java 行只统计入口级适配器。这是文件级词法证据，不并入 Java 端点决策，也不代表已执行框架中间件。
- **`GET /api/reachability`**：删除未配置 package map 时的 412；始终返回有界报告。非 Java 结果带 `language`、`ecosystem`；`reachable` 仅表示含路由/handler 的文件内出现导入。
- **`GET /api/endpoints`**：统一入口 `entries[]` 带 `source`、`path_status`、`target`；`kind=request_script` 的条目带 `authz`（`decision/requirement/reason/matched_controls/runtime_status=not_run`），`application_entry` 不附着脚本鉴权。框架约定候选被统一入口过滤，数据库展开路由保留 `reason=database_urlconfig_row`。
- **Agent 工具**：`inspect_dependencies` 增加 `manifests[]`，公告路径/目录来自运行中的控制台配置；`query_endpoints` 在存在代码报告时消费统一入口证据。
- **UI**：代码页新增调用解析/变量/字符串/路由来源；依赖页新增生态、清单表；可达性页新增生态与语言覆盖；权限页新增多语言控制适配卡片。
- **验收**：`scripts/test-web.py` 改为断言 `/api/reachability` 200 + `language_files_scanned`；`go test ./...`、`go vet ./...`、`node --check`、两份验收脚本均通过。