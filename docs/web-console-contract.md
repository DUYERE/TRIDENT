# 只读 Web 分析控制台契约（R2 第十三片）

## 1. 定位与状态边界

`trident web` 为一个已 pin 的本地源码快照提供只读分析控制台。它复用 `project`、`sca`、`audit`、`dataflow`、`findings` 的既有实现，不新增分析语义，也不改变任何 finding 的静态/运行时状态。

- 不做：导入新源码、执行 Java/Maven/JUnit、调用模型、访问目标网络、创建 Run、审批或执行工具、写入原目录、修改快照。
- 不提供 Agent 控制 API；控制台只有只读查询和证据下载。**HTTP 分析控制台的存在不等于开放远程执行平面。**
- 页面上的 `runtime_status` 恒为 `not_run`；静态确认、`inconclusive` 和 `refuted` 的含义与 CLI 完全一致。未观察到的路径不是安全证明。

## 2. 启动与鉴权

```bash
trident web --snapshot <dir> --snapshot-hash <sha256> \
  [--advisories <local-advisory.json>] \
  [--addr 127.0.0.1:8787] \
  [--token <value> | --tokens <file>] \
  [--access-log <file>]
```

1. 必须提供既有快照与外部可信摘要；`webui.New` 使用 `project.Open` 重新校验清单，失败即退出。
2. `--addr` 只接受数值 loopback 地址或 `localhost`；通配地址、私网地址和外部域名一律拒绝。默认 `127.0.0.1:8787`。
3. 未提供 `--token` 时生成 48 位十六进制令牌并仅在启动终端打印一次。令牌不写入快照、日志或前端资源。
4. `--token` 与 `--tokens` 互斥，同时提供即拒绝启动。
5. 浏览器登录使用 `POST /api/session`，成功返回 `Set-Cookie: trident_console=...; HttpOnly; SameSite=Strict; Path=/`，有效期 8 小时。脚本可使用 `X-Trident-Token` 请求头。
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
| POST | `/api/session` | 用访问令牌换取 HttpOnly 会话 Cookie；仅接受 `{"token":"..."}` |
| GET | `/api/health` | 进程、快照摘要、分析是否已缓存；不触发分析 |
| GET | `/api/overview` | 快照清单、覆盖计数、类别分布、工具版本与限制 |
| GET | `/api/findings` | 支持 `status`、`category`、`q`、`limit`、`offset` 的发现摘要 |
| GET | `/api/finding?id=` | 单一发现完整证据、假设与限制 |
| GET | `/api/endpoints` | 支持 `q`、`limit`、`offset` 的入口清单 |
| GET | `/api/dependencies` | Maven 声明级 SCA 报告（模块、依赖、公告匹配、覆盖） |
| GET | `/api/files` | 快照清单分页（`prefix`、`limit`、`cursor`） |
| GET | `/api/file` | 逐行读取（`path`、`start_line`、`limit`、`cursor`），完整校验 SHA-256 |
| GET | `/api/search` | 快照内区分大小写字面量检索（`q`、`prefix`、`limit`、`cursor`） |
| GET | `/api/report` | 下载与 `trident audit findings` 相同的统一证据 JSON |
| GET | `/api/sbom` | 下载与 `trident sca sbom` 相同的 CycloneDX 1.5 JSON |
| GET | `/api/metrics` | 只读运维指标（进程生命周期计数器，见 §6.1；令牌门禁） |
| GET | `/metrics` | Prometheus 文本格式 0.0.4 抓取端点（同一组计数器；令牌门禁，接受 `Authorization: Bearer`，豁免 console 头；指标名与 `docs/deployment.md` §2.2 告警规则对齐） |
| GET | `/export/report` | 下载确定性 HTML 审阅报告（见 §6；无时间戳、无外部资源） |
| GET | `/healthz` | 未认证探活（负载均衡/反向代理用），仅返回 `status/product/version`，不含分析或令牌状态 |

`limit` 默认 50、最大 200；`offset` 最大 1,000,000；查询串与路径长度有上限。错误响应为 `{"schema_version":1,"code":"...","error":"..."}`：

- `401 unauthorized`：缺少/错误令牌；
- `403 missing_console_header`：缺少 `X-Trident-Request`；
- `400 invalid_request`：参数或游标非法；
- `404 not_found`：文件不在清单或 finding 不存在；
- `409 snapshot_integrity`：快照内容摘要不再匹配；
- `413 limit`：超过快照工具预算；
- `500 analysis_failed`：分析失败（错误写入缓存，不逐请求重试）。

## 4. 分析缓存

1. 首次调用任一分析 API 时，在进程内运行 `sca.Inspect`、`audit.Inspect` 与 `findings.Analyze` 各一次；成功后所有页面复用缓存。
2. 缓存包含耗时和生成时间；失败作为终态缓存并返回 `analysis_failed`，下一进程启动才会重试，避免对固定快照重复消耗。
3. 分析期间的并发请求由互斥锁串行等待，只有一次实际分析。快照不可变，因此不提供“刷新分析”按钮；更换快照需重启控制台。
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
| `#/overview` | 快照摘要、8 个统计卡、状态构成、覆盖门槛、10 类漏洞分布、限制 |
| `#/findings` | 状态/类别/关键字筛选、分页表格、证据抽屉（入口、数据流、证据、假设、限制） |
| `#/endpoints` | HTTP 方法、路径、控制器符号、参数绑定、路径状态；点击跳转源码 |
| `#/dependencies` | 模块卡、依赖声明表、公告匹配、SCA 边界；导出 CycloneDX SBOM |
| `#/source` | 目录清单、路径前缀过滤、源码阅读、行号跳转、分页与字面量检索 |
| `#/about` | 构建/快照/工具链信息、只读 API 表、安全边界与限制 |

前端为无构建步骤的原生 HTML/CSS/JS，通过 `go:embed` 打包进单一二进制；无 npm、无 CDN、无外部字体或图片请求。样式只使用 CSSOM 设置动态宽度，CSP 不包含 `unsafe-inline`。

## 8. 部署：TLS 反向代理与安全响应头

控制台只绑定 loopback；远程团队访问必须在**同一台主机**上加 TLS 终结反向代理（nginx/Caddy 等），把 `https://console.example` 反代到 `127.0.0.1:8787`。代理要求：

- 仅转发到数值 loopback 目标；强制 HTTPS，HTTP 请求 301 到 HTTPS；开启 HSTS。
- 不得剥离或覆盖应用安全响应头（CSP/`nosniff`/`DENY`/`no-referrer`/`CORP`/`no-store`）；可在其上追加头部，不可降低。
- 不得记录 `X-Trident-Token`、Cookie 或 Authorization 等请求头（nginx 默认不记录自定义头，保持默认；自定义日志格式不得加 `$http_x_trident_token`/`$http_cookie`）。
- 代理层访问日志可记录来源 IP 与时间，与应用层 JSONL 审计日志（无 IP、无令牌）互补。
- 反向代理不改变只读边界：控制台仍无写路由、无执行/修复入口；OIDC 仅以令牌文件 `role` 字段预留接口，不实现任何供应商。

## 9. 限制与非目标

- 只读控制台不改变 R2 分析能力：没有 Java AST、别名/指向分析、跨模块类型解析或运行时验证。
- 不提供多快照工作区、源码导入、任务管理、Agent 会话或工具审批。
- 不把入口注解当作已部署路由，不把公告精确版本命中当作可利用漏洞。
- `--advisories` 文件与快照摘要不绑定；更换公告目录不会自动刷新已有进程。
- 应用层只读不等于 OS 级不可变；持有令牌的本机用户仍可读取快照内全部允许文件。

## 10. 验收

1. `go test ./internal/webui ./cmd/trident -count=1`：令牌/头鉴权、Cookie 标志、CSP、资产目录拒绝、概览/发现/详情/入口/依赖/文件/检索/报告、路径遍历与缺失文件、并发缓存；多用户令牌文件（隔离、轮换、撤销、格式校验拒绝、互斥参数）、审计访问日志（字段、无令牌明文、未认证行）、导出确定性（两次字节一致、无外部 URL、无 ISO 时间戳）、`/healthz` 未认证探活与 `/api/metrics` 门禁计数器单调性。
2. `python scripts/test-web.py`：构建真实 CLI、导入合成快照、在随机 loopback 端口启动服务，验证登录与会话、全部只读 API、401/403/400/404 负例、报告下载、快照与样本字节级不变；`/healthz` 与 `/api/metrics` 字段与门禁断言；第二阶段以 `--tokens` + `--access-log` 启动第二个服务，验证多用户隔离（不同令牌不同 `token_id`）、轮换（旧令牌 401/新令牌 200）、`/export/report` 两次字节一致且无外部 URL/时间戳、JSONL 审计日志存在且不含令牌明文；全程不连接数据库、不调用模型、不执行 Java/Maven。
3. 人工浏览器检查只用于视觉与交互，不作为安全验收的替代。

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
