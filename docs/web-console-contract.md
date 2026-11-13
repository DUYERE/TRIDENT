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
  [--addr 127.0.0.1:8787] [--token <value>]
```

1. 必须提供既有快照与外部可信摘要；`webui.New` 使用 `project.Open` 重新校验清单，失败即退出。
2. `--addr` 只接受数值 loopback 地址或 `localhost`；通配地址、私网地址和外部域名一律拒绝。默认 `127.0.0.1:8787`。
3. 未提供 `--token` 时生成 48 位十六进制令牌并仅在启动终端打印一次。令牌不写入快照、日志或前端资源。
4. 浏览器登录使用 `POST /api/session`，成功返回 `Set-Cookie: trident_console=...; HttpOnly; SameSite=Strict; Path=/`，有效期 8 小时。脚本可使用 `X-Trident-Token` 请求头。
5. 所有 `/api/` 请求必须携带 `X-Trident-Request: console`。跨源页面无法在不触发 CORS 预检的情况下设置该头，服务端不授予任何 CORS 预检；配合 `SameSite=Strict` Cookie 构成 CSRF 防线。
6. 统一响应头：`Content-Security-Policy`（不含 `unsafe-inline`，脚本/样式全部为同源外部文件）、`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`、`Cross-Origin-Resource-Policy: same-origin`；API 为 `Cache-Control: no-store`。

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

## 5. 前端视图

| 路由 | 内容 |
|---|---|
| `#/overview` | 快照摘要、8 个统计卡、状态构成、覆盖门槛、10 类漏洞分布、限制 |
| `#/findings` | 状态/类别/关键字筛选、分页表格、证据抽屉（入口、数据流、证据、假设、限制） |
| `#/endpoints` | HTTP 方法、路径、控制器符号、参数绑定、路径状态；点击跳转源码 |
| `#/dependencies` | 模块卡、依赖声明表、公告匹配、SCA 边界；导出 CycloneDX SBOM |
| `#/source` | 目录清单、路径前缀过滤、源码阅读、行号跳转、分页与字面量检索 |
| `#/about` | 构建/快照/工具链信息、只读 API 表、安全边界与限制 |

前端为无构建步骤的原生 HTML/CSS/JS，通过 `go:embed` 打包进单一二进制；无 npm、无 CDN、无外部字体或图片请求。样式只使用 CSSOM 设置动态宽度，CSP 不包含 `unsafe-inline`。

## 6. 限制与非目标

- 只读控制台不改变 R2 分析能力：没有 Java AST、别名/指向分析、跨模块类型解析或运行时验证。
- 不提供多快照工作区、源码导入、任务管理、Agent 会话或工具审批。
- 不把入口注解当作已部署路由，不把公告精确版本命中当作可利用漏洞。
- `--advisories` 文件与快照摘要不绑定；更换公告目录不会自动刷新已有进程。
- 应用层只读不等于 OS 级不可变；持有令牌的本机用户仍可读取快照内全部允许文件。

## 7. 验收

1. `go test ./internal/webui ./cmd/trident -count=1`：令牌/头鉴权、Cookie 标志、CSP、资产目录拒绝、概览/发现/详情/入口/依赖/文件/检索/报告、路径遍历与缺失文件、并发缓存。
2. `python scripts/test-web.py`：构建真实 CLI、导入合成快照、在随机 loopback 端口启动服务，验证登录与会话、全部只读 API、401/403/400/404 负例、报告下载、快照与样本字节级不变；全程不连接数据库、不调用模型、不执行 Java/Maven。
3. 人工浏览器检查只用于视觉与交互，不作为安全验收的替代。

## 8. 实际结果（2026-11-13）

- `go build ./...`、`go test ./... -count=1`、`go vet ./...`：通过（含 `internal/webui` 7 项与 `cmd/trident` 2 项新测试）。
- `go test ./internal/webui -count=1 -v`：7 项通过（鉴权、资产与安全头、会话 Cookie、概览与发现、入口与依赖、文件/检索/报告、并发缓存）。
- `go test ./cmd/trident -run 'TestValidateLoopbackAddr|TestRunWebRejectsUnsafeArguments' -count=1 -v`：通过。
- `python scripts/test-web.py`：通过；仅 loopback、无需数据库/模型；快照与 fixture 前后 SHA-256 字节级一致。
- 回归：`test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py` 全部通过且分析计数不变；`test-local.py`（真实 PostgreSQL）、`test-agent.py`（loopback 非真实 LLM，Run 28/29）与 `test-linux.py`（`-race -tags=integration -p 1 ./...`）通过。
- 浏览器人工检查：登录页、概览、发现列表与证据抽屉、入口、依赖、源码阅读与检索、820px 响应式布局；无控制台错误。390px 移动截图因浏览器工具超时未采集，不据此声称移动端已验证。
- 未运行：真实外部模型、Java/Maven/JUnit、运行时漏洞验证、多用户并发压力测试、HTTPS/TLS 终止、操作系统级快照隔离。
