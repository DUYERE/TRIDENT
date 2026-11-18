# P2 优化路线（可信度与可用性）

## 目标

在不重写 `codescan` 的前提下，先解决 P2 当前最影响判断的两类问题：

1. `partial` 含义混在一起：文件拒绝、符号上限、finding 上限都只显示一个布尔值。
2. Web 端看到了符号数量，但不能解释“为什么 partial”、不能从符号跳到源码；模型页仍以 Java AST 为主。

本批只做 P2.1 / P2.2，不进入 P3 鉴权、跨文件解析或数据库动态路由。

## 路线

| ID | 需求 | 精确边界 | 文件/消费者 | 可观察断言 | 验证 |
|---|---|---|---|---|---|
| A1 | 拆分 `partial` 轴 | `Report` 增加 `file_partial`、`symbol_partial`、`finding_partial`；`partial` 保持 OR 兼容；`markPartial(report, limitation)` 统一分类 | `internal/codescan/model.go`、`analyze.go`；CLI/Web 消费者 | 文件类限制只置 `file_partial`；符号类限制只置 `symbol_partial`；finding 限制只置 `finding_partial`；三者任一为真时 `partial` 为真 | `go test ./internal/codescan` |
| A2 | Web 暴露 partial 轴与拒绝文件 | `/api/code-audit` 增加 `file_partial`、`symbol_partial`、`finding_partial`、`rejected_files`（≤200）；`available=false` 时为空数组 | `internal/webui/code_audit.go` | JSON 字段存在；拒绝文件只含 `status=rejected`；不新增分析语义 | `go test ./internal/webui` |
| A3 | 模型缓存只带符号 partial | `/api/model` 的 `symbol_partial` 使用 `Report.SymbolPartial`，不再使用全局 `Partial`；未缓存仍返回 `analysis_pending` | `internal/webui/model_views.go` | 文件拒绝不会让模型页符号卡误报截断 | `go test ./internal/webui` |
| A4 | 代码页显示 partial 轴与文件拒绝 | 代码页 KPI 分开展示文件/符号/finding 状态；新增“文件拒绝”卡，显示 file、language、reason | `assets/app.js`、`assets/styles.css` | 代码页可见 `file_partial` / `symbol_partial`；拒绝文件原因可读 | `node --check`；浏览器 |
| A5 | 符号证据可下钻 | 符号样本改为可点击 chip，携带 file/line，点击进入源码页；模型页同样生效 | `assets/app.js` | 点击 `Layuipaginate` 样本可打开 `#/source?path=...&line=...` | 浏览器 |
| A6 | 模型页语言中立概览 | 模型页首屏增加“代码模型概览”，按语言展示 files/rejected/symbols/calls/unresolved；Java AST 卡保留但不再是唯一主体；未缓存时显示运行代码审计入口 | `assets/app.js`、`assets/styles.css` | 非 Java 项目首屏可见 PHP 文件/符号摘要 | 浏览器 |
| V1 | 仓库原生验证 | `go test -p 1 -count=1 -timeout 10m ./...`；`go vet ./...`；`node --check`；`python scripts/test-web.py`；`python scripts/test-code-audit.py` | 全仓 | 全部退出 0；p2d 启动 `/healthz` 200 | 记录完整输出 |

## 本批非目标

- 不提高 `MaxSymbols` / `MaxCalls` / `MaxUnresolved`。
- 不做跨文件符号解析、类型解析、真实调用图。
- 不做变量/字符串常量索引。
- 不做 ThinkPHP 数据库动态路由解析。
- 不做代码审计缓存持久化。
- 不做 P3 鉴权适配。

## 完成口径

- A1–A6 全部有新鲜测试或浏览器证据。
- 任何后端改动后重新构建并重启控制台，不能只验证旧进程。
- 浏览器验证用真实登录入口，不把 `about:blank` 或旧页面当作证据。

## 执行结果（2026-11-17）

- A1–A3 已落地：`Report` 输出 `file_partial` / `symbol_partial` / `finding_partial`；`/api/code-audit` 输出这些轴和 `rejected_files`；`/api/model` 的 `symbol_partial` 只读符号轴。
- A4–A6 已落地：代码页分出“文件/符号”状态并新增文件拒绝卡；符号 chip 可跳源码；模型页新增按语言概览。
- 最终二进制 `trident-p2e.exe`，PID `12768`，`/healthz` 200。
- `www.test.com` 实测：`partial=true`、`file_partial=true`、`symbol_partial=true`、`finding_partial=false`、`rejected_files=12`、`symbols=2000`。
- 验证：`go test -p 1 -count=1 -timeout 10m ./...` 全部通过；`go vet ./...` 通过；`node --check` 通过；`test-web.py` 8 项 PASS；`test-code-audit.py` 11 项 PASS。

## 第二批（P2.3）执行结果

- `/api/symbols` 已落地：支持 `language`、`kind`、`q`、`limit`、`offset`，复用同一份懒加载代码审计缓存；返回 `items`、`total`、`kinds`、`languages`、`partial`、`symbol_partial`。
- 代码页新增“符号浏览”卡：语言/类型/关键词筛选、分页、文件行跳源码；模型页新增“打开符号浏览”入口。
- `codescan.FileSummary` 增加 `scope=project|vendor|generated` 提示；`/api/code-audit` 增加 `rejected_scopes`；代码页文件拒绝卡显示第三方依赖/生成产物分类。
- 最终二进制 `trident-p2g.exe`，PID `63120`；`www.test.com` 实测 `rejected_scopes=vendor:12`、`/api/symbols?kind=class` 返回 `total=145`。
- 浏览器实测：`#/code` 符号浏览默认 50 条、分页到 `51–100 / 2,000`、`Layuipaginate` 搜索 15 条、点击 `app/Layuipaginate.php:L8` 进入源码；`#/model` 的“打开符号浏览”可跳代码页。
- 验证：全量 Go 测试、`go vet`、`node --check`、`test-web.py` 8 项、`test-code-audit.py` 11 项均通过。

## 第三批（P2.4）执行结果

- 代码审计缓存持久化：workspace `cache/code-audit/<snapshot>.<cache-version>.json`；启动后首次请求命中缓存，`www.test.com` 实测 112ms；快照/工具版本/缓存版本不匹配自动忽略。
- ThinkPHP 动态路由显式化：`app/route.php:17` 的 `\think\Route::rule($k,$val)` 输出 `path="<dynamic>"`、`path_status="dynamic_unresolved"`、`reason="route_path_not_literal"`；`/api/endpoints` 的 `entry_total` 从 2 变为 3。
- 修复 PHP 命名空间选择器匹配：`\think\Route::rule` 可按 `Route::rule` 匹配，同时避免 `Route` 类名产生动态路由噪声。
- 代码页声明入口卡显示“动态未解析”；入口页统一证据显示“动态路由 · 路径未解析”。
- 最终二进制 `trident-p2j.exe`，PID `28864`；重启后代码审计命中缓存，浏览器验证通过。
- 验证：全量 Go 测试、`go vet`、`node --check`、`test-web.py` 8 项、`test-code-audit.py` 11 项均通过。

## 仍未落地

- 数据库 `urlconfig` 表驱动的动态路由真实 URL 展开。
- 变量/字符串常量索引、跨文件调用图、类型解析、框架绑定。
- P3 鉴权适配、P4 多生态 SCA/SBOM、P5 可达性、P6 补丁验证。


