# TRIDENT 跨语言能力缺口与完善顺序

日期：2026-11-17
范围：Java、PHP、C#/.NET、Python、JavaScript/TypeScript、Go 与 TRIDENT 的静态分析、入口、数据流、鉴权、依赖、可达性、运行时关联、补丁验证、Agent 工具和 Web 展示。
结论：**“Java 有的能力”并不是一个功能，而是一组九类能力；当前只有多语言代码审计完成了 7 语言前端，其余能力仍以 Java/Maven 为主。** 本轮先修复最明显的假零值：非 Java 项目不再只显示“0 个入口”，而是返回跨语言应用入口文件候选；完整对齐仍需按阶段实施，不能把文件候选当成已解析路由。

## 1. 判定口径

| 状态 | 含义 |
|---|---|
| 已实现（有界） | 有代码、有测试、有明确上限与 limitation；不等于编译器级完整语义 |
| 部分 | 已有通用层或单一生态适配，其他语言会返回空/未知，但未显式标注 |
| 缺失 | 入口、扫描或执行路径只接受 Java/Maven/Gradle，其他语言不会被处理 |
| 不适用 | 该能力本身依赖 JVM/构建工具，不能简单复制；应做“语言等价能力”或明确 `not_supported` |

关键原则：**空结果不能自动解释为“没有入口/没有漏洞”**。当前控制台部分页面仍存在这个问题。

## 2. 能力矩阵

| 能力 | Java | PHP | C#/.NET | Python | JS/TS | Go | 结论 |
|---|---|---|---|---|---|---|---|
| 代码审计（规则、污点、SARIF） | 有界实现 + Java 主线增强 | 有界词法规则 | 有界词法规则 | 有界词法规则 | 有界词法规则 | 有界词法规则 | 7 语言已接入 `internal/codescan`；同文件、词法级，不是完整 AST |
| HTTP 入口（注解/路由声明） | Spring MVC、JAX-RS、Servlet | 代码审计的 `Route::...` 形状 + 框架无关的 `request_script` 候选；请求脚本带文件级行序鉴权决策；ThinkPHP 动态路由仍为 `<dynamic>` | 代码审计的 `HttpGet/MapGet` 等声明 | Flask/Django/FastAPI 路由声明 | Express 等路由声明 | `http.HandleFunc`/Gin 等声明 | 已新增 `internal/evidence` 统一证据模型和入口 Provider，入口页同时展示 Java 注解、7 语言声明路由与文件候选；PHP 请求脚本候选不等于已部署路由，脚本鉴权也不等于中间件执行 |
| 应用入口文件候选 | 新增 `Application.java/Main.java` 识别 | `public/index.php`、`router.php` + 有界 `request_script` | 新增 `Program.cs`、`Startup.cs` | 新增 `manage.py`、`wsgi.py`、`app.py` | 新增 `server.js/ts`、`app.js/ts` 等 | 新增 `main.go` | **文件级候选，不证明 URL**；PHP 请求脚本按内容识别，不依赖 ThinkPHP |
| 语义模型（类型/方法/调用） | `internal/javaast` 受限 Java 语义模型 | 无 | 无 | 无 | 无 | 无 | Java 专有 |
| 数据流 | `internal/dataflow` JDBC/SQL 等 Java 有界分析 | 仅 codescan 同文件污点 | 仅 codescan 同文件污点 | 仅 codescan 同文件污点 | 仅 codescan 同文件污点 | 仅 codescan 同文件污点 | 两套模型未统一；Java 有独立引擎，其他语言只有声明式规则 |
| 鉴权/访问控制 | Spring Security、MVC interceptor、Servlet filter、手工 session | 请求脚本端点级词法决策（`protected/public/unprotected/unknown`）+ 文件级控制证据 | 无适配器 | 无适配器 | 无适配器 | 无适配器 | `internal/authz` 的 Java 主线仍只加载 `.java`；PHP 请求脚本有端点级有界决策，但不是路由/中间件执行；其他语言仍只有文件级或未接入，不能默认 public |
| SCA/依赖 | Maven/Gradle 声明与有效树 | Composer `composer.json/lock` | NuGet `.csproj/packages.config` | pip `requirements/pyproject` | npm `package.json/lock` | Go `go.mod/go.sum` | `internal/sca` 已支持六类生态；公告匹配已覆盖 Composer/npm/NuGet/PyPI/Go |
| SBOM | 由 SCA 生成 | Composer purl | NuGet purl | PyPI purl | npm purl | Go purl | `internal/sbom` 已支持 `pkg:composer` 等非 Maven purl |
| 可达性 | Java 类级调用图 | 无 | 无 | 无 | 无 | 无 | `internal/reach` 只解析 Java import/同包类型 |
| 运行时 HTTP 关联 | 通用 HTTP 执行器可验证给定路由 | 理论可用 | 理论可用 | 理论可用 | 理论可用 | 理论可用 | `internal/httpverify`/`correlate` 语言无关，但静态路由输入仍主要来自 Java 入口 |
| 补丁验证 | Maven、Gradle、javac、JUnit | `php -l` | `dotnet build` | `python -m py_compile` | `node --check` | `go test` | `caseagent` 已有语言 profile；PHP 仍只做语法 lint，不等于 PHP 8 运行时或漏洞修复证明 |
| Agent 工具 | `inspect_dependencies`、`trace_dataflow`、`list_findings` 等 | `codescan` 语言过滤可用 | 同左 | 同左 | 同左 | 同左 | 代码审计工具已多语言；依赖/入口/数据流工具描述和底层仍偏 Java |
| Web 展示 | 入口、权限、代码模型、可达性、依赖 | 入口页显示应用入口候选与 `request_script` 端点鉴权；其余页面仍以 Java 语义为主 | 同左 | 同左 | 同左 | 同左 | `代码审计` 页 7 语言；入口页统一证据表显示 PHP 脚本决策 |

## 3. 代码证据

### 3.1 已经多语言的部分

- `internal/codescan/spec.go`：`php`、`csharp`、`python`、`javascript`、`typescript`、`java`、`go` 七个前端。
- `internal/codescan/analyze.go`：统一 token/statement IR、声明式 source/sink/sanitizer、同文件有界污点、路由声明扫描、Findings/SARIF 导出。
- `docs/code-audit-contract.md`：明确 `lexical_token_ir`、`intraprocedural_only`、`route_declaration_not_deployment`、`no_runtime_verification`。
- `internal/webui/code_audit.go`：`/api/code-audit` 已返回 `Routes`、`Languages`、`Coverage`；`#/code` 已消费 7 语言数据。

### 3.2 仍然 Java/Maven 专有的部分

- `internal/audit/audit.go`：从 manifest 过滤 `.java`；只识别 Spring MVC、JAX-RS、`@WebServlet`；覆盖字段是 `java_files_scanned`。
- `internal/javaast/model.go`：`ScanSnapshot` 只扫描 `.java`；受限 Java 语义模型。
- `internal/dataflow/model.go`：包注释即 JDBC SQL 构造的 Java source-to-sink；依赖 `audit` 与 `javaast`；上限常量是 `MaxJavaFiles/Bytes/Tokens`。
- `internal/authz/authz.go`：端点决策包注释明确 Spring Security/MVC/Servlet；`Coverage.JavaFilesScanned` 仍只统计 `.java`；`language.go` 另有 PHP 等文件级控制证据，并已对 PHP `request_script` 生成文件内行序决策，但不是框架路由/中间件决策。
- `internal/reach/reach.go`：Java 类级调用图 + Maven 依赖；不跟随反射/字节码。
- `internal/sca/sca.go`：Maven/Gradle 主线仍在；`internal/sca/ecosystems.go` 已扩展 Composer/npm/NuGet/pip/Go 声明与锁定版本，`advisory` 已支持对应生态。
- `internal/r3/run.go`：Maven/Gradle/Javac/JUnit profile；`internal/caseagent` 另提供 PHP `php -l`、Node `node --check`、Python `py_compile`、Go `go test`、.NET `dotnet build` 的隔离验证 profile。
- `internal/webui/api.go`：`handleEndpoints` 原先只取 `state.audit.Endpoints`；P1 试点已通过 `internal/entry` 把 Java 注解、`codescan.Routes` 和应用入口候选合并为 `entries`，同时保留旧 `items` 兼容字段。多语言声明仍未进入 `audit` 的 taint/statement 主线。

### 3.3 P1 入口统一试点（已落地）

新增两层，不重写任何分析器：

- `internal/evidence`：唯一的入口证据 DTO，字段包括 `language`、`source`、`kind`、`http_methods`、`path`、`path_status`、`file`、`start_line`、`parameters`、`authz`、`confidence`、`reason`；`coverage` 记录每个 source/language 实际扫描与拒绝数量；`partial` 与 `limitations` 显式标注缺口。
- `internal/entry`：`JavaAuditProvider`、`CodeRouteProvider`、`ApplicationEntryProvider`；`NewRegistry().Build(ctx, Input)` 只消费已经计算好的报告，按 `language/file/line/path/methods` 去重，Java 注解优先于声明路由，声明路由优先于文件候选。
- `/api/endpoints`：新增 `entries`、`entry_total`、`entry_coverage`、`entry_partial`、`entry_limitations`；旧 `items`、`total`、`coverage`、`application_entries` 字段保持不变。`q` 与 `authz` 过滤同时作用于统一视图。
- `#/endpoints`：新增“统一入口证据”表，显示语言/来源、方法、路径/文件、证据类型、权限、置信度；Java 兼容表继续保留。

边界：`codescan` 的路由声明不是已部署 URL；应用入口文件候选和 `request_script` 也不是已部署 URL；ThinkPHP `urlconfig` 行可解析，但 `Route::rule($k,$val)` 的最终动态值仍无法从静态快照得出；非 Java 入口没有端点级 framework authz。P1 只解决“统一可见与统一边界”，不解决“与 Java 同等语义深度”。

## 4. 当前 `www.test.com` 的验证结果

- 项目：`D:\Code\PHP\www\www.test.com`
- 快照：1084 文件、42,208,753 字节、hash `31cf57077eba27446bee8cf33c76f87d5e5f9f1f832e71fb0806e77884c24f07`
- 真实入口：`public/index.php`（ThinkPHP 5）、`public/router.php`（PATH_INFO）
- 领域事实：`app/route.php` 从 `urlconfig` 表读取 `aliases,url` 后调用 `Route::rule`，是数据库驱动动态路由；静态扫描无法知道最终路径。
- 本轮复核：`GET /api/endpoints` 返回 `total=0`（Java 注解清单确实不适用），统一入口证据 `entry_total=3`：
  - `public/index.php`，`php`，`ThinkPHP`，证据行 23，`application_entry`
  - `public/router.php`，`php`，`ThinkPHP`，证据行 16，`application_entry`
  - `public/ipapi.php`，`php`，`request_script`，证据行 263
- PHP 请求脚本鉴权（2026-11-18）：`public/ipapi.php:263` 返回 `unprotected`，`reason=php_script_no_recognized_guard_before_request_access`；应用入口 `index.php`/`router.php` 不附着脚本鉴权，权限保持“未评估”。`/api/authz` 只统计 Java 端点决策，脚本决策在 `language_adapters` 与统一入口 `authz` 字段。
- 概览：`application_entries=2`、`application_entry_languages=1`；入口页不再只显示空表，而是明确“这是文件级候选，不是已部署 URL”。

## 5. 完善顺序

### P0（本轮已落地）：入口可见性与假零值

- 新增 `internal/entrypoint`：识别 7 类应用入口文件，排除 `vendor/node_modules/tests/examples/docs/target/obj/bin/dist`，单文件最多读 1 MiB，不执行代码。
- `/api/endpoints` 新增 `application_entries`、`application_entries_partial`、`application_entry_limitations`；概览新增 `application_entries` 与 `application_entry_languages`。
- `#/endpoints` 新增“应用入口候选”表；空态明确注解清单只覆盖 Java，不能据此判断非 Java 项目没有 HTTP 入口。
- 验收：`go test ./...`、`go vet ./...`、`node --check internal/webui/assets/app.js`、`python scripts/test-web.py` 全部通过；真实快照 API 已验证。

**P0 不解决**：HTTP 路径、控制器映射、框架鉴权、数据流、依赖、可达性、补丁验证。

### P1（本轮已落地）：入口统一证据试点

目标：把 `audit.Endpoints`（Java 注解）与 `codescan.Routes`（7 语言声明路由）统一成一张只读入口证据表，并在入口页展示；文件候选进入同一模型但保持独立类别。

- 已落地 `internal/evidence` 与 `internal/entry`，详见 3.3。
- `/api/endpoints` 同时返回统一 `entries` 和旧 Java `items`；`#/endpoints` 展示统一表并保留 Java 兼容表。
- 已验证 `www.test.com`：代码审计尚未运行时 `total=0`、`entry_total=2`、`entry_partial=false`；两条 PHP 入口文件候选；`coverage` 同时有 `application_entry/php` 与 `java_audit/java`（后者 `no_source_files`）。代码审计缓存后，若存在 `lex_rejected`/`bounded_token_budget` 等文件级缺口，入口页会如实标记 `entry_partial=true`。
- 已落地 ThinkPHP 动态路由证据：`app/route.php:17` 的 `\think\Route::rule($k,$val)` 现在返回 `path="<dynamic>"`、`path_status="dynamic_unresolved"`、`reason="route_path_not_literal"`；入口页 `entry_total=3`，不再把这条入口线索静默丢弃。
- 仍未落地：数据库 `urlconfig` 表内容解析、动态路由的真实 URL 展开、ThinkPHP 默认路由 `convention_candidate`；这些需要单独解析器与产品口径。

### P1.5（本轮已落地）：PHP 语言级请求脚本入口候选

目标：入口证据不再只覆盖 ThinkPHP 文件名和 `Route::...` 声明，让普通 PHP Web 脚本也能进入统一入口证据模型。

- `internal/entrypoint` 在文件名候选之后做第二遍有界扫描：`.php/.phtml/.php5`、单文件 ≤1 MiB、路径不在 `vendor/node_modules/tests/examples/docs/src/app/lib/libs/library/libraries/framework/system/core/config/routes/resources/storage/bootstrap/database/migrations/extend/thinkphp/think/static/assets/includes/include/3rdparty/thirdparty` 等目录。
- 内容出现 `$_GET`、`$_POST`、`$_REQUEST`、`$_FILES`、`$_COOKIE`、`php://input`，或 `$_SERVER` 的 `REQUEST_METHOD/REQUEST_URI/QUERY_STRING/PATH_INFO` 时，生成 `kind=request_script`、`reason=php_request_superglobal_observed` 的文件级候选，记录首次出现行和文件 SHA-256。
- 已通过 `index.php/router.php` 等文件名规则识别的文件不会重复生成；候选总数受 `MaxEntries` 限制，超限置 `partial=true`。
- `internal/entry` 将 `kind=request_script` 保留为 `application_entry` 证据，置信度为 `request_script_heuristic`，不伪造权限决策。
- 限制：`php_request_script_candidate_not_route`、`php_request_script_not_deployed`、`php_request_script_content_bounded_1mib`。这是“脚本读取请求数据”的语言级证据，不是已部署 URL、调用图或漏洞结论；PHP 请求脚本端点级鉴权已另片实现（文件内、首次请求访问行之前），但完整 AST、跨文件数据流和框架中间件仍未实现。

### P2：跨语言符号/语义层

目标：以 `codescan` 的统一 IR 为底座，增加受限的符号索引，先服务入口到 sink 的路径证据，不追求完整 AST。

已落地（有界 v1）：
- `codescan.Symbol` / `Call` / `Unresolved`，覆盖 PHP、C#、Python、JS/TS、Java、Go；声明类型为函数、方法、类、接口、结构、枚举、记录、Trait、type。
- 调用点带 `caller`、`callee`、参数数量、文件和行号；只有同文件 exact simple name 命中声明才标 `same_file`，其余标 `external_or_unresolved`，不生成跨文件调用图。
- `Report` 输出 `symbols`、`calls`、`unresolved`；`Coverage` 输出 `symbols_found`、`calls_found`、`unresolved_found`；`LanguageSummary` 输出每语言计数。
- 上限 `MaxSymbols=2000`、`MaxCalls=4000`、`MaxUnresolved=2000`，超限置 `partial` 并记录 `symbol_limit` / `call_limit` / `unresolved_limit`。
- `Report` 同时输出 `file_partial`、`symbol_partial`、`finding_partial`：文件拒绝/文件上限只置 `file_partial`，符号上限只置 `symbol_partial`，finding 上限只置 `finding_partial`；`partial` 仍为三者 OR，兼容旧消费者。
- Web `/api/code-audit` 增加 `file_partial`、`symbol_partial`、`finding_partial`、`rejected_files`（≤200）、`rejected_scopes`；文件摘要新增 `scope=project|vendor|generated` 提示，只用于区分缺口来源，不改变 partial 口径。
- Web `/api/symbols` 提供完整符号浏览：`language`、`kind`、`q` 过滤与 `limit/offset` 分页，复用同一份懒加载代码审计缓存；返回 `items`、`total`、`kinds`、`languages`、`partial`、`symbol_partial`。
- `/api/model` 仅在代码审计已缓存时附带符号摘要，不主动启动重分析；`#/model` 增加“打开符号浏览”入口。
- `#/code` 新增按语言分组的符号卡和独立“符号浏览”表：可按语言/声明类型/关键词筛选、翻页，点击文件行跳源码。
- `#/code` 的“文件拒绝”卡显示 `第三方依赖`/`生成/压缩产物`/`项目源码` 分类及汇总，避免把 vendor 缺口误读成业务源码缺口；只是展示提示，`file_partial` 仍按全量文件计算。
- 模型页首屏新增“代码模型概览”，按语言展示文件、拒绝、符号、调用、未解析；Java AST 卡保留但只是 Java 视图。
- 入口能力与符号上限解耦：`internal/entry` 只在 `file_limit`、`file_too_large`、`lex_rejected`、`statement_limit` 等入口相关限制下置 `entry_partial=true`；`symbol_limit`、`call_limit`、`unresolved_limit` 和 `symbol_*` 限制不进入入口视图。真实 `www.test.com` 代码审计存在 JS/PHP 文件拒绝，入口页 `entry_partial=true` 是文件级覆盖缺口，不是符号上限。`entry_total=2` 仍为 `public/index.php`、`public/router.php`。
- 代码审计缓存新增 workspace 持久化：`cache/code-audit/<snapshot>.<cache-version>.json`，启动后首次请求直接命中；版本、快照哈希或工具版本不匹配则忽略并重新分析。`www.test.com` 重启后代码审计命中约 112ms。
- `/api/endpoints` 统一入口现在保留 `path_status` 与 `reason`，变量路径路由以 `dynamic_unresolved` 显式展示。
- 每个语言有一个 fixture 断言：PHP 函数/类/方法、C# 类/方法、Python 函数、JS/TS 函数、Java 类/方法、Go 函数/结构。

仍未落地：
- 变量和字符串常量索引（本版显式不暴露原始字符串值，避免泄密和假类型语义）。
- 类型解析、import/receiver/overload/dynamic dispatch、跨文件调用图、框架绑定。
- 数据库 `urlconfig` 的真实路由展开、ThinkPHP 默认路由 `convention_candidate`。
- 这些属于 P2 增量，不应把 `external_or_unresolved` 当成“无调用”或“清洁”。

### P3：鉴权适配器

按框架而非语言硬编码：
- PHP：请求脚本已落地文件内、首次请求访问行之前的词法控制与 `protected/public/unprotected/unknown` 决策；ThinkPHP/Laravel 中间件、控制器基类、路由级登录态仍未实现。
- .NET：ASP.NET Core middleware/filter、`[Authorize]`。
- Python：Django middleware/decorator、Flask before_request、FastAPI dependency。
- JS/TS：Express/Koa/Nest middleware。
- Go：Gin/Echo/net/http middleware。
验收：每语言至少 protected/public/unprotected 三态 fixture；未知控制输出 `unknown`，不能默认 public。

### P4：多生态 SCA 与 SBOM

- Composer（`composer.json/composer.lock`）、NuGet（`packages.config/*.csproj`）、pip（`requirements.txt/pyproject.toml`）、npm（`package.json/package-lock.json`）、Go（`go.mod/go.sum`）。
- 先做声明级和可离线解析的锁定版本；公告生态按 `Composer/npm/NuGet/PyPI/Go` 扩展。
- 输出语言、生态、直接/间接、版本状态、解析限制；SBOM 组件带 ecosystem/purl。
验收：每生态一个离线 fixture；无锁文件时明确 `version_unresolved`；不把声明命中当可利用漏洞。

### P5：可达性

- Java 保留现有类级图。
- PHP/.NET/Python/JS/Go 先做 import/use/require/namespace 级有界图，再逐步加方法级；反射/动态调用输出 `unknown`。
- 目标不是完整调用图，而是把“依赖已声明”和“依赖可能被入口使用”分开。
验收：每语言 reachable/unreachable/unknown 三态；路径带文件/行号与上限。

### P6：补丁验证 profile

- PHP：`php -l`、PHPUnit（若工具链存在）。
- .NET：`dotnet build`、`dotnet test`（若 SDK 存在）。
- Python：`pytest`/`python -m compileall`（若解释器存在）。
- JS/TS：`npm test`/`tsc --noEmit`（若工具链存在）。
- Go：`go test ./...`。
- 所有 profile 必须先探测工具链；缺失时 `toolchain_unavailable`，不能假装通过。Maven/Gradle 行为保持。
验收：一个语言至少一个 compile/lint profile；隔离副本、原快照复验、失败关闭保持。

### P7：运行时关联、Agent 工具与 UI 收口

- `internal/correlate` 接多语言入口/发现，而不是只吃 Java 入口。
- Agent 的依赖/入口/数据流工具按语言返回 `supported/unsupported`，不再用 Maven 描述覆盖所有语言。
- 导航与页面标题去掉 `JAVA MODEL` 的全局暗示；按语言显示覆盖与限制。
验收：Agent 工具描述、Web 页面、契约文档三者一致；不支持的能力显式 `not_supported`。

## 6. 现在不能宣称什么

- 不能宣称 PHP/.NET/Python/JS/Go 已经具备与 Java 同等语义深度的入口、鉴权、数据流、可达性和补丁验证。
- 不能把 `public/index.php` 当成已部署 URL；它只是应用入口文件候选。
- 不能把 ThinkPHP 数据库动态路由猜成具体路径；只能标记动态未解析。
- 不能把 `codescan` 的同文件词法污点等同于跨过程、跨文件、框架绑定后的完整数据流。
- 不能把 Maven 公告生态套到 Composer/npm/NuGet/PyPI/Go；需要各自生态数据。

## 7. P1/P2 阶段变更（历史）

已改：
- `internal/entrypoint/entrypoint.go`、`entrypoint_test.go`
- `internal/evidence/model.go`、`model_test.go`
- `internal/entry/registry.go`、`providers.go`、`entry_test.go`
- `internal/webui/api.go`、`application_entries_test.go`、`webui_test.go`
- `internal/webui/assets/app.js`、`styles.css`
- `docs/web-console-contract.md`
- `.trae/documents/capability-entry-pilot_plan.md`

验证：
- `go test ./...`：全部包通过
- `go vet ./...`：通过
- `node --check internal/webui/assets/app.js`：通过
- `python scripts/test-web.py`：8 项全部 PASS
- 最终二进制 `C:\Users\zx\AppData\Local\Temp\trident-p1c.exe` 已启动，PID `61284`，`127.0.0.1:8791`，`/healthz` 200
- `www.test.com` 的 `/api/endpoints` 返回 `total=0`、`entry_total=2`、`entry_partial=false`（P1 基线；代码审计缓存后因文件级拒绝如实转为 true）；`q=thinkphp` 返回两条 PHP 文件候选；`authz=protected` 返回 0（PHP 入口无权限证据，未伪造决策）

未完成：
- ThinkPHP 静态/动态路由解析、`convention_candidate`
- P2 变量/字符串常量索引与跨文件符号解析
- P3 鉴权
- P4 SCA/SBOM
- P5 可达性
- P6 补丁验证
- P7 运行时/Agent/UI 全域收口
- P6 补丁验证
- P7 运行时关联/Agent/UI 全面收口

这些不是“再补一个 switch”，而是按语言实现解析器、框架适配器和验证 profile的多阶段工程；本报告的顺序用于避免先做 UI 再补假数据。

## 8. 2026-11-17：C1–C7 一次收口

本节替代第 7 节的“未完成”清单；第 7 节保留为 P1/P2 时点记录。

### C1 变量、字符串常量与跨文件调用
- `codescan.Report` 新增 `variables`、`string_constants`；`Call` 新增 `receiver`、`resolved_file`、`resolved_symbol`，调用状态为 `same_file | same_project | ambiguous_symbol | external_or_unresolved`。
- 变量索引只登记简单赋值左值，目标是 `$obj->field` 等成员访问时不误记为局部变量；字符串常量只发布 SHA-256 与长度，不输出原文。
- 上限：变量 10000、字符串常量 5000；达到上限时报告计数仍为真实观察值但条目分页截断，页面只展示有界列表。

### C2 ThinkPHP 动态路由与框架默认路由
- 支持快照内 SQL dump 的 `INSERT INTO urlconfig ...` 与 JSON `urlconfig` 数组；只在存在动态 `Route::rule` 时把 `<dynamic>` 展开为明确的 aliases 行，标记 `source=database`、`reason=database_urlconfig_row`、`target=url`。
- 从 `app/*/controller/*.php` 方法生成 `/module/controller/method` 候选，标记 `path_status=convention_candidate`、`source=convention`；统一入口过滤这些候选，避免入口表膨胀。
- 边界：不读取 SQLite `.db` 实文件，不执行 ThinkPHP，不把数据库行或框架约定当成已部署路径。

### C3 多语言鉴权适配
- 新增 PHP / C# / Python / JS / TS / Go 文件级词法适配器；决策为 `protected | public | unprotected | unknown`。
- 语言适配证据与 Java 端点决策分开返回，Web 权限页新增“多语言控制适配”卡片；文件级证据不证明端点级鉴权。

### C4 Composer / NuGet / pip / npm / Go SCA 与 SBOM
- 支持 `package.json` / `package-lock.json`、`composer.json` / `composer.lock`、`requirements*.txt` / `pyproject.toml` / `Pipfile`、`go.mod`、`*.csproj` / `packages.config` / `packages.lock.json`。
- 锁文件优先精确版本；声明范围标记 `range`，缺失版本标记 `missing`；不执行包管理器、不联网、不解析传递依赖。
- SBOM purl 覆盖 `pkg:npm`、`pkg:composer`、`pkg:nuget`、`pkg:pypi`、`pkg:golang`；公告匹配支持生态字段，跨生态同名包不会误配。
- 真实 `www.test.com`：5 个清单、8 条 Composer 声明，全部为版本区间，因此 `dependencies_resolved=0`、`dependencies_unresolved=8`。

### C5 多语言可达性
- PHP / C# / Python / JS / TS / Go 按导入/引用匹配 SCA 依赖；匹配位于含路由/handler 的文件时标 `reachable`，否则 `unknown`；无匹配标 `unreachable`。
- 非 Java 的 `reachable` 只是文件级导入证据，不证明类加载或运行时利用；`/api/reachability` 不再要求 package map，没有映射时 Java 依赖为 `unknown`。

### C6 补丁验证 profile
- 白名单新增 `php-lint`、`python-compile`、`pytest`、`node-check`、`npm-test`、`go-test`、`dotnet-build`、`dotnet-test`。
- 通过 `exec.LookPath` 探测工具链；Docker/gVisor sandbox 对语言 profile 返回 `start_error`，不伪装成功；`safeEnv` 仍限制环境变量。
- 边界：这些 profile 只验证构建/测试命令，不证明补丁语义正确，也没有把工具链探测暴露为 Web 配置项。

### C7 Web / Agent / UI
- `/api/code-audit` 返回 `variables`、`string_constants`；`/api/authz` 返回 `language_adapters`；`/api/dependencies` 返回 `manifests`、生态与版本状态；`/api/endpoints` 和 Agent `query_endpoints` 使用统一入口证据并带 `source`、`path_status`、`target`。
- 代码页显示调用已解析数、变量/字符串计数、路由来源与目标、框架约定候选；依赖页显示生态/清单；可达性页显示生态/语言；权限页显示多语言适配。
- Agent `inspect_dependencies` 增加 `manifests` 列表，并读取运行中的控制台公告路径/目录，不再使用启动时副本。
- `/api/reachability` 的 412 旧契约已移除；验收脚本同步为 200 + 有界语言覆盖断言。

### 验证（2026-11-17）
- `go test ./... -count=1 -p 1`：全部包通过。
- `go vet ./...`：通过。
- `node --check internal/webui/assets/app.js`：通过。
- `python scripts/test-web.py`：8 项 PASS。
- `python scripts/test-code-audit.py`：11 项 PASS。
- `go test ./internal/r3 -run TestNodeCheckLanguageProfile` 与 `TestPythonCompileLanguageProfile`：真实调用本机 node/python 并通过；PHP/dotnet 未安装，无法实测。
- Agent 真实 Run（deepseek-flash）：Run #123 completed，6 次模型调用、12 次工具调用、83,631 tokens；随后 Run #124 仅 2 次模型调用、1 次工具调用、6,236 tokens，确认 `advisory_configured=true`、`manifests=5`、NuGet 1 + Composer 4。
- 新二进制 `C:\Users\zx\AppData\Local\Temp\trident-p3b.exe` 已构建并运行在 `127.0.0.1:8791`，PID 21968；`/healthz` 200。

## 9. 2026-11-18：PHP 请求脚本端点级鉴权

本轮只补 PHP 语言能力，不新增第 8 种语言，也不引入完整 PHP AST、跨文件数据流或运行时探测。目标是把 `request_script` 从“入口线索”升级为**可复核的端点级鉴权结论**。

### 9.1 决策模型

- 绑定同一行：`internal/entrypoint` 导出 `PHPRequestAccessLine(content []byte)`，`internal/authz` 复用它，保证 `request_script` 的 `line` 与鉴权判定行一致。
- 控制模式（文件内词法）：`permission_check`（`isActionAccessible`、`hasAccess`、`checkPermission`、`canAccess`、`requirePermission`）、`role_check`（`hasRole`、`hasPermission`、`isAdmin`、`authorize`、`Gate::`、`in_array(...admin/role/permission)` 等）、`session_guard`（`if (!isset($_SESSION`、`if (empty($_SESSION` 等）、`auth_call`（`checkLogin`、`isLoggedIn`、`Auth::check`、`current_user_can` 等）、`auth_file`（`require/include` 目标含 `auth/login/session/guard/permission/security`）、`middleware`、`explicit_public`。
- 行序规则：
  - 控制行早于首次请求访问行 → `protected`；
  - 显式公开标记早于请求访问行 → `public`；
  - 控制/公开标记与请求行同一行 → `unknown`（`php_script_guard_at_request_line`）；
  - 控制仅出现在请求行之后 → `unknown`（`php_script_guard_after_request_access`）；
  - 控制与公开标记同时早于请求行 → `unknown`（`php_script_conflicting_controls`）；
  - 没有任何识别控制 → `unprotected`（`php_script_no_recognized_guard_before_request_access`）。
- 证据字段：`scope=request_script`、`line=请求行`、`control_line=最早控制行`、`matched_controls`（如 `permission_check@33`）、`reason`；统一入口 `authz` 只附着在 `kind=request_script`，`application_entry` 保持“未评估”。

### 9.2 代码与测试

- `internal/authz/authz.go` / `language.go`：脚本适配器、控制模式、行序判定、`isVendorPath` 排除 `vendor/node_modules/static/assets/extend/thinkphp/library/tests/docs/...`。
- `internal/entry/providers.go`：只对 `request_script` 附着 `authz`；`internal/webui/model_views.go` 与 `app.js` 显示 `scope/control/control_line/matched_controls` 及 `未知/公开` 计数。
- `tests/fixtures/php-script-authz/public/`：protected、public、open、late、require-auth、role、permission、conflict、same-line、no-request、static/lib、thinkphp/library 十二类夹具；`internal/authz/language_test.go` 断言决策、行号、控制行、原因与排除。
- `internal/webui/application_entries_test.go` 断言 `application_entry` 不得收到脚本鉴权。

### 9.3 真实结果

- 真实 Gibbon v30.0.00 五文件子集（8793，p2f）：
  - `modules/Reports/archive_manage_uploadPreview.php:42` → `protected`，`requirement=role`，`permission_check@33`；
  - `modules/Reports/archive_manage_addProcess.php:28` → `unknown`，`php_script_guard_after_request_access`，`permission_check@32`（该文件在 line 28 先读 `$_POST` 做 sanitize，line 32 才做 `isActionAccessible`；控制存在但不在首次请求访问之前，不冒充 protected/unprotected）；
  - `index.php` 为 `application_entry`，不附着脚本鉴权；`/api/authz` 只保留 6 条适配器（过滤后）。
- ThinkPHP `www.test.com` 快照（8791，p2f）：
  - `public/ipapi.php:263` → `unprotected`；
  - `public/index.php:23`、`public/router.php:16` → `application_entry`，权限“未评估”；
  - 框架 `thinkphp/library/think/*`、`public/static/...`、`extend/PHPExcel/*` 不再进入语言适配噪声。
- `/api/authz` 顶层 `authzCounts` 仍只统计 Java 注解端点；PHP 脚本决策在 `language_adapters` 和 `/api/endpoints.entries[].authz` 中，不能把“无控制 0”读成 PHP 没有决策。

### 9.4 边界

- `php_script_authz_file_local`：只分析文件内、请求行之前的词法控制；`include/require` 目标、分支可达性、中间件执行、跨文件登录态均未解析。
- `php_script_unprotected_inconclusive`：没有识别控制不等于已证明可未授权访问；`unprotected` 不是运行时确认。
- 不覆盖路由级 authz、ThinkPHP/Laravel 中间件、数据库动态路由展开和完整 AST。
