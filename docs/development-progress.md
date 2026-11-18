# TRIDENT 开发进度与维护入口

> 当前路线：[`TRIDENT_统一安全Agent执行方案_v2.0.md`](TRIDENT_统一安全Agent执行方案_v2.0.md)。本文件记录工程进度，不是运行时 Run 状态；运行状态以 PostgreSQL 为准。核心实现保持 Go，Java 是审计样本，Python 仅辅助验收。

## 当前能力矩阵

| 范围 | 状态 | 维护入口 |
|---|---|---|
| P0.1/P0.2 离线治理 | 已实现，历史验收记录保留 | `p0-contracts.md`、`p0-acceptance.md` |
| R0 合成 Java/Maven 样本与断言 | 已交付；未执行 Java/Maven/JUnit | `java-fixture-acceptance.md`、`tests/fixtures/java-maven/` |
| R1 快照与四项只读工具 | 已实现并完成本地验收 | `snapshot-contract.md`、`internal/project/` |
| R1 Core、Run、OpenAI 适配 | 已实现并完成本地协议验收与两次真实模型只读闭环；DeepSeek `reasoning_content`/Schema 数值兼容、48 KiB 检查点硬上限已于 2026-11-16 删除（压缩保留为可选/测试路径） | `agent-contract.md`；下方 2026-11-12 与 2026-11-13 记录 |
| R1 真实模型自主工具闭环 | 已完成获准验收：DeepSeek `deepseek-flash` Run 43、`deepseek-v4-pro` Run 46，均仅合成样本且 `completed`；其他模型/快照需逐次授权 | `agent-contract.md` §6.1；下方 2026-11-13 记录 |
| R2 供应链/AST/漏洞分析 | 声明级 Maven/Gradle、Maven/Gradle 有效依赖树（临时副本、默认离线、显式按工具批准）、公告精确版本与调用者声明区间/别名、模块依赖树、Spring MVC/JAX-RS/Servlet 入口清单、10 类注入与非 SQL 类别（命令注入/SSRF/路径遍历/模板注入/XSS/反序列化/XXE/LDAP/上传）Source/Sink（含 `+`/builder/`format`/返回值/builder 突变/继承分派/字段污点/重载/集合与字面量元素/导入感知类型解析/`produces` 反射返回值/链式反序列化/更多 XXE）、统一 Finding/Hypothesis、SARIF 2.1.0、本地制品 SHA-256/调用者哈希清单、类级有界入口可达性、受限 Java 语义模型与方法级调用图已实现并验收；AST 解析出的唯一调用目标在词法解析 unresolved/ambiguous 时按文件+行号+调用名回退参与跨方法解析；完整控制流/跨方法污点未实现 | `sca-contract.md`、`audit-contract.md`、`dataflow-contract.md`、`findings-contract.md`、`internal/sca/`、`internal/audit/`、`internal/dataflow/`、`internal/findings/`、`internal/sarif/`、`internal/reach/`、`internal/javaast/` |
| R2 只读 Web 分析控制台 | 已实现并完成本地验收；单快照、loopback、令牌鉴权、只读 JSON API 与嵌入前端；不改变分析语义，不提供 Agent 控制 API | `web-console-contract.md`、`internal/webui/`、`cmd/trident/web.go` |
| R2 Agent 分析工具 | 已实现并完成本地验收与真实模型/真实项目使用；11 个只读工具（4 快照 + 7 分析）、分析缓存、Run 公告配置、实际读取行引用与证据账本桥接 | `agent-contract.md`、`internal/tools/analysis.go`、`internal/agent/` |
| R2 CycloneDX SBOM | 已实现并完成官方 Schema 验收；确定性 1.5 JSON、依赖声明/公告候选映射、本地观测制品 SHA-256；无传递树，依赖可达性不写入 SBOM | `sbom-contract.md`、`internal/sbom/`、`cmd/trident/sca.go` |
| R3 隔离验证/补丁闭环 | 已实现调用者与 AI 生成补丁、remediation policy、隔离副本、离线 Maven（含有效依赖树）/maven-compile/maven-test/javac/JUnit、Docker/gVisor、质量评分、最多 5 轮修复、原快照复验；支持新文件/BOM/多文件补丁；真实 Java/Maven/JUnit、真实模型合成补丁、真实项目编译级补丁、集中式访问控制运行时单测与真实 Tomcat/MySQL HTTP 权限测试已完成；运行时 HTTP 验证执行器已实现（显式 origin、cookie session、有界断言）；硬件 VM 与生产验证未实现 | `patch-contract.md`、`runtime-contract.md`、`internal/r3/`、`internal/httpverify/`、`cmd/trident/patch.go`、`cmd/trident/runtime.go`、`docs/evidence/2026-11-14-market-access-control.patch` |

## 2026-11-18（续三）：A/B/C 剩余项收口

### A3 SQLite urlconfig

- 新增 `internal/codescan/thinkphp_sqlite.go`：快照字节落临时文件、`PRAGMA query_only=ON`、仅查 `sqlite_master` 中名字含 `urlconfig` 的表、`PRAGMA table_info` 定位 aliases/url 列、标识符双引号转义、最多 500 行 / 5 秒。
- `internal/codescan/thinkphp.go` 候选扩展到 `.db/.sqlite/.sqlite3`，上限 32 MiB；`internal/project/policy.go` 只放行文件名含 `urlconfig` 的 SQLite。
- 依赖 `modernc.org/sqlite v1.62.0`（纯 Go），`go mod tidy` 补齐 `golang.org/x/sync` 条目。
- 验收：SQLite 单表解析、无表、真实 `project.Import → Open → loadURLConfigRows` 集成测试通过；真实 `www.test.com` 路由表仍在 MySQL 运行时库，`app/route.php:17` 保持 `database_urlconfig_absent`。

### A4 有界 receiver/container 解析

- `codescan.Call` 新增 `receiver_type`；`scanSymbolIndex` 从 `$x = new Type` 推导文件内变量类型，`$this/self/static` 取调用者容器，裸类名取末段；同名多候选按 `Symbol.Container` 过滤。
- 新增 `TestReceiverContainerDisambiguatesMethodCalls`：`$u` 与 `$this` 解析到 `User.save`，未类型化 `$o` 保持 `ambiguous_symbol`。
- 边界 `receiver_type_file_local`：跨方法返回类型、字段类型、接口/重载/动态分派与完整跨文件调用图未做。

### A5 PHP 框架级鉴权

- `internal/authz/language.go` 删除泛化 `extends (Auth|Controller)` 误报；识别 `$middleware/$beforeActionList`、`->middleware('auth')`、`Auth::check/checkLogin`；按类名解析 `extends BaseController` 继承链（最多 8 层），输出 controller scope 的 `php_controller_declared_auth` / `php_controller_inherited_auth`；路由级输出 `php_route_middleware`。
- `LanguageAdapter` 新增 `ControlFile` 指向基类文件；夹具 `tests/fixtures/php-framework-authz`。
- 验收：`go test ./internal/authz -count=1` 通过。仅 PHP，.NET/Python/JS/Go 框架级中间件继承未做。

### A6 工具链探测 Web 化与 PHP 验证边界

- 新增 `internal/r3/toolchains.go` 固定探测 `php-lint/python-compile/pytest/node-check/npm-test/go-test/dotnet-build/dotnet-test`；缺失工具从 `start_error` 改为 `toolchain_unavailable`，映射为 `ValidationError`。
- `profileLimitations()` 为 PHP/Python/Node/Go/.NET profile 写入 `php_lint_syntax_only` 等明确边界；新增 `GET /api/toolchains` 与设置页“验证工具链”卡片。
- 验收：`go test ./internal/r3 ./internal/webui`、`python scripts/test-web.py` 8 项全 PASS。

### B1 Java AST 接入污点引擎

- `internal/dataflow` 从 `javaast.ScanSnapshot` 改为 `javaast.Analyze`，一次解析同时获得声明覆盖与调用边；新增 `java_ast_bridge.go`，按 `文件+行号+调用名` 保存 AST 已解析目标。
- 词法解析器 unresolved/ambiguous 时，`resolveCallWithAST` 用 AST 唯一目标回退；不扩大词法方法集，不绕过参数兼容，不参与 source/sink 匹配。
- 验收：`TestJavaASTHintResolvesAmbiguousCall`、`TestJavaASTAnalysisIsAttachedToTaintIndex`、`go test ./internal/dataflow -count=1` 通过。控制流、分支敏感、别名/points-to、完整跨方法污点仍未实现。

### B2 Gibbon 全量导入

- 根因：`cmd/trident` 对 `project` 子命令固定 2 分钟上下文；全量 `cases/gibbon-v30.0.00/target` 首次实测在 132.93 秒被取消。
- 修复：`project import` 使用 10 分钟，查询子命令保持 2 分钟；新增 `TestProjectCommandTimeout`。
- 验收：同一 target 重新导入 `EXIT=0`、41.45 秒、3,107 文件 / 31,099,411 字节、`partial=true`、`vendor` 按策略排除；`snapshot_hash=40f1586c…`。

### B3 生产/VM 门槛

- 新增 `docs/production-vm-gates.md`：发布前置、硬件 VM/等效隔离、生产部署、验收记录格式四组可勾选门槛；明确 Docker/gVisor 不能替代硬件 VM，两条门槛当前未通过。
- 从 `deployment.md` 与 `release-checklist.md` §6 链接。

### B4 Agent 多轮上下文与会话

- 复核：`internal/agent/context.go` 已有 `PriorContext`（同会话 terminal Run、untrusted 提示、字节上限），`agent_chat.go` 已注入；会话详情已返回 `tasks`，planner/worker Run 不再单独占会话。
- 补齐：`store.normalizeConversationTitle`、`Store.UpdateConversationTitle`、`POST /api/agent/conversations/rename`、会话头“重命名”入口。
- 验收：`go test ./internal/store -run TestNormalizeConversationTitle`、`go test ./internal/webui -run TestConversationRenameRequiresStore`、全仓 `go test ./...` 通过。心跳唤醒、`steer_work`、独立复核未在本批展开。

### 门禁与剩余

- `go test ./... -count=1`、`go vet ./...`、`node --check internal/webui/assets/app.js` 全绿。
- `python scripts/test-web.py` 8 项 PASS；`python scripts/test-code-audit.py` 11 项 PASS。
- 未做：真实浏览器人工验收、硬件 VM、生产部署、A5 其他语言框架级继承、A4 完整跨文件调用图、B4 心跳/steer/独立复核。


### P7 统一展示面与入口 kind

- `internal/authz/language.go`：PHP 路由判定删除 `public function ...` 分支，只保留 `Route::`/`route(`/`->rule(`/`$this->fetch`；`app/admin/model/*` 的普通方法不再被当成路由。
- `internal/authz.LanguageAdapter` 新增 `entry_kind`：`application_entry | request_script | route_declaration`。
- `internal/webui`：`/api/authz` 复用统一入口构建器，把适配器拆成入口级 `language_adapters[]` 与 `file_evidence[]`（未附着到入口，另给 `file_evidence_total`）；新增 `language_counts[]`，固定 7 语言四态 + `file_evidence`，Java 行复用顶层 `counts`，非 Java 行只统计入口级适配器。
- `internal/webui/assets/app.js`：权限页统计条增加“非 Java 入口 / 文件级证据”；卡片按语言显示四态与入口数；文件级证据单列并标注“未附着到入口，不计入入口统计”。
- 回归：先写失败测试 `TestPHPRoutePatternSkipsPlainClassMethods`（普通模型方法曾被当作路由）与 `TestAuthzViewAttachesLanguageAdaptersToEntries`（适配器缺 `entry_kind`），确认失败原因后实现；`internal/authz`、`internal/webui` 两包全绿，`node --check` 0。

### C1/C2 核验（计划口径已过期）

- C1 实际已在 11-17 落地：`codescan` 输出 `variables`/`string_constants`（`kind=variable|constant`），`Call` 带 `resolved_file`/`resolved_symbol`，唯一跨文件匹配为 `same_project`、同名冲突为 `ambiguous_symbol`（`symbols_test.go` 覆盖）；`/api/code-audit` 与 `#/code` 已消费。
- C2 实际已在 11-17 落地：`thinkphp.go` 从快照内 `urlconfig` 的 SQL/JSON 行展开动态路由（`source=database`、`path_status=declared`），默认控制器生成 `convention_candidate`；本次补 `reason=database_urlconfig_absent`，区分“快照无 urlconfig 行”与“路径表达式非字面量”。
- 真实 `www.test.com`（控制台实测）：`/api/code-audit` 覆盖 694 文件，`calls_resolved=442/4000`，变量 10000、字符串 5000（均触上限并标 partial）；路由 82 条 = 81 条 `convention_candidate` + 1 条 `dynamic_unresolved`（`app/route.php:17`，快照内无 urlconfig 数据）。
- 边界：SQLite 格式未支持（需新增驱动，当前只解析快照内 `.sql`/`.json`）；真实路由表在 MySQL 运行时库中，快照不含时保持 `dynamic_unresolved`，不连库、不猜 URL。

### 验证

- `go test ./... -count=1` 30 包全绿，`go vet ./...` 与 `node --check internal/webui/assets/app.js` 退出 0；两个 P7 测试均先确认失败原因再实现。
- 以 `trident-p7b.exe` 重启 `127.0.0.1:8791`（PID 45564），`/healthz` 200；`/api/endpoints` 仍为 4 条统一入口（2 `application_entry`、1 `request_script`、1 `route_declaration`）。
- 真实 `www.test.com` `/api/authz`：入口级适配器从 31 条降到 2 条（`app/route.php:1` `route_declaration`、`public/ipapi.php:263` `request_script`，均 `unprotected`）；19 条控制器/模型级观测进入 `file_evidence`，`model` 文件在 `language_adapters` 中为 0；`language_counts` 仅 php 有值（入口 2、文件级 19），Java 行沿用顶层 `counts=0`。
- `/api/code-audit`（缓存版本 `p3.1`）：694 文件、`calls_resolved=442/4000`、变量 10000/字符串 5000、路由 82 条（81 `convention_candidate` + 1 `dynamic_unresolved`）；`app/route.php:17` 的 `reason` 为 `database_urlconfig_absent`。

## 2026-11-18：PHP 请求脚本端点级鉴权证据（续 P1.5）

### 修改

- `internal/authz`：新增 `request_script` 作用域的 PHP 脚本适配器。复用 `entrypoint.PHPRequestAccessLine` 绑定首次请求访问行，在文件内、该行之前识别 `permission_check`、`role_check`、`session_guard`、`auth_call`、`auth_file`、`middleware` 与 `explicit_public`；输出 `protected | public | unprotected | unknown`，并带 `control_line`、`matched_controls`、`reason`。
- `internal/entry`：统一入口只对 `kind=request_script` 附着 `authz`；`application_entry` 不再误收脚本鉴权（此前 `public/router.php` 曾被标“无控制”）。
- `internal/webui`：`/api/authz` 的 `language_adapters` 返回 `scope/control_line/matched_controls`；`/api/endpoints.entries[].authz` 显示脚本决策、访问要求、原因和控制行；`#/authz` 统计增加“未知/公开”，`#/endpoints` 权限列显示脚本结论。
- 排除噪声：`isVendorPath` 增加 `static/assets/extend/thinkphp/library/libraries/tests/docs/examples/third_party...`，避免 PHPExcel、UEditor、ThinkPHP 框架文件进入语言适配。
- 新增 `tests/fixtures/php-script-authz/public/` 夹具：protected、public、open、late、require-auth、role、permission、conflict、same-line、no-request、static 与 thinkphp/library 排除用例。

### 验证

- `go test ./... -count=1`、`go vet ./...`、`node --check internal/webui/assets/app.js` 全部 exit 0（此结果对应最终路径过滤版本；`trident-p2f.exe` 已构建并重启 8791/8793）。
- `go test ./internal/authz ./internal/entry ./internal/webui -count=1` 通过；`internal/authz` 断言 `protected/public/unprotected/unknown`、控制行与 `application_entry` 不附着。
- 真实 Gibbon v30.0.00 五文件子集 `/api/endpoints`：`modules/Reports/archive_manage_uploadPreview.php:42` 为 `protected`（`permission_check@33`），`modules/Reports/archive_manage_addProcess.php:28` 为 `unknown`（`php_script_guard_after_request_access`，控制 `permission_check@32`），`index.php` 为 `application_entry` 且不附着脚本鉴权。
- 真实 ThinkPHP `www.test.com` `/api/endpoints`：`public/ipapi.php:263` 为 `unprotected`；`public/index.php:23`、`public/router.php:16` 保持 `application_entry`/“未评估”。`/api/authz` 语言适配器从数百条降到 6 条（Gibbon 子集），`thinkphp/library`、`public/static`、`extend/PHPExcel` 噪声被排除。

### 边界

- 仅文件内词法、首次请求访问行之前；`include/require` 目标、分支可达性、中间件执行、跨文件登录态不解析。
- `unprotected` 只表示未识别到守卫，不等于已证明可未授权访问；`unknown` 不等于漏洞。
- 仍无路由级/框架中间件 authz、完整 PHP AST 或运行时探测；`/api/authz` 顶部 `authzCounts` 仍只统计 Java 端点，PHP 脚本决策在 `language_adapters` 与统一入口 `authz`。

## 2026-11-18：PHP 语言级入口证据（续 P1.5）

### 修改

- `internal/entrypoint`：在既有 `index.php/router.php` 文件名候选之后，新增有界 `request_script` 第二遍扫描。普通 PHP 脚本读取 `$_GET/$_POST/$_REQUEST/$_FILES/$_COOKIE`、`$_SERVER` 请求键或 `php://input` 时生成文件级候选。
- 排除 `vendor/node_modules/tests/.../src/app/lib/library/thinkphp/think/static/assets/...` 等框架、依赖和静态资源目录；已由文件名规则识别的入口不重复。
- `internal/evidence` 新增 `kind=request_script`；`internal/entry` 保留该 kind 与 `request_script_heuristic` 置信度，coverage 区分 `filename_heuristic`、`request_script_heuristic` 与混合来源。
- `internal/webui/assets/app.js` 显示“请求脚本候选”和对应限制；`docs/multi-language-parity-gap.md` 修正过时的“PHP 无 Composer”等口径。

### 验证

- `go test ./... -count=1`、`go vet ./...`、`node --check internal/webui/assets/app.js` 全部 exit 0；最新二进制 `C:\Users\zx\AppData\Local\Temp\trident-p2.exe` 已重启 8791/8793。
- 真实 Gibbon 五文件快照 `/api/endpoints`：`entry_total=3`、`entry_partial=false`；`modules/Reports/archive_manage_addProcess.php:28`、`modules/Reports/archive_manage_uploadPreview.php:42` 为 `request_script`；coverage 为 `mixed_entry_heuristics`。
- ThinkPHP `www.test.com` 快照回归：`entry_total=3`，保留 `public/index.php`、`public/router.php`，新增 `public/ipapi.php:263` 为 `request_script`；`thinkphp/library/think/*` 与 `public/static/.../ueditor` 未被误报。8791 入口页硬刷新后显示“请求脚本候选”。
- P1-2 的 `export_case` 真实 Run：Run 141 暴露返回的 `export_sha256`/`export_bytes` 按未追加换行的 JSON 计算，与磁盘文件不一致；已改为对实际写入字节计算，并加 `caseagent_test.go` 断言。Run 142 在新二进制下返回 `export_sha256=14fe5ea6...`、`export_bytes=21672`，与磁盘文件 21,672 bytes 的实际 SHA-256 一致；`patch_sha256=34792ae5...` 与真实补丁一致，审计 `audit.jsonl` 末条同步。
- 真实 Gibbon 全量 `target` 导入仍因目录规模/导入超时未完成；当前使用五文件真实子集。PHP authz 仍只有文件级证据，不生成端点决策；PHP 修复验证仍只有 `php -l`。

## 2026-11-17：P0 真实 Case 闭环与 P1/P2 跨语言层（补记）

> 本日为补记：当天证据分散在 `.trae/documents/` 各计划文档与 `cases/gibbon-v30.0.00/`，此处汇总并给出可复核入口。

### P0 证据驱动的真实 Case（Gibbon v30.0.00）

- 双实例：`trident-gibbon-vuln`（127.0.0.1:8081）、`trident-gibbon-patched`（127.0.0.1:8082）、`trident-gibbon-db`（127.0.0.1:3307，MySQL 8.0，一次性演示库）。
- 两个运行时确认的发现：`TRIDENT-GIBBON-2026-001`（Reports 归档 LFI→PHP 执行，标记 `TRIDENT_LFI_OK`）、`TRIDENT-GIBBON-2026-002`（认证后 Tracking 时间盲注，注入 23.48s、与基线差值 18.54s，阈值 8s）。
- 补丁 `patch.diff`（255 行，`src/View/Page.php`）与 `verify.log`（`FULL_CASE_VERIFIED`）；`upstream/` 含规范化补丁、advisory、复现步骤、测试计划与 PR 正文，仅本地，未提交上游。
- 边界：两个发现均需登录；LFI 用本地标记而非持久 webshell；SQLi 依赖种子 Markbook 行；官方 v30.0.01 diff 是 ground truth，不主张首次发现。

### P1 入口统一（试点）

- `internal/evidence` 统一证据模型；`internal/entry` 三类 Provider（Java 注解、codescan 七语言声明路由、应用入口文件）。
- `/api/endpoints` 增加 `entries/entry_total/entry_coverage/entry_partial/entry_limitations`，保留旧 `items/total/application_entries`；入口页新增统一证据表。
- 真实 `www.test.com` 实测 `total=0`、`entry_total=2`、`entry_partial=false`（`public/index.php`、`public/router.php`）。

### P2 跨语言符号层与符号浏览

- `internal/codescan` 输出 `symbols/calls/unresolved`，上限 2000/4000/2000；`/api/code-audit`、`/api/model`、`#/code`、`#/model` 消费。
- 第二批：`/api/symbols`（language/kind/q/limit/offset）；`#/code` 支持筛选、分页与源码行跳转；`FileSummary.scope=project|vendor|generated` 与 `rejected_scopes`。
- 实测 `www.test.com`：符号 2000、class 145、`Layuipaginate` 搜索 15 条、分页 1–50/2000→51–100、`rejected_scopes=vendor:12`、跳转 `app/Layuipaginate.php:L8`。
- 未完成：变量/常量索引、跨文件/类型解析、调用图（计划 C1）；其中变量/常量索引与唯一跨文件调用解析已于同日 P3 批次补齐，类型解析与完整调用图仍未实现。

### P3–P6 有界适配器

- `internal/authz/language.go`：PHP/C#/Python/JS/TS/Go 声明级控制模式，输出 `protected/public/unprotected/unknown`；未识别控制一律 unknown，不默认 public。
- `internal/sca/ecosystems.go`：Composer/NuGet/pip/npm/Go 声明与锁文件；`internal/sbom` 输出非 Maven purl。
- `internal/reach/language.go`：七语言 import/require/use 与依赖包前缀匹配，三态输出，限制 `language_reachability_file_local`（无 route→controller 绑定）。
- `internal/r3/language_profiles.go`：`php -l`、`python -m py_compile`、`node --check`、`go test`、`dotnet build`；工具链缺失报 `toolchain_unavailable`，不伪造通过。
- 夹具与测试：`tests/fixtures/{multi-authz,php-script-authz,polyglot-audit}` 与 `internal/{authz,sca,sbom,reach,r3}` 单测。

### P1-2 Agent 修复工具与多轮上下文

- 三工具 `propose_patch` / `verify_patch` / `export_case`，要求服务端 `ApproveRepair`；产物只落 `<workspace>/repairs/<case>/`，审计写 `audit.jsonl`。
- 真实 Run（隔离 8793、Gibbon 五文件子集）：Run 134 产出 1,790B 补丁（`src/View/Page.php` +23/−7，SHA-256 `34792ae5…`）；Run 135 `verify_patch` 因 PATH 无 `php` 报错、`export_case` 导出 21,672B；Run 136 补 PHP 7.3 PATH 后 `validation_passed`（5 文件 `php -l` exit 0，quality B/80）。
- 边界：`php -l` 只做语法检查，不是 PHP 8 运行时或漏洞修复证明；Run 最终 envelope 失败不当作补丁成功。

## 2026-11-18（续）：基线入库与控制台复验

### 修改

- `.gitignore`：新增 `cases/*/dbdata|target|patched|vendor` 与 `composer.phar` 忽略项——Case 目录含约 850MB 应用副本与 MySQL 数据目录，只保留证据与脚本入库。
- 将 11-15 之后的全部工作按 7 个切片提交：`c0dbd6c` chore、`54bbbf7` 分析内核、`7a1cead` Agent 运行时、`5c707d0` Case/修复工具、`f0bd759` Web 控制台、`9f5cf15` 文档、`25f0f1d` 门禁脚本；`main` 领先 `origin/main` 8 个提交，未推送。

### 验证

- 提交前门禁：`go build ./...`、`go vet ./...`、`node --check internal/webui/assets/app.js` 退出 0；`go test -count=1 ./...` 29 包全绿（`internal/model` 无测试文件）。
- 以 `trident-baseline.exe`（build 0）重启控制台 `127.0.0.1:8791`；`/healthz` 200、`/api/agent/runtime` `ready=true`（`dsn_target=127.0.0.1:55432/trident_test`、`model_ready=true`）、`/api/overview`、`/api/agent/conversations`、`/api/endpoints`、`/api/code-audit`、`/api/config` 均 200。
- 真实 `www.test.com`：`entry_total=4`（`public/index.php:23`、`public/router.php:16`、`public/ipapi.php:263` request_script、`app/route.php:17` route_declaration / `dynamic_unresolved`），`entry_partial=true`；`/api/authz` 返回 31 条语言适配器；`/api/symbols?limit=5` 返回 total=2000、5 条。

### 发现（未修，待定口径）

- `/api/authz` 的语言适配器当前覆盖到 `app/admin/model/*`、`app/route.php`、`public/ipapi.php` 等并非请求脚本的文件，并为模型层给出 `unprotected`；与「仅 `request_script` 附着 authz」的入口口径不一致，容易被读成“模型层无鉴权”。展示面与入口 kind 的收敛待决。

### 边界

- 本次只做基线入库与运行面复验，未新增分析能力；C1（变量/常量索引、唯一跨文件调用解析）与 C2（ThinkPHP 快照内 urlconfig 展开）已在 11-17 落地，核验见上方「续二」。

## 2026-11-16：删除 48 KiB 检查点硬上限（续九）

### 修改

- `internal/agent/loop.go`：`maxCheckpointBytes` 与 `checkpointCompactTarget` 改为包级变量，生产默认均为 `0`；`loadCheckpoint` 与 `commit` 不再按检查点大小拒绝，模型响应提交也不再产生 `checkpoint_limit` accounting-only 终态；默认不自动压缩历史工具结果。
- `internal/webui/assets/app.js`：删除“会话上下文超过 48 KiB 检查点上限…”提示；旧 Run 的 `checkpoint limit` reason 仅追加历史说明“该限制已删除，可重新发起”。
- `docs/agent-contract.md` §5.2/§5.3 与 `docs/agent-orchestration-contract.md` 同步：检查点压缩默认关闭，accounting-only reason 仅保留 `response_byte_limit|stored_byte_limit`；旧 `checkpoint_limit` 仅兼容读取。

### 验证

- 新增 `TestCheckpointLimitDisabledByDefault`、`TestLoadCheckpointAcceptsCheckpointAboveLegacyLimit`、`TestCommitAcceptsCheckpointAboveLegacyLimit`；旧 `TestCompactCheckpointBoundsHistoryWithoutBreakingPairing` 在测试内临时设置 48 KiB/40 KiB，继续覆盖可选压缩路径。
- `node --check internal/webui/assets/app.js`、`go build ./...`、`go test -count=1 ./...`、`go vet ./...` 全部 exit 0。
- 控制台以新二进制重启，`/api/agent/runtime` 返回 `ready=true`。真实 Run 121 在 40,391 字节检查点、4 次模型调用/7 次工具调用、27,714 tokens 时仍处于 running，未出现 `checkpoint_limit`；随后在 `search_source` 工具执行阶段挂起，属独立问题，控制台重启后该 Run 以 `unknown` 记录（不冒充完成）。
- 未构造超过 48 KiB 检查点的真实模型 Run；该边界由 `TestLoadCheckpointAcceptsCheckpointAboveLegacyLimit` 与 `TestCommitAcceptsCheckpointAboveLegacyLimit` 的 60,000 字节载荷覆盖。单个工具结果仍上限 24 KiB，整体 `MaxStoredBytes` 仍为 32 MiB。

## 2026-11-12：已完成快照切片（上轮基线）

1. Go SourceSnapshot、manifest SHA-256、Windows/Linux 路径边界、默认敏感排除、资源限制和源变化检查。
2. `project import/inspect/list/read/search`；工具输出分页、文件 hash、行号和 partial。快照为应用层只读，不是 OS 级不可变。
3. 合成 Maven 双模块，依赖版本候选/对照、SQL 注入正例、参数化负例和动态调用 unknown；标签是预期，不是分析器输出。
4. 上轮实际结果：Windows 普通 `go test ./...`/`go vet ./...`、真实 CLI、静态样本校验通过；Linux 非数据库 `-race` 通过。两个真实 bind mount 测试缺 `CAP_SYS_ADMIN` 跳过，不能算已验证；Windows NTFS junction 专项无跳过。
5. 上轮 PostgreSQL 新一轮回归未运行，原因是测试持久写入需单独授权；历史成功记录不改变此事实。详见快照契约的日期记录。

## 2026-11-12：Agent Core 切片（本地协议验收完成）

### 本轮决定与授权边界

- 用户选择 OpenAI/兼容服务作为第一个适配器，采用官方 Go SDK，核心业务不绑定供应商。
- 用户允许对专属本机 `trident_test`（`127.0.0.1:55432`）新增迁移及测试写入；不删库、不重置身份、不修改已应用的 001—003。测试可清理自己新建的临时 schema。
- **未许可真实模型/付费请求或源码外发**。本轮仅 Fake 和 loopback HTTP 验收；不得读取本机现有会话配置推定服务或偷用凭据。
- 新增 Run/AgentStep 独立于 legacy Mission；PostgreSQL 存权威协议/检查点。源码快照继续使用既有安全实现。

### 交付与验收状态

- [x] 模型中立协议及四工具注册、严格 JSON 参数与策略。
- [x] 受限官方 OpenAI Go SDK Chat Completions 适配器及 loopback 测试。
- [x] 004 前向迁移、Run owner/CAS/预算/检查点和驱动互斥。
- [x] 单一 Agent 循环、停止/恢复、CLI 入口及证据校验。
- [x] accounting-only 终态：模型已返回且用量已知、但响应/检查点/本地存储超限时，原子结算实际用量并停止；不冒称 unknown、不重放、不重复收费。
- [x] 普通单测/vet、指定测试库集成与历史回归、真实 CLI 本地服务、Linux race。
- [x] 更新精确结果、跳过、遗留问题和下一次接续入口。

### 验证记录（2026-11-12 收尾）

此前记录形成时本轮尚未运行验收；以下为收尾后的实际结果。工程仍无 Git 仓库（无 `.git`），因此无 commit；结果对应当前工作区文件内容。

- Windows / Go 1.27.1（`go.mod` 声明 1.26.3）：`go build ./...`、`go test ./... -count=1`、`go vet ./...` 通过。`internal/project` 全量约 60s，其余包通过。
- 真实 PostgreSQL（`127.0.0.1:55432/trident_test`，容器 healthy）：`python scripts/test-local.py` 通过，覆盖迁移、历史 P0 集成回归、Agent Run 所有权/CAS/预算/恢复/accounting-only、`demo-offline` 和只读 Schema 检查；退出码 0。
- Agent Run 集成专项：`go test -tags=integration -run 'TestAgentRuns' -count=1 -v ./tests/integration/` 六项全部 PASS，新增 `TestAgentRunsAccountingOnlyTerminal` 通过；非法 accounting 载荷（retained、usage 不一致、替换 checkpoint）被拒绝且 Version/预算不变。
- 真实 Go CLI：`python scripts/test-project.py` 通过（14 个合成文件；分页、读取、检索、越界/篡改/覆盖/错误摘要拒绝，源与快照不变）；`python scripts/test-agent.py` 通过（loopback 脚本化协议 3 次模型调用、2 次工具调用；happy=`completed`、corrupt=`failed`；不是真实 LLM，未外发）。
- Linux 容器：`python scripts/test-linux.py` 通过，固定 `golang:1.26.3-bookworm` 镜像执行 `-race -tags=integration ./...`。容器经独立 compose 网络访问同一 `trident_test`；测试夹具新增显式 `TRIDENT_TEST_DATABASE_NETWORK=isolated-compose` 才接受服务别名，默认仍只接受 loopback。
- 未验证：真实外部模型、付费请求、源码外发、Maven/Java/JUnit 执行、R2 供应链/AST 分析、R3 补丁与隔离验证。accounting-only 是本地协议与存储行为，不是漏洞分析或修复验证。
- 跳过项：本轮 Linux 容器未以 `-v` 复核历史 bind mount 测试的 `CAP_SYS_ADMIN` 跳过详情；不把退出码 0 扩大解释为该项已验证。

### 下一次接续入口（Agent Core）

1. 在获得明确端点、模型、数据外发与费用许可后，按 `agent-contract.md` §6 执行真实模型 R1 闭环验收。
2. R2 声明级首片已另行完成（见下方记录）；后续为 Java AST/入口/Source-Sink、SBOM 导出和 Agent 工具接入。
3. 不把本轮 Fake/loopback 结果当作真实自主审计证据。

## 2026-11-12：R2 首片（Maven 声明 + 固定公告）

### 范围与决定

- 新增 `internal/sca` 与 `trident sca inspect`；只读已 pin 的快照，不执行 Maven/Java，不访问仓库或模型。
- 仅解析本地 POM 声明：parent/properties/dependencyManagement/dependencies/modules；父 POM 只走快照内 relativePath；子属性覆盖参与被管理版本插值。
- 公告目录必须由 `--advisories` 显式指定为本地普通文件；只做精确版本 case，不实现区间、别名或传递解析。
- 未把 SCA 接入 Agent 工具集；`agent run` 仍只有四项快照工具。工具契约、Run 配置绑定和测试更新留待下一片。

### 交付

- [x] POM 解析与路径/大小/深度/DTD 防护；单个 POM 失败标记 partial，不静默跳过。
- [x] 父 POM/属性/dependencyManagement/子覆盖解析；管理项不误报为实际依赖；重复声明标记。
- [x] 固定公告 JSON 严格加载、精确版本匹配、candidate/not_affected/unknown 分层。
- [x] CLI 输出结构化报告、覆盖计数与固定 limitations。
- [x] SCA 单测、CLI 测试和 `scripts/test-sca.py`。
- [x] 更新 SCA 契约与 README。

### 验证记录

- `go test ./internal/sca ./cmd/trident -count=1`：通过（6 个 SCA 单测 + CLI 测试）。
- `python scripts/test-sca.py`：通过；3 个 POM、2 个模块、6 条直接依赖、2 条公告匹配；`jdbc-app` Commons Text 1.9 为 `version_matched/candidate`，`advisory-control` 1.10.0 为 `not_affected`。
- 负例：DTD、父 POM 环、管理项误报、重复声明、无公告目录、非法公告、错误摘要、快照篡改均按预期拒绝或标记。
- `go test ./... -count=1`、`go vet ./...`、`python scripts/test-project.py`、`python scripts/test-agent.py`、`python scripts/test-linux.py` 均通过（Agent 仍为四项工具、loopback 非真实模型）。
- Linux 使用 `-race -tags=integration -p 1 ./...`：SCA 包与历史数据库回归通过。并行包执行时遗留 `TestToolApprovalExpiryAfterLedgerLock`（1.1s 审批过期 + 账本锁）出现时序抖动，单独与串行包均通过；脚本仅改为串行包调度，未放宽断言。
- 未运行：Maven/Java/JUnit、真实外部模型、传递依赖解析、Java AST/污点、运行时验证和补丁。
- 工程仍无 Git 仓库（无 `.git`），无 commit；结果对应当前工作区文件内容。

### 下一次接续入口（R2 第一片）

1. Spring MVC 入口清单已完成（见下方第二片）；下一步为基础 Source/Sink 与方法内有界追踪。
2. 固定 SBOM 导出格式并用官方 Schema 校验；随后评估将 SCA/入口工具接入 Agent 工具注册与 Run 配置。

## 2026-11-12：R2 第二片（Spring MVC 入口清单）

### 范围与决定

- 新增 `internal/audit` 与 `trident audit endpoints`；只读已 pin 快照，不执行 Java/编译器/Maven，不调用模型或网络。
- 采用有界词法扫描 + 结构匹配，排除注释/字符串；识别 `Controller/RestController`、`RequestMapping` 家族、base+method 路径和常见参数绑定。
- 这是**注解级入口清单**，不是 JavaParser/类型解析；元注解、接口继承、Servlet/JAX-RS/WebFlux、context-path 和配置类路由均未覆盖。
- 非字面量路径、text block 文件、嵌套类、非控制器映射均显式标记 unresolved/partial/limitation，不静默猜测。

### 交付

- [x] Java 词法扫描、类/方法/注解/参数结构解析；注释和字符串不产生误匹配。
- [x] Spring MVC 控制器与映射注解识别、base+method 路径组合、多路径/多 HTTP 方法展开。
- [x] `RequestParam/PathVariable/RequestBody` 等参数绑定、显式绑定名与 required 记录。
- [x] `fixture:*` 锚点、文件 SHA-256、起止行、路径状态/原因与覆盖限制输出。
- [x] 重复路由、非控制器映射、未解析路径、文本块/嵌套类等负例处理。
- [x] `audit endpoints` CLI、单测、CLI 测试与 `scripts/test-audit.py`。
- [x] 更新入口清单契约、README 与样本验收记录。

### 验证记录

- `go test ./internal/audit ./cmd/trident -count=1`：通过（5 个 audit 单测 + CLI 测试）。
- `python scripts/test-audit.py`：通过；8 个 Java 文件、1 个控制器、3 个 GET 入口；三个入口的 `@RequestParam("name") String name`、路径、锚点均正确；未执行 Java/模型，源与快照不变。
- 负例：注释/字符串不匹配；多路径数组展开为 4 个组合；`RequestMapping` 多 HTTP 方法展开；常量路径 unresolved；text block 文件拒绝并 partial；嵌套类跳过并 partial；非控制器映射只记 limitation；非法转义路径 unresolved；快照篡改失败关闭。
- `go test ./... -count=1`、`go vet ./...`、`python scripts/test-project.py`、`python scripts/test-sca.py`、`python scripts/test-audit.py` 通过（Windows / Go 1.27.1）。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、历史 P0 集成回归、`demo-offline`、只读 Schema 检查）。
- `python scripts/test-agent.py`：通过（loopback 脚本化协议，非真实 LLM；happy Run=6、corrupt Run=7）。
- Linux race：此前一次尝试因 Docker Desktop 引擎未运行未完成；用户重新启动 Docker Desktop 并启动 `trident-p0-postgres-1` 后补跑，`python scripts/test-linux.py` 通过。`internal/audit`、`internal/sca` 与历史数据库回归均在固定 Linux 容器的 `-race -tags=integration -p 1 ./...` 下通过。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、Java AST/类型解析、Source/Sink/污点、运行时验证和补丁。
- 工程仍无 Git 仓库（无 `.git`），无 commit。

### 下一次接续入口（R2 第二片）

1. 基础 Source/Sink 已完成（见下方第三片）；下一步为 Finding/Hypothesis 证据模型与更多 sink 类别。
2. 固定 SBOM 导出格式并用官方 Schema 校验；评估将 SCA/入口/数据流工具接入 Agent 工具注册与 Run 配置。

## 2026-11-13：R2 第三片（JDBC SQL Source/Sink）

### 范围与决定

- 新增 `internal/dataflow` 与 `trident audit dataflow`；复用注解级入口清单，只读已 pin 快照，不执行 Java/Maven，不调用模型或网络。
- 只建模 JDBC SQL：`Statement.execute*/prepareStatement` 的 SQL 参数为 sink；常量结构 `PreparedStatement` + 值绑定为防护/负例。
- 方法内支持简单赋值与字符串 `+` 拼接；跨方法通过字段/局部变量类型解析同项目方法，深度 8、visited 防环。
- 每参数独立 finding，状态分为 `static_confirmed` / `refuted` / `inconclusive`；动态/未解析边界和“未观察到路径”都输出 inconclusive，不冒充安全。

### 交付

- [x] Java 方法/字段模型与同项目跨文件索引；注释/字符串排除，text block 拒绝并 partial。
- [x] Source（请求绑定参数）、JDBC SQL sink、PreparedStatement 值绑定、反射/未解析边界识别。
- [x] 方法内赋值/拼接传播与有界跨方法 taint 映射；visited 防环。
- [x] Finding 状态/严重度/flow/evidence/anchor/limitations 输出。
- [x] `audit dataflow` CLI、单测、CLI 测试与 `scripts/test-dataflow.py`。
- [x] 更新数据流契约、README 与样本验收记录。

### 验证记录

- `go test ./internal/dataflow ./cmd/trident -count=1`：通过（4 个 dataflow 单测 + CLI 测试）。
- `python scripts/test-dataflow.py`：通过。3 个 finding：
  - unsafe：`static_confirmed`，跨方法到 `CustomerRepository.java:28` 的 `Statement.executeQuery`，flow 含 call/concat/sink。
  - parameterized：`refuted`，常量 SQL + `setString`（`CustomerRepository.java:39`）。
  - dynamic：`inconclusive`，tainted 值到达反射 `invoke`。
- 负例：同方法 sink 确认；常量 SQL + 值绑定 refuted；未解析调用/递归/无路径 inconclusive；字符串中的 SQL 文本不误报；text block 文件拒绝；快照篡改失败关闭。
- `go test ./... -count=1`、`go vet ./...`、`python scripts/test-project.py`、`python scripts/test-sca.py`、`python scripts/test-audit.py`、`python scripts/test-dataflow.py` 通过（Windows / Go 1.27.1）。
- `python scripts/test-local.py`、`python scripts/test-agent.py`、`python scripts/test-linux.py` 通过（专属 PostgreSQL + 固定 Linux 容器，`-race -tags=integration -p 1 ./...`）。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、完整 AST/污点、其他漏洞类别、运行时验证和补丁。
- 工程仍无 Git 仓库（无 `.git`），无 commit。

### 下一次接续入口（R2）

1. 统一 Finding/Hypothesis 证据模型已完成（见下方第四片）；下一步扩展 Source/Sink：`StringBuilder`/`String.format`、返回值污点、接口/重载/继承、其他注入类别；每类补正例、负例、边界例。
2. 固定 SBOM 导出格式并用官方 Schema 校验；评估将 `inspect_dependencies`/`match_advisories`/`query_endpoints`/`trace_dataflow` 接入 Agent 工具注册与 Run 配置。

## 2026-11-13：R2 第四片（统一 Finding/Hypothesis 证据模型）

### 范围与决定

- 新增 `internal/findings` 与 `trident audit findings`；在同一只读快照上运行声明级 SCA、注解级入口清单和 JDBC 数据流，规范化为统一 finding、假设和证据。
- 静态与运行时分离：finding 的 `status` 只表示静态判断，`runtime_status` 恒为 `not_run`；每类 finding 的运行时利用假设恒为 `unverified` 并列出 `required_evidence`。
- 关联不等于利用：SCA 精确版本命中输出 `vulnerable_dependency` / `inconclusive` / `severity=unknown`；依赖可达入口、运行时利用和数据流运行时利用均显式 `unverified`。
- `refuted` 只覆盖被观察参数/值绑定；`inconclusive` 表示证据未采集，不输出“安全”。
- 证据带稳定 ID、文件 SHA-256/行号/anchor；公告目录是调用者配置，`advisory` 证据不伪造 file/SHA。
- 不执行 Java/Maven/模型/网络；快照只读；公告目录可选。

### 交付

- [x] `internal/findings`：finding/evidence/hypothesis/coverage/limitations 模型与确定性排序。
- [x] SCA candidate、入口清单和数据流 finding 的规范化与证据关联；POM 证据摘要取自快照 manifest。
- [x] `audit findings` CLI、dispatch、单测和 CLI 测试。
- [x] `scripts/test-findings.py` 真实 CLI 验收。
- [x] `findings-contract.md`、README、样本验收记录。

### 验证记录

- `go test ./internal/findings ./cmd/trident -count=1`：通过（3 个 findings 单测 + CLI 测试）。
- `python scripts/test-findings.py`：通过。4 个 finding：
  - `/synthetic/customers/unsafe`：`static_confirmed`，`source_to_sink=supported`，证据含 `fixture:unsafe-http-source`、`fixture:sql-concatenation` 与 `statement.executeQuery` 行号 28。
  - `/synthetic/customers/parameterized`：`refuted`，`source_to_sink=unsupported`，`value_binding=supported`。
  - `/synthetic/customers/dynamic`：`inconclusive`，`source_to_sink=unverified`，原因 `dynamic_invocation`。
  - `CVE-2022-42889` / `org.apache.commons:commons-text 1.9`：`vulnerable_dependency`、`inconclusive`、`severity=unknown`；版本假设 `supported`，依赖可达入口与运行时利用均 `unverified`。
- 计数：confirmed=1、refuted=1、inconclusive=2；hypotheses supported=3、unsupported=1、unverified=6；SCA candidate=1、not affected=1；入口=3、数据流 finding=3。
- POM 证据 SHA-256 与实际快照文件一致；重复运行输出字节级一致；每个 finding 的证据 ID 唯一。
- 负例：缺少 `--snapshot-hash`、错误摘要、缺失公告文件、快照篡改均失败关闭且不输出成功 JSON；快照与合成源目录不变。
- `go test ./... -count=1`、`go vet ./...` 通过（Windows / Go 1.27.1）。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py` 全部通过（真实 Go CLI，无数据库）。
- `python scripts/test-local.py` 通过（真实 PostgreSQL、迁移、历史 P0 集成回归、Agent Run、`demo-offline`、只读 Schema）。`python scripts/test-agent.py` 通过（loopback 脚本化协议，非真实 LLM；happy Run=10、corrupt Run=11）。
- `python scripts/test-linux.py` 通过：固定 Linux 容器 `-race -tags=integration -p 1 ./...`，含 `internal/findings`。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、依赖 import graph/有效依赖树/classpath、依赖到入口可达性、运行时验证和补丁。
- 工程仍无 Git 仓库（无 `.git`），无 commit。

### 下一次接续入口（R2）

1. 扩展 Source/Sink：`StringBuilder`/`String.format`、返回值污点、接口/重载/继承、其他注入类别；每类补正例、负例、边界例（`StringBuilder`/`String.format` 见第五片，返回值/builder 突变见第六片）。
2. 固定 SBOM 导出格式并用官方 Schema 校验；评估依赖 import graph 与入口可达性分析，避免把“同仓存在”误写成可达。
3. 评估将 `inspect_dependencies`/`match_advisories`/`query_endpoints`/`trace_dataflow`/`list_findings` 接入 Agent 工具注册与 Run 配置。

## 2026-11-13：R2 第五片（SQL 构造覆盖扩展）

### 范围与决定

- 在既有 JDBC SQL 词法数据流上扩展 SQL 构造：`StringBuilder`/`StringBuffer.append`、`builder.toString()`、字面量 `String.format`；每类补正例、负例和边界例。
- 传播规则：已知 builder 类型接收者的 tainted `append` 标记 builder；`toString()` 在 sink 参数或赋值右值复制 taint。`String.format` 仅当格式串为字面量且含转换符（`%%` 不算）时让后续 tainted 实参进入结果；无转换符时 Java 忽略多余实参，保持负例。
- 边界：计算出的格式串 → `boundary.kind=string_format_dynamic`；未知/链式 builder 接收者与无法解析的 helper 保持 `unresolved_call`。边界一律 `inconclusive`，不升级为确认，也不降级为安全。
- 不执行 Java/Maven/模型/网络；快照只读。原 `java-maven` 样本的 endpoint/finding 计数保持不变，新覆盖放入独立样本 `tests/fixtures/java-builder-format`。

### 交付

- [x] `internal/dataflow`：表达式级有界求值（builder append/toString、字面量 format）、动态格式边界；`ToolVersion=0.2.0-p0.2+r2-jdbc-sql-flow-v2`、`analysis_scope=single_parameter_jdbc_sql_v2`。
- [x] 新增独立合成样本 `tests/fixtures/java-builder-format`（8 个 endpoint）与 `TestAnalyzeBuilderAndFormatFlows`。
- [x] `scripts/test-dataflow.py` 扩展第二样本真实 CLI 验收（正例/负例/边界/锚点/快照不变）。
- [x] `dataflow-contract.md`、README、本记录同步。

### 验证记录

- `go test ./... -count=1`：通过（含 `internal/dataflow` 6 个单测）。
- `go vet ./...`：通过。
- `python scripts/test-dataflow.py`：通过。原样本 3 endpoint/3 finding 不变（confirmed=1、refuted=1、inconclusive=1）；新样本 8 endpoint/9 finding（confirmed=4、inconclusive=5、refuted=0）。
  - 正例：builder、buffer→toString、format 赋值、format 直接 sink 均 `static_confirmed`。
  - 负例：仅常量 append、无转换符 format 均 `inconclusive` 且无 sink。
  - 边界：动态 format 2 个 finding（`string_format_dynamic`）、未知 helper 修改 builder（`unresolved_call`）均 `inconclusive`。
  - 源目录与快照运行前后字节级不变；未执行 Java/Maven、未调用模型。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-findings.py`：通过。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、P0 集成回归、Agent Run）。`python scripts/test-agent.py`：通过（loopback 脚本化协议，非真实 LLM）。
- `python scripts/test-linux.py`：通过（固定容器 `-race -tags=integration -p 1 ./...`，含 `tests/integration`）。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、完整 AST/别名分析、builder 跨方法突变、返回值污点、运行时验证。
- 工程仍无 Git 仓库（无 `.git`），无 commit。

### 下一次接续入口（R2）

1. 返回值污点与 builder 跨方法突变建模；接口/重载/继承分派；其他注入类别（命令注入、SSRF、路径遍历等）（返回值/builder 突变见第六片，接口/继承分派与字段污点见第七片）。
2. 固定 SBOM 导出格式并用官方 Schema 校验；评估依赖 import graph 与入口可达性。
3. 评估将 `inspect_dependencies`/`match_advisories`/`query_endpoints`/`trace_dataflow`/`list_findings` 接入 Agent 工具注册与 Run 配置。

## 2026-11-13：R2 第六片（返回值污点与 builder 跨方法突变）

### 范围与决定

- 对 resolved 同项目方法的调用，按目标方法的参数 taint 汇总其 `return` 表达式：拼接、builder `toString()`、字面量 `format` 和被调方法继续返回的 taint 可继续传播（`flow.kind=return`）。
- resolved 方法收到 builder 实参且对同名参数执行 tainted `append`（直接或经 resolved 调用传递）时，调用方 builder 标记为 tainted（`flow.kind=builder_mutated`）。
- 清洁返回值不因实参 tainted 而误报；目标方法内携带 taint 的未解析调用输出 `return_value_unresolved` / `callee_effects_unresolved`，保持 `inconclusive`。
- 方法效果摘要按方法 + 参数名缓存；递归命中标记 unresolved，不假定清洁；不执行 Java/Maven/模型/网络，快照只读。
- 新覆盖放入独立样本，原 `java-maven` 与 `java-builder-format` 计数不变。

### 交付

- [x] `internal/dataflow`：`evaluateExpressionIn`、`methodEffects`、builder 参数突变回写、返回值 flow 与效果缓存；`ToolVersion=0.2.0-p0.2+r2-jdbc-sql-flow-v3`、`analysis_scope=single_parameter_jdbc_sql_v3`。
- [x] 新增独立合成样本 `tests/fixtures/java-return-flow`（6 个 endpoint / 7 个 finding）与 `TestAnalyzeReturnAndBuilderMutationFlows`。
- [x] `scripts/test-dataflow.py` 扩展第三样本真实 CLI 验收（正例/负例/边界/锚点/快照不变）。
- [x] `dataflow-contract.md`、README、本记录同步。

### 验证记录

- `go test ./... -count=1`：通过（含 `internal/dataflow` 7 个单测）。
- `go vet ./...`：通过。
- `python scripts/test-dataflow.py`：通过。原样本 3/3 与 builder-format 8/9 计数不变；新样本 6 endpoint/7 finding（confirmed=3、inconclusive=4、refuted=0）。
  - 正例：返回拼接赋值、sink 实参内直接调用、helper 修改 builder 后 `toString()` 均 `static_confirmed`。
  - 负例：清洁返回值、helper 忽略 tainted 实参均 `inconclusive` 且无 sink。
  - 边界：返回值内动态 `String.format` 的两个参数 finding 均为 `string_format_dynamic`。
  - 源目录与快照运行前后字节级不变；未执行 Java/Maven、未调用模型。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-findings.py`：通过。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、P0 集成回归、Agent Run）。`python scripts/test-agent.py`：通过（loopback 脚本化协议，非真实 LLM；happy Run=14、corrupt Run=15）。
- `python scripts/test-linux.py`：首轮在既有 P0 计时测试 `TestClaimRechecksDeadlineAfterPoolLock` 失败（`deadline passed during pool wait but claim succeeded`）；该测试与 dataflow 无关且本片未修改，原命令重跑通过。首轮失败保留记录，不用重跑覆盖。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、完整 AST/别名分析、接口/继承/重载分派、字段污点、运行时验证。
- 工程仍无 Git 仓库（无 `.git`），无 commit。

### 下一次接续入口（R2）

1. 接口/继承/重载分派与字段污点；其他注入类别（命令注入、SSRF、路径遍历等），每类补正例、负例、边界例（接口/继承分派与字段污点见第七片）。
2. 固定 SBOM 导出格式并用官方 Schema 校验；评估依赖 import graph 与入口可达性。
3. 评估将 `inspect_dependencies`/`match_advisories`/`query_endpoints`/`trace_dataflow`/`list_findings` 接入 Agent 工具注册与 Run 配置。

## 2026-11-13：R2 第七片（接口/继承分派与字段污点）

### 范围与决定

- 解析类型头部的 `extends`/`implements`（含泛型深度与多父类型）；方法解析沿继承链上溯，子类覆写优先。
- 无方法体的接口/抽象方法调用只接受唯一具体实现；多个实现输出 `boundary.kind=ambiguous_dispatch`，不任选实现。
- 字段写入支持 `this.field = expr` 与无同名局部变量的裸 `field = expr`；字段按声明类归属，支持基类字段；字段读取支持 `this.field`、裸字段名和跨方法读取。
- 字段污点在单个 endpoint/finding 内按「类 + 字段名」flow-insensitive 传播，方法入口和 resolved 调用返回后重新注入；`return this.field` 走方法效果摘要。
- 修正零实参调用的 arity 归一化（空参数列表不再被当作 1 个空实参），使无参字段 getter 可解析。
- 不执行 Java/Maven/模型/网络；快照只读；原三套样本计数不变。

### 交付

- [x] `internal/dataflow/parse.go`：类型 `Kind`/`Parents`/`Bases`、类型头部父类解析、继承方法解析与唯一实现分派、类层级字段归属。
- [x] `internal/dataflow/flow.go`：`seedFields`/`writeField`、`field_write`/`field_read` 流、`ambiguous_dispatch` 边界、字段注入与返回效果。
- [x] `ToolVersion=0.2.0-p0.2+r2-jdbc-sql-flow-v4`、`analysis_scope=single_parameter_jdbc_sql_v4`。
- [x] 新增多文件样本 `tests/fixtures/java-dispatch-field`（9 个 Java 文件、8 个 endpoint）与 `TestAnalyzeDispatchAndFieldTaint`。
- [x] `scripts/test-dataflow.py` 扩展第四样本真实 CLI 验收；`dataflow-contract.md`、README、本记录同步。

### 验证记录

- `go test ./... -count=1`：通过（含 `internal/dataflow` 8 个单测）。
- `go vet ./...`：通过。
- `python scripts/test-dataflow.py`：通过。原样本 3/3、builder-format 8/9、return-flow 6/7 计数不变；新样本 8 endpoint/8 finding（confirmed=6、inconclusive=2、refuted=0）。
  - 正例：唯一接口实现、继承方法、子类覆写、`this` 字段写→读、字段复制、基类字段跨方法写读均 `static_confirmed`。
  - 负例：helper 只写常量字段时无 sink。
  - 边界：双实现接口调用为 `ambiguous_dispatch`。
  - 源目录与快照运行前后字节级不变；未执行 Java/Maven、未调用模型。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-findings.py`：通过。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、P0 集成回归、Agent Run）。`python scripts/test-agent.py`：通过（loopback，happy Run=16、corrupt Run=17）。
- `python scripts/test-linux.py`：通过（固定容器 `-race -tags=integration -p 1 ./...`，含 `tests/integration`）。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、完整 AST/别名分析、重载歧义派发、未解析父类型、其他对象字段、运行时验证。
- 工程仍无 Git 仓库（无 `.git`），无 commit。

### 下一次接续入口（R2）

1. 其他注入类别（命令注入、SSRF、路径遍历、模板注入等），每类补正例、负例、边界例；评估重载消解与跨模块类型解析（重载选择与未解析父类型见第八片）。
2. 固定 SBOM 导出格式并用官方 Schema 校验；评估依赖 import graph 与入口可达性。
3. 评估将 `inspect_dependencies`/`match_advisories`/`query_endpoints`/`trace_dataflow`/`list_findings` 接入 Agent 工具注册与 Run 配置。

## 2026-11-13：R2 第八片（重载选择与未解析父类型）

### 范围与决定

- 重载候选按方法名与参数个数沿继承链收集；同签名的子类覆写覆盖基类方法，避免把覆写误判为重载。
- 用简单实参类型消解重载：字符串/字符/数值字面量、局部变量、字段、`(Type)` 强转、`new Type(...)`、`String.format(...)`；精确匹配优先于数值拓宽/装箱。
- 无法消解时输出 `boundary.kind=ambiguous_overload`；不按候选顺序任选。
- 类型头部父类型在快照内无法解析时记录 `MissingParents`；已知层级找不到方法/字段且存在未解析父类型时输出 `boundary.kind=unresolved_parent`，不把“未找到”当作不存在。
- 自有或可解析父类型方法仍正常命中；新增 `ReturnType` 仅用于简单调用类型推断，不执行 Java。
- 不执行 Java/Maven/模型/网络；快照只读；原四套样本计数不变。

### 交付

- [x] `internal/dataflow/parse.go`：限定名父类型解析、`MissingParents`、重载候选去重与类型匹配、`ambiguous_overload`/`unresolved_parent` 判定、方法返回类型。
- [x] `internal/dataflow/flow.go`：实参类型推断、重载分派接入、父类型边界与 this 字段边界。
- [x] `ToolVersion=0.2.0-p0.2+r2-jdbc-sql-flow-v5`、`analysis_scope=single_parameter_jdbc_sql_v5`。
- [x] 新增多文件样本 `tests/fixtures/java-overload-parent`（6 个 Java 文件、5 个 endpoint）与 `TestAnalyzeOverloadAndUnresolvedParent`。
- [x] `scripts/test-dataflow.py` 扩展第五样本真实 CLI 验收；`dataflow-contract.md`、README、本记录同步。

### 验证记录

- `go test ./... -count=1`：通过（含 `internal/dataflow` 9 个单测）。
- `go vet ./...`：通过。
- `python scripts/test-dataflow.py`：通过。原四套样本计数不变；新样本 5 endpoint/5 finding（confirmed=3、inconclusive=2、refuted=0）。
  - 正例：String 重载、Integer 装箱重载、自有方法优先于未解析父类型均 `static_confirmed`。
  - 边界：`Object` 实参无法匹配 String/Integer → `ambiguous_overload`；快照外父类型成员 → `unresolved_parent`。
  - 源目录与快照运行前后字节级不变；未执行 Java/Maven、未调用模型。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-findings.py`：通过。
- `python scripts/test-agent.py`：通过（loopback，happy Run=18、corrupt Run=19）。
- `python scripts/test-linux.py`：通过（固定容器 `-race -tags=integration -p 1 ./...`）。
- `python scripts/test-local.py`：首轮在既有治理计时测试 `TestToolApprovalExpiryAfterLedgerLock` 失败（`expired approval admitted after ledger wait`）；该测试与 dataflow 无关且本片未修改，同命令重跑通过。首轮失败保留记录，不用重跑覆盖。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、完整 AST/别名分析、lambda/泛型重载、可变参数、快照外父类型实现、运行时验证。
- 工程仍无 Git 仓库（无 `.git`），无 commit。

### 下一次接续入口（R2）

1. 其他注入类别（命令注入、SSRF、路径遍历、模板注入等，见第十片），每类补正例、负例、边界例；评估跨模块类型解析与显式数组实参（lambda/泛型/可变参数重载见第九片）。
2. 固定 SBOM 导出格式并用官方 Schema 校验；评估依赖 import graph 与入口可达性。
3. 评估将 `inspect_dependencies`/`match_advisories`/`query_endpoints`/`trace_dataflow`/`list_findings` 接入 Agent 工具注册与 Run 配置。

## 2026-11-13：R2 第九片（Lambda、泛型与可变参数重载）

### 范围与决定

- 实参类型新增 lambda/方法引用识别；lambda 匹配已知函数式接口或项目中只有一个方法的接口，多个候选都可接受时输出 `ambiguous_overload`。
- lambda 方法体不做独立污点分析；捕获的 taint 通过调用实参的保守词法扫描进入目标方法。
- 泛型按擦除处理，类型实参不进入匹配；方法级类型变量在返回类型推断时用同名实参的已知类型替换，用于外层重载选择；泛型类参数不建模。
- 可变参数按“固定参数 + 组件类型”匹配；实参个数不少于固定参数，尾部逐个匹配组件类型；显式数组实参不建模。
- 精确匹配优先；无法消解统一为 `ambiguous_overload`；不执行 Java/Maven/模型/网络；快照只读；原五套样本计数不变。

### 交付

- [x] `internal/dataflow/parse.go`：`Varargs`/`TypeParams`/泛型方法返回类型、lambda/函数式接口/JDK 集合/项目继承匹配、可变参数 arity 与组件匹配、类型变量返回类型替换。
- [x] `internal/dataflow/flow.go`：lambda/方法引用检测、调用返回类型推断、递归深度保护。
- [x] `ToolVersion=0.2.0-p0.2+r2-jdbc-sql-flow-v6`、`analysis_scope=single_parameter_jdbc_sql_v6`。
- [x] 新增多文件样本 `tests/fixtures/java-lambda-generic-varargs`（5 个 Java 文件、6 个 endpoint）与 `TestAnalyzeLambdaGenericVarargsOverloads`。
- [x] `scripts/test-dataflow.py` 扩展第六样本真实 CLI 验收；`dataflow-contract.md`、README、本记录同步。

### 验证记录

- `go test ./... -count=1`：通过（含 `internal/dataflow` 10 个单测）。
- `go vet ./...`：通过。
- `python scripts/test-dataflow.py`：通过。原五套样本计数不变；新样本 6 endpoint/6 finding（confirmed=4、inconclusive=2、refuted=0）。
  - 正例：lambda 选择 Function 重载、varargs 选择 String...、泛型 identity 选择与嵌套返回类型替换、泛型直接赋值均 `static_confirmed`。
  - 边界：Function/Consumer 双函数式接口与零可变参数双候选均为 `ambiguous_overload`。
  - 源目录与快照运行前后字节级不变；未执行 Java/Maven、未调用模型。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-findings.py`：通过。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、P0 集成回归、Agent Run）。`python scripts/test-agent.py`：通过（loopback，happy Run=20、corrupt Run=21）。
- `python scripts/test-linux.py`：通过（固定容器 `-race -tags=integration -p 1 ./...`）。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、完整 AST/别名分析、lambda 方法体污点、泛型类型实参与边界、显式数组实参、运行时验证。
- 工程仍无 Git 仓库（无 `.git`），无 commit。

### 下一次接续入口（R2）

1. 其他注入类别（命令注入、SSRF、路径遍历、模板注入等）见第十片；评估跨模块类型解析与显式数组实参。
2. 固定 SBOM 导出格式并用官方 Schema 校验；评估依赖 import graph 与入口可达性。
3. 评估将 `inspect_dependencies`/`match_advisories`/`query_endpoints`/`trace_dataflow`/`list_findings` 接入 Agent 工具注册与 Run 配置。

## 2026-11-13：R2 第十片（命令注入、SSRF、路径遍历与模板注入）

### 范围与决定

- 在既有有界词法数据流上增加 sink 类别，taint 传播语义复用，sink/边界按类别隔离。
- SQL 保持每参数一个 finding；其他类别仅在该参数观察到类别 sink 或类别边界时附加 finding，避免对未触及的类别批量输出。
- 命令注入：`Runtime.getRuntime().exec(tainted)`；`ProcessBuilder.command(tainted)` 标记接收者，`start()` 确认。
- SSRF：`URL u = new URL(tainted)`/`URI.create(tainted)` 后 `openConnection()/openStream()`；`RestTemplate` 常见方法。
- 路径遍历：文件流/读写器构造器；`Files.*` 文件访问方法。
- 模板注入：`SpelExpressionParser.parseExpression(tainted)`；已知模板引擎类型的 `process(tainted, ...)`。
- 构造器与静态工厂结果可传播 taint；`Paths.get`/`Path.of`/`URI.create` 不产生 `unresolved_call`。
- 仅构造 `new File(...)`/`new URL(...)` 不确认；接收者类型未知但方法名具有类别特征时输出 `boundary.kind=unresolved_sink`。
- 不执行 Java/Maven/模型/网络；快照只读；原六套样本计数不变。

### 交付

- [x] `internal/dataflow/model.go`：`categorySpec` 与五类 sink 元数据；每参数按类别装配 finding；多类别报告级 limitations。
- [x] `internal/dataflow/flow.go`：类别 sink 识别、`command_append`、`unresolved_sink`、构造器/工厂污点传播；抽取 `analyzeResolvedCall`。
- [x] `internal/findings/findings.go`：按 CWE 映射 `command_injection`/`ssrf`/`path_traversal`/`template_injection` 及对应 hypothesis 语句。
- [x] `ToolVersion=0.2.0-p0.2+r2-source-sink-flow-v7`、`analysis_scope=single_parameter_multi_category_v7`、`analysis_kind=source_sink_multi_category_v1`。
- [x] 新增多文件样本 `tests/fixtures/java-injection-sinks`（5 个 Java 文件、12 个 endpoint）与 `TestAnalyzeInjectionSinkCategories`。
- [x] `scripts/test-dataflow.py` 扩展第七样本真实 CLI 验收；`dataflow-contract.md`、`findings-contract.md`、README、本记录同步。

### 验证记录

- `go test ./... -count=1`：通过（含 `internal/dataflow` 11 个单测）。
- `go vet ./...`：通过。
- `python scripts/test-dataflow.py`：通过。原六套样本计数不变；新样本 12 endpoint/21 finding（confirmed=8、inconclusive=13、refuted=0），其中 SQL finding 12 个且全部 inconclusive。
  - 正例：Runtime.exec、ProcessBuilder command→start、URL.openConnection、RestTemplate.getForObject、new FileInputStream、Files.readAllBytes(Paths.get)、Spel parseExpression、模板引擎 process。
  - 负例：常量命令、常量 URL、常量路径均不产生对应类别 finding。
  - 边界：`String.format` 计算格式串进入 exec → `unresolved_sink`，保持 inconclusive。
  - 源目录与快照运行前后字节级不变；未执行 Java/Maven、未调用模型。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-findings.py`：通过。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、P0 集成回归、Agent Run）。`python scripts/test-agent.py`：通过（loopback，非真实 LLM）。
- `python scripts/test-linux.py`：通过（固定容器 `-race -tags=integration -p 1 ./...`）。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、完整 AST/别名分析、链式构造器与 `HttpClient` builder、框架封装调用、XSS/反序列化/LDAP/XXE、运行时验证。
- 工程仍无 Git 仓库（无 `.git`），无 commit。

### 下一次接续入口（R2）

1. 其他漏洞类别（XSS、反序列化、LDAP 注入、XXE）或链式构造器/`HttpClient` builder/框架封装调用的有界建模；评估跨模块类型解析与显式数组实参。
2. 固定 SBOM 导出格式并用官方 Schema 校验；评估依赖 import graph 与入口可达性。
3. 评估将 `inspect_dependencies`/`match_advisories`/`query_endpoints`/`trace_dataflow`/`list_findings` 接入 Agent 工具注册与 Run 配置。

## 2026-11-13：R2 第十一片（XSS、反序列化、XXE 与 LDAP 注入）

### 范围与决定

- 在既有 `categorySpec` 框架内新增四类 sink，taint 传播与跨方法解析语义完全复用，sink/边界按类别隔离。
- XSS（CWE-79）：`PrintWriter`/`JspWriter`/`ServletOutputStream`/`Writer` 的 `write`/`print`/`println`/`append`，含 `resp.getWriter().write(...)` 链式。
- 反序列化（CWE-502）：`new ObjectInputStream(tainted)`/`new XMLDecoder(tainted)` 在构造处确认；已污点流接收者的 `readObject()` 再次确认。
- XXE（CWE-611）：`DocumentBuilder`/`SAXParser.parse`、`XMLInputFactory.createXMLStreamReader`、`Unmarshaller.unmarshal`、`Transformer.transform`。
- LDAP 注入（CWE-90）：`InitialDirContext`/`DirContext`/`LdapContext`/`LdapTemplate`/`LdapOperations` 的 `search`/`lookup`/`authenticate`。
- 构造器块对非反序列化类别静默跳过，避免把普通 `new` 当成 sink；无法确认参数被消费时输出 `boundary.kind=unresolved_sink`。
- SQL 仍每参数一个 finding；四类仅在观察到对应 sink/边界时附加 finding；未观察不等于安全。
- 不执行 Java/Maven/模型/网络；快照只读；原七套样本计数不变。

### 交付

- [x] `internal/dataflow/model.go`：新增 `xss`/`deserialization`/`xxe`/`ldap` 四类 spec（`allCategories` 共 9 类），报告级 limitations 增加 `deserialization_and_xss_bounds`。
- [x] `internal/dataflow/flow.go`：`analyzeCategorySink` 四个新 case 与 `isWriterMethod`/`isWriterTypeName`/`isResponseWriterChain`/`isDeserializationStreamType`/`isXMLParserType`/`isLDAPQueryName`/`isLDAPContextType`。
- [x] `internal/findings/findings.go`：CWE-79/502/611/90 映射 `xss`/`deserialization`/`xxe`/`ldap_injection` 及 hypothesis 语句。
- [x] `ToolVersion=0.2.0-p0.2+r2-source-sink-flow-v8`、`analysis_scope=single_parameter_multi_category_v8`、`analysis_kind=source_sink_multi_category_v1`。
- [x] 新增样本 `tests/fixtures/java-extra-sinks/src/main/java/example/extra/ExtraSinkController.java`（14 个 endpoint）与 `TestAnalyzeExtraSinkCategories`。
- [x] `scripts/test-dataflow.py` 新增 `EXTRA_FIXTURE` 与 `[09]` 块；`dataflow-contract.md`、`findings-contract.md`、README、本记录同步。

### 验证记录

- `go test ./... -count=1`：通过（含 `internal/dataflow` 12 个单测）。
- `go vet ./...`：通过。
- `python scripts/test-dataflow.py`：通过。原七套样本计数不变（3/9/7/8/5/6/21）；新样本 14 endpoint/24 finding（extra_confirmed=8、extra_inconclusive=16、extra_refuted=0），其中 SQL finding 14 个且全部 inconclusive。
  - 正例：`resp.getWriter().write`、`PrintWriter.write`、`new ObjectInputStream`、`new XMLDecoder`、`DocumentBuilder.parse`、`SAXParser.parse`、`InitialDirContext.search`、`InitialDirContext.lookup`。
  - 负例：常量响应/反序列化流/XML/LDAP 不产生对应类别 finding。
  - 边界：`String.format(q)` 动态格式串进入 XSS/XXE sink → `unresolved_sink`，保持 inconclusive。
  - 源目录与快照运行前后字节级不变；未执行 Java/Maven、未调用模型。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-findings.py`：通过。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、P0 集成回归、Agent Run）。`python scripts/test-agent.py`：通过（loopback，非真实 LLM；happy Run=24、corrupt Run=25）。
- `python scripts/test-linux.py`：通过（固定容器 `-race -tags=integration -p 1 ./...`）。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、完整 AST/别名分析、集合传播、反序列化 gadget 链、响应返回值型 XSS、运行时验证。
- 工程仍无 Git 仓库（无 `.git`），无 commit。

### 下一次接续入口（R2）

1. 继续有界建模未覆盖项：反射/SpEL 之外的 XSS 反射返回值（Controller 直接 `return` 用户输入）、反序列化链式 `new(...).readObject()`、XXE 的 `XMLInputFactory`/`Transformer` 更多入口、集合传播。
2. 固定 SBOM 导出格式并用官方 Schema 校验；评估依赖 import graph 与入口可达性。
3. 评估将 `inspect_dependencies`/`match_advisories`/`query_endpoints`/`trace_dataflow`/`list_findings` 接入 Agent 工具注册与 Run 配置。

## 2026-11-13：R2 第十二片（集合容器污点传播）

### 范围与决定

- 在既有 `categorySpec` 九类框架与共享 taint 语义上新增集合容器传播，sink 与边界仍按类别隔离，SQL 仍每参数一个 finding。
- 写入：`List`/`ArrayList`/`LinkedList`/`Set`/`HashSet`/`LinkedHashSet`/`TreeSet`/`Map`/`HashMap`/`LinkedHashMap`/`TreeMap`/`Collection`/`Queue`/`Deque`/`ArrayDeque` 的 `add`/`addAll`/`addFirst`/`addLast`/`offer`/`push`/`put`/`putIfAbsent`/`putAll(tainted)` 标记容器变量（`flow.kind=collection_add`），容器变更本身不是 sink。
- 读取：同一容器的 `get`/`getOrDefault`/`values`/`keySet`/`entrySet`/`toArray`/`iterator`/`peek`/`poll`/`pop`/`first`/`last` 在赋值或 sink 实参中传播 taint（`flow.kind=collection_read`）。
- 容器污点 flow-insensitive 地按局部变量/字段名在单个 finding 内传播；`clear`/`remove`、元素下标、跨方法容器内容与其他对象容器不建模。
- 泛型声明类型按擦除解析：修正 `declarationType` 把 `Map<K, V>`/嵌套泛型中的逗号误当声明分隔符的问题，接收者类型记为 `Map` 而非 `V`。
- `add(String.format(q))` 动态实参 → `limitation=collection_dynamic` 且保持 `inconclusive`；接收者类型非集合时 `store.add(q)` 仍走 `boundary.kind=unresolved_call`。
- 不执行 Java/Maven/模型/网络；快照只读；原八套样本计数不变。

### 交付

- [x] `internal/dataflow/flow.go`：`analyzeMethod` 集合变更分支、`evaluateExpression`/`evaluateExpressionIn` 的 `collection_read` 分支、`analyzeAssignment` 的 `collection_read` kind，以及 `isCollectionMutation`/`isCollectionRead`/`isCollectionType`；`declarationType` 泛型感知。
- [x] `internal/dataflow/model.go`：`ToolVersion=0.2.0-p0.2+r2-source-sink-flow-v9`、`analysis_scope=single_parameter_multi_category_v9`；`lexical_flow_not_ast` 移除集合字样，新增 `collection_taint_bounds`。
- [x] 新增样本 `tests/fixtures/java-collections/src/main/java/example/coll/CollectionController.java`（8 个 endpoint）与 `TestAnalyzeCollectionTaint`。
- [x] `scripts/test-dataflow.py` 新增 `COLLECTION_FIXTURE` 与 `[10]` 块、输出字段与检查项；`dataflow-contract.md`、README、本记录同步。

### 验证记录

- `go test ./... -count=1`：通过（含 `internal/dataflow` 13 个单测）。
- `go vet ./...`：通过。
- `python scripts/test-dataflow.py`：通过。原八套样本计数不变（3/9/7/8/5/6/21/24）；新样本 8 endpoint/10 finding（collection_confirmed=4、collection_inconclusive=6、collection_refuted=0），其中 SQL finding 8 个（2 confirmed）。
  - 正例：`List.add`→`get`→SQL 拼接、`Map.put`→`get`、集合→`Runtime.exec`、集合→`PrintWriter.write`。
  - 负例：常量入容器后读取/执行不产生对应类别 sink 证据（SQL 保持 inconclusive）。
  - 边界：`add(String.format(q))` → `collection_dynamic`；未知接收者 `store.add(q)` → `unresolved_call`。
  - 源目录与快照运行前后字节级不变；未执行 Java/Maven、未调用模型。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-findings.py`：通过。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、P0 集成回归、Agent Run）。`python scripts/test-agent.py`：通过（loopback，非真实 LLM；happy Run=26、corrupt Run=27）。
- `python scripts/test-linux.py`：首轮在既有治理计时测试 `TestToolApprovalExpiryAfterLedgerLock` 失败（`expired approval admitted after ledger wait`），该测试与 dataflow 无关且本片未修改；原命令重跑通过（`-race -tags=integration -p 1 ./...`）。首轮失败保留记录，不用重跑覆盖。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、完整 AST/别名分析、集合的 `clear`/`remove` 与跨方法容器内容、响应返回值型 XSS、反序列化 gadget 链、运行时验证。
- 工程仍无 Git 仓库（无 `.git`），无 commit。

### 下一次接续入口（R2）

1. 继续有界建模未覆盖项：集合的 `clear`/`remove` 与跨方法容器内容、元素下标、可控 XSS 反射返回值（Controller 直接 `return` 用户输入）、反序列化链式 `new(...).readObject()`、XXE 的 `XMLInputFactory`/`Transformer` 更多入口。
2. 固定 SBOM 导出格式并用官方 Schema 校验；评估依赖 import graph 与入口可达性。
3. 评估将 `inspect_dependencies`/`match_advisories`/`query_endpoints`/`trace_dataflow`/`list_findings` 接入 Agent 工具注册与 Run 配置。

## 2026-11-13：R2 第十三片（只读 Web 分析控制台）

### 范围与决定

- 新增 `internal/webui` 与 `trident web`；为一个已 pin 的本地快照提供只读分析控制台，复用 `sca`/`audit`/`dataflow`/`findings`，不新增分析语义。
- 控制台不导入源码、不执行 Java/Maven、不调用模型、不访问目标网络、不连接数据库，也不提供 Run/审批/工具执行 API。它不是 HTTP 执行平面。
- 仅监听 loopback；启动生成或显式指定访问令牌，浏览器通过 `POST /api/session` 换取 `HttpOnly; SameSite=Strict` Cookie，脚本使用 `X-Trident-Token`；所有 API 还要求 `X-Trident-Request: console`。CSP 无 `unsafe-inline`，响应启用 `nosniff`、`DENY`、`no-referrer` 与 API `no-store`。
- 前端为无构建步骤的原生 HTML/CSS/JS，经 `go:embed` 打入单一二进制；无 npm、CDN、外部字体或图片。视觉参考 ARTEX/CodeScan 的暗色控制台布局：侧边导航、紧凑统计卡、状态徽章、证据抽屉与源码工作区。
- 分析在首次 API 请求时运行一次并缓存；失败终态缓存，不逐请求重试。`--advisories` 仍为调用者显式配置，不与快照摘要绑定。
- `runtime_status` 恒为 `not_run`；静态确认、`inconclusive`、`refuted` 与 CLI 一致，未观察路径不冒充安全。

### 交付

- [x] `internal/webui`：快照打开、令牌/会话鉴权、CSRF 头校验、安全响应头、分析互斥缓存、10 条只读查询与 1 条会话交换、嵌入资产与错误映射。
- [x] `cmd/trident/web.go`：`--snapshot`/`--snapshot-hash`/`--advisories`/`--addr`/`--token`，强制 loopback 并打印一次性地址与令牌。
- [x] 六个前端视图：概览、安全发现（筛选/分页/证据抽屉）、HTTP 入口、依赖与公告、源码浏览与检索、边界与关于；统一证据 JSON 下载。
- [x] `internal/webui/webui_test.go` 7 项测试与 `cmd/trident/web_test.go` 监听地址/参数负例。
- [x] `scripts/test-web.py` 真实 CLI 验收；`docs/web-console-contract.md`、README、版本字符串同步。
- [x] 版本标识新增 `r2-readonly-web-console`；未修改迁移、快照格式或既有分析模型。

### 验证记录

- Windows / Go 1.27.1：`go build ./...`、`go test ./... -count=1`、`go vet ./...` 通过（含 `internal/webui` 7 项与 `cmd/trident` 2 项新测试）。
- `python scripts/test-web.py`：通过。真实 CLI 导入 14 个合成文件，在随机 loopback 端口启动控制台；验证登录/会话 Cookie、401/403/400/404 负例、概览/发现/详情/入口/依赖/文件/检索/报告、路径遍历拒绝；快照与 fixture 前后字节级一致，未连接数据库、未调用模型、未执行 Java/Maven。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`：全部通过，既有分析计数不变。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、历史 P0 集成回归、Agent Run、`demo-offline`、只读 Schema）。`python scripts/test-agent.py`：通过（loopback 脚本化协议，非真实 LLM；happy Run=28、corrupt=29）。
- `python scripts/test-linux.py`：通过（固定 Linux 容器 `-race -tags=integration -p 1 ./...`，含 `internal/webui` 与 `tests/integration`）。
- 浏览器人工检查：1440×900 下登录、概览、发现与证据抽屉、入口、依赖、源码阅读/检索无控制台错误；820px 下侧栏转离屏、统计卡两列、双栏转单栏。390px 移动截图因浏览器工具超时未采集，不据此声称移动端已验证。
- 未运行：真实外部模型、Java/Maven/JUnit、运行时漏洞验证、多用户压力测试、TLS 终止、OS 级快照隔离。
- 当前工作区存在 Git 仓库（`main`，HEAD `c44fb1f`），本片改动未提交；不以文档虚构提交。

### 下一次接续入口（R2/R3）

1. Agent 工具注册仍未接入 `inspect_dependencies`/`match_advisories`/`query_endpoints`/`trace_dataflow`/`list_findings`；需先设计分析证据如何进入工具证据账本，避免模型引用未读行。
2. 固定 SBOM 导出格式与官方 Schema 校验仍未实现；当前控制台只下载统一证据 JSON。
3. R3 隔离验证/补丁闭环未实现；控制台不提供执行或修复入口。
4. 如继续扩展分析：集合 `clear`/`remove`、跨方法容器内容、元素下标、XSS 反射返回值、链式反序列化与更多 XXE 入口。

## 2026-11-13：R2 第十四片（Agent 分析工具接入）

### 范围与决定

- 工具注册从 4 个扩展为 9 个：新增 `inspect_dependencies`、`match_advisories`、`query_endpoints`、`trace_dataflow`、`list_findings`。
- 分析工具复用既有 `sca/audit/findings`，首次调用运行一次并缓存；分页不重复分析。
- 分析结果只返回有界摘要（默认 10、最大 20 条），每条最多 2 个源码引用；引用在返回前通过 `Snapshot.Read` 实际读取并写入证据账本。最终答案只能引用这些已读取行或后续 `read_source` 行。
- `agent run --advisories <absolute-file>` 将本地公告目录写入 Run 配置；resume 复用该配置。`match_advisories` 未配置时明确返回 `configured=false`。
- 检查点版本升至 v2；v1 检查点不可恢复，不静默重放旧对话。
- 分析工具不执行 Java/Maven/Shell，不改变外发许可；真实模型仍未授权。

### 交付

- [x] `internal/tools/analysis.go`：分析缓存、五个工具、参数校验、分页、引用登记与去重。
- [x] `internal/tools/registry.go`、`evidence.go`：工具定义、分发、分析引用解析。
- [x] `internal/agent/config.go`、`loop.go`、`cmd/trident/agent.go`：公告配置、九工具提示、checkpoint v2。
- [x] 分析工具单测 3 项、配置单测、注册表/循环测试更新；`scripts/test-agent.py` 更新为九工具白名单。
- [x] `agent-contract.md`、README、版本标识同步。

### 验证记录

- `go test ./internal/tools ./internal/agent ./cmd/trident -count=1`：通过。
- 分析工具测试覆盖：依赖摘要、未配置公告、入口引用、SQL finding 引用、`ExtractEvidence` 与 `ValidateEvidence` 一致、偏移空页、非法分类/状态/限额、配置公告后的精确匹配。
- `python scripts/test-agent.py`：通过（loopback 脚本化协议，非真实 LLM；happy Run=31、corrupt=32，仍为 3 次模型请求/2 次工具调用）。
- 未运行：真实模型、分析工具在真实模型自主选择下的闭环。

## 2026-11-13：R2 第十五片（CycloneDX 1.5 SBOM）

### 范围与决定

- 新增 `internal/sbom` 与 `trident sca sbom`；只消费声明级 SCA 报告，不执行 Maven、不解析传递依赖。
- 输出确定性 CycloneDX 1.5 JSON：序列号由快照 SHA-256 派生，不写时间戳；组件按唯一 GAV 去重，根组件声明全部直接依赖。
- 公告候选映射为 `analysis.state=in_triage`、`severity=unknown`、`affects` 指向组件；metadata properties 固定写入 `runtime_status=not_run`、`dependency_reachability=unverified`、`transitive_tree=not_available` 与限制。
- 官方 Schema（CycloneDX 1.5，Apache-2.0）固定副本加入 `tests/schemas/`，由 Python `jsonschema` Draft 7 校验；运行时不访问网络。
- Web 控制台新增 `GET /api/sbom` 与依赖页“导出 SBOM”。

### 交付

- [x] `internal/sbom/sbom.go`、单测；`cmd/trident/sca.go` 的 `sbom` 子命令。
- [x] Web `/api/sbom`、依赖页导出按钮、Go/Python 验收。
- [x] `docs/sbom-contract.md`、README、版本标识同步。

### 验证记录

- `go test ./internal/sbom ./internal/webui ./cmd/trident -count=1`：通过。
- `python scripts/test-sbom.py`：通过。5 个唯一组件、1 个 candidate vulnerability；两次输出字节级一致；官方 Schema 校验通过；无公告目录时无 vulnerability；错误快照摘要失败关闭；快照与 fixture 前后 SHA-256 一致。
- `python scripts/test-web.py`：通过，包含 `/api/sbom` 下载与 `bomFormat=CycloneDX` 检查。
- 未运行：传递依赖解析、制品哈希、依赖可达性、Maven 实测 classpath。

## 2026-11-13：R3 首片（隔离补丁验证）

### 范围与决定

- 首片只做“调用者提供统一 diff → 独立可写副本 → 固定 profile 编译运行 → 原快照复验”，不生成补丁、不调用模型。
- 工作区必须新建、位于快照之外；逐文件经 `Snapshot.ReadFile` 校验后复制；不复制 manifest。
- 统一 diff 仅支持已存在 UTF-8 文本文件；拒绝创建/删除/重命名/二进制、绝对路径、`..`、盘符、反斜杠和引号；上下文逐行精确匹配，无 fuzz。
- `--profile maven` 执行 `mvn -o -B -q -DskipTests compile` 后运行 main class；`--profile javac` 编译 `src/main/java` 后运行；`--profile junit` 用调用者 `--test-classpath` 提供的 JUnit jar 编译 main/test 并运行 JUnitCore 单个测试类，不依赖 Surefire/网络。必须显式 `--approve-execution`。
- 验证环境使用白名单，不传递 `TRIDENT_*`、数据库 URL 或模型密钥；输出各限 64 KiB，超时终止。
- 报告状态区分 `validation_passed/failed/timeout/error/patch_failed/snapshot_integrity_failed/setup_failed`；`runtime_status=isolated_validation_only`。
- 明确：不是 OS 级沙箱、无网络命名空间、无 Surefire/JUnit XML 解析、无 AI 补丁生成，不证明生产可利用性或修复上线。

### 交付

- [x] `internal/r3`：工作区复制、统一 diff 解析/应用、Maven/javac/JUnit 验证、环境白名单、报告。
- [x] `cmd/trident/patch.go`：`trident patch verify`。
- [x] 合成 fixture `tests/fixtures/java-patch`（基线不安全代码、`baseline.patch`、`safe.patch`、Main 检测宿主密钥泄漏）。
- [x] Go 单测、`scripts/test-patch.py`、`docs/patch-contract.md`、README、版本标识同步。

### 验证记录

- 环境：Windows 11、Temurin Java 17.0.16、Maven 3.9.9、Go 1.27.1。
- `go test ./internal/r3 -count=1`：通过（工作区复制、补丁应用、穿越/上下文不匹配/创建文件拒绝、审批/profile/main class 校验）。
- `python scripts/test-patch.py`：通过。
  - 基线补丁 + Maven：`validation_failed`，Java 退出 1，`injection guard missing`。
  - 安全补丁 + Maven：`validation_passed`，输出 `safe`；原快照未修改。
  - 安全补丁 + javac：`validation_passed`。
  - 基线补丁 + JUnit 4.12：`validation_failed`（`Tests run: 1, Failures: 1`）。
  - 安全补丁 + JUnit 4.12：`validation_passed`（`OK (1 test)`）。
  - 未审批、错误哈希、路径穿越、上下文不匹配、已存在 workspace、workspace 位于快照内均拒绝。
  - 宿主注入的 `TRIDENT_MODEL_API_KEY`/`TRIDENT_DATABASE_URL` 未传入验证进程；快照与 fixture 前后字节级一致。
- 未运行：容器/VM 沙箱、网络隔离、AI 补丁生成、真实模型、目标网络执行。

## 2026-11-13：R2 第十六片（集合跨方法突变/clear、反射型返回值与 SAXReader XXE）

### 范围与决定

- 在第十二片集合容器传播之上补齐三个有界缺口，仍不执行 Java/Maven、不调用模型、快照只读。
- 集合跨方法突变：resolved 同项目方法收到调用方集合局部变量，方法体内对同名参数执行 tainted `add`/`put` 时，调用方集合被标记（`flow.kind=collection_mutated`）；方法内 `clear()` 丢弃该容器污点（`collection_clear`），clear 后再写入可重新污染；callee 内 `clear` 会撤销该参数的突变摘要。
- 反射型返回值：endpoint 返回 `String`/`CharSequence` 且 `return` 表达式带 taint 时，仅记录 `boundary.kind=reflected_return` 与 `limitation=reflected_return_content_type_unverified`，保持 `inconclusive`；不解析 `produces`/content-type/框架转义，返回常量不产生 XSS finding。
- XXE 入口扩展：`SAXReader.parse/read`、`XMLReader.parse/read` 纳入既有 `xxe` 类别，接收者类型必须可解析。
- 字段容器 `clear` 仍不建模并记录 `collection_clear_field_unmodeled`；`remove`/元素下标/其他对象容器不变。

### 交付

- [x] `internal/dataflow/flow.go`：`analyzeMethod` 的 `clear` 分支与 endpoint `return` 检测、`collectionArguments`、`methodEffects` 的集合写入/clear 摘要、`observeReflectedReturn`、`isXMLParserType`/XXE `read`、`returnsTextual`。
- [x] `internal/dataflow/model.go`：`ToolVersion=0.2.0-p0.2+r2-source-sink-flow-v10`、`analysis_scope=single_parameter_multi_category_v10`、`collection_taint_bounds`/`deserialization_and_xss_bounds`/`multi_category_sinks` 更新。
- [x] 新增样本 `tests/fixtures/java-container-reflect/src/main/java/example/container/ContainerReflectController.java`（8 个 endpoint）与 `TestAnalyzeCollectionCrossMethodClearAndReflectedReturn`。
- [x] `scripts/test-dataflow.py` 新增 `CONTAINER_REFLECT_FIXTURE`、`[11]` 块、输出字段与 8 个检查项；`dataflow-contract.md`、README 同步。

### 验证记录

- `go test ./internal/dataflow -count=1`：通过（14 个 dataflow 单测）。
- `python scripts/test-dataflow.py`：通过。原九套样本计数不变（3/9/7/8/5/6/21/24/10）；新样本 8 endpoint/10 finding（container_reflect_confirmed=3、inconclusive=7、refuted=0），SQL finding 8 个。
  - 正例：`/container/mutate`（`collection_mutated`→`collection_add`→`sink`）、`/container/clear-refill`、`/xxe/sax-reader`（`SAXReader.read`）。
  - 负例：`/container/clear`（`collection_clear` 后无 sink）、`/container/constant`、`/reflect/clean`。
  - 边界：`/container/helper-clear`（callee `clear` 撤销突变）、`/reflect/return`（`reflected_return`，XSS inconclusive）。
  - 源目录与快照运行前后字节级不变；未执行 Java/Maven、未调用模型。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、完整 AST/别名分析、集合 `remove`/元素下标/字段 `clear`、`produces`/content-type 解析、运行时验证。
- 当前工作区存在 Git 仓库（`main`，HEAD `c44fb1f`），本片改动未提交。

## 2026-11-13：R2 第十七片（数组下标、remove 保守语义、字段集合、produces 与链式反序列化/XXE）

### 范围与决定

- 在第十六片基础上补齐用户点名的剩余分析缺口，仍不执行 Java/Maven、不调用模型、快照只读。
- 数组元素：`values[i] = tainted` 标记数组（`array_write`），`values[i]` 读取传播（`array_read`）；声明类型保留 `[]`（参数/字段/局部变量），resolved 方法内数组参数写入进入效果摘要，调用方数组标记为 `collection_mutated`。
- `remove`/`removeAll`/`retainAll`/`removeIf`：flow-insensitive 容器无法证明元素级删除，因此不清除污点，记录 `collection_remove` 与 `limitation=collection_remove_flow_insensitive`；这是保守过近似，可能保留已移除的 taint。
- 字段集合：`this.field.add/put(tainted)` 写入字段污点；`this.field.clear()` 删除字段污点（`collection_clear`）；同名局部/参数遮蔽字段。
- 入口清单新增 `produces`/`produces_status`/`response_body`：解析字符串字面量与已知 `MediaType.*_VALUE` 常量，未知表达式为 `unresolved`；`@RestController` 或 `@ResponseBody` 标记 `response_body=true`。
- 反射型返回值：只处理 `response_body=true` 的 `String`/`CharSequence` 返回；`produces` 为 HTML → 确认 XSS（`sink.api=return:<media-type>`）；明确非 HTML → `refuted` 并记录 protection；缺失/未解析 → `reflected_return` 边界保持 `inconclusive`；普通 `@Controller` 视图名不产生 XSS finding。
- 链式反序列化：`new ObjectInputStream(...).readObject()`/`new XMLDecoder(...).readObject()` 在 `readObject` 处确认一次，构造处不重复确认。
- 更多 XXE 入口：`SAXBuilder.build`、`Digester.parse`、`DocumentHelper.parseText`、`XMLInputFactory.createXMLEventReader`。

### 交付

- [x] `internal/audit/audit.go`、`java.go`：`Produces`/`ProducesStatus`/`ResponseBody`、`annotationProduces`/`mediaTypeValues`/`knownMediaType`、`ToolVersion=...endpoint-inventory-v2`。
- [x] `internal/dataflow/flow.go`、`parse.go`、`model.go`：数组下标读写、`remove` 保守分支、字段集合写/清、`produces` 判定、链式反序列化、新 XXE 入口；`ToolVersion=...source-sink-flow-v11`、`analysis_scope=...v11`。
- [x] 新增样本 `tests/fixtures/java-flow-gaps`（`GapController.java` 16 endpoint、`ViewController.java` 视图名负例）。
- [x] Go 单测：`TestInspectProducesAndResponseBody`、`TestAnalyzeArrayRemoveFieldClearProducesAndChains`。
- [x] `scripts/test-dataflow.py` 新增 `GAPS_FIXTURE`、`[12]` 块与 16 个检查项；`dataflow-contract.md`、`audit-contract.md`、README 同步。

### 验证记录

- `go test ./internal/audit ./internal/dataflow -count=1`：通过（audit 新增 1 项；dataflow 15 项）。
- `python scripts/test-dataflow.py`：通过。原十套样本计数不变（3/9/7/8/5/6/21/24/10/10）；新样本 16 endpoint/23 finding（confirmed=10、refuted=1、inconclusive=12）。
  - 正例：数组下标读写、数组跨方法突变、字段集合、`produces=text/html` 反射返回、链式反序列化、四个新增 XXE 入口。
  - 负例：常量数组、常量 HTML 返回、普通 `@Controller` 视图名、常量链式反序列化。
  - 保守语义：`remove` 保留污点并标记限制；字段 `clear` 后不确认。
  - 源目录与快照运行前后字节级不变；未执行 Java/Maven、未调用模型。
- 未运行：Java 编译/运行、Maven/Gradle、真实外部模型、完整 AST/别名分析、集合元素级 `remove`、其他对象容器、`produces` 之外的内容协商、运行时验证。
- 当前工作区存在 Git 仓库（`main`，HEAD `c44fb1f`），本片改动未提交。

## 2026-11-13：R1 真实模型只读闭环（DeepSeek deepseek-flash）

### 范围与决定

- 用户提供 DeepSeek 官方 API key，明确要求用 `deepseek-flash` 测试并节省成本；沿用此前约束：仅外发 `tests/fixtures/java-maven` 合成样本、单次 Run 最多 10 次模型调用。
- 端点 `https://api.deepseek.com/v1`，`--output-parameter max_tokens`，`--approve-egress`；密钥仅从 `TRIDENT_MODEL_API_KEY` 读取，不写入 Run、日志或仓库文件。
- 未执行 Java/Maven/Shell，未访问目标网络；Agent 仍只有九个只读工具。

### 兼容性修复（真实调用暴露）

- [x] 响应含 `reasoning_content` 时被旧解码器整体拒绝：改为接受该不透明字段（不进入最终答案），`reasoning_details`/`reasoning` 仍拒绝。
- [x] 工具 Schema 数值关键字被 SDK 编码为字符串（`"maxLength":"2048"`），DeepSeek 以 `Invalid schema ... is not of type "integer"` 拒绝：`objectJSON` 改用标准 JSON 解码，数值保持 JSON number。
- [x] 新增 `TestToolSchemaNumbersStayNumeric` 与 `reasoning-content` 正例；`reasoning_content` 非字符串仍拒绝。
- [x] 未提高 48 KiB 检查点或 64 KiB 工具结果上限；通过收紧模型工具预算完成闭环。

### 验证记录

- Run 43：`completed`，3 次模型调用、4 次工具调用、18,394 tokens；模型自主选择 `inspect_project` → `trace_dataflow` → `query_endpoints` → `read_source`。
- 最终 envelope：2 条 `UNVERIFIED INFERENCE` 假设；引用 `CustomerController.java:22-26/34-38/35` 与 `CustomerRepository.java:24/27-28`，全部通过证据账本校验；显式声明 `runtime_status=not_run`、无 AST、未执行代码、未做依赖公告匹配。
- 早期失败保留：Run 37 响应被协议拒绝（可能已计费、未记账，以 DeepSeek 控制台为准）；Run 38/39/40 被 400 Schema 拒绝；Run 41 在 60k token 预留处停止（3 次模型调用/9 次工具调用/15,484 tokens）；Run 42 在 48 KiB 检查点上限停止（5 次模型调用/10 次工具调用/33,620 tokens）。这些记录不删除、不覆盖。
- Run 46（`deepseek-v4-pro`，同一快照/工具，最多 10 次模型调用）：`completed`，3 次模型调用、4 次工具调用、21,956 tokens；模型自主选择 `trace_dataflow` → `query_endpoints` → `list_files` → `read_source`，输出 2 条 `UNVERIFIED INFERENCE` 假设，引用 `CustomerController.java:22-26/34-37` 与 `CustomerRepository.java:28`，全部通过证据账本校验。另有 105 tokens 的 v4-pro 响应形状探测。
- 该验收覆盖 DeepSeek flash 与 v4-pro 的只读分析，不证明漏洞可利用、覆盖完整或生产部署；不构成对其他端点或真实项目快照的验收。

## 2026-11-13：R2/R3 第十八片（上下文压缩、真实快照验收、AI 补丁与 Docker 沙箱）

### 范围与决定

- 用户要求完成三项：长上下文预算策略、真实项目快照验收、R3 AI 补丁生成 + 沙箱。
- 上下文压缩不提高 48 KiB 硬上限：40 KiB 软目标触发确定性工具结果截断，保留消息与 tool_call/result 配对、证据账本和最新两条结果；`compactions`/`compacted_bytes` 写入检查点，最终答案追加固定限制。
- 真实快照选用 `CodeScan-Artex-main`（667 文件、15 MB、Go 安全工具），用户以“按推荐”明确授权本次外发；模型 `deepseek-flash`，最多 10 次调用。
- AI 补丁：新增 `trident patch propose`，只生成并验证 diff，不执行、不写快照；生成后仍需 `patch verify --approve-execution`。
- Docker 沙箱：新增 `--sandbox docker`，固定 digest 镜像、`--network none`、`--cap-drop ALL`、内存/CPU/PID 限额、可选只读 `.m2`；junit profile 暂不支持 docker。

### 交付

- [x] `internal/agent/loop.go`、`compaction_test.go`：检查点压缩、审计字段、最终限制。
- [x] `internal/r3/propose.go`、`propose_test.go`：finding/路径上下文、严格 JSON、临时副本精确应用验证。
- [x] `cmd/trident/patch.go`：`patch propose` 与 verify 的 `--sandbox` 参数。
- [x] `internal/r3/sandbox.go`、`sandbox_test.go`、`run.go`、`verify.go`：Docker 命令、隔离参数、容器清理、报告/限制。
- [x] `scripts/test-patch-ai.py`：loopback 模型 + process Maven + Docker 验收。
- [x] `docs/agent-contract.md`、`docs/patch-contract.md`、README 同步。

### 验证记录

- `go test ./internal/agent ./internal/r3 -count=1`：通过（压缩边界/幂等/配对、AI 补丁正负例、sandbox 参数与 docker 命令）。
- 真实快照 Run 48：`completed`，4 次模型调用、5 次工具调用、37,153 tokens；`compactions=2`、`compacted_bytes=19,994`；模型自主选择 `inspect_project` → `read_source` → `search_source` → `search_source` → `read_source`，输出 2 条关于 `server/customtool.go` 的未验证推断（命令模板注入、HTTP SSRF），引用 331-347/494-503/427-456/461-486 行，全部通过证据账本校验。首轮 Run 47 因 16 次工具预算耗尽（10 次模型调用/119,318 tokens），保留记录。
- AI 补丁真实模型：`deepseek-flash` 对 `tests/fixtures/java-patch` 生成参数化 SQL 补丁；process Maven `validation_passed`，Docker sandbox（`maven:3.9.9-eclipse-temurin-17@sha256:f58d…`）`validation_passed`，原快照未修改。
- `python scripts/test-patch-ai.py`：通过（loopback，非真实 LLM；process + Docker；network none/cap-drop/快照不变）。
- 未验证：真实项目 AI 补丁、多文件/复杂修复、补丁质量评分、VM 级隔离、docker junit、目标网络执行。
- 当前工作区存在 Git 仓库（`main`，HEAD `c44fb1f`），本片改动未提交。

## 全量回归（2026-11-13，第十八片后）

- `go build ./...`、`go test ./... -count=1`、`go vet ./...`：通过（`internal/agent` 新增压缩测试；`internal/r3` 新增 Propose/sandbox 测试）。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-web.py`、`test-sbom.py`、`test-patch.py`、`test-patch-ai.py`：全部通过；`test-dataflow.py` 计数不变（flow_gaps 23/10/1/12）；`test-patch-ai.py` 的 process 与 Docker 均为 `validation_passed`。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、历史 P0 集成回归、Agent Run、`demo-offline`、只读 Schema）。
- `python scripts/test-agent.py`：通过（loopback 脚本化协议，非真实 LLM；happy Run=49 `completed`、corrupt=50 `failed`）。
- `python scripts/test-linux.py`：首轮通过（固定 `golang:1.26.3-bookworm` 容器，`-race -tags=integration -p 1 ./...`）。
- 真实模型：Run 43（flash）、Run 46（v4-pro）、Run 48（flash + 真实 `CodeScan-Artex-main` 快照，压缩 2 次）；AI 补丁真实生成并通过 process/Docker 验证。
- 未运行：VM 级隔离、docker junit、真实项目 AI 补丁、补丁质量评分、其他模型/快照、生产运行时验证。
- 当前工作区存在 Git 仓库（`main`，HEAD `c44fb1f`），本片改动未提交。

## 全量回归（2026-11-13，真实模型闭环后）

- `go build ./...`、`go test ./... -count=1`、`go vet ./...`：通过（`internal/model/openai` 新增 `reasoning_content` 与 Schema 数值测试）。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-web.py`、`test-sbom.py`、`test-patch.py`：全部通过；`test-dataflow.py` 计数不变（flow_gaps 23/10/1/12）。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、历史 P0 集成回归、Agent Run、`demo-offline`、只读 Schema）。
- `python scripts/test-agent.py`：通过（loopback 脚本化协议，非真实 LLM；happy Run=44 `completed`、corrupt=45 `failed`）。
- `python scripts/test-linux.py`：首轮通过（固定 `golang:1.26.3-bookworm` 容器，`-race -tags=integration -p 1 ./...`）。
- 真实模型：Run 43 `completed`（`deepseek-flash`，3 次模型调用/4 次工具调用/18,394 tokens）；Run 46 `completed`（`deepseek-v4-pro`，3 次模型调用/4 次工具调用/21,956 tokens）；均仅合成样本。
- 未运行：其他模型/端点、真实项目快照外发、生产运行时验证。
- 当前工作区存在 Git 仓库（`main`，HEAD `c44fb1f`），本片改动未提交。

## 全量回归（2026-11-13，第十七片后）

- `go build ./...`、`go test ./... -count=1`、`go vet ./...`：通过（`internal/audit` 新增 produces/response_body 测试；`internal/dataflow` 15 个单测）。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-web.py`、`test-sbom.py`、`test-patch.py`：全部通过；`test-dataflow.py` 新增 `[12]` 块（flow_gaps 23 finding / confirmed=10 / refuted=1 / inconclusive=12）。
- `python scripts/test-local.py`：首轮在既有治理计时测试 `TestOutboxAckRechecksExpiryAfterLock` 失败（`ack after lease expiry=<nil>`），该测试与本片无关且未修改；同命令重跑通过。首轮失败保留记录，不用重跑覆盖。
- `python scripts/test-agent.py`：通过（loopback 脚本化协议，非真实 LLM；happy Run=35 `completed`、corrupt=36 `failed`）。
- `python scripts/test-linux.py`：首轮通过（固定 `golang:1.26.3-bookworm` 容器，`-race -tags=integration -p 1 ./...`，含 `internal/audit`、`internal/dataflow` 与 `tests/integration`）。
- 未运行：真实外部模型（需端点/模型/数据外发/费用许可）、Java 编译/运行（本片）、容器/VM 沙箱、生产运行时验证。
- 当前工作区存在 Git 仓库（`main`，HEAD `c44fb1f`），本片改动未提交。

## 全量回归（2026-11-13）

- `go build ./...`、`go test ./... -count=1`、`go vet ./...`：通过（含 `internal/r3`、`internal/sbom`、`internal/tools` 与 `internal/agent` 新测试）。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-web.py`、`test-sbom.py`、`test-patch.py`：全部通过。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、历史 P0 集成回归、Agent Run、`demo-offline`、只读 Schema）。
- `python scripts/test-agent.py`：通过（loopback，非真实 LLM；happy Run=31、corrupt=32）。
- `python scripts/test-linux.py`：首轮既有治理计时测试 `TestClaimRechecksDeadlineAfterPoolLock` 失败（`deadline passed during pool wait but claim succeeded`），该测试与本片无关且未修改；原命令重跑通过（`-race -tags=integration -p 1 ./...`，含 `internal/r3`/`internal/sbom`）。首轮失败保留记录，不用重跑覆盖。
- 未运行：真实外部模型、容器沙箱、网络隔离、生产运行时验证；Linux 容器只执行 Go 测试，不执行 Java/Maven/JUnit。
- 当前工作区存在 Git 仓库（`main`，HEAD `c44fb1f`），本片改动未提交。

## 全量回归（2026-11-13，第十六片后）

- `go build ./...`、`go test ./... -count=1`、`go vet ./...`：通过（`internal/dataflow` 14 个单测，含新增 `TestAnalyzeCollectionCrossMethodClearAndReflectedReturn`）。
- `python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-web.py`、`test-sbom.py`：全部通过；既有样本计数不变，`test-dataflow.py` 新增 `[11]` 块（container_reflect 10 finding / confirmed=3 / inconclusive=7）。
- `python scripts/test-patch.py`：通过（真实 Java 17/Maven 3.9.9/JUnit 4.12；基线失败、补丁通过、原快照不变）。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、历史 P0 集成回归、Agent Run、`demo-offline`、只读 Schema）。
- `python scripts/test-agent.py`：通过（loopback 脚本化协议，非真实 LLM；happy Run=33 `completed`、corrupt=34 `failed`）。
- `python scripts/test-linux.py`：首轮通过（固定 `golang:1.26.3-bookworm` 容器，`-race -tags=integration -p 1 ./...`，含 `internal/dataflow` 与 `tests/integration`）。
- 未运行：真实外部模型、Java 编译/运行（本片）、容器/VM 沙箱、生产运行时验证。
- 当前工作区存在 Git 仓库（`main`，HEAD `c44fb1f`），本片改动未提交。

## 下一次接续入口（R2/R3）

1. 真实模型闭环：已完成 DeepSeek `deepseek-flash`（Run 43）、`deepseek-v4-pro`（Run 46）合成样本验收，以及真实 `CodeScan-Artex-main` 快照 Run 48。其他模型、其他真实项目快照或更高调用额度仍需逐次批准，并按 `agent-contract.md` 绑定快照 hash、端点、模型、有效期与费用上限。
2. R3 后续：VM 级隔离与系统调用过滤、docker junit profile、Surefire/JUnit XML 报告解析、多测试类/覆盖率、补丁质量评分与多轮修复、真实项目 AI 补丁。
3. Agent 预算：当前压缩是确定性截断，后续可评估不调用模型的有界摘要或按工具类型差异化保留策略。
4. 分析深度：集合元素级 `remove` 精度、其他对象持有的容器/字段、`produces` 之外的内容协商与转义、更多框架 sink、完整 AST/别名与跨模块类型。
5. 供应链：有效依赖树、制品哈希、公告区间/别名、import graph 与入口可达性。

## 2026-11-13：R2/R3/R5/R6 第十九片（供应链扩展、SARIF/可达性、R3 修复闭环强化）

### 范围与决定

- 一次性补齐上一轮列出的可实现待办：公告区间/别名、Gradle 声明、模块依赖树、JAX-RS/Servlet 入口、上传 sink、框架 SQL/SSRF sink、字面量元素精度、导入感知类型解析、SARIF、import 可达性、R3 多测试类/JUnit XML/JaCoCo/补丁质量/多轮修复/gVisor、Agent 按工具压缩与证据导出、基准与发布检查表。
- 仍不执行 Java/Maven、不访问目标网络、不调用真实模型；所有新增验收使用合成样本、loopback 或本地固定容器。
- 真实项目 AI 补丁、硬件 VM 隔离和其他模型/快照外发仍需逐次授权，未在本片执行。

### 交付

- [x] `internal/sca`：Gradle 常见 Groovy/Kotlin 声明、公告区间与别名、模块依赖树 `sca tree`；ToolVersion `0.2.0-p0.2+r2-sca-declarations-v2`。
- [x] `internal/audit`：JAX-RS `@Path/@GET` 家族与 `@WebServlet` doGet/doPost 入口、JAX-RS 参数绑定与 `@Produces`；ToolVersion `...endpoint-inventory-v3`。
- [x] `internal/dataflow`：JdbcTemplate/JPA/Hibernate SQL sink、HttpClient/WebClient SSRF、MultipartFile/Part 上传、字面量元素级集合/数组污点、`remove(index)` 精度、导入感知类型解析；10 类 sink；ToolVersion `...source-sink-flow-v12`。
- [x] `internal/sarif`、`internal/reach` 与 `audit sarif`、`audit reachability`；import 可达性必须显式 `--package-map`，否则 `unverified`。
- [x] `internal/r3`：Docker/gVisor JUnit、多测试类、Surefire XML 解析、可选 JaCoCo、补丁质量评分、remediation policy、`patch repair` 最多 5 轮 propose→verify；gVisor 使用 `--runtime=runsc` 并在未注册时失败关闭。
- [x] `internal/agent`：按工具类型的确定性压缩保留策略与有界 JSON 摘要；`agent export` 只读导出 Run/Step 证据并执行保留窗口检查（agent 表保持 append-only，不做数据库删除）。
- [x] 新样本 `tests/fixtures/java-advanced-sinks`、`tests/fixtures/gradle-basic`；新验收 `scripts/test-intel.py`、`scripts/benchmark.py`；README 与契约同步。

### 验证记录

- Windows / Go 1.27.1：`go build ./...`、`go test ./... -count=1`、`go vet ./...` 通过。
- `python scripts/test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-sbom.py`、`test-web.py`、`test-patch.py`、`test-patch-ai.py`、`test-intel.py` 全部通过。
  - 新 `java-advanced-sinks`：11 个分析入口、14 finding（confirmed=7、inconclusive=7、refuted=0）；框架 SQL、SSRF、上传、字面量元素精度与导入感知 helper 均按预期。
  - `test-intel.py`：SARIF 2.1.0 结果 3 条且 `runtime_status=not_run`；commons-text import 可达 2 条；Maven 树 2 模块；Gradle 5 条直接声明（4 resolved/1 dynamic unresolved）；区间/别名命中与区间外 not_affected 均正确；错误哈希与不安全 package map 拒绝。
- `python scripts/test-patch.py`：真实 Java 17/Maven 3.9.9/JUnit 4.12 通过。
- `python scripts/test-patch-ai.py`：loopback 非真实 LLM；process Maven 与 Docker 沙箱均 `validation_passed`，快照不变。
- `python scripts/test-local.py`：通过（真实 PostgreSQL、迁移、历史 P0 集成回归、Agent Run、`demo-offline`、只读 Schema）。`python scripts/test-agent.py`：通过（loopback，happy Run=51 `completed`、corrupt=52 `failed`）。`python scripts/test-linux.py`：通过（固定 `golang:1.26.3-bookworm`，`-race -tags=integration -p 1 ./...`，含 `internal/reach`、`internal/sarif` 与 `tests/integration`）。
- `python scripts/benchmark.py 2`：4 个合成样本 × 7 条只读命令全部成功；Maven 样本 `audit findings` 中位约 151 ms，`audit dataflow` 约 229 ms；仅 wall-clock，不包含数据库/模型/Java/Maven。
- 未运行：真实项目 AI 补丁、硬件 VM/系统调用沙箱、Maven 在线解析、传递依赖与制品哈希、其他真实模型/快照外发。
- 工作区当前有未提交改动；本片记录的测试结果对应当前工作区内容，提交后在 Git 历史中复核。

## 2026-11-14：Maven 有效依赖树与 gVisor 失败关闭实测

- 用户明确“授权，执行”。已执行可离线复现且无需模型密钥的部分，未伪造真实模型结果。
- 新增 `sca resolve`（`internal/sca/resolve.go`、`cmd/trident/sca.go`）：在快照临时副本上执行 Maven `dependency:tree`，默认离线、需 `--approve-maven`，联网需额外 `--approve-network`；输出直接/传递依赖、scope、depth、冲突省略与版本管理注记；`runtime_status=not_run`、`artifact_hashes=not_available`、`classpath_verified=false`。
- 实测离线 `sca resolve`（java-maven 合成样本）：3 个模块、31 条依赖、25 条传递依赖；`jdbc-app` 下 `commons-lang3` 深度 2；快照与 fixture 字节级未变。Maven 依赖树插件首次在线解析成功，随后离线缓存可用。
- 新增 `python scripts/test-resolve.py`，离线缓存缺失时报告 `skipped`，不伪造结果。
- gVisor：本机 Docker 仅注册 `runc`/`nvidia`，`--sandbox gvisor` 按设计失败关闭，未执行容器；报告 `runtime_status` 已修正为 `not_run`（此前 setup error 会误标 `isolated_validation_only`）。
- 仍阻塞：真实模型调用需要 `TRIDENT_MODEL_API_KEY`（当前环境与 `.env` 均未设置）；工作区内没有真实 Java 项目可供“真实项目 AI 补丁”验证；硬件 VM 隔离不在当前环境能力内。
- 本片验证：`go test ./internal/sca ./cmd/trident`、`python scripts/test-resolve.py` 通过；未调用模型、未写数据库、未修改快照。

### 2026-11-14 续：获准真实模型补丁修复（合成 Java 目标）

- 用户书面授权 DeepSeek 真实模型 + 现有 `tests/fixtures/java-patch` 合成目标；密钥从 `%USERPROFILE%\.trident-model-key` 读入进程环境，未写入仓库、日志、Run 或补丁报告。
- 共 3 次模型调用：`deepseek-flash` 第 1 次 `stop=length`（2048 输出上限）、第 2 次返回的 hunk 行数不匹配；`deepseek-v4-pro` 第 3 次返回严格可应用的 unified diff。`patch repair` 按设计在模型失败/无效补丁时停止，不自动重试。
- 成功补丁 SHA-256 `69aee83e…`，只改 `src/main/java/demo/Vulnerable.java` 1 行，与既有 `safe.patch` 字节一致：`query` 返回常量参数化 SQL `name=?`。
- process Maven 验证：`mvn -o -B -q -DskipTests compile` 与 `java -cp target/classes demo.Main` 均退出 0，`Main` 输出 `safe`；quality 85、grade A。
- 另一轮 JUnit 4.12 验证：`javac` main/test 编译通过，`JUnitCore demo.VulnerableTest` 输出 `OK (1 test)`，tests=1/failures=0/errors=0；quality 100。
- 两轮均 `original_snapshot_intact=true`，`runtime_status=isolated_validation_only`。该补丁只是合成 fixture 的编译/单元测试通过，不证明真实数据库绑定、真实项目语义或生产修复有效。
- 真实项目 AI 补丁仍未执行：工作区没有含 `pom.xml`/`build.gradle` 的真实 Java 项目；需另行提供路径与授权。

### 2026-11-14 续二：真实 Java 项目 AI 补丁（D:\Code\Java\market）

- 目标：`D:\Code\Java\market`（Spring MVC 4.3.14 + MyBatis，84 个 Java 文件，Java 8，war，无 `src/test`）。快照 SHA-256 `3de9c6c480c1b753a61aacb13f0938b65c92633f98c857da573e00f9337e5873`。
- 本地只读分析：20 个 controller、186 个入口、109 条 SQL finding，全部 `inconclusive`，未发现 `Statement`/`JdbcTemplate` 直接拼接；MyBatis 自定义 SQL 使用 `#{}`。决定修复真实可验证的访问控制缺陷：`/manager/getbyid`、`/manager/update`、`/manager/toupdate` 未校验管理员会话。
- 为真实项目新增 `maven-compile` profile：仅执行 `mvn -o -B -q -DskipTests compile`，不要求 main class；同时修复 `Apply` 对 CRLF 文件的上下文匹配并新增 `TestApplyPreservesCRLF`。`maven-compile` 不运行应用或测试，属于编译级验证。
- 模型调用：`deepseek-v4-pro` 8192 输出上限时 `stop=length`；提升至 16384 后返回可应用 diff。共 2 次调用。
- 补丁 SHA-256 `cecacc06…`，单文件 `ManagerController.java`，+12/-3：三个方法增加 `HttpSession` 参数，并在任何 service 调用前检查 `Constants.Manager_SESSION`，缺失时重定向 `/manager/login`。
- 验证：`mvn -o -B -q -DskipTests compile` 退出 0；`validation_passed`、quality 80/B、`original_snapshot_intact=true`、`runtime_status=isolated_validation_only`。项目无测试，未做运行时访问控制验证；其他管理员接口仍未覆盖。
- 仍阻塞：真实项目运行时行为/权限测试、硬件 VM 隔离、Gradle 有效依赖树（前两项见续三/续四，Gradle 见续五）。

### 2026-11-14 续三：真实项目集中式访问控制补丁与运行时测试

- 复核发现全部业务 controller 都挂在 `/manager/flatform/**` 或 `/staff/flatform/**` 下，方法级逐个加检查会遗漏。最终采用集中式方案：新增 `LoginInterceptor`，在 `spring-mvc.xml` 对 `/manager/**` 与 `/staff/**` 全量拦截，仅排除 `/manager/login`、`/manager/dologin`、`/staff/login`、`/staff/dologin`。该方法覆盖 20 个 controller 的业务入口，替代此前 AI 生成的 3 个方法级 guard（后者仍作为 AI 补丁样例保留在记录中）。
- 新增 4 个 JUnit 运行时测试：无会话重定向、正确会话放行、错误会话类型拒绝、员工会话放行。`mvn test` 结果 `Tests run: 4, Failures: 0, Errors: 0`。
- 为工具补齐真实项目所需能力：
  - `Apply` 支持新文件创建（`--- /dev/null`）、UTF-8 BOM 和 git 多文件 diff；仍拒绝覆盖、删除、重命名与越界路径，并新增单测。
  - 新增 `maven-test` profile：离线执行 `mvn -o -B -q test`，自动解析 Surefire XML；不需要 main class。
  - 修复 `scorePatch` 同时读取 `TestSummary` 与 `JUnitXML` 时的测试数重复计数。
- 最终补丁通过 TRIDENT 自身验证：`patch verify --profile maven-test --patch docs/evidence/2026-11-14-market-access-control.patch` → `validation_passed`、`mvn -o -B -q test` 退出 0、tests=4/failures=0/errors=0、quality 75/B、`original_snapshot_intact=true`、`runtime_status=isolated_validation_only`。
- 补丁工件：`docs/evidence/2026-11-14-market-access-control.patch`（4 个文件，+207/-0：POM 测试依赖、LoginInterceptor、spring-mvc.xml 拦截配置、JUnit 测试）。
- 未覆盖：真实 Tomcat/MySQL 部署下的 HTTP 权限验证、其他安全缺陷、Gradle 有效树、硬件 VM（HTTP 权限验证已在续四补齐，Gradle 有效树已在续五补齐）。原项目目录未被修改。

### 2026-11-14 续四：真实 Tomcat/MySQL HTTP 权限验证

- 环境：MySQL 8.0.46 容器 `trident-market-mysql`（127.0.0.1:3307，仅容器内改测试密码哈希）；Tomcat 9.0.106 监听 18080，JDK 8u202；部署补丁后的 `chaoshi.war`。SQL 导入 `market_optimized.sql`，共 11 张表。
- 未认证结果：
  - `/chaoshi/manager/login`、`/chaoshi/staff/login` → 200。
  - `/chaoshi/manager/getbyid?managerid=15203111`、`/manager/flatform/main`、`/manager/toupdate` → 302 到 `/chaoshi/manager/login`。
  - `/chaoshi/staff/flatform/main`、`/staff/flatform/product/getlist`、`/staff/flatform/custom/getall` → 302 到 `/chaoshi/staff/login`。
- 已认证结果：管理员 `15203111` 与员工 `15203122` 使用同一测试密码登录均 302 到各自 `/flatform/main`；随后 manager main/getbyid/toupdate 与 staff main/product/custom/getbyid 全部 200。
- 隔离与负例：manager 会话访问 staff 端点 → 302 到 `/staff/login`；员工错误密码 → 200 登录页且后续访问 main 仍 302。
- 说明：`/staff/flatform/product/getall` 不存在对应映射（实际为 `getlist`），返回 500，不计入权限绕过；验证改用真实映射。
- 结论：集中式拦截器在真实 Tomcat/MySQL 部署下生效；仅证明未登录访问被拒绝和登录后放行，不证明其他漏洞、授权粒度或生产配置安全。原项目 `D:\Code\Java\market` 未被修改（非 Git 仓库，全部改动只在临时副本）。

### 2026-11-14 续五：Gradle 有效依赖树

- 新增 `sca resolve --tool gradle`：在快照临时副本上按模块执行 `gradle --offline --no-daemon --console=plain -q -p <module> dependencies`，必须显式 `--approve-gradle`；支持 `--gradle` 绝对路径、`--gradle-user-home` 和 `--gradle-init-script`。Maven 仍为 `--tool maven` + `--approve-maven`。
- 解析器覆盖：配置块识别、`+---`/`\---` 深度、`runtimeClasspath` 优先（其次 `compileClasspath`，再按 `*RuntimeClasspath` 后缀与全配置回退）、`project :x` 边、`a:b:1.0 -> 1.2` 版本升级、`(*)` 省略、`(c)` 约束、`(n)` 未解析、`FAILED`；部分模块失败输出 `status=partial` 并保留已解析模块。
- 输出新增 `gradle.version/executed/duration_ms/offline/configurations/modules_attempted/modules_parsed`；模块新增 `build_file`，依赖新增 `failed`；`runtime_status=not_run`、`artifact_hashes=not_available` 保持不变。
- 同时修复 Maven/Gradle 解析的超时：此前 `--timeout-seconds` 只被校验、未真正生效，现在通过 `context.WithTimeout` 约束执行；输出截断会显式记录 `*_output_truncated`。
- 验收：`python scripts/test-gradle-resolve.py`（Gradle 8.14.3 + JDK 17，离线 file 仓库）通过：3 个模块、5 条依赖、2 条传递；`jdbc-app` 含 `project :common`、`commons-text:1.9` 直接边与 `commons-lang3` 深度 2；快照与 fixture 字节级不变，`runtime_status=not_run`。
- 限制：build.gradle 是可执行输入，`dependencies` 报告不是 classpath 加载；未解释 Android variant、version catalog、BOM/platform 语义与插件脚本副作用。

### 2026-11-14 续六：依赖升级验证

- 新增 `sca upgrade`：从声明清单中选择唯一已解析依赖，支持 Maven 属性/直接版本/dependencyManagement 与 Gradle 字符串/map，生成只改版本的最小 unified diff；目标版本由 `--to` 显式指定，计划阶段不执行构建工具。
- 校验与隔离：补丁必须写到快照外的新文件；提供 `--workspace` 时要求 `--approve-execution`，先在临时副本跑基线，再用 R3 隔离副本应用补丁并跑同一 profile，输出 `baseline` 与 `verification`。基线失败与升级后失败分别标记为 `baseline_validation_failed` 和 `validation_failed`。
- 新增 `tests/fixtures/java-upgrade` 与 `python scripts/test-upgrade.py`：commons-text 1.9 → 1.10.0，基线 1 个测试通过，升级后 1 个测试通过，快照与 fixture 字节级不变，同版本目标被拒绝。
- 限制：不自动选择目标版本、不验证制品哈希、不分析传递依赖升级；Gradle 升级目前只生成补丁，验证 profile 仍为 Maven/javac/JUnit。

### 2026-11-14 续七：权限/越权控制清单

- 新增 `internal/authz` 与 `audit authz`：复用入口清单，扫描 Java/XML 识别 Spring Security 方法/类注解、MVC interceptor、servlet filter（注解与 `web.xml`）、`security-constraint`、`WebMvcConfigurer.addInterceptors` 与 `HttpSecurity` matcher 链。
- 决策与证据：Ant 路径匹配、control class 解析与认证 token 判定；输出 `protected`/`public`/`unprotected`/`unknown`、匹配控制、原因与 `coverage`。无控制入口生成 CWE-306、`status=inconclusive`、`runtime_status=not_run` 的 finding；手工 session 检查只记为 `unknown`。
- 集成：`audit findings` 新增 `authz_controls`/`authz_unprotected`/`authz_findings`、`missing_authentication_or_authorization` kind、`route`/`method`/`control_absence` 证据与 `authz_*` limitations；Web 控制台新增“认证/授权缺失”分类。
- 新增 `tests/fixtures/java-authz`、`go test ./internal/authz` 与 `python scripts/test-authz.py`：5 个控制、11 个入口，6 protected/2 public/2 unprotected/1 unknown；2 条 finding 均为 `inconclusive`、CWE-306、`runtime_status=not_run`，快照与 fixture 字节级不变。
- 限制：不评估 Spring EL、filter-chain 全局顺序、自定义 AOP/网关、context-path、部署配置；`unprotected` 不是未授权访问证明。

### 2026-11-14 续八：运行时 HTTP 验证自动化

- 新增 `internal/httpverify` 与 `trident runtime http`：按调用者 JSON 计划顺序执行请求，支持每 session 内存 cookie、状态码、`Location` 前缀、响应体包含/不包含与响应头包含；不跟随重定向、不并发、不使用代理、默认 TLS 校验。
- 安全边界：必须是显式 `--approve-target` 的精确 origin；loopback 还需 `--allow-loopback`；单计划最多 64 请求/1 MiB，单响应最多 64 KiB；`form`/`json`/header 值不写入报告，`location` 只保留路径。
- 输出：`analysis_kind=http_runtime_assertions_v1`、`runtime_status=observed`、逐请求断言与 `coverage`；截断体的“不包含”断言为 `inconclusive`。运行时结果不自动修改静态 finding 的 `runtime_status`。
- 新增 `python scripts/test-runtime.py`：loopback 服务 4 条请求全部通过，覆盖 session 复用、302 不跟随、凭据不落报告、错误断言失败、未批准 origin 与未授权 loopback 拒绝。
- 真实环境复测：Tomcat 9.0.106 + MySQL 8.0.46 部署 `D:\Code\Java\market` 补丁，15 条请求覆盖登录页、未登录 302、管理员/员工登录后 200、跨会话 302 与错误密码不建立会话，结果 `status=passed`、15/15、`runtime_status=observed`。该结果只证明这些请求的响应，不证明其他漏洞或生产安全。

### 2026-11-14 续九：R5/R6 发布治理

- 新增 GitHub Actions 离线工作流模板 `.github/workflows/ci.yml`：Go 测试/vet、10 个离线 CLI 验收、SARIF 生成与 artifact 上传；不调用模型、数据库、Java/Maven/Gradle。
- 新增 `scripts/verify-offline.ps1`，串联 Go 测试/vet 与离线验收脚本，作为本地可复现门禁。
- 新增 `docs/deployment.md`：构建、环境变量/凭据、迁移、`pg_dump`/`pg_restore`、CI/SARIF、版本矩阵与未完成生产门槛。
- 新增 `db/roles.example.sql`：`trident_migrator`/`trident_runtime`/`trident_readonly` 的 DDL/DML/只读分离模板；未在独立生产库执行。
- 新增 `docs/benchmark-report.md`：`python scripts/benchmark.py 3`，4 个合成 fixture × 7 条只读命令，仅 wall-clock；不含 DB/模型/Java/Maven。
- 仍未完成：CI 的 Java/Maven/Gradle、模型与运行时 job 需专用 runner 和授权；生产凭据分权/备份恢复演练、多用户/TLS、硬件 VM 与完整 AST/调用图仍未验证。

### 2026-11-14 续十：数据库分权与备份恢复演练

- 新增 `scripts/test-db-governance.py`：在一次性 PostgreSQL 18 固定镜像容器中创建 `trident_drill` 库与 `trident_migrator`/`trident_runtime`/`trident_readonly` 三个随机密码角色，演练结束随容器销毁；不接触既有测试库，不写磁盘密码。
- 分权结果：`trident_migrator` 连续两次 `migrate` 成功（幂等）；runtime/readonly 均可执行 `trident check`；runtime 执行 `migrate`、建表与建角色均被拒绝；readonly 写入被拒绝；migrator 新建表自动继承默认权限，runtime 可 INSERT/UPDATE、readonly 只读。
- 应用路径：`bootstrap` 与 `demo-offline` 使用 runtime 账号完成真实写入（`principals` ≥ 2），证明最小权限角色足以支撑现有应用 DML。
- 备份恢复：容器内 `pg_dump --format=custom` → 新建 `trident_drill_restore` → `pg_restore` → `trident check` 通过；`principals`、`tasks`、`tool_calls`、`approvals`、`schema_migrations` 行数与源库一致。
- 限制：演练库是本机一次性容器，不等于生产环境；未覆盖生产数据量、备份窗口、异地存储、恢复时限、密钥管理和审计审批。CI runner 实际执行与硬件 VM 隔离仍未验证。

### 2026-11-14 续十一：M1 证据可信度（制品哈希与有界可达性）

- 新增 `internal/sca/artifacts.go` 与 `sca inspect --maven-repo/--gradle-user-home/--hash-catalog`：对已解析 GAV 在调用者显式本地仓库/缓存中计算 jar/pom SHA-256 与字节数；输出 `artifacts[]`、`coverage.artifact_hashes=observed|partial|unavailable`、`artifact_hash_local_only`、`artifact_signature_not_verified`。不下载、不验证签名、不推断默认仓库。
- 哈希清单严格 JSON（≤128 KiB、≤4096 项、64 hex、键唯一），支持 exact match、mismatch 与 catalog-only；mismatch 只写 `artifact_hash_mismatch:<g:a:v:kind>` 证据，不升级漏洞结论。SBOM 组件新增 `hashes[]`（仅本地 observed SHA-256）与 `trident:artifact_hashes` 属性。
- 重写 `internal/reach` 为类级有界调用图：package/import/首个类型声明/同包类型引用/反射标记；从 `audit.Inspect` 入口做深度 ≤8、节点 ≤4000、边 ≤20000 的 BFS；输出 `reachable|unreachable|unknown`、入口与每一步的文件 SHA-256/行号、命中 import、模块作用域与 reason。
- `audit findings --package-map` / `audit sarif --package-map`：依赖假设 `dependency_reachable_from_http_entrypoint` 映射为 `supported/unsupported/unverified`；`reachable` 仅静态调用证据，`findings` 仍 `inconclusive`、`runtime_status=not_run`，不回写运行时结果。
- 新增 fixture `tests/fixtures/java-artifact-hash`、`tests/fixtures/java-reachability`，以及 `scripts/test-artifact-hash.py`、`scripts/test-reachability.py`；加入 `scripts/verify-offline.ps1`。
- 验收结果：`go test ./...` 通过；`python scripts/test-artifact-hash.py` 通过（本地命中/清单 exact/mismatch/catalog-only/空仓库/SBOM/确定性）；`python scripts/test-reachability.py` 通过（三态、2 步路径与 SHA-256/行号、findings unsupported/unverified、无映射全 unknown）；`test-sca.py`、`test-sbom.py`、`test-intel.py`、`test-findings.py` 均通过，快照与 fixture 字节不变。
- 限制：制品哈希不证明来源；可达性不解析字节码、方法重载/继承/接口分派、AOP、异步、动态代理或网关；`unreachable` 是有界静态图结论，不是运行时不可能性证明。

### 2026-11-14 续十二：M2 受限 Java 语义层（P0-3 第一片）

- 新增 `internal/javaast`：基于 `text/scanner` 的受限 Java 子集解析器（package/import/嵌套类型/枚举/记录/注解/字段/方法/构造器/初始化块边界），以及确定性语义模型 `java_semantic_model_v1`。
- 建模：擦除后的类型与签名、`java.lang`/显式导入/同包/通配导入/唯一简单名解析、内部类到外部类方法、常量折叠（字面量、`static final`、字符串拼接、整数加法、class literal、枚举常量、数组）与注解实参折叠。
- 方法级调用图：局部变量/参数/字段/类型/外部接收者解析；泛型擦除后按实参类型选择重载；继承链与接口参与查找；唯一实现记 `resolved/interface_dispatch`，多实现记 `ambiguous/ambiguous_dispatch`，反射 API 只记边界；输出调用者/文件/SHA-256/行号、实参推断类型、目标符号与目标文件/SHA-256。
- 新增 CLI `audit java-model` 与 fixture `tests/fixtures/java-ast-model`（5 文件：1 个语法错误、嵌套类、泛型重载、接口分派/歧义、注解常量）及 `scripts/test-java-ast.py`；`go test ./internal/javaast` 覆盖同一组断言。
- dataflow 升级到 `0.2.0-p0.3+r1-source-sink-flow-v13`：仅新增 `coverage.java_ast=restricted_subset|partial|not_available`、`java_ast_types`、`java_ast_methods` 与 `java_ast_semantic_model_staged` 限制；sink/source 匹配与既有 finding 计数不变。findings 同步透传 `coverage.java_ast` 并升级到 `finding-evidence-v3-reachability-ast`。
- 验收：`go build ./...`、`go vet ./internal/javaast ./internal/dataflow ./internal/findings ./cmd/trident`、`go test ./internal/javaast ./internal/dataflow ./internal/findings -count=1`、`python scripts/test-java-ast.py`、`python scripts/test-dataflow.py`、`python scripts/test-findings.py` 通过；fixture 与快照字节不变。
- 限制：AST 尚未接入 sink/source 匹配，控制流、别名/points-to、跨方法污点、AOP/动态代理仍未实现；lambda、方法引用、文本块、匿名类为边界；不编译、不运行 Java。

### 2026-11-14 续十三：P0-4 权限链语义与上下文

- `internal/authz` 升级到 `0.2.0-p0.4+r1-authz-chain-v2`：`SecurityFilterChain` 按方法边界分组，链顺序取 `@Order`/`Ordered`，缺省 `2147483647`，同序按 source/file/line 稳定排序；`securityMatcher` 限定链作用域，`requestMatchers`/`anyRequest` 保持链内声明顺序，首条命中生效。
- 输出新增 `chains[]`（id/source/file/line/order/order_source/security_matchers/custom_filters/rules/status）、`controls[].chain`、`endpoints[].chain`/`roles`/`external_path`，`coverage` 新增 `chains`/`method_security`/`context_path`/`context_path_source`。
- 方法安全：`@EnableMethodSecurity`/`@EnableGlobalMethodSecurity` 记入 coverage；`@PreAuthorize` 受限 SpEL（常量布尔、`permitAll/denyAll`、`isAuthenticated()/isAnonymous()`、`hasRole/hasAnyRole/hasAuthority/hasAnyAuthority`、`&&/||/!`）参与判定，`hasRole` 归一化为 `ROLE_`；复杂表达式与 `@PostAuthorize/@PreFilter/@PostFilter` 为 `unknown`。
- context path：读取 `server.servlet.context-path`（properties/yml）与 `web.xml` `<context-param>`，仅写入 `endpoints[].external_path`；匹配仍相对 context path。多值/非字面量记 `context_path_unresolved`，不改写结论。
- 新 limitation：`filter_chain_order_bounded`、`filter_chain_rule_order_bounded`、`spel_subset_only`、`context_path_unknown`；findings 的 `authz_control_inventory_lexical` 文案同步。
- 新增 fixture `tests/fixtures/java-authz-chain`：`@Order(1)` + `securityMatcher("/chain/api/**")` 链（`permitAll`→`hasRole("ADMIN")`→`anyRequest().authenticated()`）、默认 `permitAll` 链、方法注解 `isAuthenticated()`/`hasRole('ADMIN')`/`false`/复杂 SpEL、`application.properties` 的 `/app`。
- 验收：`python scripts/test-authz.py` 通过（2 条链；5 protected/3 public/1 unknown/0 unprotected；`ROLE_ADMIN`；`/ctx/hello` 的 `external_path=/app/ctx/hello`；`partial=false`、`runtime_status=not_run`、快照与 fixture 字节不变）；`go test ./internal/authz` 覆盖同一场景；旧 `java-authz` 的 6/2/2/1 与 2 条 finding 不变。
- 限制：不执行 `addFilterBefore/After` 或过滤器体，不解析自定义 AOP、外部网关/反向代理、重写规则；`unprotected` 仍是静态缺省证据，不是未授权访问证明。

### 2026-11-14 续十四：P1-1 运行时多角色矩阵与 CSRF

- `internal/httpverify` 升级到 `0.2.0-p1.1+r1-http-runtime-v2`：计划新增可选 `roles`（`id`/`session`/`login`/`csrf`）与 `matrix`（角色 × 请求 × 期望）；不同角色必须使用不同 session，`(role, request)` 不得重复。
- 登录步骤先解析 `${ENV:NAME}` 凭据占位符（未设置则 `credential_placeholder_unresolved` 并停止该角色），再按需注入 CSRF；CSRF 仅从显式 `meta[name=...]`/`input[name=...]` 提取（≤512 字节），非 `GET/HEAD/OPTIONS` 注入表单字段或请求头；提取失败为 `inconclusive` + `csrf_token_not_found`，矩阵单元为 `role_login_incomplete`。
- 输出新增 `results[].role/matrix/csrf`、`coverage.roles{requests,passed,failed,inconclusive,login_status}`；新 limitation `roles_caller_defined`、`csrf_token_extraction_bounded`；凭据解析值、Cookie 与 token 均不写入报告。
- 验收：`go test ./internal/httpverify` 通过（矩阵 10 次执行全 passed、每角色 4/4、`token_injected`、缺失 token inconclusive、共享 session/非法 selector 拒绝）；`python scripts/test-runtime.py` 通过（基础 4/4；矩阵 admin/guest 各 4/4、`login_status=complete`、admin /reports 200 与 guest 403；`secret-runtime`/`token-csrf` 不出现在 stdout；缺失 token、未设置占位符、共享 session 均失败关闭）。
- 真实环境 15 条 Tomcat/MySQL 计划未纳入仓库，本次变更未重跑；该结果仅覆盖当时的声明请求，不是生产安全证明。
- 限制：不渲染浏览器、不自动发现账号或密码、不绕过验证码；token 仅来自登录响应 HTML 的显式选择器，不做 JS 计算或多次刷新；`runtime_status=observed` 不回写静态 finding。

### 2026-11-14 续十五：P1-2 静态—运行时关联报告

- 新增 `internal/correlate`（`0.2.0-p1.2+r1-static-runtime-correlation-v1`）与 `trident runtime correlate --findings <json> --runtime <json> --out <file>`：读取 `audit findings` 与 `runtime http` 两份 JSON，生成独立的 `static_runtime_correlation_v1` 报告；不读快照、不联网、不调用模型。
- 关联语义：仅按静态 `endpoint.path` + `http_methods` 精确对照运行时 `results[].path/method`，输出 `correlated`（恰好 1 条）、`ambiguous`（≥2 条，典型为角色矩阵）与 `not_correlated`（0 条）；无 endpoint 的 finding 记为 `not_correlated` + `finding_has_no_endpoint`，未命中的运行时结果列入 `unmatched_runtime[]`；未声明方法按不受限处理并附 wildcard limitation。
- 报告输出 `findings_source`/`runtime_source`（路径 + SHA-256）、逐 finding 的静态 route/method 证据 ID 与运行时 `id/observed_status/location/body_sha256/role/matrix`、三态覆盖与未命中列表；固定限制 `correlation_not_exploit_proof`、`runtime_observed_not_exploit_proof`、`route_method_exact_match`、`static_findings_not_modified`。`correlated` 不证明参数可控、控制缺失或可利用。
- 输入只读：不修改 findings/runtime JSON 字节，不改变 finding 的 `status`/`runtime_status`；输出必须为新文件且不得覆盖任一输入；未观测运行时（`runtime_status!=observed` 或空结果）、重复 finding ID、缺失 `id/method/path`、非 `/` 路径均失败关闭。
- 验收：`go test ./internal/correlate` 通过（三态、无端点、未命中运行时结果、wildcard、拒绝条件、确定性）；`python scripts/test-runtime.py` 通过（`/dologin` 唯一匹配、`/admin` 歧义、`/missing` 无匹配、依赖 finding 无 endpoint；原 findings 字节不变；两次关联输出字节一致；覆盖输入/缺失输入/未观测运行时失败关闭）。
- 限制：路径按注解级字面量比较，不解析 context path、部署前缀、路径变量或归一化；不自动定级、不生成利用链、不替代人工复核。

### 2026-11-14 续十六：P1-3 补丁验证与回滚增强

- `internal/r3` 新增 `gradle-test` 验证 profile：工作区需存在 `build.gradle`/`build.gradle.kts`，执行 `gradle --offline -q test`（不需要 main class），成功后解析 `build/test-results/test` 的 JUnit XML；新增限制 `gradle_test_profile_runs_tests_only`、`gradle_profile_offline`。docker/gVisor 沿用固定镜像 digest 与只读 Maven 依赖缓存。
- `patch verify`/`sca upgrade` 报告新增 `rollback`：`snapshot_hash`、逐文件 `steps[]`（`restore_original`/`remove_created_file`、`sha256_before`、`sha256_after`）与人工回退说明；验证失败同样附带，且不执行任何回滚命令。
- 新增多模块验证：`patch verify --module <dir>`（`sca upgrade --module-dir`）可重复最多 8 个，必须是工作区内相对目录，拒绝绝对路径、`..` 逃逸与重复项；逐模块输出 `validation.modules[]` 与 `commands[].module`，聚合状态取最差模块，测试/JUnit/覆盖率按模块累加，限制 `module_selection_caller_supplied`。
- `quality` 增加 `rubric_version=r3-quality-rubric-v2`；评分仍为启发式，不参与通过判定。
- 验收：`go test ./internal/r3` 通过（回滚计划、模块路径逃逸/数量上限、Gradle 构建文件检测）；`python scripts/test-patch.py` 通过（失败/通过报告均含正确 rollback 与 rubric；`--module .` 聚合；越界模块拒绝；`gradle-test` 使用 PATH 桩工具链验证命令、退出码、JUnit 汇总与离线限制）。`scripts/test-upgrade.py` 的 Gradle 依赖升级场景因缺少真实 Gradle/离线缓存未运行。
- 未验证：真实 Gradle 工具链与缓存、多模块真实构建、回滚命令自动化（保持人工，非目标）。

### 2026-11-14 续十七：P1-4 派生索引缓存与性能门槛

- 新增 `internal/cache`：条目键为 `SHA-256(tool_version, kind, file_sha256)`，JSON 信封带 `schema_version/kind/key/tool_version` 校验；缺失条目为 miss，损坏/不匹配条目返回 `ErrCorrupt` 并按 miss 重建；写入使用同目录临时文件 + 原子重命名（`0600`/`0700`），单条目上限 8 MiB。
- `trident audit endpoints --cache-dir <dir>` 缓存单文件端点派生索引（路径、方法、注解、参数、文件 SHA-256、行号），不存源码/凭据/密钥；`coverage` 新增 `cache=not_used|miss|hit|partial`、`cache_files_hit`、`cache_files_miss`、`cache_corrupt`，并追加 `cache_derived_index_only`、`cache_key_file_sha_tool_version`、`cache_entry_corrupt_rebuilt` 限制。缓存目录与快照任一方向重叠、缓存路径为文件均失败关闭。
- `scripts/benchmark.py` 新增 `--baseline <json>` 与 `--max-ratio <n>`（默认 3.0），按相对中位数断言性能不回退，并新增 `audit endpoints cached` 场景；重申不访问网络/模型/Maven/Java。
- 验收：`go test ./internal/cache` 通过（往返、缺失、版本不匹配、损坏、非法键、无源码）；新增 `scripts/test-cache.py` 通过（冷 `miss` → 热 `hit` 且结果与冷一致、输出确定；缓存全为 JSON 且无源码标记；损坏条目 → `partial` + 重建限制且结果不变；修改单文件 → `partial` 且其余结果不变；缓存/快照重叠与文件路径拒绝且快照字节不变）；`python scripts/benchmark.py 3 --baseline <baseline> --max-ratio 4` 通过（相对比较，非绝对阈值）。
- 未验证：大型仓库的实际加速比、并发进程下的缓存竞争、跨机器缓存共享（非目标）。

### 2026-11-14 续十八：P2-2 Web 控制台多用户、审计日志与确定性导出

- `internal/webui/tokens.go`（新增）：多用户令牌注册表。`--tokens <file>` 读取 JSON 数组 `[{id, role, token_hash}]`，`token_hash` 为令牌明文 SHA-256 十六进制（文件永不存明文）；校验 id/role 字符集（`A-Za-z0-9._-`，1–64）、64 位十六进制哈希、id/哈希重复、未知字段，启动失败即退出。呈现令牌 → SHA-256 → 注册表比对（命中后常数时间比较）。每次授权请求检查文件 mtime+size 签名热重载：同 id 换哈希=轮换、删条目=撤销，下一请求生效；重载解析失败沿用最后已知良好注册表并向 stderr 告警一次，合法空数组按全部撤销处理（仅启动时拒绝空数组）。单 `--token` 兼容：注册表内固定身份 `local`/`reviewer`，`Token()` 仍打印明文；`--token` 与 `--tokens` 互斥。
- `internal/webui/accesslog.go`（新增）：`--access-log <file>` JSONL 审计访问日志（追加、0600）。记录全部 `/api/` 与 `/export/` 请求（含未认证行），字段固定 `time`（UTC RFC3339 微秒）/`token_id`/`method`/`path`（无查询串）/`status`；永不记录令牌明文或 Cookie 值；写失败 best-effort 并告警。响应状态经 `statusRecorder` 捕获。
- `internal/webui/export.go`（新增）：`GET /export/report` 确定性 HTML 审阅报告（`text/html` 附件）。内容为快照信息、结论概要、类别分布、按 ID 排序的逐发现明细（类型/类别/CWE/严重度/状态/runtime_status/入口/组件/证据/假设/限制）与统一限制；不含生成时间/耗时/启动时间/访问者身份；无外部资源引用（无 http(s)、无外链脚本/样式/图片），全部动态文本 HTML 转义；同一快照+公告目录+二进制两次导出字节一致。中间件将 `/export/` 纳入令牌+console 头门禁与 `no-store`。
- `cmd/trident/web.go`：新增 `--tokens`/`--access-log`；多用户模式打印用户 id 列表与文件路径，不打印任何令牌明文。
- 前端：顶栏新增“导出报告”按钮（复用既有下载管线），about 视图 API 表新增 `/export/report` 行。
- 契约与部署：`docs/web-console-contract.md` 新增 §2.1 多用户令牌文件（含 POSIX/PowerShell 哈希生成命令）、§5 审计访问日志、§6 确定性报告导出、§8 TLS 反向代理部署要求并重排章节；`docs/deployment.md` 新增 §2.1 nginx 示例与令牌文件管理要求。
- 验收：`go test ./internal/webui ./cmd/trident -count=1` 通过（新增令牌文件轮换+审计日志、格式校验拒绝、导出确定性 3 项）；`python scripts/test-web.py` 通过并在第二阶段以 `--tokens`+`--access-log` 启动第二个服务，验证多用户隔离（alice/bob/carol 各自 `token_id`）、轮换（旧令牌 401/新令牌 200）、撤销、导出两次跨用户字节一致且无 `http://`/`https://`/ISO 时间戳、审计日志字段固定且不含令牌明文；快照与 fixture 字节不变。
- 限制：多用户令牌文件热重载依赖 mtime+size 签名（原子重写或整体重写场景）；role 当前仅为审计身份标注，不构成权限边界；TLS 反代说明未经真实域名/证书联调；多快照对比、finding 状态流转、PDF 导出明确不做（写入口与只读边界冲突）。

### 2026-11-14 续十九：P2-3 本地部分——/healthz、只读指标与告警模板

- `internal/webui/webui.go`：新增 `GET /healthz`（未认证探活，仅返回 `status/product/version`，供负载均衡/反向代理探活，不含分析或令牌状态）与 `GET /api/metrics`（令牌 + console 头门禁）。指标为进程生命周期单调计数器：`requests.total/unauthorized/forbidden`（仅中间件门禁层 `/api/` 与 `/export/` 计数，handler 内部错误不计）、`analysis.runs_total/cache_hits_total/failures_total/cached/cached_ok/last_duration_ms/last_error`（冷分析计数含失败终态、缓存命中、终态缓存状态与最后失败消息）。`analyze()` 插桩冷热计数与耗时/失败记录；拒绝路径（401/403）在中间件同步计数。
- `internal/webui/metrics_test.go`（新增）：`/healthz` 未认证 JSON 探活字段断言、`/api/metrics` 无令牌 401、请求/拒绝/分析计数器单调性与轻量端点不触发分析的语义断言。
- `scripts/test-web.py`：新增 [04] 断言（`/healthz` 字段、`/api/metrics` 401 门禁、字段集、`cached/cached_ok/runs_total`），八项 PASS 全绿。
- 文档：`docs/web-console-contract.md` API 表新增 `/api/metrics` 与 `/healthz`、新增 §6.1 指标字段契约；`docs/deployment.md` 新增 §2.2 监控与告警规则模板（探活/指标/JSONL 结构化日志三类信号 + Prometheus `trident-console.rules.yml` 模板：ConsoleDown/UnauthorizedSpike/ForbiddenSpike/AnalysisFailure/AnalysisStale 与响应手册要点），并明确模板未经真实监控系统联调。
- 验收：`go test ./internal/webui ./cmd/trident -count=1` 通过；`python scripts/test-web.py` 通过（8 项）。
- 限制与 pending：Run 状态指标属 Agent Core（`agent status`），不在控制台进程内，本片指标覆盖控制台自身；生产备份演练与 RTO/RPO、容量/成本实测、真实 Prometheus/Alertmanager 联调待真实生产设施（P2-3 剩余项保持 pending）。

### 2026-11-14 续二十：P3 SARIF 规则分类细化与 GitHub code scanning 映射

- `internal/sarif/sarif.go`：规则元数据新增 GitHub code scanning 分类——`security-severity`（`static_confirmed`→`7.5`、`inconclusive`→`3.0`、`refuted`→`0.0`；未确认假设永不高于其证据）、`precision`/`problem.precision`（仅确认数据流为 `high`）、`problem.severity`、`tags`（`security` + 可解析 `CWE-<n>`）；结果新增确定性 `partialFingerprints["primaryLocationLineHash"]`（`sha256(ruleId|uri|startLine)` 前 16 字节，供跨上传合并告警）。全部由静态状态推导，`runtime_status=not_run` 不变，不添加 `helpUri`。
- `internal/sarif/sarif_test.go`：新增 `TestBuildGitHubCodeScanningMapping`（映射值、确定性指纹、不同主位置不同指纹）与 `TestSecuritySeverityAndCWEClassification`（映射边界与 CWE 解析拒绝）。
- 契约：`docs/findings-contract.md` 新增 2026-11-14 GitHub 映射扩展节。
- 验收：`go test ./internal/sarif -count=1` 通过。
- 限制与 pending：真实 GitHub code scanning 上传验收需 push/仓库授权（与 P2-1 同因 pending）；VEX 导出未做（`not_affected` 声明语义的证据门槛需产品决策，见续二十一前确认）。

### 2026-11-14 续二十一：P2-1 CI 门禁真实 runner 落地（仓库公开后授权 push）

- 前置尽职检查：仓库设为 public 后，对当前树与全部 24 个提交做凭据扫描（DSN/AWS/GitHub/OpenAI/Slack key 与弱信号 password/secret/api_key 赋值）；唯一命中为两处测试占位 DSN（`test:test@127.0.0.1:1`、`user:secret-password@example.invalid`）与两处 Go 测试占位 key（`test-explicit-key`、换行拒绝用例），无真实凭据。
- push 授权后推送全部本地提交（`0c489df..6e18c81`）。baseline run 43585245302（HEAD `6e18c81`）`completed success`——首次真实 runner 全绿记录。
- `.github/workflows/ci.yml` 扩展（commit `d6826da`，run 43585400725 全绿）：
  - `offline` job 增加 SARIF 上传 code scanning（`github/codeql-action/upload-sarif@v3`，job 级 `security-events: write`，顶层保持 `contents: read`）。
  - 新增 `db-governance` job：真实 runner 上运行 `scripts/test-db-governance.py`（脚本自管一次性 digest 固定的 PostgreSQL 18 容器，runner 自带 docker），`success`。
  - 新增 `release-artifacts` job：`v*` tag push 触发，构建 linux/windows amd64 二进制（`-trimpath -ldflags "-s -w"`）、固定 fixture 生成 SBOM + SARIF、SHA256 校验和、上传 artifact；不创建 GitHub Release，保持最小权限。本次 run 按条件 skipped（非 tag push），tag 构建尚未演练。
- 红灯可复现演练（P2-1 验收标准）：提交故意失败探针 `e1119d3`（`internal/webui/redprobe_test.go` 的 `t.Fatal`）→ run 43585523523 `completed failure`，失败步骤为 `offline -> Go tests and vet`，证明门禁失败关闭；`git revert` 为 `97a04e7` → run 43585811775 恢复。
- 文档同步：`docs/deployment.md` §5 重写为三 job 实况（含红灯演练记录），§7 更新 CI 门槛现状；`docs/release-checklist.md` "CI 工作流模板"行改为"CI 门禁真实 runner 落地"并记录 run 结论，SARIF 行更新为已上传 code scanning；improvement-plan P2-1 状态块与头部块更新；版本串追加 `+ ci-offline-gate-live`。
- 限制与 pending：`release-artifacts` 需要一次 `v*` tag push 演练（未执行）；code scanning 页面的告警呈现未人工复核；Java/Maven/Gradle、模型与运行时 CI job 仍需专用 runner 与密钥管理；本文档提交自身触发的 run 结论不回写文档（提交先于结论），后续以 Actions 页面为准。

### 2026-11-14 续二十二：P2-1 tag 产物演练 + P3 CycloneDX VEX 分析状态

- **tag 产物演练（P2-1 收尾）**：推送 tag `v0.2.0-p0.2`（与版本串一致）→ run 43587721384 全绿：`offline`、`db-governance`、`release-artifacts` 三个 job 全部 `success`——真实 runner 上产出 linux/windows amd64 二进制、CycloneDX SBOM、SARIF 与 SHA256 校验和 artifact；文档提交 run（43586028180）亦绿。
- **P3 VEX**（`internal/sbom/sbom.go`、`cmd/trident/sca.go`）：`sca sbom` 新增 `--package-map`（仅 sbom 子命令，其余拒绝），提供时在本次进程内运行有界调用图并按固定保守映射生成 CycloneDX 1.5 VEX 声明：`unreachable` → `not_affected` + `code_not_reachable`（detail 写明有界边界：≤8 跳 import/type-ref 图，反射/动态分派/框架装配/外部配置不在声明范围）；`reachable` → `in_triage`（静态可达永不升级为 `exploitable`）；`unknown`/无输入 → `in_triage`（写明 reason）。每个 vulnerability 附 `trident:reachability`/`trident:reachability_tool=not_run`/`trident:reachability_claim` 属性；`metadata` 新增 `trident:vex_basis`。输出保持确定性（无时间戳）。
- 测试：`internal/sbom/sbom_test.go` 新增三态映射、边界文案、metadata、无 map 基线不变与确定性断言；`scripts/test-sbom.py` 新增 [04]（真实 CLI + `--package-map` → `not_affected/code_not_reachable`、官方 CycloneDX 1.5 Schema 校验、两次字节一致、flag 误用拒绝）。CLI 实测：java-maven fixture 的 commons-text 无 import → `unreachable/no_path_from_module_entrypoints` → `not_affected/code_not_reachable`。
- 契约：`docs/sbom-contract.md` 新增 §9 VEX 分析状态（映射表、声明边界、确定性、验收）。
- 验收：`go test ./internal/sbom ./cmd/trident -count=1` 与 `python scripts/test-sbom.py`（5 项）通过。
- 限制与 pending：`not_affected` 是最小可信形态（有界图负判定），不证明类加载/运行时利用/供应链完整性；下游应结合 `detail` 与 `trident:reachability_claim` 解读；code scanning 页面告警呈现仍未人工复核。

### 2026-11-14 续二十三：P2-3 生产设施项——真实监控联调、数据量级备份与容量模型

- **控制台 Prometheus 抓取端点**（`f2568ec`）：`GET /metrics`（文本格式 0.0.4，与 JSON 端点同一组计数器，指标名对齐告警规则）；`authorize()` 增加 `Authorization: Bearer` 支持，`/metrics` 豁免浏览器专用 console 头（运维面），仅 GET；每次抓取落入 JSONL 审计日志。测试：`metrics_test.go`（401 门禁、Bearer 200、全部 TYPE 行、scrape/JSON 计数器一致性、Bearer 无 console 头访问 API 面仍 403）与 `test-web.py`（真实 CLI 全链路断言）。
- **真实监控联调**（`9787d2f`）：`ops/monitoring/`（prometheus.yml 经 `authorization.credentials_file` 注入 Bearer 抓宿主 loopback、alerts.yml 六条规则对齐真实指标名、docker-compose prometheus v2.53.0 + alertmanager v0.27.0）+ `scripts/test-monitoring.py` 端到端演练：抓取 target up → 指标可查询 → 告警经 Alertmanager webhook 送达本地 receiver → 抓取落审计日志，四项 PASS。**调试记录**：首次通知在 Alertmanager gossip settle（~10s）前失败、重试退避数分钟——演练分两段等待（AM 收到告警 → webhook 送达），生产验收窗口按分钟计。控制台保持 loopback 绑定不放宽；Windows/macOS 经 host.docker.internal，Linux 需 socat sidecar。镜像 tag pin，生产须 digest pin。
- **数据量级备份演练**（`ff53636`）：`scripts/test-backup-scale.py` 在真实迁移 Schema 上灌 50 万 principals + 100 万 activities + 20 万 outbox_events（624 MB），实测 pg_dump(custom,compress=6) 3.6s（归档 37 MB，压缩比约 16:1）、pg_restore 6.7s、check+行数核对 3.1s，**RTO（restore+verify）9.8s**；RPO 语义演示：备份后写入 5000 行全部不在恢复点（backup-only 策略最大丢失窗口）。行数核对五表全匹配，`trident check` 通过。
- **容量与成本模型**：新增 `docs/capacity-cost.md`——RTO/RPO 外推公式（restore 吞吐 ≈105 MB/s、dump ≈175 MB/s、归档压缩比、RPO 由备份策略决定）、静态分析容量（内建有界上限 + 缓存语义 + 大项目必须单次重基准化）、DB 增长模型（审计类表为主，公式 + 复核要求）、模型 token 成本公式（明确标注未实测，live-model pending）。`docs/deployment.md` §2.2 重写为真实联调实况、备份节加 RTO/RPO 实测引用。
- 验收：`go test ./internal/webui ./cmd/trident -count=1`、`python scripts/test-web.py`（8 项）、`python scripts/test-monitoring.py`（4 项）、`python scripts/test-backup-scale.py` 全部通过；全量 `go build/vet/test` + `verify-offline.ps1`（14 脚本）绿。
- 限制与 pending：RTO/RPO 实测仅覆盖本机容器与该数据量，生产承诺须按容量模型在生产硬件重测；组织级分权审批记录（表 owner 审批单、密钥系统登记）需组织流程，工具侧无法替代；Alertmanager 探针规则（TridentAlertDeliveryProbe）仅演练用，生产删除；真实项目规模基准与 live-model 成本实测待授权。

### 2026-11-14 续二十四：一键工作区控制台、权限/代码模型视图与 java-model 死循环修复

- **`audit java-model` 无限循环修复**（`internal/javaast/parse.go`）：`skipAngles` 在遇到不配对的 `<`（真实代码里的比较运算符）时返回原位置，`parseTypeAt` 的 `for tokens[index]=="<"` 永不推进。修复为未闭合时只消费开括号；真实项目 `D://Code//Java//market`（84 个 Java 文件）从 **>230s 挂死**降为 **0.61s**。新增 `TestUnbalancedAngleBracketsTerminate` 与 `TestSkipAnglesAlwaysAdvance` 回归测试，并加入 `profile_local_test.go`（仅在设置 `TRIDENT_PROFILE_SNAPSHOT/HASH` 时运行）。
- **性能记忆化**：`javaast` 索引新增四种缓存（方法擦除参数类型、调用候选集、字段查找、子类型判定），避免每次调用重复解析参数与遍历继承链；语义不变，现有测试全绿。
- **一键工作区模式**（`cmd/trident/web.go`、`internal/webui/config.go`）：`trident web --project <dir>` 单条命令完成导入→摘要→启动；`--workspace`（默认 `.trident`）持久化 `console.json` 与 `snapshots/<sha256>/`，再次启动只需 `--workspace`；自动拾取 `<workspace>/advisories/` 与 `<workspace>/package-map.json`。`--advisories` 现同时接受文件或目录（`sca.Options.AdvisoryDir`，目录内 `*.json` 按名排序加载，重复 advisory_id 失败关闭）。
- **运行期配置与项目切换 API**：`GET/POST /api/config`、`POST /api/project`、`POST /api/analysis/rerun`。所有变更先校验后落盘，失败返回 400 且不改动已存配置；成功后清空分析缓存与可达性缓存。pinned 模式返回 `409 pinned_console`，保持原完全只读语义。
- **新增只读视图 API**：`GET /api/authz`（决策分布、逐入口决策、控制与过滤器链）、`GET /api/model` 与 `GET /api/model/type`（类型索引、方法/字段、出向/入向调用边）；`GET /api/endpoints` 增加 `authz` 映射与 `authz_counts`，可按决策筛选；`GET /api/overview` 增加 `authz` 与 `model` 摘要。
- **前端**：新增「权限清单」「代码模型」「设置」三个路由；HTTP 入口表增加权限列与筛选；概览增加无控制入口与代码模型统计卡；限制项改为中文标题 + 截断详情；可点击行支持键盘 Enter/Space；登录占位符改为“终端打印的访问令牌”；无令牌时不再发起必然 401 的 `/api/health`；表格使用 CSS 列宽（CSP 禁止内联样式）。
- **契约**：`docs/web-console-contract.md` 增加 workspace 模式、可变配置边界、新 API 与视图；README 控制台章节重写为一键模式。
- **验收**：`go build ./...`、`go vet ./...`、`go test ./...` 全绿；新增 `internal/webui/config_test.go`（权限/模型视图、pinned 拒绝变更、配置往返、重启恢复）；真实项目端到端：`trident web --project D://Code//Java//market` → 首次分析 2.3s（含 authz 与 90 类型/1815 方法/1224 条已解析调用），界面导入切回 fixture 与 market 均成功。
- **限制与 pending**：工作区模式新增了可变状态（项目切换与路径配置），仍不执行项目代码、不调用模型；`snapshots/` 无自动回收策略；`--agent-dsn` 仍只能在启动时指定；Java 模型上限 2000 文件，超出时界面明确显示未启用原因。

### 2026-11-14 续二十五：Web 项目选择器（空启动 + 目录浏览 + 项目切换）

- **空工作区启动**：`trident web --workspace <dir>` 可先不加载快照；`webui.New` 放宽为"要么 workspace、要么 snapshot+hash"，`Console` 全链路 nil-safe（`Close`/`SnapshotHash`/`buildConfigSnapshot`/`analyze`）。分析类路由由中间件统一拦截并返回 `409 no_project`（`/api/session`、`/api/health`、`/api/config`、`/api/projects*`、`/api/fs`、`/api/metrics` 豁免），前端在无项目时停留在 `#/projects`。
- **项目注册表**：`<workspace>/projects.json`（来源、快照目录、摘要、文件数、字节、导入时间，上限 50 条，按最近导入排序）。启动时自动登记当前项目；`GET/POST /api/projects`、`POST /api/projects/select`（复用磁盘快照，不重新导入）、`POST /api/projects/forget`（仅移除列表项，当前项目拒绝移除，不删快照文件）。
- **目录选择器** `GET /api/fs`：只列子目录，跳过隐藏目录与符号链接，上限 500 项，Windows 返回盘符；对"看起来像项目"的目录做浅层标记（pom.xml/build.gradle/src/.git，不遍历）。该接口仅在 workspace 模式开放，仍受令牌与 console 头双重门禁。
- **前端**：「项目」页（当前项目卡片、目录浏览/上级/盘符、路径输入导入、已导入列表与切换/移除）；无项目时顶栏导出禁用、底栏显示"未选择项目"；登录/刷新路径不再触发必然 409 的 overview 请求；设置页的项目导入入口改为跳转项目页，避免两套导入流程。
- **契约**：`docs/web-console-contract.md` 增加空启动语义、四个项目接口、`/api/fs` 边界、错误码（`no_project`/`project_active`/`project_unknown`）与新视图；README 一键模式补充"空启动后选项目"。
- **验收**：新增 `internal/webui/projects_test.go`（无项目启动与 409、导入/切换/移除、目录选择器拒绝文件与不存在路径）；`go test ./internal/webui ./cmd/trident`、`go vet ./...`、`go build ./...` 全绿；浏览器实测：空工作区启动 → 浏览 D:// → 导入 market（256 文件）→ 导入 fixture（14 文件）→ 切换回 market，全部成功，切换后自动重新分析。
- **限制与 pending**：目录选择器按设计暴露本机目录结构（loopback + token 前提下），不适用于把控制台反代给不可信用户的场景；`projects.json` 与 `console.json` 是两处状态，手工编辑后需重启；快照目录仍无回收策略。

### 2026-11-15：`trident web` 参数错误诊断（可用性修复）

- 现象：`trident web workspace .trident --token 123` 只打印一行 usage，无法判断错在哪。
- 两个真实原因：① `workspace` 漏写 `--`，Go flag 在第一个非 flag token 处停止解析，后续 `--token 123` 全被当作位置参数；② `--token 123` 本身不合法（要求 16–256 字节）。
- 修复：`flags.NArg()>0` 时逐一列出多余参数，命中已知 flag 名时提示"应该是 --workspace，缺少 --"；`--token` 在导入前提前校验并报出实际字节数，附可复制的示例命令；usage 首项改为 `--workspace` 以匹配"空启动选项目"的新主流程。
- 验收：新增 `TestRunWebExplainsBadArguments`（缺 `--` 的诊断、短 token 的实际长度）；`go test ./cmd/trident ./internal/webui` 通过；`trident web --workspace .trident --token <16+ 字节>` 实测启动成功。

### 2026-11-15：真实模型闭环（Run 1–3）与本地数据库可用性修复

- **环境**：Docker Desktop 由用户启动后可用；原 `trident-p0-postgres-1` 无法启动——宿主端口 55432 落在 Windows 保留区间（`netsh int ipv4 show excludedportrange` 显示 55391–55490），改为同名数据卷 + 宿主 5432 重建容器 `trident-pg`（镜像 digest 不变、`postgres -c max_connections=200`），数据卷 `trident-p0_postgres-data` 为空库，重新 `migrate`（`TRIDENT_MIGRATION_ACTOR` 必需）并 `bootstrap web-admin`。
- **Run 1**（deepseek-flash，默认预算 8/24/131072）：`budget_exhausted`，8 次模型调用、16 次工具调用、69,005 tokens。工具序列正常（inspect→list→read×4→trace_dataflow→query_endpoints），只是耗尽调用次数前未收口。**CLI 报错不当**：`agent.Execute` 返回 `store.ErrBudget` 时只打印 "insufficient reserved budget"，已改为输出 `model x/y · tool x/y · tokens x/y` 并说明 `budget_exhausted` 不是结论。
- **Run 2**（deepseek-flash，14/30/262144）：`failed: invalid final envelope or unobserved evidence`，5 次模型调用、7 次工具调用、38,832 tokens——`validateFinal` 拒绝了信封（字段缺失或引用未实际读取的行）。
- **Run 3**（deepseek-v4-pro，14/30/262144，goal 中显式给出 JSON 信封与"只引用实际读到的行"）：`completed`，4 次模型调用、9 次工具调用、28,495 tokens、25s。最终信封 1 条假设，引用 `CustomerController.java:23-25` 与 `CustomerRepository.java:22-28`，通过证据账本校验；limitations 6 条，runtime_status=not_run。
- **控制台**：以 `--agent-dsn` 启动后可读取 3 条 Run；新增 Chrome autofill 覆盖（亮色主题下自动填充输入框不再变深底白字）。
- 验收：`go vet ./cmd/trident`、`go test ./cmd/trident` 通过；`/api/agent/runs` 返回 3 条且 UI 列表正常。
- 限制：Run 3 只证明单次真实模型的自主只读分析与可校验引用，不代表漏洞可利用或覆盖完整；`deepseek-flash` 在该 goal 下两次未收口，说明轻量模型对证据约束的遵循弱于 v4-pro，属于模型行为而非引擎缺陷。

### 2026-11-15：Web 端 Agent 对话（可选控制平面）与渲染修复

- **参考**：本机 192.168.41.12:7777「全链哨兵」控制台。借鉴两点——① 工具活动折叠成一行「过程 · N 次工具调用」摘要，正文只保留结论；② 会话按项目隔离（它为每个项目起独立容器，我们用快照摘要做数据隔离）。
- **后端**（`internal/webui/agent_chat.go`）：`GET /api/agent/chat/state`、`GET /api/agent/threads`、`POST /api/agent/chat`、`POST /api/agent/chat/cancel`（当前固定 501）。创建 Run 复用 `store.CreateAgentRun` + `agent.Execute`，与 CLI 同一条路径；模型密钥只在每个 Run 前从环境变量读取。守卫：默认关闭（`--enable-agent-chat`）、需要 `--agent-dsn` + `--agent-token`（主体令牌）+ 模型绑定、每次请求必须 `approve_egress=true`、同进程单 Run、预算上限 32/64/400k。
- **前端**：`#/agent` 从只读表格改为对话页：左栏按当前快照过滤的会话、右栏消息流、底部目标输入 + 外发批准 + 预算。消息流规则：模型正文按段落/列表渲染（先转义再套极简 markdown）；工具调用合并为单个「过程」块（跨多轮合并、执行中自动展开）；终态渲染独立状态卡并给出 checkpoint 上限提示；模型吐出的 JSON 片段折叠为「模型结构化输出」；结论卡片列出假设与可点击的行号引用（跳转源码）。
- **实测**：Run 4（合成样本，12/24/131072）在第 8 次模型调用时因 **checkpoint 48 KiB 上限**停止 → 状态卡正确显示原因与建议；Run 5（收敛目标，8/10）`completed`，3 模型/4 工具/14,893 tokens，结论含 `CustomerController.java:23`、`CustomerRepository.java:24` 两处引用。
- **修复**：预算耗尽原先误映射为 "insufficient reserved budget"（CLI 同源问题已在 11-14 修过），页面侧补齐终止卡；未执行工具不再显示"等待结果"；会话列表状态不刷新。
- **限制**：48 KiB 检查点上限是硬约束，长对话必然中断——需要拆小目标；没有中途取消（显式 501，不假装支持）；开启对话后控制台不再是纯只读，契约已同步说明。

### 2026-11-15：向参考控制台对齐交互（侧边栏折叠、模型配置、项目切换）

- **参考**：192.168.41.12:7777。取四点：① 图标栏可折叠（64px，保留图标与悬浮标签）；② 设置作为分组，下挂子页（模型 / 路径）；③ 模型库表格（模型+端点、状态、能力、角色、操作）与卡片内标签页；④ 顶栏项目下拉切换。
- **侧边栏折叠**：`#navCollapse` 切换 `body[data-nav]`，折叠态隐藏文字/分组标题/徽标/快照条，分组间加分隔线，状态落 `localStorage`。
- **模型配置**（`internal/webui/agent_model.go`）：`GET /api/agent/models` 用启动时配置的端点探测 `/models`（10s 超时、512 KiB 上限、密钥只用于该请求），`POST /api/agent/model` 仅接受端点实际提供的模型并写入工作区 `agent_model`；有 Run 执行中拒绝切换。页面为 `#/settings/model`，含模型库与预算两个标签页；预算页明示 32/64/400k 上限与 48 KiB 检查点。
- **项目切换**：顶栏下拉从 `/api/projects` 填充，切换走 `POST /api/projects/select` 并清空分析缓存；设置父项在子路由下保持高亮。
- **修复**：顶栏标题在加入切换器后被挤成两行（改为 nowrap + ellipsis）；折叠态快照条残留空胶囊；折叠态缺悬浮标签。
- **验收**：`go build`、`go test ./internal/webui ./cmd/trident` 通过；浏览器实测折叠/展开、模型列表（deepseek-flash、deepseek-v4-pro）、预算页、项目下拉均正常。
- **限制**：模型能力（上下文长度、是否支持思考/图片）端点不返回，页面只标注「端点声明」，不编造；一次只绑定一个端点，多端点需重启。

### 2026-11-15：模型库（多端点）与超大工具结果的降级

- **密钥管理决策**：密钥永不落盘。`<workspace>/models.json` 只存「用哪个环境变量」，多端点靠多个变量区分；端点强制 https（loopback 可 http）。理由：控制台是本地工具，但没有密钥托管设施，明文写盘等于把凭据复制到另一个位置；环境变量是唯一不新增泄露面的做法。
- **模型库**（`internal/webui/model_profiles.go`）：配置档案 CRUD、默认档案、单档探测（`GET {endpoint}/models`，10s/512 KiB）。启动时用 flags 播种一次并落盘；之后模型库优先于 flags。对话请求可带 `profile_id` 指定档案，预算默认取自该档案；执行中的 Run 已固定端点/模型/密钥变量，切换不影响。
- **前端**：模型库表（配置、端点、密钥状态、探测结果、角色、操作）＋新建/编辑表单＋预算标签页；对话输入框新增档案下拉，切换时预算自动跟随。
- **引擎修复（重要）**：单次工具结果超过 24 KiB 原先直接终止 Run（`budget_exhausted`，结果不截断也不提交）。`limit=200` 的 `list_files` 就能触发，属于「合法调用打死 Run」。改为返回 `{"error":"result_too_large","limit_bytes":24576,"hint":"request a smaller page…"}`，不提交结果、不产证据、不截断，Run 继续并可重试。
- **实测**：Run 6（flash，`list_files limit=200`）在旧逻辑下 `budget_exhausted`；修复后 Run 7 同一调用模式收到 `result_too_large` 并自行改用小页，最终 `completed`（5 模型 / 5 工具 / 23,787 tokens），DB 中 `config.model=deepseek-flash` 证明档案路由生效。
- **披露**：Run 7 实际跑在当前项目 market 上（此前为验证项目切换把项目切回 market，未切回合成样本），因此文件清单、`CustomController.java:1-117` 与 483 字节检索结果发送到了 DeepSeek。属操作失误，已在此记录；后续验收应固定合成样本。
- 限制：探测会对任意 https 端点发起请求（令牌持有者可控），仅用于本地工具场景；单次只跑一个 Run；48 KiB 检查点上限仍在。

### 2026-11-15：修复亮色下拉样式、启用运行时关联并重做其页面

- **亮色主题下拉变灰块**：`[data-theme="light"] .input, .select { background: #fff }` 的 `background` 简写重置了 `background-position/size/repeat`，而亮色规则只补了 `background-image`，两个渐变被拉满整个控件（灰底 + 大白三角）。改为 `background-color` 并在亮色规则里补全 position/size/no-repeat。
- **模型名不翻译**：模型库里 `deepseek-flash` 的显示名被写成「DeepSeek 快速」，已改为 `flash`。规则：模型标识（id）不得意译，显示名默认等于模型名。
- **运行时关联启用**：用 `trident runtime http` 对**本机控制台自身**（127.0.0.1:8787，`--allow-loopback`）执行 2 条断言（`/healthz`、`/`），再 `runtime correlate` 与当前项目发现合并，产出 `.trident/runtime-report.json`（发现 6 · 运行时结果 2 · 已关联 0 · 未关联 6）。该目标是自身服务，未接触任何外部系统。报告路径通过 `POST /api/config` 写入工作区，重启后仍在。
- **运行时页面重做**：原先只贴 JSON 原文，且用了内联 `style`（被 CSP 拦截，导致整页被 JSON 撑满）。改为：KPI 条 + 发现关联表（关联/类型/入口/方法/静态状态/原因）+ 未被引用的运行时结果表 + 限制 + 折叠的 JSON 原文；关联原因中文化。
- **观察**：期间出现一次默认档案被改写为 `deepseek-flash`，未复现；后续多次 upsert 均保持 `default`。当前 `models.json` 的 `default` 显式为 `default`（v4-pro）。
- 验收：`go build`、`go test ./internal/webui ./cmd/trident`；浏览器实测下拉、模型库、运行时关联三处。

### 2026-11-15：移除对话页预算控件（配置档案接管运行上限）

- **动机**：对话输入框的「预算」折叠框（模型调用/工具调用/Token 三个数字）只是开发期省成本的手动旋钮，实际使用不应要求用户每轮估算；运行上限改由所选模型配置档案决定。
- **前端**：删除 composer 中的 `<details class="budget">` 与三个输入框，删除配置切换时的预算同步逻辑，`POST /api/agent/chat` 不再携带 `max_model_calls/max_tool_calls/max_tokens`；清理 `.budget` 的 5 条 CSS 规则与亮色主题引用。模型设置页的标签页由「预算」更名为「运行上限」，只读展示各档案默认值，并说明“对话不再逐轮设置预算”。
- **兜底**：`profileLimit()` 在档案默认值为 0 或负数时回退到内置基线（12/24/131072），避免手改 `models.json` 得到零额度 Run；`clampInt` 仍按 32/64/400000 硬上限与 4096 下限裁剪。新增 `TestChatLimitsResolveFromProfile` 覆盖这两种情况。
- **契约**：`POST /api/agent/chat` 说明预算取自配置档案、页面不传；`#/agent` 视图描述同步去掉“预算”。
- **验收**：`go vet`/`go test ./internal/webui ./cmd/trident` 通过；浏览器实测输入栏只剩「模型 / 外发批准 / 发送」，无残留空隙；`POST /api/agent/chat` 空目标仍返回 400，不创建 Run。
- **观察**：历史会话仍在（Run 1–5），其 terminal 状态「预算耗尽」保留原义，属状态描述而非功能入口。

### 2026-11-15：折叠侧边栏图标对齐与关于页文案精简

- **折叠态图标歪斜的根因**：`body[data-nav="collapsed"] .nav-parent::after { content: "" }` 会在 flex 容器里生成一个空项目，配合 `gap: 10px` 把「设置」项唯一可见的图标向左挤 5px，其余项正常，于是整列看起来歪。删除该规则，折叠态 `gap: 0`、图标 `flex: none`；同时隐藏折叠态导航滚动条（`scrollbar-width: none` / `::-webkit-scrollbar`），避免滚动条出现时再次平移图标列。
- **验证**：折叠态 14 个可见导航项的图标中心全部为 33.7px（此前「设置」为 28.7px）；展开态标签、徽标、子菜单无回归。
- **关于页「构建版本」**：`productVersion` 把 21 个能力标记拼在版本号后用 ` + ` 连接，原先原样显示，单行值把 `构建版本` 标签挤成一字一行。改为 `describeBuild()` 拆分：行内只显示短版本（去掉与卡片标题重复的产品名前缀），能力标记折叠进 `<details>`（chips 展示），括号内说明保留在展开区底部。
- **顺带修复**：`固定快照` 卡片的 `Manifest / Policy` 显示 `vundefined`——前端读 `snap.manifest`，接口字段是 `manifest_version`。
- **排版**：`.kv-key` 改为 `white-space: nowrap`、`.kv-val` 用 `overflow-wrap: anywhere` 取代 `word-break: break-all`；工具链版本号在 `+` 后插入零宽空格，长版本串按能力段换行，不再从单词中间断开。
- **验收**：`go vet`/`go test ./internal/webui ./cmd/trident` 通过；浏览器复核折叠/展开、关于页三张卡片与工具链长版本串。

### 2026-11-15：借鉴参考控制台（工作台化概览、严重度分流、会话管理、目标预设）

- **概览工作台化**：10 个统计卡变为可点击（带 `data-action`，跳转目标视图并预置筛选：无控制入口→权限清单「无控制」、证据待定→发现「证据待定」等）；「发现构成」卡新增严重度分布（高/中/低/未知，排除已反驳，点击进入对应筛选）；新增「最近会话」卡（最近 4 条，显示状态、目标、调用量与时间，点击直达对话；Agent 库不可用时整卡隐藏）。
- **发现严重度筛选**：`GET /api/findings` 新增 `severity` 参数与分面 `severities`（随 status/category/q 联动、不随 severity 自身），前端下拉显示各档计数；`GET /api/overview` 新增 `severities`（排除已反驳）。语义：severityKey 将未识别值归入 unknown，避免发现从分布中消失。
- **对话页会话管理**：左栏新增筛选框（按别名/目标过滤）；会话头部新增「重命名 / 复制目标 / 以此目标新建」；重命名只写本机 localStorage（`trident.thread.aliases`，按 snapshot+run 键），不改动数据库里的 Run 记录；结论卡新增「复制结论」（摘要+假设+限制的纯文本）。「以此目标新建」把原目标填入输入框开新会话，不是续跑。
- **目标预设**：composer 上方 4 个常用目标（未授权访问/SQL 注入/路径遍历/依赖风险），点击填入输入框。
- **布局修复**：chat 头部加入操作按钮后 `.chat-head-main` 缺 `min-width:0`，长标题把按钮挤出视口（宽 851px vs 容器 623px），已修。
- **借鉴与取舍**：取了参考控制台的「卡片即入口、严重度分流、会话管理、预设」；未取「报告中心归档」（TRIDENT 导出是确定性的，重复归档只增加状态）、「命令级审批/终端/子代理/容器隔离」（执行平面，与只读定位冲突）、「资产库」（TRIDENT 的对应物是入口/依赖清单）。
- **验收**：`go vet`、`go test ./internal/webui ./cmd/trident` 通过；浏览器实测：严重度行→发现页带筛选（未知 5 条）、卡片→权限清单带筛选、最近会话→对话页选中 Run 5、重命名持久化、筛选「SQL」命中 4 条、预设填入、结论复制按钮渲染、chat 头部按钮在视口内。

### 2026-11-15：登录页重设计（分栏叙事 + 主题切换）

- **布局**：从单卡片居中改为「品牌叙事 + 登录卡」分栏（≤920px 自动只留卡片）。左侧：品牌行、渐变标题「静态证据，而不是猜测。」、四条产品要点（只读快照/分析零外呼/证据账本/确定性导出，逐条淡入）、边界 chips；右侧：登录卡（顶部青蓝渐变饰线、品牌、令牌输入、进入按钮、提示行）。
- **动效**：卡片与叙事面板入场（translateY + fade，cubic-bezier）、要点列表逐条错峰、右上光斑缓慢漂移；`prefers-reduced-motion` 全部关闭。CSP 无内联样式，全部走 styles.css。
- **主题切换上登录页**：右上角加 `theme-toggle` 按钮，`applyTheme` 改为更新 `.theme-toggle` 集合（登录页与顶栏共用）；亮色主题提供完整配色（浅底、白卡、渐变文字换色）。
- **顺带修复**：① 令牌输入框一直缺 `class="input"`，吃的是浏览器默认样式——暗色下看不出来，亮色下变成深底浅字，补上后走统一输入样式；② 无令牌启动时 `showLogin(msg, true)` 的提示框与卡片上方说明文字重复，改为不显示（保留会话失效等真实提示）。
- **验收**：`go vet`、`go test ./internal/webui ./cmd/trident` 通过；浏览器实测暗色/亮色/760px 窄屏三种形态、登录流程（进入控制台→概览）、主题切换跟随。

### 2026-11-15：多语言代码审计引擎（P0-5，主攻代码审计能力）

- **动机**：评审结论指出 R2 全链路只覆盖 Java/Spring，且 Java 自身仍以入口锚点 + 词法流为主。逐语言复制 Java 逻辑会把噪声一起复制，因此改为「统一 IR + 声明式规则」。
- **借鉴（只取架构/规则形态，不引入代码或依赖）**：Semgrep `mode: taint` 的 source/sink/sanitizer 规则形态与规则自带正/负例测试；Joern x2cpg 的「语言前端 → 统一 IR」；CodeQL 的三元组与路径证据。tree-sitter / Roslyn / PHP-Parser 需要 cgo 或外部运行时，与纯 Go、离线、不执行项目代码、确定性输出的边界冲突，明确不引入。
- **实现**：新增 `internal/codescan`（model/spec/rules/load/lex/ir/analyze/findings）。7 个语言前端（php、csharp、python、javascript、typescript、java、go）只描述注释、字符串、成员符、语句切分与路由形状；统一 token/语句 IR 含规范化调用链、参数切分、赋值目标与作用域；50 条内置规则覆盖 11 类 CWE；`--rules` 支持调用者规则 JSON，未知字段/重复 ID/非法语言/越界参数一律失败关闭，`ruleset_version` 随规则数据 SHA-256 变化。
- **关键正确性修复（开发中实测发现，均已加回归测试）**：① `chainsIn` 向左拼成员链时误用循环变量，导致 `end`/`kind` 落在链首 → `db.Query()`、`$request->input()`、`html.escape()` 全部漏识别（漏报 + 转义负例误报）；② Go/JS 无分号语言只按 `;` 切语句，整个函数体被合成一条语句 → Go 全漏报；③ 注解带参数时（`@RequestParam("id")`）kind 变成 call，注解源规则不匹配，且注解参数被注册在类作用域污染兄弟方法 → 改为名称匹配并绑定到所属方法体作用域；④ TS `const name: string = ...` 把类型名当成赋值目标 → 加类型注解/`:=`/多返回值处理；⑤ 方法签名头被当作可执行调用产生重复 finding → 声明头跳过；⑥ 新增 `receiver` sink kind 覆盖 `ois.readObject()` 这类危险输入是接收者而非参数的 API。
- **集成**：`trident audit code`（`--language`/`--rules`/`--format json|findings|sarif`）；`audit findings|sarif --include-code-audit` 显式合并，默认输出字节不变；`codescan.AsFindingsReport`/`MergeFindings` 复用统一证据模型与 SARIF 2.1.0；Web 新增 `#/code` 页、`GET /api/code-audit`、`/api/overview.code` 摘要，控制台受支持源码 > 1500 文件时跳过并显示原因。
- **验收（本机 Windows，Go 1.27.1）**：`go test ./... -count=1` 全绿、`go vet ./...` 无告警；`go test ./internal/codescan -count=1` 通过（词法隔离、链规范化、语句切分、赋值目标、流证据、负例、receiver sink、7 语言路由、规则校验、确定性）；`python scripts/test-code-audit.py` 11 组断言全 PASS（7 语言、25 条正例证据链、显式负例零误报、注释/字符串诱饵、7 类漏洞、24 条声明入口、两次输出字节一致、语言过滤、调用者规则与非法规则失败关闭、统一模型/SARIF、默认 findings 兼容、错误哈希失败关闭、Web 只读接口/筛选/概览、样本与快照字节不变）；`python scripts/test-web.py` 9 项 PASS 无回归。新增 fixture `tests/fixtures/polyglot-audit`（含嵌套 go.mod，避免 Go 工具链编译合成 Go 样本）。
- **浏览器实测**：Edge 打开 `#/code`，渲染 25 行发现、7 语言覆盖、24 条入口、12 条限制与规则集版本；PHP 筛选得到 5 行且全为 PHP；证据流折叠显示 `$_GET → mysql_query` 与 4 步传播；除既有 `/api/agent/threads` 412 外无新增控制台错误。首次误判是临时服务用了改动前编译的旧二进制 + 浏览器缓存资源，重新构建并加 cache-bust 参数后恢复正常，非产品缺陷。
- **未验证 / 遗留**：真实 PHP/.NET/Python/Node/Go 项目检测率、真实框架路由解析、跨函数/跨文件污点、类型系统、框架绑定/ORM/AOP/反射、运行时可利用性；Python 为文件级作用域（已知假阳性来源）；未写正/负例的内置规则只保持存在，不宣称已验证。引擎不编译、不运行、不导入被审计代码，不访问网络、不调用模型。
- **契约与文档**：新增 `docs/code-audit-contract.md`；同步 README、improvement-plan（P0-5/M2b）、web-console-contract（API/视图/缓存/限制/验收）、release-checklist、`scripts/verify-offline.ps1`（15 个离线脚本）。

### 2026-11-15：Java 主线检测力（P0-6，MyBatis / 非入口 sink / 低噪声）

- **动机**：上一轮结论明确指出多语言引擎没有解决 Java 老引擎的根本短板。真实项目 `D:\Code\Java\market` 实测基线：`audit dataflow` 109 条 finding，全部 `CWE-89` / `inconclusive` / `boundary.kind=unresolved_call`，**0 条 sink 证据**。
- **契约先行**：`docs/dataflow-contract.md` §6 先写清默认低噪声语义、MyBatis 分级判定、`audit sinks` 状态纪律与 v13→v14 版本矩阵，再实现。
- **MyBatis 建模**（`internal/dataflow/mybatis.go`）：读取快照中的 Mapper XML 与 `@Select` 等注解 SQL，识别 `<mapper namespace>`、`<select|insert|update|delete|sql id>`、`#{}` / `${}` 及参数名，带文件 SHA-256 与行号。判定分级：`parameterized`（仅 `#{}`，反驳证据）、`substitution`（语句体内 `${}` 且非框架内部，确认证据）、`framework_fragment`（`<sql>` 片段 / `${criterion.condition}` 等生成式条件，不误报）、`unknown`。索引按 `namespace.id` 或唯一简单名解析，简单名冲突时用接收者类型的 namespace 后缀消歧，歧义不任选。调用点在词法引擎标为 `unresolved_call` 之前消费，证据写入 `finding.orm` / `protection` / `sink` 并指向 XML 行。
- **非入口 sink 锚定**（`internal/dataflow/sinks.go`、`trident audit sinks`）：遍历全部项目方法（含 `main`、定时任务、监听器，不要求 controller），定位反序列化、命令、SQL、SpEL、XXE、LDAP、上传、SSRF、文件访问等高危 API；输出位置、所属方法、参数词法可达性、`evidence_strength` 与限制。状态恒 `inconclusive`、`runtime_status=not_run`——方法参数不等于攻击者可控输入。`--include-sink-anchors` 可合并进 dataflow 报告，默认不混进漏洞列表。
- **低噪声**（`internal/dataflow/model.go`）：默认 `analysis_kind=source_sink_multi_category_v2`，只输出有 sink / protection / 类别边界 / 高信息量边界（反射、歧义分派、重载、父类型、动态格式串）的 finding；无观察路径记 `coverage.unobserved_paths`、通用 `unresolved_call` 边界记 `coverage.boundary_only`、MyBatis `#{}` 反驳记 `coverage.mybatis_refuted`。`--emit-unobserved` 复现 v1 语义（`analysis_kind=source_sink_multi_category_v1`），`scripts/test-dataflow.py` 统一带该开关，既有 16 套样本断言不变。每条 finding 新增 `evidence_strength`。
- **开发中修的实现问题**：① 初次实现把「非 SQL 类别」也按通用 observation 放开，java-maven 从 3 条暴涨到 30 条、market 到 1026 条 → 恢复「非 SQL 类别必须 categoryObserved」；② 注解 SQL 的 `@Select` 在词法流里是 `@` + `Select` 两个 token，且接口方法无方法体，改为从后随 `(` 反推方法名。
- **验收（Go 1.27.1 / Windows）**：`go test ./internal/dataflow -count=1` 全绿（新增 5 个单测：XML 分级、索引消歧、默认/兼容语义与 MyBatis 证据、非入口锚点、旧样本证据保持）；既有 15 处 `dataflow_test.go` 调用统一改为 `AnalyzeWithOptions(..., Options{EmitUnobserved:true})`，与 `test-dataflow.py` 的兼容开关口径一致，不改写旧断言语义；`python scripts/test-java-mainline.py` 7 组 PASS；`python scripts/test-dataflow.py`（兼容模式）、`test-findings.py`、`test-web.py` 无回归；`powershell -File scripts/verify-offline.ps1` 全绿（16 个脚本）。
- **真实项目复测**：`market` 默认输出 **109 → 0 findings**；`coverage.unobserved_paths=981`、`boundary_only=45`、`mybatis_refuted=64`、`mybatis_statements=96`；`--emit-unobserved` 仍为 109（49 inconclusive + 60 refuted，其中 60 条由 MyBatis `#{}` 提供反驳证据）。`audit sinks` 定位 1 个非入口锚点（`TestMybatisGenerator.main` 的 `openStream`）。合成样本 `java-mybatis-sinks` 上：`#{}` 反驳、`${}` 确认、`<sql>` 片段不误报、注解 SQL 解析、`main` 的 `readObject` 与定时任务的 `exec` 均被锚定。
- **诚实边界**：0 findings **不表示项目安全**，只表示没有可输出的静态证据；被抑制的是「未观察到 / 通用边界 / 框架绑定证据」，不是「已反驳漏洞」。MyBatis Provider、`<foreach>` 展开、插件改写、跨过程污点、框架注册解析、运行时可利用性、真实项目检测率均未验证。不编译、不运行 Java/Maven、不访问网络、不调用模型；快照与样本字节不变。
- **文档同步**：dataflow-contract §6、README、improvement-plan（P0-6 / M2c / 基线表）、release-checklist、verify-offline.ps1、`internal/findings` 新增 `dataflow_v14_evidence_only` 限制说明。

### 2026-11-15：真实 PHP 项目使用反馈（导入转圈 / 0 发现 / 会话消失）

- **用户场景**：`trident.exe web --token <token> --workspace .trident`，导入 `D:\Code\PHP\www\www.test.com`（1084 文件 / 42 MB）。三个反馈均属实，均经只读复现定位。
- **导入转圈**：`projects.json` 显示导入已成功；瓶颈是 `importProject()` 把 toast 与按钮恢复放在 `await ensureOverview(true)` 之后，而首分析同步执行 `codescan.Analyze` 耗时 **35.4 秒**（`audit findings` 等其他分析各 <0.5 秒）。改：`codescan.Analyze` 从 `analyze()` 移到 `codeMu` 惰性缓存（首次 `/api/code-audit` 才跑，结果/跳过/失败均缓存）；`/api/overview` 未运行时返回 `analysis_pending` 不触发分析；前端导入成功立即反馈、恢复按钮、跳转，不再等待首分析；`#/code` 首次加载提示"大项目可能需要数十秒"。
- **0 发现的正确性**：不正确——用户看的是「安全发现」页（Java/Spring + SCA + 访问控制统一证据模型），对 PHP 项目为 0 属预期；同一快照 `audit code` 有 **22 条**静态发现（21 PHP + 1 JS，`partial=true`，694/1084 文件）。改：findings 零结果页明确说明覆盖范围并给 `#/code` 跳转；概览多语言卡片在惰性未运行时显示「点击运行（非 Java 项目看这里）」；已缓存时显示发现数。
- **Agent 会话消失**：启动命令未带 `--agent-dsn`，`agentStore=nil` → `/api/agent/threads` 412，前端原来吞成空列表；且该接口默认按当前 `snapshot_hash` 过滤，切换项目后看不到其它项目会话。两者都不是数据删除。改：中文 412 原因 + 启动示例；`?hash=all` 与「全部项目」按钮取消过滤；空列表按 412 / 其它错误 / 全部项目 / 当前项目分别给出说明。
- **实测（临时 8798 端口 pinned 同一快照）**：首次 `/api/overview` 0.06 s（`code.available=false`）；`/api/code-audit` 35.68 s、22 条；再次 `/api/overview` 0.00 s、`code.findings=22`；`/api/agent/threads` 412 中文。Edge 实测三个页面渲染与交互正常，除预期 412 无新增控制台错误。
- **回归**：`go test ./...`、`test-web.py`、`test-code-audit.py`（新增「首次概览惰性」与「会话库中文提示」断言）、`test-java-mainline.py`、`powershell -File scripts/verify-offline.ps1` 全绿。
- **诚实边界**：22 条是静态证据不是确认漏洞，多条在 `extend/PHPExcel` 第三方库；`partial=true` 表示部分文件触发字节/token 预算；用户 `.trident` 与正在运行的进程全程只读未改动。文档同步 `docs/web-console-contract.md`（API/缓存/视图/限制/验收/实际结果）。

### 2026-11-15：Agent 会话库默认开启（DSN 持久化）

- **需求**：用户不想每次启动都拼 `--agent-dsn` 连接串。实现三层解析：`--agent-dsn` 显式参数 > workspace `console.json` 的 `agent_dsn`（0600，`.trident/` 已 git 忽略）> 环境变量 `TRIDENT_AGENT_DSN`。设置页新增「Agent 会话库」输入框：保存前真连库校验（失败 400 `agent_dsn_invalid` 并保留旧值），成功即热替换观察库并持久化；「清除已保存的连接」恢复未配置态；仅保存 DSN 不再清空分析缓存（`consoleConfig` 相等性比较后才 reset）。
- **降级语义**：显式 flag 的 DSN 连接失败仍 fail-fast（`AgentDSNExplicit`）；持久化/环境 DSN 失败不阻止启动，`/api/agent/threads` 503 `agent_database_unreachable` 带中文原因，设置页显示详情。新增 `swapAgentStore`（加锁热替换 + 关旧连接）。
- **实测**：`.trident/console.json` 已写入用户真实 DSN；临时实例（仅 `--workspace .trident`，无 DSN 参数）`threads?hash=all` 返回 **52 条历史 Run**（Run 43/46 Spring 审计、Run 48 CodeScan-Artex）；新增 3 个 Go 回归全绿；`go test ./...`（23 包）、`test-web.py`、`test-code-audit.py`、`test-java-mainline.py`、离线全量门禁通过。
- **边界**：`console.json` 含数据库凭据，仅本机使用；旧二进制读新 `console.json` 会失败（`DisallowUnknownFields`），升级需整组替换；有效连接的 E2E 依赖真实库，门禁只覆盖无效 DSN 的降级路径。

### 2026-11-15：代码审计引擎 v2（插值感知 + 同文件函数摘要）与 Agent 配合度增强

- **需求**：用户要求深度优化代码审计能力与 Agent 配合度。摸底确认三个真实缺口：① 插值字符串（PHP 双引号变量 / Python f-string / C# `$""` / JS-TS 反引号）内的 source 全部漏报——真实项目最高频注入写法；② 同文件跨函数流（helper→sink）不连接；③ Agent `list_findings` 的 category 过滤对 `code:` 发现失效、无语言/位置筛选、上限 10 条、Agent 无法查询规则集。
- **引擎 v2**（`tool_version=0.2.0-p0.6+r1-multi-language-code-audit-v2`、`analysis_kind=multi_language_code_audit_v2`、规则集 `trident-core-rules-2026-11-15-v2`）：
  - 插值感知词法：`languageSpec.Interpolation` + `expandInterpolation`（`lex.go`），插值表达式子词法后注入并打 `fromString` 标记；`dropFromStringChains` 保证字符串文本永远不产生 sink/路由/注解绑定（诱饵语义不变），只在表达式求值中充当 source/sanitizer。子词法失败降级为不透明文字，绝不拒绝整个文件。不插值构造（PHP 单引号/heredoc、Python 普通与 r 前缀、Go 原始字符串、`{{}}` 转义）保持不透明。
  - 同文件函数摘要（`summary.go`，每规则）：source 包装（return 含 source）、taint-through（参数→返回值）、sink 包装（参数直接流入体内 sink，证据链 `source → propagation(调用点) → sink(函数内)`，limitation 加 `cross_function_wrapper_sink`）；精确简单名（PHP 大小写不敏感）、一层深度、调用点在函数自身作用域内跳过、512 函数/文件上限；Go 取参数段第一个 ident 其余取最后（类型前置/后置差异）。
  - 新规则 8 条：6 语言开放重定向（`redirect`/CWE-601，Go 为第 3 参数、gin/echo 第 2 参数）+ PHP/Java XPath（`xpath`/CWE-643）。内置规则 50 → 58。
  - 开发中修的真实问题：C# `$"` 前缀 `i++` 后 StringDelimiters 循环仍用缓存 rune 导致整个文件被判 unterminated string（改用当前索引）；f-string 判定未接入普通字符串 handler；摘要名未按 PHP 大小写规则 normalize；sanitizer wrapper 负例语义修正（净化必须发生在 wrapper 体内 sink 的参数处，v1 宽松传播下实参直连 source 的写法本就会命中）。
- **Agent 工具面**（`internal/tools`）：`list_findings`/`trace_dataflow` 加 `language` 参数与 `language_<name>` counts、`q` 匹配 `location`（file:line）、分页上限 10→25、`code:` 发现按规则类别双匹配修复（`category=sql` 现在能筛到 `php.sql.query`）；新工具 `list_rules`（内置规则集元数据摘要，`q`/`category`/`language` 过滤，披露规则是名字模式）；工具定义 9 → 10，`list_rules` 压缩预算 2048。
- **fixture 与验收**：polyglot fixture 追加 11 条 v2 正例（插值 SQL ×3、sink/source 包装 ×2、redirect ×3、xpath、TS 模板 XSS）与负例（非插值字符串 ×4、净化包装器）；`test-code-audit.py` EXPECTED 25 → **36 条**、负例行扩容，11 组断言全 PASS（含负例零误报、字节确定性、默认 findings 兼容、快照字节不变）；`go test ./...` 全仓库全绿（23 包）；`test-web.py` 9 项 PASS。新增 Go 测试：插值提取/不透明负例/字符串 sink 诱饵、函数摘要正负例、redirect/xpath 规则、category/language/location 过滤、limit 25、list_rules。
- **文档同步**：code-audit-contract §10（v2 契约）、web-console-contract（续十一）、README R2 段、improvement-plan 基线表。
- **诚实边界**：同文件摘要仅一层、按精确简单名——重载、动态分发、跨文件流、递归、框架绑定仍未解析；插值仅覆盖四种标注形式（heredoc、组合前缀、格式说明符边界不透明）；Agent 语义仍是静态证据引用，不升级为可利用性证明；真实项目检测率未验证。

### 2026-11-15：多 Agent 编排切片（参考 CodeScan-Artex 三角色）

- **需求**：用户要求参考 `E:/pentest agent/CodeScan-Artex-main`（SCA Audit，agent 包 11K 行）实现同等编排。完整读其 mainagent/planner/worker/assembly/constraints/wrapup/coldgraph/finding_workflow 后落地 C 级方案：三角色 + 探索图 + PG 存储。
- **架构决策（与 Artex 的差异都是刻意的）**：① 图写回权在引擎不在 LLM——Planner/Worker 在终局 JSON 声明 intents/facts/candidates，引擎校验引用覆盖后才落图（Artex 是图写回工具进 worker 工具面；TRIDENT 治理面不做写工具）；② MainAgent 无独立 LLM 会话——控制台 #/agent 对话 + REST 操舵 API 承担观察/操舵职责；③ 会话仍是普通 agent_runs——预算/CAS/checkpoint/引用验证零放宽；④ 无心跳/复核/冷压缩（后续切片）。
- **实现**：契约 `docs/agent-orchestration-contract.md`；迁移 `005_agent_orchestration.sql`（4 表）；`internal/store/orchestration.go`（任务/节点/边/约束 CRUD + 状态 CAS + 图聚合）；`internal/orchestrator/`（engine.go 事件循环 + goals.go 提示构造——硬底线/防重复/量化验收/串行链纪律对齐 Artex planner prompt）；`internal/agent/loop.go` FinalEnvelope v3 + settlement 收尾轮（哨兵防重复 + 收尾轮禁发工具 + 预算内注入）；`internal/webui/agent_orchestration.go` 5 个 API + `#/tasks` 页（列表/创建/图分组/操舵/5 秒轮询）；编排与手动 Run 互斥。
- **测试**：agent 包——FinalEnvelope v3 校验正负例（observed 覆盖/置信度枚举/intents ≤4/legacy 兼容）+ settlement 两例（预算内写回 + 关闭时保持 budget_exhausted 旧行为）；orchestrator 纯函数（allGoalsMet/pickReadyIntents 确定性排序/planner+worker goal 渲染含纪律与约束）。`go build ./...`、go vet、受影响 4 包全绿；离线门禁全量复跑。
- **诚实边界**：引擎与 store 的 E2E 依赖真实 PG + 模型（本轮无 scripted 全链编排测试——store 单测与引擎 scripted 驱动是下一步）；真实模型多轮收敛质量未验证；心跳唤醒/steer_work/独立复核未实现。

### 2026-11-16：模型库 v2（参考「全链哨兵」的模型配置设计）

- **需求**：用户提供内网实例，要求学习其模型配置设计并落地 P0/P1/P2；P1 明确要求适配 TRIDENT 的 Agent 现状，不照抄六角色。
- **研究**：Playwright 注入 Cookie 登录后拆解「设置 → 模型」；从 WebSocket 帧取到真实数据模型（channel → entry → roles → resolved、hasKey、cost、promptCache）。关键结论：渠道目录服务端化、能力/价格结构化、角色槽位 + follow-main + resolved、探测瞬态 + 错误归因、删除引用保护、密钥只回 hasKey、全局默认 vs 会话级覆盖。
- **落地（刻意差异化）**：TRIDENT 只有三类真实模型消费方，角色定为 `main`（对话主 Agent）/`planner`（编排规划轮）/`worker`（编排执行会话），不设守门/评审/监督/指挥/监测——产品没有这些 LLM 会话，凭空加角色只会制造「配置了不生效」。
- **P0**：`models.json` schema 2（api、capabilities、cost；schema 1 自动升级并在首次写入落 v2）；7 个 OpenAI 兼容渠道的离线目录 + 3 个只读 API；按模型 ID 查目录补能力价格；探测 7 类归因 + 跨主机重定向拒绝；前端三段式抽屉、能力 chips、价格行。**协议收窄**：运行时只有 OpenAI Chat Completions 适配器，因此只允许 `openai-completions`；其他协议在旧文件中保留展示但聊天/编排拒绝运行（避免「配了但跑不通」）。
- **P1**：`roles` + `resolved`；`POST /api/agent/models/roles`；删除被引用条目 409 + `details.roles`；对话解析 main，编排分别解析 planner/worker（`orchestrator.Params.WorkerBinding`，两端点可不同、共享任务预算）。
- **P2**：对话页「跟随默认（主模型）」+ 按项目持久化的会话级覆盖；`/api/agent/steps` 返回 `usage`（input/output/estimated_cost_usd/pricing_source/note），只统计 known usage，不做跨 Run 汇总。
- **验收**：`go test ./...` 全绿（新增 schema 迁移、字段校验、角色解析、删除保护、目录查询、探测归因、成本估算、双绑定测试）；`go vet` 干净；真实 workspace 的 schema 1 文件成功升级并落盘为 v2；Playwright 实测模型库/角色分配/抽屉/角色选择器页面。
- **边界**：目录价格是离线快照；能力声明不做探测验证；成本不含缓存分项与阶梯价；无跨 Run 汇总。

## 维护规则

1. 每个开发切片同步更新能力矩阵及日期记录；明确 implemented/verified/pending/blocked，而不是只追加“完成”。
2. 记录准确命令、平台/工具链、测试范围、退出结果和跳过原因；代码版本标识如无 Git 则明确无 commit，不能虚构 revision。
3. 保留历史结果，不用新结果覆盖旧失败/未运行事实。原始日志不包含密钥、完整 DSN、源码秘密或 HTTP 认证头。
4. 修改迁移只新增文件；变更工具/策略/恢复格式需版本化并更新契约。模型接入成功、源码漏洞确认和修复验证是不同门槛。
5. 继续开发先读 README → 本文件 → 对应契约及当前代码，不重新返回已废止的三角色/P0—P6路线。

### 2026-11-16（续）：模型页反馈三项修复

- **浅色模式勾选框发黑**：根因是 `<meta name="color-scheme" content="dark">` + 缺少 CSS `color-scheme` 覆盖，原生 checkbox/radio/下拉弹层始终按暗色渲染。改为 `dark light` 并在 `:root` / `:root[data-theme="light"]` 声明 `color-scheme`，原生控件跟随主题（实测浅色下为白色底）。
- **启动时没配 Key 就必须重启**：新增本机密钥能力。`POST /api/agent/models/key` 保存/清除，写入 `<workspace>/model_keys.json`（schema 1，0600，原子替换）；**本机优先于环境变量**，清除后回退；聊天、编排、探测、成本注记统一走 `profileKey`。响应只回 `key_present` / `key_source`，永不回显；删除条目一并删除密钥。设置页新增 API Key 输入与保存/清除按钮，新建条目可在创建时一并保存。新增测试：保存/权限/优先级/清除/随条目删除/拒绝控制字符/不回显。
- **删除「运行上限」模块**：移除模型页「运行上限」页签、预算面板与抽屉里的上限字段（后端默认值仍作为内部兜底，界面不再暴露）。**修复连带缺陷**：删除该模块时误删了相邻的模型页辅助函数（`viewSettingsModel` 等），导致主题切换或刷新后 `viewSettingsModel is not defined`；已恢复并重新验证模型库/角色分配/主题切换。
- **验收**：`go test ./internal/webui` 全绿；Playwright 实测浅色主题勾选框、密钥保存→表格显示「密钥本机」→清除→「缺密钥」、主题切换后页面不丢。

### 2026-11-16（续二）：Agent 运行时配置搬进设置

- **动机**：编排页与对话页仍要求启动时带 `--enable-agent-chat --agent-token --agent-dsn`，漏传就只能重启；用户要求像参考产品一样在设置里改。
- **实现**：`console.json` 新增 `agent_token`、`agent_chat_enabled`；新增 `GET/POST /api/agent/runtime`，启用前真实 `store.Open` + `Authenticate`，失败不落盘；成功后热替换写库会话与编排引擎（互斥：有 Run/编排时 409）；观测库跟随 DSN 重建，失败只记错误。启动时持久化值参与解析，显式参数仍可一次性覆盖；移除 `--agent-endpoint/--agent-model` 的启用前置条件（端点由模型库角色解析）。
- **前端**：设置页新增「Agent 与编排」卡片（状态 kv、启用开关、DSN、令牌、保存/清除），分析配置卡不再放 DSN；能力状态新增「Agent 编排」。
- **安全**：响应只回 `dsn_target`（host/db）与 `token_stored`；令牌/DSN 不回显、不导出、不进 Run 配置；固定快照模式拒绝修改。
- **测试**：`agent_runtime_test.go` 覆盖凭据不回显、缺 DSN/坏 DSN 拒绝、关闭持久化、清除令牌自动停用、运行中拒绝修改。
- **边界**：启用不代表可运行（仍需模型与密钥）；不支持运行中热切换；数据库凭据轮换后需在设置里更新。

### 2026-11-16（续三）：设置页热配置的收尾

- **排查**：按用户反馈「启动时未配置就要重启，这个问题好多地方存在」逐条扫了面向用户的提示，发现 8 处仍把操作引向启动参数/重启：会话库三个只读端点、编排未启用提示、公告横幅、可达性空态、会话列表空态、API 清单、固定快照模式说明。全部改为「设置页可立即修改，无需重启」，启动参数保留为可选次要路径。
- **文案一致性**：`chat.reason` 的四个赋值点统一为「未启用：在「设置 → Agent 与编排」里开启（无需重启）」；编排未启用提示去掉面向用户暴露内部文档路径的说法。
- **UI**：修复「分析配置」卡多余闭合标签造成的按钮错位；Playwright 重载后两个按钮同属 `.form-row mt-14`。
- **验证**：新增 `TestUnconfiguredAgentHintsPointToSettings`（3 个端点）；本地 PG 一次性 `admin` 主体走通 `POST /api/agent/runtime` 启用 → `ready=true` → 会话历史 200 → 停用，随后删除主体、恢复 `console.json` 字节一致；重建二进制并绕过浏览器缓存复验，当前页无新增 console error。在线实测不是自动化门禁，也不覆盖真实模型调用。

### 2026-11-16（续四）：把「三样东西都要懂」压成一次点击

- **动机**：用户反馈配置太麻烦——要理解 DSN、`principals`、role、64 位令牌，还要去 `secrets/` 里翻文件。
- **实现**：`docs/agent-runtime-contract.md` §8 定义 `agent_runtime_quick_setup_v1`。新增 `internal/webui/agent_runtime_quick.go`：`quickCandidates()` 只读本机已有配置（已存 DSN / `TRIDENT_DATABASE_URL`、已存令牌 / 两个 `secrets/` 目录），`liveQuickProbe()` 用 `store.Open` + `Authenticate` + 新增的只读 `store.DescribePrincipal` 校验候选；`GET/POST /api/agent/runtime/quick`。`quickProbe` 做成可注入函数，离线测试不连库。
- **复用而非另开一条链**：把 `handleAgentRuntimeUpdate` 的校验/持久化/热替换抽成 `applyAgentRuntimeRequest`，手动表单与一键启用共用；POST 重新真实连接与认证，探测只作预检，避免 TOCTOU 和「探测说可用就落盘」的伪报。
- **前端**：设置页主操作改为「一键启用」+ 三个状态 pill，原字段进 `<details>` 高级区；模型密钥缺失时给「设置 → 模型」跳转。CSS 用变量并补浅色模式 pill 配色，无内联样式。
- **明确不做**：不启 Docker、不 bootstrap 主体、不自动启用（仍要用户点一次）、不替代模型配置、不跳过校验。

### 2026-11-16（续五）：按深度分析报告的排序落地七项修复

- **方法**：全部走 RED→GREEN（先写失败测试并确认失败原因，再最小实现），未写无测试的生产代码。
- **O1 目标证据门**：`goal_proved` 原先只校验非空/≤256 字节（`internal/agent/loop.go` 的 `validateFinal`）。新增 `^goal-[1-9][0-9]{0,17}$` 与 `ParseGoalRef`；`plannerRound` 逐条校验引用是否为本图已登记 goal 节点、任务是否已有带非空 `evidence` 的 fact/finding_candidate，未通过的声明不写节点状态，拒绝理由拼进 summary 并进入下一轮 trigger（`engine.go` 的 `plannerRound`/`goalNodeIndex`/`evidenceBearingRecords`）。
- **O2 目标寻址**：操舵新增的 goal 节点真正可被 `goal-N` 引用；`drive` 不再丢弃 `roundSummary`，连续两轮判空才结束。
- **D1 表达式赋值传播**：`flow.go` 的 `default:` 分支改为传播 `result.taint` 到左值并记 `flow.kind=expression`，删除误导性的 `return_value_taint_not_modeled`。
- **D4 text block 中和**：新增 `internal/javasrc`（`Strip` 把 `"""` 内容替换为 `""` + 等量换行），`dataflow/parse.go`、`audit/java.go`、`javaast/parse.go` 三处统一调用，限制为 `text_block_content_not_analyzed`；text block 内的注解仍不识别。
- **W2/O6 跨进程单任务**：新增 `db/migrations/006_orchestration_single_running.sql` 的部分唯一索引（`owner_id` where `state='running'`）；`Engine.Start` 在派发 goroutine 前同步抢占 `created→running`，失败回滚引擎状态；store 把 23505 映射为 `ErrOrchestrationBusy`，控制台返回 409 `orchestration_busy`。本地 `trident_test` 库已执行 `trident migrate`（actor `w2-single-running`），`trident check` 通过。
- **O_EXCL 写文件**：`internal/webui/atomicwrite.go` 用随机命名临时文件（`os.CreateTemp` 即 `O_EXCL`）+ rename；`config.go` 与 `model_keys.go` 不再用固定的 `.tmp`。测试用硬链接预置同名文件，证明旧实现会写穿、新实现不会。
- **W3 操舵状态校验**：`/steer` 先 `GetOrchestrationTask`，只接受 `created`/`running`；终态任务返回 409 `orchestration_steer_rejected`，不再产生孤儿节点。
- **W1 会话限速**：`/api/session` 按客户端 host 计数，5 次失败锁 30 秒（`Retry-After`），成功清零。仍只挡本机脚本猜测，不替代令牌强度。
- **R1/R2/R3**：`Apply` 两阶段（先全部 plan 再 commit）；新建文件 `O_EXCL`；`VerifyOptions.KeepWorkspace` 与 `patch verify --keep-workspace` 控制失败副本清理；`RepairOptions.ApproveExecution` 成为必填参数。
- **验证**：`go build ./...` 退出 0；`go vet ./internal/r3 ./cmd/trident` 无输出；`go test -count=1 ./internal/r3 ./internal/dataflow ./internal/orchestrator ./internal/webui ./internal/agent ./internal/audit ./internal/javaast ./internal/javasrc` 八包全 ok。迁移在一次性 scratch 库上按 006 全量重放并用 psql 证明第二个 running 被拒（23505）、前一个完成后可再抢占。
- **未验证**：真实 docker/gVisor 执行、真实浏览器端到端（`/steer` 的 DB 拒绝分支只测了纯规则函数）、真实模型调用。

### 2026-11-16（续六）：真机启动与闭环验收

- **启动**：`trident-verify.exe`（`TRIDENT 0.2.0-p0.6`）以 `web --workspace .trident --addr 127.0.0.1:8791 --enable-agent-chat --access-log <tmp>` 启动，复用 market 项目（hash `3de9c6c4…`，256 文件/3554368 字节）。`/healthz` 200；无令牌 `/api/overview` 401；带 `X-Trident-Request: console` + `X-Trident-Token` 后 overview 200、`/api/findings` total=182、`/api/endpoints` total=186、`/api/config` 200。
- **鉴权/限速**：`POST /api/session` 正确令牌 204 + `Set-Cookie: trident_console=…; HttpOnly; SameSite=Strict; Max-Age=28800`；连续 5 次错误 401，随后正确令牌 429 + `Retry-After: 30`（`session_rate_limited`）。access log 只记 time/token_id/method/path/status。
- **Agent 运行时热启用**：`secrets/` 中两个令牌与库中 `credential_hash` 均不匹配（根因：`credential_hash = sha256(json.Marshal(token))`，即 token 先加 JSON 双引号再 SHA-256，不是 `sha256(raw token)`）。插入一次性 `verify-admin-*` 主体（id 4766）后 `POST /api/agent/runtime {"enabled":true,"token":…}` 返回 200 `ready=true, token_stored=true, model_ready=true`，无需重启。
- **W2 真机**：用 psql 插入 `state='running'` 的编排任务（id 1），再 `POST /api/agent/orchestration` 创建第二个任务 → 409 `orchestration_busy`，任务 2 落 `failed`，reason 明确「数据库拒绝第二个运行中任务（orchestration_tasks_one_running）」；进程内 `active_task` 此时为 0，证明是 DB 级约束生效。
- **W3 真机**：running 任务 `/steer`（kind=intent）→ 202 `{node_id:1,state:"open"}`；把任务置为 `completed` 后再次 `/steer` → 409 `orchestration_steer_rejected`。
- **数据流**：`audit dataflow` 对 market 快照 exit 0，`findings=0`、`java_files_scanned=84`、`methods_parsed=754`、`endpoints_inventoried=186`、`unobserved_paths=981`、`boundary_only=44`、`mybatis_statements=96`、`mybatis_refuted=65`，`partial=true`（`v14` 语义）。
- **补丁闭环**：`patch verify --snapshot <market> --snapshot-hash <hash> --patch docs/evidence/2026-11-14-market-access-control.patch --profile maven-compile --approve-execution` → `validation_passed`，workspace 256 文件/3554368 字节，`original_snapshot_intact=true`，maven 26.37s，quality 60/C，`runtime_status=isolated_validation_only`；失败补丁（context mismatch `pom.xml:165`）→ `patch_failed`、workspace 自动删除；`--keep-workspace` 保留 256 文件副本。
- **清理/恢复**：删除验证任务/节点/主体（tasks=0、nodes=0、principals=4764），停止控制台（8791 已释放），`console.json` 恢复为不含 `agent_token`/`agent_chat_enabled` 的原始字节；补丁临时副本删除。
- **门禁**：`go build ./...`、`go vet ./...` 退出 0；`go test -count=1 ./...` 25 包全 ok（`internal/model` 无测试文件）。
- **未验证**：真实模型调用（`deepseek-flash` 密钥已存但未发起，涉及外发/费用）；真实 docker/gVisor 执行；浏览器端到端；planner/worker 全流程（本次只验证了启动拒绝与操舵状态机）。

### 2026-11-16（续七）：Agent 真机编排闭环与 14 项修复

- **目标**：在用户承担费用的前提下，用真实 DeepSeek 模型跑通单 Run 与 planner→intent→worker→goal_proved 编排；优先 `deepseek-flash` 省钱。
- **结果**：task 24（`agent-search-flash`）与 task 25（同目标重跑）均 `completed`、goal `met`。task 24：planner r1 run 109（1 call/0 tool/3836 tokens）→ worker run 110（2 calls/1 tool/10505 tokens，2 facts+1 candidate）→ planner r2 run 111（1 call/0 tool/7002 tokens，`goal_proved`）。task 25：run 112（1/0/3754）→ worker 113（3/2/19563）→ planner 114（1/0/7882）。两任务图均为 goal met、intent done、facts+candidate、spawns/yields 边完整。
- **修复（RED→GREEN 或真机复测）**：
  1. `Start` 改用 `context.WithCancel(context.WithoutCancel(parent))`，避免请求 ctx 取消导致任务永久 running。
  2. `normalizeNodePayload`：空 `json.RawMessage` → `{}`，修 SQLSTATE 22P02。
  3. 意图预算守卫改 `>=` 并按剩余预算截断落图，修小预算首轮误判。
  4. planner JSON 示例去 `//` 注释，`TestPlannerGoalJSONExampleIsValid`。
  5. `finalEnvelopeFromStep` 同时接受 run.completed 直出 envelope 与 legacy `{"result":...}`。
  6. planner 目标文本禁止调用工具并允许空 hypotheses；run 109/111 实测 1 call/0 tool 产出 JSON。
  7. `workerNodeState`：unknown、paused → blocked（原先落入 default done）。
  8. 会话 `MaxOutputTokens` 4096 → 8192，避免 worker 终局 JSON 被截断。
  9. `NodeRef` 接受数字/带引号/`goal-` 前缀的 parent id，修 planner 被整轮拒绝。
  10. planner 会话 `AllowUnobservedHypotheses`：允许引用图上已固定证据（planner 无工具），manual/worker 仍要求本轮观测。
  11. worker 的 hypotheses 带证据时写成 inferred fact，修“worker 成功但图内零证据、goal 永远无法证明”。
  12. 意图预算用尽且无 open 意图时，仅当图内**无**证据记录才提前结束；有证据则继续 proof 轮。
  13. 提示词 JSON 字段顺序改为 `limitations` 最后，防模型在 limitations 后提前闭合对象（run 97 的 extra `}`）。
  14. 对应新增测试：`TestStartDetachesFromRequestCancellation`、`TestOrchestrationNodePayloadDefaultsToEmptyObject`、`TestDrivePlansWithSmallIntentBudget`、`TestDriveCapsPlannerIntentsAtTaskBudget`、`TestFinalEnvelopeFromCompletedStep`、`TestPlannerGoalJSONExampleIsValid`、`TestWorkerNodeStateMapsUnknownToBlocked`、`TestValidateFinalAcceptsQuotedParentID`、`TestValidateFinalPlannerAcceptsGraphEvidence`、`TestDriveWritesHypothesesAsEvidenceFacts`、`TestDriveProofRoundRunsAfterIntentBudget`。
- **模型/费用**：`deepseek-flash` 直接请求 200；`deepseek-v4-pro` 直接请求 402 `Insufficient Balance`；`default` profile `key_missing`。闭环证据全部来自 flash；task 24/25 成功路径合计 52,542 tokens（21,343 + 31,199），失败重试另计。
- **门禁**：`go build ./...`、`go vet ./...` 退出 0；`go test -count=1 ./...` 25 包 ok（`internal/model` 无测试文件）。
- **未覆盖**：仅验证机械检索型目标，复杂审计质量未验证；worker 仍可能在宽目标下预算耗尽/unknown；`list_files` 对模型传 `prefix` 返回 `invalid_arguments`（未改 schema）。
- **状态**：控制台仍在运行（8791）；测试数据 tasks 3–25、runs 53–114、principal 4767、profile `agent-verify-pro` 保留待复查；`console.json` 含 `agent_token`/`agent_chat_enabled`，停服后需恢复。完整证据见 `TRIDENT-Agent真机验证-2026-11-16.md`。

### 2026-11-16（续八）：统一 Agent 工作台 v1

- **动机**：用户反馈「编排任务和 Agent 配合奇怪、Agent 对话简陋」。根因是会话列表实际列的是 `agent_runs`：每次聊天新建 Run，planner/worker 也写同一张表，worker 跑一次就多一条「会话」；聊天与编排两套入口，任务详情里的 `Run N` 只跳 `#/agent` 不定位。
- **模型**：新增 `agent_conversations` 作为用户可见上层实体；`agent_conversation_runs` 与 `agent_conversation_tasks` 只做关联，不改 `agent_runs`/`orchestration_tasks` 既有列。Run/Task 唯一归属一个会话；会话按 owner + snapshot 隔离。
- **迁移**：`db/migrations/007_agent_conversations.sql`。本地 `trident migrate` 以 actor `agent-verify-20261116171409` 应用成功，`schema_migrations` 已到 007；`/api/agent/runtime` 由 `ready=false`（schema gate）变为 `ready=true`。
- **后端**：`internal/domain/conversation.go`；`internal/store/conversations.go` 提供 `CreateConversation`、`GetConversation`、`ListConversations`、`ConversationDetail`、`LinkConversationRun`、`LinkConversationTask`、`ConversationIDForTask`，全部走 `agentActor` 归属校验。`agent_conversations.go` 新增列表/详情 handler；`agent_chat.go`、`agent_orchestration.go` 增加可选 `conversation_id`，创建 Run/Task 后写关联表，响应回传 `conversation_id`；任务详情返回该字段。
- **前端**：左栏改为 `/api/agent/conversations`；会话内显示轮次按钮与任务卡；`#chatMode` 支持「单次对话 / 编排任务（小预算）」；`#/agent?run=N` 打开指定 Run，`#/agent?conversation=N` 打开会话，`#/tasks?task=N` 打开任务并在深链时把任务详情提到 Hero 之后；任务节点 Run 链接带 `run`，任务头部「会话 N」回跳会话。
- **真机**：conversation 1 两次聊天 run 115/116 均 `completed`（各 1 call/0 tool，2753/2853 tokens），详情 `runs=2`；同一会话内编排 task 26 `completed`、`reason=全部目标已判定达成`、图 7 节点，详情 `tasks=1`、`task.conversation_id=1`。浏览器验证：会话工作台显示「2 轮 / 1 任务」、任务卡可点；任务深链落在详情；任务头部「会话 #1」可回跳；`#/agent?run=115` 显示独立 Run。
- **修复**：`ConversationDetail` 的 joined SELECT 使用未限定列名导致 `column reference "created_at" is ambiguous`（SQLSTATE 42702）；新增 `qualifySQLColumns` 给 `agent_runs`/`orchestration_tasks` 列加别名前缀后恢复。深链优先级：URL 带 `conversation` 时不再复用浏览器内存里的旧 `openId`。
- **门禁**：`go build ./...`、`go vet ./...` 退出 0；`go test -count=1 ./...` 25 包 ok（`internal/model` 无测试文件）；`node --check internal/webui/assets/app.js` 退出 0。
- **未完成/边界**：仍不实现「候选发现一键提升为 findings/补丁」；聊天「多轮」只是同一会话内分组展示，**没有把前序 Run 的结论注入下一次模型上下文**；会话标题不可编辑；worker/planner Run 不进入会话列表。测试数据 tasks 3–26、runs 53–116、principal 4767、profile `agent-verify-pro` 保留；代码未提交 git。

### 2026-11-16（续十）：Agent 对话视觉重做（参考全链哨兵控制台）

- **动机**：用户反馈 Agent 对话框仍「太丑」，要求参考 `https://192.168.41.12:7777/` 的对话页视觉与交互。参考页为浅色单栏、白色大留白、紧凑工具条、纯文本回答、底部固定输入卡；原 TRIDENT 在 603px 视口是 268px 会话栏 + 对话栏 + 右侧详情栏，正文被压到约 270px。
- **布局**：`internal/webui/assets/styles.css` 新增「agent chat: single-column workspace」段。`<=1100px` 时 `.chat-shell` 变单列，250px 会话栏变为 fixed 左抽屉（遮罩、关闭按钮、顶部「会话」入口）；`>1100px` 恢复 250px 会话栏 + 主对话区。抽屉在 517px 视口实测可开合，亮/暗主题均正常。
- **Header**：`chat-head` 改为 `AGENT SESSION · Run #id` + 两行标题 + 状态/模型调用/工具调用/token/成本统计；操作收敛为「会话 / 重命名 / 复制目标 / 以此目标新建」。
- **对话**：`buildBlocks` 渲染 `run.goal` 为用户消息块；assistant 加 `AGENT` 标签并去掉旧气泡背景，亮色下也强制透明；工具过程缩成可展开胶囊；最终/状态卡收敛为左强调线。新增 `run.unknown` 状态块（Run 121 现在显示「状态不明 / console stopped during read-only tool execution」及可重新发起的提示），并对 failed/paused/budget_exhausted/cancelled 使用中文状态名。
- **会话内历史**：右侧默认只显示会话标题和「历史」按钮，`history` 展开后才显示 Run 轮次/编排任务；默认折叠，避免窄屏历史 chip 占掉正文高度。Run 切换仍走 `data-conv-run`。
- **输入区**：Composer 改为大输入框 + 预设 chips + 运行方式/模型/外发批准 + 右下角发送。`<=720px` 隐藏控件文字标签、把控件压成单行；`<=480px` 再纵排，避免 517px 下标签竖排。
- **验证**：`node --check internal/webui/assets/app.js` 退出 0；`go build ./...`、`go vet ./...` 退出 0；`go test -count=1 ./...` 25 包全 ok（`internal/model` 无测试文件）。浏览器在 517px 亮/暗主题下验证了单栏、折叠历史、历史展开、抽屉开合；603px 亮色截图见 `C:\Users\zx\AppData\Local\Temp\trident-chat-v9-collapsed.png` 等。
- **未验证/边界**：`>1100px` 宽屏布局当前浏览器窗口无法调到该宽度，仅有代码级响应式实现，**没有截图证据**；未在本轮发起新的聊天 Run 验证发送后的流式刷新；抽屉截图使用临时 `willChange` 强制重绘，实际生产代码未保留该调试属性。参考站 Cookie 只在浏览器会话中使用，未写入仓库。

### 2026-11-16（续十一）：Web API 前后端一一对应

- **盘点口径**：以 `internal/webui/webui.go` 的 `HandleFunc` 注册为后端全集，以 `internal/webui/assets/app.js` 的 `api()`/`downloadArtifact()` 实际调用为前端全集；路径参数 `{provider}` 与前端模板变量归一后逐方法比对。结果：后端由 61 条降至 57 条 `HandleFunc`；前端 47 条路径 / 53 个方法+路径调用，缺失后端路由 0 条。
- **删除**：`GET /api/agent/runs`（会话工作台已改用 conversations/threads）、`POST /api/agent/models/default`（默认档案已由 roles 的 `main` 角色维护）、`POST /api/agent/chat/cancel`（固定 501，无前端调用）、`POST /api/project`（单数旧导入入口，已被 `POST /api/projects` 替代）。同步删除 `handleAgentRuns`、`handleModelProfileDefault`、`handleAgentChatCancel`、`handleProjectImport` 及旧导入 DTO；清理 `extended.go` 的 `context`、`agent_chat.go` 的 `strconv`、`config.go` 的 `time` 导入。
- **保留**：`GET /api/agent/threads` 仍被概览页真实调用；`/api/metrics`、`/metrics`、`/healthz` 是运维/探活面，不是浏览器 UI 调用；`/export/report` 被顶栏导出按钮真实调用。三者均不按“前端未用”删除。
- **前端**：关于页标题改为「控制台 API」，删除 `/api/agent/runs`，补齐 conversations、chat/state、models、model-channels、model-catalog、runtime、orchestration、projects、config、fs、analysis rerun 等当前调用；修正过期的「没有 Agent 控制或审批 API」文案；编排详情与停止接口的查询参数按实际改为 `id=`，模型目录查询为 `model_id=`/`base_url=`。
- **契约**：`docs/web-console-contract.md` API 表由 56 行覆盖后端全部 56 条 API 路由（脚本比对无缺项/无多项），删除四个旧接口并补齐 Agent 会话、运行时、模型通道与编排接口；`docs/model-library-contract.md` 删除 `/models/default`，把误写的 `/models/upsert` 修正为 `/api/agent/models`，并注明 roles `main` 同步维护兼容字段 `default`。
- **测试/脚本**：新增 `internal/webui/routes_test.go`，先红后绿地锁定四个旧接口返回 404；`config_test.go` 改用 `/api/projects` 并适配 `{"project":{...}}` 响应；`agent_dsn_test.go` 移除 `/api/agent/runs`；`scripts/test-web.py` 的未配置 Agent 断言改用 `/api/agent/threads`。
- **门禁**：`node --check internal/webui/assets/app.js` 退出 0；`go build ./...`、`go vet ./...` 退出 0；`go test -count=1 ./...` 25 包 ok（`internal/model` 无测试文件）；`python scripts/test-web.py` 八项全部 PASS（含多用户令牌、确定性 HTML 导出、JSONL 审计、快照字节不变）。
- **真机闭环**：最终二进制 `%TEMP%\trident-verify-final.exe` 重启于 `127.0.0.1:8791`；`/api/agent/runtime` 重新连接后 `ready=true`；四个旧路由均 404；`/api/agent/threads`、`/api/agent/conversations`、`/api/agent/orchestration/detail?id=26`、`/api/overview`、`/export/report` 均 200。浏览器的关于页、概览页、Agent 会话页、任务深链均正常；关于页不再出现 `/api/agent/runs` 或旧安全文案。
- **边界**：本机 Git CLI 不在 PATH，未执行 `git diff --check`；已改用尾随空白扫描并保留实际命令结果。`development-progress.md` 早期条目里的旧接口名称属于历史记录，当前契约以 `web-console-contract.md` API 表为准。
