# 多语言代码审计契约（`audit code`）

- 日期：2026-11-15
- 状态：已实现并通过 `python scripts/test-code-audit.py`、`go test ./internal/codescan` 验收；**不是完整 AST、类型系统、跨过程污点或可利用性证明**。
- 入口：`trident audit code`、`internal/codescan/`、`internal/webui/code_audit.go`、`#/code`。
- 版本：`tool_version=0.2.0-p0.5+r1-multi-language-code-audit-v1`，`analysis_kind=multi_language_code_audit_v1`，`schema_version=1`。

本片回答“在受信任快照中，哪些语言文件里存在声明式的 source → sink 有界流”。它不编译、不运行、不导入被审计代码，不解析类型系统，不建立完整调用图，不访问网络，不调用模型，不连接运行时验证。

## 1. 为什么这样设计（借鉴与取舍）

现有 R2 分析链路（入口清单、词法数据流、Spring Security 控制、Java 语义模型、SCA）全部以 Java/Spring 为前提。把这套逻辑逐语言复制会把 Java 引擎已有的边界和噪声一起复制，因此本片采用**统一 IR + 语言前端 + 声明式规则**，而不是写 N 个分析器。

借鉴的开源做法（只借鉴架构与规则形态，未引入其代码或依赖）：

| 项目 | 借鉴点 | 本项目取舍 |
|---|---|---|
| Semgrep OSS | `mode: taint` 的 `pattern-sources` / `pattern-sinks` / `pattern-sanitizers`；规则带 CWE/severity 元数据；规则自带正/负例测试；OSS 版仅函数内污点 | 规则表用结构化 name selector（不是 YAML/正则/AST pattern），仅 scope 内污点；每条内置规则在 `tests/fixtures/polyglot-audit` 有正例与负例 |
| Joern / x2cpg | 各语言前端输出统一 Code Property Graph，查询语言无关 | 只输出 token/语句 IR 与规范化调用链，不建 CPG、不做图查询 |
| CodeQL | source / sink / sanitizer 三元组与可达路径证据 | 输出 source → propagation → sink 步骤，每条带文件 SHA-256 与行号；不写查询语言 |
| tree-sitter / Roslyn / PHP-Parser | 真正的多语言语法前端 | **不引入**：需要 cgo、外部运行时或构建工具，违反纯 Go / 离线 / 不执行项目代码 / 确定性输出的既有边界 |

因此本片的诚实定位是：**受限词法前端上的有界、规则驱动审计**，不是"支持 PHP/.NET 的完整静态分析"。语法复杂度高的构造一律记为边界，不猜测。

## 2. 输入与信任边界

1. 只读取已导入并通过 `snapshot_hash` 绑定的 `SourceSnapshot`；每个文件通过 `Snapshot.ReadFile` 重新校验大小与原始字节 SHA-256。完整性失败直接中止。
2. 源码、注释、字符串、路由字面量、调用名都是不可信数据，不能改变工具集合、授权、输出路径或执行行为。规则文件只允许声明式 selector，不接受表达式、正则或代码。
3. 不执行被审计源码、编译器、包管理器、测试框架或模型；不访问网络；不写快照。
4. 文件所有权按扩展名判定，且每种扩展名只属于一个前端；不支持的文件（如 `.txt`）不参与分析。
5. 有界量：4000 文件、2 MiB/文件、200000 token/文件、20000 语句/文件、10000 finding、32 步/流、64 KiB 规则文件、256 规则。超限输出 `partial=true` 与明确 limitation，不静默截断后当作完整结论。

## 3. 语言前端

统一前端配置只描述：扩展名、行注释/块注释、字符串分隔符、成员操作符、语句切分方式、声明式路由形状。

| 语言 | 扩展名 | 特殊处理 |
|---|---|---|
| `php` | `.php` `.phtml` `.php5` | `<?php`/`?>` 标签、`#` 注释、heredoc/nowdoc 跳过、`->`/`::` 成员、`$var` 标识符、PHP 函数名大小写不敏感 |
| `csharp`（.NET / `dotnet`） | `.cs` | Razor `@* *@` 注释、逐字字符串 `@"..."`、插值字符串前缀、注解/特性名去 `@` |
| `python` | `.py` `.pyw` | `#` 注释、三引号字符串、按行切分（文件级 scope） |
| `javascript` / `typescript` | `.js/.jsx/.mjs/.cjs` / `.ts/.tsx` | `//`、`/* */`、模板字符串、类型注解不参与赋值目标 |
| `java` | `.java` | 注解参数绑定为方法体作用域的 tainted 参数、泛型/注解名规范化 |
| `go` | `.go` | 无分号语句按换行切分、`:=` 赋值、多返回值赋值 |

所有前端输出同一 `statement` IR：`tokens[]`、`occurs[]`（规范化调用/访问链）、`calls[]`（含按顶层逗号切分的参数）、`assign`（目标、全链、右值）、`scope`。`{ }` 产生子作用域（Python 例外）。

## 4. 规则模型

规则是数据，不是代码。内置规则集 `trident-core-rules-2026-11-15-v1`，报告中的 `ruleset_version` 始终带**全部规则数据的 SHA-256 前 12 位**，规则一变版本就变，旧报告不会被新语义静默重解释。

```
RuleSpec: id, languages[], category, cwe, severity, confidence, title, message,
          sources[], sinks[], sanitizers[], safe_calls[]
PatternSpec: kind, names[], arg_index
```

- `kind` ∈ `call`（调用）/`access`（属性或超全局读取）/`identifier`/`assign`（危险属性被赋值）/`statement`（`echo` 一类语句构造）/`receiver`（危险输入是调用接收者，如 `ois.readObject()`）/`any`。
- `names` 为结构化 selector：短名做后缀匹配，限定名（`Route::get`、`req.query`、`cmd.CommandText`）做后缀或前缀匹配，`*` 匹配一段；不做正则。
- `arg_index` 为 1-based，仅对 sink 生效；0/省略表示任意参数。SQL/命令类 sink 固定 `arg_index=1`，使 `cursor.execute("... %s", (user,))`、参数化 `db.query(..., [id])` 不会因为用户数据位于后续的绑定参数而被误报。
- `sanitizers` 命中所在表达式即抑制污点；`safe_calls`（参数绑定/预编译）在 sink 前后 3 条语句内抑制**同规则**的该 sink，是有界误报控制，不是安全证明。
- 类别白名单：sql、command、code_exec、deserialization、path、ssrf、xss、xxe、template、upload、ldap。CWE 必须匹配 `CWE-<数字>`。

外部规则：`--rules <json>` 追加调用者规则（`schema_version=1`）。未知字段、重复 ID、不支持语言、非法类别/CWE/severity、越界 `arg_index`、selector 字符不合法、多 JSON 文档一律失败关闭并返回非零。

## 5. 分析语义

1. **切分**：注释与字符串不产生可执行 token；字符串字面量保留为一个 token 供路由读取。换行在括号深度为 0 且不以运算符结尾时结束语句（Go/JS 无分号必需）；`{ }` 建立子作用域。
2. **source**：按声明式规则识别超全局、`Request.QueryString`、`req.query`、`@RequestParam String name` 等。注解参数只绑定到其所属方法体作用域，不污染同类的其它方法。
3. **传播**：赋值（`=`/`:=`/`.=`/`+=`）、字符串拼接、局部变量引用、数组/集合元素读取。作用域进入时继承父作用域污点。
4. **sanitizer**：`htmlspecialchars`、`intval`、`html.escape`、`escapeHtml`、`strconv.Atoi`、`Path.GetFileName` 等按语言规则命中即清除该表达式污点。
5. **sink**：调用名 / 赋值目标 / 语句构造 / 调用接收者命中规则，且指定参数表达式被污染 → 产出 finding。每条 finding 必须带 source、sink、`flow[]`（source → 若干 assignment → sink）、`evidence[]`，全部带文件 SHA-256 与行号。
6. **状态**：`status=static_confirmed` 仅表示"同一有界作用域内观察到完整静态流"；`runtime_status` 恒为 `not_run`。不生成假设、不自动定级为可利用。
7. **入口清单**：从 `Route::get`、`[HttpGet]`、`@app.route`、`app.get`、`@GetMapping`、`http.HandleFunc` 等声明中读取第一个字符串字面量。非字面量、疑似无关字符串（不含 `/` 或 `[` 且非框架相对路由）不猜测；声明不等于部署或可达。
8. **确定性**：文件按路径排序，规则按 ID 排序，finding 按 (file, line, rule_id, id) 排序；无时间戳；同一输入字节级一致。

## 6. 输出契约

`trident audit code --snapshot <dir> --snapshot-hash <sha256> [--language ...] [--rules ...] [--format json|findings|sarif]`

- 身份：`schema_version`、`tool_version`、`snapshot_hash`、`analysis_kind`、`ruleset_version`、`partial`。
- `languages[]`：语言、扩展名、扫描/拒绝文件数、活跃规则数、finding 数、路由数、`scanned|no_source_files|skipped_by_filter`。
- `files[]`：文件、语言、SHA-256、字节、token 数、语句数、`scanned|rejected` 与原因。不存源码。
- `routes[]`：语言、路径、HTTP 方法、符号、文件、SHA-256、行号、形状类别。
- `findings[]`：ID、规则 ID、语言、类别、CWE、severity、confidence、status、runtime_status、标题/说明、文件与行范围、source/sink/sanitizer 引用、`flow[]`、`evidence[]`、`limitations[]`。
- `coverage`：文件/token/语句/规则/路由/finding 计数，按语言与类别的确定性 `Count[]`，`runtime_status`、`analysis_scope`。
- `limitations[]`：固定边界 + 动态边界（`file_limit`、`finding_limit`、`lex_rejected` 等），排序去重。

`--format findings` 输出统一证据模型（`internal/findings.Report`），ID 前缀 `code:`，可被既有证据抽屉消费；`--format sarif` 复用 `internal/sarif.Build` 导出确定性 SARIF 2.1.0。`audit findings --include-code-audit` / `audit sarif --include-code-audit` 可显式合并；**不带该开关时旧输出字节不变**。

## 7. Web 控制台

- `GET /api/code-audit?language=&category=&severity=&q=&limit=&offset=`：只读筛选/分页，返回报告摘要、`items[]`、`by_language/by_category/by_severity`、语言覆盖、入口、限制。附加列表上限 200 条。
- `GET /api/overview` 新增 `code` 摘要（available、reason、findings、languages、rules、routes、ruleset_version、partial）。
- `#/code` 页：KPI、规则集版本、筛选表格、可折叠的 source→sink 证据流、语言覆盖、声明入口、限制清单。点击位置跳转源码浏览。
- 控制台首分析额外跑一次多语言引擎；受支持源码文件 > 1500 时跳过并在页面显示原因，不阻塞其它分析。不提供任何执行/修复入口。

## 8. 限制与非目标

固定 limitation 见报告 `limitations[]`，核心如下：

- `lexical_token_ir`：不是 AST、CFG、类型系统或 points-to 分析；对象字面量、复杂 lambda、宏、模板元编程、语法糖按边界处理。
- `intraprocedural_only`：只在同一作用域内追踪；跨函数、跨文件、跨请求、框架绑定、ORM、AOP、反射、动态代理、依赖注入不解析。
- `rules_are_data_not_semantics`：按名字匹配；同名的本地 helper 可能改变结果，被重命名的框架 API 不会被跟随。
- `sanitizer_is_pattern_level` / `safe_call_lookahead_3`：sanitizer 与参数绑定是模式级误报控制，不证明净化覆盖或参数绑定正确性。
- `string_interpolation_not_modeled`：插值字符串、heredoc、模板表达式按不透明字面量处理。
- `python_scope_file_level`：Python 采用文件级作用域，可能产生跨函数污染，这是已知假阳性来源。
- `route_declaration_not_deployment`：声明入口不是部署路由，也不证明可达。
- `no_runtime_verification` / `absence_is_not_safety`：无运行时验证、无发现不等于安全。

非目标：不实现完整语言编译器、字节码/IL 分析、跨过程污点、自动定级、自动修复、依赖解析、在线规则库、对任意语言的语法完备支持。未写正/负例的内置规则保持"存在但未单独验证"，不得表述为已验证的检测能力。

## 9. 验收

- `go test ./internal/codescan`：词法隔离、链规范化、语句切分、赋值目标、source→sink 流、sanitizer/`arg_index` 负例、receiver sink、多语言路由、规则校验失败关闭、别名、报告确定性。
- `python scripts/test-code-audit.py`：真实 CLI 与真实 Web 服务；7 种语言、25 条正例证据链、显式负例零误报、注释/字符串诱饵、7 类漏洞、24 条声明入口、两次输出字节一致、语言过滤、调用者规则、非法规则失败关闭、统一模型/SARIF、默认 findings 向后兼容、错误哈希失败关闭、`/api/code-audit` 筛选与概览摘要、fixture 与快照字节不变。
- `powershell -File scripts/verify-offline.ps1`：加入上述脚本的离线门禁。

未验证：真实 PHP/.NET/Python/Node/Go 生产项目、真实框架路由解析、编译或运行被审计代码、跨文件污点、运行时可利用性。合成样本通过不等于对真实项目的检测率承诺。

## 10. v2 增强：插值字符串感知与同文件函数摘要（2026-11-15 同日续）

本节是 v1 之上的第一轮检测力改造。版本升级为 `tool_version=0.2.0-p0.6+r1-multi-language-code-audit-v2`、`analysis_kind=multi_language_code_audit_v2`、`RuleSetVersion=trident-core-rules-2026-11-15-v2`（仍带全量规则数据 SHA-256 摘要）。

### 10.1 插值字符串感知（修真实漏报）

v1 把字符串字面量当不透明 token，导致四种**真实世界最高频**的注入写法全部漏报：PHP 双引号内嵌变量（`"SELECT * FROM t WHERE id=$_GET[id]"`）、Python f-string（`cursor.execute(f"... {request.args['x']}")`）、C# 插值字符串（`$"..."`）、JS/TS 模板字面量（`` `SELECT ... ${req.query.id}` ``）。

v2 在词法层提取插值表达式，并给所有从字符串派生的 token 打 `fromString` 标记。标记的语义边界：

- **允许**：`evalExpr` 中的 source/sanitizer 匹配、变量传播——插值表达式在运行时确实被求值，污染会真实进入宿主表达式。
- **禁止**：`stmt.calls`、`stmt.occurs`、路由识别、注解参数绑定——字符串文本里出现的 `mysql_query(...)`、`Route::get(...)` 是数据不是执行，不得产生 sink、入口或绑定。
- 文字部分保持一个 `tokString`；仅插值表达式（PHP `$var`/`$var->m`/`$var[i]`/`{$expr}`、Python `{expr}`、C# `{expr}`、JS/TS `${expr}`）经子词法器重新分词后注入。
- 不插值的构造保持不透明：PHP 单引号、heredoc/nowdoc、Python 普通与 r 前缀字符串、Go 原始字符串（反引号在 Go 中不插值）、Python `{{`/`}}` 转义。

### 10.2 同文件函数摘要（一层跨函数）

v1 的污点只在同一作用域内流动；真实代码中 source 与 sink 常隔一个同文件 helper。v2 增加**规则相关**的函数摘要层（`internal/codescan/summary.go`）：

1. 摘要预扫（每规则）：对文件内每个函数声明提取简单名、形参名（近似：Go 取每参数段第一个 ident，其余语言取最后一个）、函数体 scope；在函数体内以「形参为污染起点 + 规则 source」传播，记录 `returns_source`（return 表达式含 source）、`return_params`（形参流向返回值）、`sink_params`（形参直接流入的 sink 观测）。上限 512 函数/文件，超出记 partial。
2. 调用点回扫（每规则）：调用简单名精确匹配摘要时——source 函数调用作为污染源；`return_params` 实参污染透传返回值；`sink_params` 命中且对应实参被污染 → 产出 finding，证据链为 `source → cross_function_call(调用点) → sink(函数体内)`。
3. 匹配边界：仅限同一文件、简单名精确匹配、一层调用深度；被调函数体内的再次调用不递归；调用点位于被调函数自身作用域时跳过（防自递归）。
4. 证据诚实性：包装器 sink 的 finding 仍为 `static_confirmed` 但 limitations 追加 `cross_function_wrapper_sink`，声明这是名字级摘要不是类型解析或调用图。`FlowStep.Kind` 复用既有 kind，不新增枚举。

由此 v1 limitation `intraprocedural_only` 更新为 `intra_file_function_summary`（如实描述上述边界）；`string_interpolation_not_modeled` 更新为 `string_interpolation_bounded`。**跨文件污点、重载/动态分发、框架绑定仍然是非目标**。

### 10.3 新规则（58 条）

新增 8 条：6 语言开放重定向（`CWE-601`，category `redirect`；PHP `header`、Java `sendRedirect`、C# `Redirect`、Python `redirect`/`HttpResponseRedirect`、JS/TS `res.redirect`、Go `http.Redirect` arg_index=3）与 PHP/Java XPath 注入（`CWE-643`，category `xpath`）。`allowedCategories` 同步扩容，旧规则与负例不变。

### 10.4 Agent 配合度（`internal/tools`）

- `list_findings`/`trace_dataflow`：`category` 过滤修复——统一模型发现按 kind 映射匹配，`code:` 发现按 `finding.Category` 直接匹配，`category=sql` 现在能同时筛到两类；新增 `language` 过滤（`code:` 发现取自报告语言，Java 统一模型发现为 `java`）；`q` 匹配范围增加 `location`（`file:line`）；分页上限 10 → 25；响应 `counts` 增加 `language_<name>` 分布。
- 新工具 `list_rules`：返回内置规则集摘要（id、语言、类别、CWE、严重度、置信度、模式计数），支持 `q`/`category`/`language` 过滤，让 Agent 在引用规则 ID 前先理解引擎能力；描述明确规则是名字模式不是语义分析。
- 工具描述同步：说明 `code:` 发现的 `location` 语义、`language` 参数、低噪声合并语义。前端与 `/api/*` 契约不变。
