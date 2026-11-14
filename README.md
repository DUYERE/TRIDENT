# TRIDENT

**TRIDENT 是一个全新的统一安全 Agent**，吸收 Sapper、ARTEX、CodeScan 的优点，面向软件供应链安全分析、源代码审计、AI 辅助漏洞挖掘、漏洞自动化修复与补丁生成。不是调度三个项目或三个自主角色的平台。

**当前执行基线：[TRIDENT 统一安全 Agent 执行方案 v2.0](docs/TRIDENT_统一安全Agent执行方案_v2.0.md)。** 旧三角色架构和 P0—P6 平台路线已废止，后续按新方案 R0—R6 推进。

**当前开发基线保留 `0.2.0-p0.2` 离线治理，已新增 R0 样本、R1 快照/四项只读工具、统一 Agent Core/持久 Run/OpenAI 兼容协议适配，R2 离线 Maven/Gradle 声明、公告区间/别名、模块依赖树、Spring MVC/JAX-RS/Servlet 入口清单、10 类 Source/Sink 静态证据、统一 Finding/Hypothesis 证据模型、SARIF/import 可达性、只读 Web 分析控制台、九个 Agent 只读工具和 CycloneDX SBOM，以及 R3 补丁生成、策略约束、隔离验证（JUnit XML/JaCoCo/多测试类）、质量评分、多轮修复、Docker/gVisor 沙箱。已完成获准的真实模型只读闭环（DeepSeek `deepseek-flash` Run 43、`deepseek-v4-pro` Run 46、真实 `CodeScan-Artex-main` 快照 Run 48）与真实模型补丁生成 + Maven/Docker 验证；其他模型/快照仍需逐次授权。Maven/Gradle 在线有效依赖树、完整 Java AST/污点分析、硬件 VM 隔离、真实项目 AI 补丁与更多生产验证未实现；这不是完整 R1—R6，也不是 MVP。实际验证与限制以进度记录为准。**

**开发交接入口：[当前进度与维护记录](docs/development-progress.md)。** 每个切片在该文档记录已实现/已验证/待完成、准确测试结果和下一步，运行时状态不以 Markdown 作为权威源。剩余功能、验收标准与里程碑见 [剩余功能改进计划](docs/improvement-plan.md)。

## 新开发主线

输入源码与依赖 → 统一 Agent 分析与挖掘 → 获取漏洞证据 → 独立副本生成补丁 → 隔离验证 → 导出报告与补丁。

首版优先 Java / Maven / Spring；先做一个可运行的分析—验证—修复闭环，再扩大覆盖。分析快照只读，修复副本可写，用户原仓库不被自动覆盖。现有治理与事务代码按需复用，不再以继续建设多 Worker/跨角色调度为主线。

## 本地源码快照与只读项目工具（R1 首片）

不需要数据库或模型密钥，不调用网络和外部构建程序。仅导入明确许可的本地目录；原项目不作为写入或测试目录。当前仅支持 Windows 本地 NTFS，以及具备 `openat2`/`statx` Mount ID 的 Linux 5.8+ 允许文件系统；链接、junction/reparse point、网络/FUSE 和无法安全判断的配置拒绝使用。快照是应用层只读基线，非 OS 级不可变；调用者应在快照目录之外可信保存导入返回的 `snapshot_hash`。默认排除敏感路径不等于源码已充分脱敏，**读取许可不包含模型外发许可**。

以下在 Git Bash 中导入合成样本到独占的新临时目录；不会执行其中的 Java/Maven 代码。目录已存在会拒绝覆盖。

```bash
# [01] 新建受控父目录；snapshot 本身由导入器独占创建。
TRIDENT_DEMO_PARENT="$(mktemp -d)"
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident project import --source 'E:/pentest agent/TRIDENT/tests/fixtures/java-maven' --snapshot "$TRIDENT_DEMO_PARENT/snapshot" > "$TRIDENT_DEMO_PARENT/import.json"

# [02] 摘要记录在 snapshot 之外，后续查询显式携带。
TRIDENT_SNAPSHOT_HASH="$(python -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["snapshot_hash"])' "$TRIDENT_DEMO_PARENT/import.json")"
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident project inspect --snapshot "$TRIDENT_DEMO_PARENT/snapshot" --snapshot-hash "$TRIDENT_SNAPSHOT_HASH"
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident project list --snapshot "$TRIDENT_DEMO_PARENT/snapshot" --snapshot-hash "$TRIDENT_SNAPSHOT_HASH" --limit 20

# [03] 字面量检索返回路径/行号/内容摘要；从 list 结果选择 --path 后可按行读取。
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident project search --snapshot "$TRIDENT_DEMO_PARENT/snapshot" --snapshot-hash "$TRIDENT_SNAPSHOT_HASH" --query 'SELECT' --limit 20
```

`project read` 支持 `--path`、`--start-line`、`--limit`；`list/read/search` 支持 `--cursor`，继续分页时保持同一查询与 limit，不能同时设置 `--start-line`。默认每页 50 项、最多 200 项；资源、编码、排除项和截断通过 `partial`/限制原因明确报告。结构识别不等于 Maven 有效依赖树或漏洞确认。

安全边界、支持限制见 [快照契约](docs/snapshot-contract.md)；合成正例、负例、未知项和后续验证设计见 [样本验收契约](docs/java-fixture-acceptance.md)。真实外部模型验收仍待明确外发与服务调用许可；工具 CLI 或本机脚本化模型服务不能作为真实自主分析的证明。

## R2 首片：离线 Maven 声明与固定公告匹配

`sca inspect` 复用已导入的只读快照，不需要数据库或模型密钥，不执行 Maven/Gradle/Java、不访问仓库。它解析本地 Maven POM 声明（父 POM、属性覆盖、dependencyManagement、直接依赖）以及常见 Gradle Groovy/Kotlin 依赖声明，并用调用者显式指定的固定公告 JSON 做精确版本或调用者声明区间/别名匹配。`version_matched` 只是候选风险，不是 RCE 或可达性确认；没有在线依赖解析、制品 Hash、AST/污点或运行时验证。`sca tree` 只输出快照内模块边与同快照 GAV 匹配，外部依赖是叶子。

```bash
# [01] 复用 project import 生成的快照；摘要仍保存在快照之外。
TRIDENT_PARENT="$(mktemp -d)"
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident project import --source 'E:/pentest agent/TRIDENT/tests/fixtures/java-maven' --snapshot "$TRIDENT_PARENT/snapshot" > "$TRIDENT_PARENT/import.json"
TRIDENT_HASH="$(python -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["snapshot_hash"])' "$TRIDENT_PARENT/import.json")"
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident sca inspect --snapshot "$TRIDENT_PARENT/snapshot" --snapshot-hash "$TRIDENT_HASH" --advisories 'E:/pentest agent/TRIDENT/tests/fixtures/java-maven/advisories/CVE-2022-42889.json'
```

结果与限制见 [SCA 契约](docs/sca-contract.md)；真实 CLI 验收为 `python scripts/test-sca.py`、`python scripts/test-intel.py`、`python scripts/test-resolve.py`、`python scripts/test-gradle-resolve.py` 与 `python scripts/test-upgrade.py`。

### 有效依赖树（需显式批准）

`trident sca resolve --snapshot ... --snapshot-hash ... --tool maven --approve-maven` 在快照的临时副本上执行 Maven `dependency:tree`；`--tool gradle --approve-gradle` 执行 Gradle `dependencies`，优先 `runtimeClasspath`、其次 `compileClasspath`。两者默认离线；只有显式 `--approve-network` 才允许下载。输出模块、直接/传递依赖、scope、冲突省略、版本升级/约束/FAILED 注记，并把 `runtime_status` 固定为 `not_run`。这是构建解析结果，不是 classpath 加载证明，也不等于漏洞可达；POM 与 build.gradle 都是不可信输入，仍应在一次性环境中执行。Gradle 需要本机可执行文件（`--gradle` 绝对路径或 PATH），可用 `--gradle-user-home` 与 `--gradle-init-script` 指向离线仓库。

### 依赖升级验证（需显式批准）

`trident sca upgrade ... --module . --dependency org.apache.commons:commons-text --to 1.10.0 --out upgrade.patch` 从快照定位版本声明（Maven 属性、直接版本或 dependencyManagement；Gradle 字符串/map），生成只改版本的最小 diff。提供 `--workspace` 时，先在未修改副本跑基线，再应用补丁跑同一 validation profile，输出 `baseline` 与 `verification`；目标版本由调用者指定，不自动选版，不验证制品哈希、传递升级或生产兼容性。Gradle 声明目前只生成补丁，验证 profile 仍为 Maven/javac/JUnit。

### SBOM：CycloneDX 1.5

`trident sca sbom` 将同一份声明级报告转换为确定性的 CycloneDX 1.5 JSON；序列号由快照 SHA-256 派生，不写时间戳，同一输入字节级一致。组件按唯一 Maven GAV 去重，公告候选写为 `in_triage`、严重度 `unknown`、`affects` 指向声明组件；`runtime_status=not_run` 与“无传递树/无制品哈希/无可达性”的限制写入 metadata properties。官方 Schema 固定副本位于 `tests/schemas/`，由 Python `jsonschema` 校验；SBOM 不是有效依赖树，也不能证明漏洞可利用。

```bash
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident sca sbom --snapshot "$TRIDENT_PARENT/snapshot" --snapshot-hash "$TRIDENT_HASH" --advisories 'E:/pentest agent/TRIDENT/tests/fixtures/java-maven/advisories/CVE-2022-42889.json'
```

Web 控制台依赖页提供“导出 SBOM”，对应 `GET /api/sbom`。契约见 [SBOM 契约](docs/sbom-contract.md)；真实 CLI + 官方 Schema 验收为 `python scripts/test-sbom.py`。

## R2 入口清单：Spring MVC / JAX-RS / Servlet 注解级

`audit endpoints` 复用同一只读快照，不编译或运行 Java。它用有界词法扫描识别 Spring MVC `Controller/RestController`、`RequestMapping` 家族，JAX-RS `@Path`/`@GET` 家族与参数绑定，以及 `@WebServlet` 的 `doGet/doPost` 入口；输出路径、符号、文件 SHA-256、起止行、`fixture:*` 锚点与覆盖限制。注释和字符串中的注解不会误匹配；非字面量路径、text block 文件和嵌套类显式标记 unresolved/partial；Servlet 参数未绑定 `HttpServletRequest.getParameter`，因此不带请求 source。**这是入口清单，不是 Java AST、调用图或污点分析；路由声明不等于部署或可利用。**

```bash
# [01] 沿用上一节导入的快照与摘要；不重新读取源目录。
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident audit endpoints --snapshot "$TRIDENT_PARENT/snapshot" --snapshot-hash "$TRIDENT_HASH"
```

契约见 [入口清单契约](docs/audit-contract.md)；真实 CLI 验收为 `python scripts/test-audit.py`。

## R4 权限/越权控制清单

`audit authz` 在同一边界内识别 Spring Security 方法/类注解（`@PreAuthorize`、`@Secured`、`@RolesAllowed`、`@PermitAll` 等）、XML `<mvc:interceptor>`、`<security:intercept-url>`、`web.xml` filter/security-constraint、Java `WebMvcConfigurer.addInterceptors`、`HttpSecurity` matcher 链和 `@WebFilter`，并按 Ant 风格路径为每个入口给出 `protected` / `public` / `unprotected` / `unknown`。`SecurityFilterChain` 按 `@Order` 与声明顺序建模，`securityMatcher` 限定链作用域，链内首条匹配规则生效；`@PreAuthorize` 支持常量布尔与 `hasRole/hasAnyRole/hasAuthority/hasAnyAuthority/isAuthenticated/isAnonymous` 的受限 SpEL，复杂表达式为 `unknown`；`server.servlet.context-path` 只写入 `external_path`。无任何已识别控制的入口输出 `inconclusive` 的 CWE-306 finding；手工 session 检查只记为 `unknown`。**这是有界静态控制清单，不执行 `addFilterBefore/After` 或过滤器体，不评估自定义 AOP、外部网关/反向代理或运行时行为；`unprotected` 不等于已证明可未授权访问。**

```bash
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident audit authz --snapshot "$TRIDENT_PARENT/snapshot" --snapshot-hash "$TRIDENT_HASH"
```

契约见 [入口清单契约](docs/audit-contract.md)；验收为 `python scripts/test-authz.py`。

## R2 数据流：JDBC SQL 与非 SQL 注入类别 Source/Sink

`audit dataflow` 复用入口清单，对请求绑定参数做有界方法内/跨方法追踪，识别 JDBC SQL sink（`Statement.execute*`、`prepareStatement`、`JdbcTemplate`/`NamedParameterJdbcTemplate` 查询更新家族、JPA/Hibernate `createQuery`/`createNativeQuery`）以及常量结构 `PreparedStatement` + 值绑定的负例；同一引擎还识别命令注入（`Runtime.exec`、`ProcessBuilder` command→start）、SSRF（`URL.openConnection/openStream`、`RestTemplate`、`HttpRequest.uri`、`WebClient.uri`）、路径遍历（文件流构造器、`Files.*`）、模板注入（SpEL `parseExpression`、模板引擎 `process`）、XSS（响应 `write`/`print`/`println`/`append`）、反序列化（`new ObjectInputStream`/`new XMLDecoder`、污点流 `readObject`、链式 `new ObjectInputStream(...).readObject()`）、XXE（`DocumentBuilder`/`SAXParser`/`SAXReader.parse`、`SAXReader`/`XMLReader.read`、`XMLInputFactory` 流/事件读取、`Unmarshaller`、`Transformer`、`SAXBuilder`、`Digester`、`DocumentHelper.parseText`）、LDAP 注入（`InitialDirContext`/`LdapTemplate` 的 `search`/`lookup`/`authenticate`）与上传（`MultipartFile.transferTo`、`Part.write`）。SQL 构造覆盖字符串 `+`、`StringBuilder`/`StringBuffer.append` + `toString()`、字面量 `String.format` 和构造器/静态工厂结果；跨方法还跟踪 resolved 方法的 tainted 返回值、builder 参数突变、接口/继承分派、重载选择（含 lambda、泛型方法、可变参数）、按类层级的字段污点和 import 感知的简单类型解析；容器传播覆盖 `List`/`Set`/`Map`/`Queue` 的 `add`/`put` 写入与 `get`/`values`/`keySet`/`entrySet`/`iterator` 读取、数组元素下标读写、字段容器写入与 `clear`，字面量下标 `set/add(index, value)`/`get(index)`/`remove(index)` 按元素跟踪，非字面量下标回退到容器聚合；resolved 方法可突变调用方集合/数组参数；聚合 `remove` 采用保守语义（保留容器污点并标记限制），不假装未知下标的元素级精度。响应体 `String`/`CharSequence` 返回按入口 `produces` 判定：`text/html`/`application/xhtml+xml` 静态确认 XSS，明确非 HTML 类型记录为 `refuted`，缺失/未解析仍为 `reflected_return` 边界；普通 `@Controller` 返回视图名不产生 XSS finding。仅常量 `append`、无转换符的 `format`、清洁返回值、常量命令/URL/路径/响应/反序列化流/XML/LDAP 或未触及的类别不产生 sink 证据；计算出的格式串、未知 builder 接收者、多实现分派、无法消解的重载、快照外父类型或未知 sink 接收者输出边界。每个参数始终有一个 SQL finding，其他类别仅在该参数观察到对应 sink/边界时附加 finding，均附 flow、文件 SHA、行号和 `fixture:*` 锚点。**这不是完整污点分析或运行时验证；动态/未解析边界和未观察到路径一律 inconclusive，不冒充安全。**

```bash
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident audit dataflow --snapshot "$TRIDENT_PARENT/snapshot" --snapshot-hash "$TRIDENT_HASH"
```

契约见 [数据流契约](docs/dataflow-contract.md)；真实 CLI 验收为 `python scripts/test-dataflow.py`。

## R2 证据模型：统一 Finding/Hypothesis

`audit findings` 在同一个只读快照上运行 SCA、入口清单和 JDBC 数据流，把结果规范化为统一的 finding、假设和证据：数据流 finding 携带入口 `route` 证据；SCA 精确版本命中的依赖产出 `vulnerable_dependency` finding，其“依赖可达入口”和“运行时可利用”假设显式保持 `unverified`。**静态状态与运行时状态分离：finding 的 `status` 只表示静态判断，`runtime_status` 恒为 `not_run`；关联不产生新的漏洞结论，也不把候选依赖或静态确认升级为运行时确认。**

```bash
# [01] 复用同一快照；公告目录可选，缺省时仍输出入口与数据流证据。
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident audit findings --snapshot "$TRIDENT_PARENT/snapshot" --snapshot-hash "$TRIDENT_HASH" --advisories 'E:/pentest agent/TRIDENT/tests/fixtures/java-maven/advisories/CVE-2022-42889.json'
```

契约见 [证据模型契约](docs/findings-contract.md)；真实 CLI 验收为 `python scripts/test-findings.py`。

## R2 CI 出口：SARIF 与有界可达性

`audit sarif` 将同一份统一 evidence 报告导出为确定性 SARIF 2.1.0；`static_confirmed` 映射为 `warning`、`inconclusive` 为 `note`、`refuted` 为 `none`，所有结果保留 `runtime_status=not_run`，不会因导出升级为运行时确认。

`audit reachability` 在类级 import/同包类型引用图上从入口做有界 BFS（深度/节点/边/路径上限），并用调用者显式提供的 `--package-map`（`group:artifact` → 包前缀）映射声明依赖。分类为 `reachable` / `unreachable` / `unknown`：`reachable` 附入口→中间类→依赖的路径证据（文件 SHA-256 + 行号）；`unreachable` 仅表示本快照有界图中无路径；缺少映射、模块无入口、版本未解析、反射或超限均为 `unknown`。**三条路径都不证明类加载或运行时利用**，`runtime_status` 保持 `not_run`。

```bash
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident audit sarif --snapshot "$TRIDENT_PARENT/snapshot" --snapshot-hash "$TRIDENT_HASH"
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident audit reachability --snapshot "$TRIDENT_PARENT/snapshot" --snapshot-hash "$TRIDENT_HASH" --package-map '/path/to/package-map.json'
```

真实 CLI 验收为 `python scripts/test-intel.py` 与 `python scripts/test-reachability.py`。

## R2 Java 语义模型：`audit java-model`

`audit java-model` 用纯 Go 解析受限 Java 子集，输出确定性语义模型：文件/类型/字段/方法（擦除后的 `pkg.Type#name(paramTypes)`）、常量与注解实参折叠，以及方法级调用图（局部变量/参数/字段/类型接收者、泛型擦除后的重载消歧、继承链与接口查找）。唯一具体实现记 `resolved/interface_dispatch`，多实现记 `ambiguous/ambiguous_dispatch`，反射只记边界。**不编译、不运行、不反编译 Java；不建模控制流、别名或跨方法污点，调用解析不等于漏洞可利用。**

```bash
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident audit java-model --snapshot "$TRIDENT_PARENT/snapshot" --snapshot-hash "$TRIDENT_HASH"
```

契约见 [入口清单契约](docs/audit-contract.md) §8；验收为 `python scripts/test-java-ast.py`。

## R2 只读 Web 分析控制台

`trident web` 为单个已 pin 的本地快照提供暗色分析控制台，视图包括概览、安全发现（含证据抽屉）、HTTP 入口、依赖与公告、源码浏览/检索和边界说明。它复用既有快照与四个分析包，不新增分析语义，不导入源码、不执行 Java/Maven、不调用模型或访问网络，也不提供 Agent 运行/审批/执行控制 API。控制台仅监听 loopback，使用启动时打印的一次性访问令牌；除登录页外所有 API 都要求令牌与 `X-Trident-Request: console` 头，响应启用 CSP、`nosniff`、`DENY` 与 `no-store`。

以下命令不连接数据库、不调用模型；令牌只打印在终端，不要写入共享日志：

```bash
# [01] 复用 project import 生成的快照与外部保存的摘要。
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident web --snapshot "$TRIDENT_PARENT/snapshot" --snapshot-hash "$TRIDENT_HASH" --advisories 'E:/pentest agent/TRIDENT/tests/fixtures/java-maven/advisories/CVE-2022-42889.json' --addr 127.0.0.1:8787

# [02] 浏览器打开终端打印的地址，粘贴同一终端打印的访问令牌；Ctrl+C 停止，不写入快照。
```

首次请求任一分析 API 时，SCA、入口清单、有界数据流和统一证据模型各运行一次并缓存；失败会作为终态缓存并返回 `analysis_failed`，不会逐请求重试。页面上的 `runtime_status` 恒为 `not_run`，静态确认、`inconclusive`、`refuted` 与 CLI 含义一致。契约见 [Web 控制台契约](docs/web-console-contract.md)；真实 CLI 验收为 `python scripts/test-web.py`。

## 统一 Agent Core（R1 本地协议验收）

核心仍为 Go。新增一个有持久检查点的只读决策循环、九个只读工具、OpenAI 官方 Go SDK Chat Completions 适配，以及 Run 所有者权限、CAS、驱动互斥、预算和保守恢复。九个工具为快照四工具（`inspect_project/list_files/read_source/search_source`）和五个分析工具（`inspect_dependencies/match_advisories/query_endpoints/trace_dataflow/list_findings`）；分析工具只返回有界摘要，并把实际读取的快照行写入证据账本后才能被最终答案引用。`agent run --advisories <file>` 可绑定本地固定公告目录。模型/端点显式配置，禁隐式重试、代理和重定向；密钥只从调用者指定环境变量读取，不写入 Run。兼容服务仅承诺通过本片 Chat Completions 契约，不代表支持所有供应商扩展或 Responses。

**风险提示：`agent run --approve-egress` 是对整份快照、目标和后续对话向精确端点/模型外发的显式授权，可能产生费用；本轮没有授权或执行真实外部模型调用。默认没有该许可会拒绝。** 不要将普通项目读取许可当作外发许可。

本机专属测试库已获授权时，可执行以下验收；会显式迁移并增加合成记录，不清库、不重置身份：

```bash
# [01] Run/身份/预算/恢复及历史 PostgreSQL 集成回归。
python 'E:/pentest agent/TRIDENT/scripts/test-local.py'

# [02] 构建真实 Go CLI，使用 127.0.0.1 脚本化服务验证工具闭环和错误证据拒绝。
# 该服务不是真实 LLM；脚本内部只读取本机测试凭据，不输出或发送凭据。
python 'E:/pentest agent/TRIDENT/scripts/test-agent.py'
```

`agent run/status/steps/resume` 使用已有 `TRIDENT_DATABASE_URL` 与 `TRIDENT_TOKEN`；调用模型还要求指定的密钥环境变量（默认 `TRIDENT_MODEL_API_KEY`）。本片没有设置真实模型默认值，也不会继承当前 Claude/OpenAI 会话凭据。`status --id` 与 `steps --id --after --limit` 不调用模型；`resume --acknowledge-unknown` 明确承认旧请求可能已计费并确认旧驱动器停止，不退款、不自动重发。拒绝/截断暂停不通过恢复偷偷重试，需重新审查后创建新 Run。检查点压缩按工具类型保留不同预览长度，并附带原始 JSON 的 `total/offset/limit/partial/counts` 有界摘要；`agent export --id --out` 只读导出 Run 与全部 Step（默认 30 天保留窗口，超期需 `--include-expired`），不删除 append-only 记录。

参见 [Agent 契约](docs/agent-contract.md) 与 [当前进度记录](docs/development-progress.md)。回答标为未验证推断，引用校验不等于漏洞成立。本轮将检查点版本升为 v2；v1 检查点不恢复。

## R3 补丁生成、隔离验证、修复循环与沙箱

`trident patch propose` 在显式 `--approve-egress` 下调用模型，基于 finding 证据或指定源码路径生成一个统一 diff；补丁先在只包含被修改文件的临时副本上做精确上下文验证，并受可选 `--policy` remediation policy（文件数、变更行数、禁止新增 API）约束，通过后才写到快照之外的新文件。`trident patch verify` 将已 pin 的快照复制到新的可写工作区，应用调用者或模型生成的 diff（支持新文件、UTF-8 BOM 与 git 多文件补丁，但不支持覆盖/删除/重命名），在离线 Maven、`maven-compile`、`maven-test`、javac 或 JUnit profile 下编译并运行，最后重新校验原快照未被修改；`maven-compile` 仅编译，`maven-test` 执行 Surefire 测试并解析 XML，均不需要 main class。JUnit profile 支持多测试类、Surefire 风格 XML 报告和可选 JaCoCo agent/XML 覆盖率，并可在 process、Docker 或 gVisor `runsc` 沙箱中运行。`trident patch repair` 在最多 5 轮内重复 propose→隔离 verify，每轮使用新工作区；模型失败不重试，重复补丁停止。必须显式 `--approve-execution`；Docker 提供固定 digest 镜像、`--network none`、`--cap-drop ALL` 与资源限额，gVisor 提供用户态内核但不是硬件 VM。AI 补丁必须人工复核；Maven 离线模式要求本机或只读挂载的 `.m2` 已缓存插件与依赖。报告附带启发式 `quality` 分数，它不是安全或正确性证明。

```bash
# [01] AI 生成补丁（合成样本或已获授权的真实项目；真实项目外发需逐次授权）。
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident patch propose \
  --snapshot "$TRIDENT_PARENT/snapshot" --snapshot-hash "$TRIDENT_HASH" \
  --path 'src/main/java/demo/Vulnerable.java' --goal 'Use a parameter placeholder instead of string concatenation.' \
  --out "$TRIDENT_PARENT/ai.patch" \
  --endpoint 'https://api.deepseek.com/v1' --model 'deepseek-flash' --approve-egress

# [02] process 或 Docker 沙箱验证。
go -C 'E:/pentest agent/TRIDENT' run ./cmd/trident patch verify \
  --snapshot "$TRIDENT_PARENT/snapshot" --snapshot-hash "$TRIDENT_HASH" \
  --workspace "$TRIDENT_PARENT/workspace" --patch "$TRIDENT_PARENT/ai.patch" \
  --profile maven --main-class demo.Main --approve-execution
```

报告以 `validation_passed`/`validation_failed`/`patch_failed` 等状态区分结果，`runtime_status=isolated_validation_only`，不把隔离副本结果升级为生产可利用性或修复上线证明。契约见 [R3 补丁契约](docs/patch-contract.md)；真实 Java/Maven 验收为 `python scripts/test-patch.py`，AI 补丁 + Docker 验收为 `python scripts/test-patch-ai.py`。

### 运行时 HTTP 验证（显式目标授权）

`trident runtime http --plan <plan.json> --approve-target <origin> [--allow-loopback]` 按调用者提供的请求计划顺序执行 HTTP 断言，支持每个 session 的 cookie 复用、状态码、`Location` 前缀、响应体包含/不包含与响应头包含。默认不跟随重定向、不并发、不使用代理、响应体上限 64 KiB；`form`/`json`/`header` 值不会写入报告。只有显式 `--approve-target` 的 origin 会被访问，loopback 还需 `--allow-loopback`。输出 `runtime_status=observed`，但只证明这些请求的实际响应，不构成漏洞利用、数据泄露或授权绕过的完整证明，也不自动修改静态 finding 的 `runtime_status`。契约见 [运行时验证契约](docs/runtime-contract.md)；本机验收为 `python scripts/test-runtime.py`。

### 发布、CI 与部署

- 构建、迁移、备份恢复、凭据分权与版本矩阵：[部署指南](docs/deployment.md)。
- 离线 CI 模板：[.github/workflows/ci.yml](.github/workflows/ci.yml)；本地等价门禁：`powershell -File scripts/verify-offline.ps1`。
- 最小权限角色模板：[db/roles.example.sql](db/roles.example.sql)（示例，未在独立生产库执行）。
- 合成样本基准：[基准报告](docs/benchmark-report.md)；只测 wall-clock，不含数据库、模型、Java/Maven。

## 已实现的历史基础（P0.1 / P0.2）

- Go + PostgreSQL，显式、按文件校验和验证的前向迁移；普通启动不建库、不自动迁移。
- 本地可信 CLI 管理员 bootstrap、随机凭据摘要、每事务身份检查及角色限制。
- 人工授权证明确认、合同激活/撤销、不可变 Scope、授权事件摘要链。
- Task / Asset / Intent / Mission / Fact，资产默认待审核，同 Task 复合外键、图类型与防环约束。
- Mission 多维预算原子预留、计量、幂等结算；资源池容量、租约与单调 Fencing Token。
- 失效 Worker 权威写回拒绝、过期执行阻断、人工确认后重试和可信对账。
- Activity + Outbox 同事务、聚合顺序、领取代数、死信、通知重放。
- 任务级成员授权与撤销；Worker/Scheduler/Reconciler 全局角色不足以访问其他任务，Outbox 领取与确认同样受任务和真实主体限制。
- Scope 新版本提交、证明绑定、摘要/旧基线校验、合同级原子切换；旧租约及未消费审批失效，资产重新待审核。
- 不可变离线工具请求、规范参数/URL/摘要、人工审批和原子一次消费；准入、步骤记账与 Outbox 同事务。
- 启动 Schema 只读门禁；已有 P0.1 数据可前向升级，旧 Worker 默认拒绝，历史预算和快照保留。
- CLI 离线审批闭环和真实 PostgreSQL 集成测试；不提供 HTTP 执行控制 API（R2 只读分析控制台不是执行平面），不访问测试目标。

## 本机复测（Git Bash）

环境：Go >= 1.26.3、Docker Desktop（Linux 容器）、Python >= 3.10。

**注意：以下命令只适用于独立本地测试库，会创建测试记录，不要连接生产数据库。不会自动清空已有数据。**

```bash
# [01] 已配置 .env 时直接启动；随机密码不要提交或发送给他人。
docker compose --project-directory 'E:/pentest agent/TRIDENT' -f 'E:/pentest agent/TRIDENT/compose.yaml' up -d --wait postgres

# [02] 单测、静态检查。
go -C 'E:/pentest agent/TRIDENT' test ./...
go -C 'E:/pentest agent/TRIDENT' vet ./...

# [02a] 无数据库的真实 CLI 端到端验收；仅复制合成样本至临时目录。
python 'E:/pentest agent/TRIDENT/scripts/test-project.py'

# [02b] 无数据库的声明级 Maven/固定公告匹配验收；不执行 Maven/Java。
python 'E:/pentest agent/TRIDENT/scripts/test-sca.py'

# [02c] 无数据库的 Spring MVC 入口清单验收；不编译/执行 Java。
python 'E:/pentest agent/TRIDENT/scripts/test-audit.py'

# [02d] 无数据库的 JDBC SQL Source/Sink 静态证据验收；不编译/执行 Java。
python 'E:/pentest agent/TRIDENT/scripts/test-dataflow.py'

# [02e] 无数据库的统一 Finding/Hypothesis 证据关联验收；不执行 Java/模型。
python 'E:/pentest agent/TRIDENT/scripts/test-findings.py'

# [02f] 无数据库的只读 Web 控制台验收；loopback 服务、不执行 Java/模型。
python 'E:/pentest agent/TRIDENT/scripts/test-web.py'

# [02g] SBOM 确定性与官方 CycloneDX 1.5 Schema 校验。
python 'E:/pentest agent/TRIDENT/scripts/test-sbom.py'

# [02h] R3 隔离副本、统一 diff、离线 Maven/javac/JUnit 基线失败/补丁通过验收。
python 'E:/pentest agent/TRIDENT/scripts/test-patch.py'

# [02i] AI 补丁生成 + process/Docker 沙箱验证；loopback 模型，不调用真实 LLM。
python 'E:/pentest agent/TRIDENT/scripts/test-patch-ai.py'

# [02j] 权限/越权控制清单；不执行 Java/模型。
python 'E:/pentest agent/TRIDENT/scripts/test-authz.py'

# [02k] 依赖升级验证；离线 Maven 基线与升级后测试。
python 'E:/pentest agent/TRIDENT/scripts/test-upgrade.py'

# [02l] Gradle 有效依赖树；需 TRIDENT_GRADLE 或 PATH 中的 Gradle。
python 'E:/pentest agent/TRIDENT/scripts/test-gradle-resolve.py'

# [02m] 运行时 HTTP 验证；loopback 服务、不访问外部网络。
python 'E:/pentest agent/TRIDENT/scripts/test-runtime.py'

# [03] 显式迁移、真实数据库测试、离线演示、只读迁移检查。
python 'E:/pentest agent/TRIDENT/scripts/test-local.py'

# [04] 本机 Windows C 工具链不兼容时，使用已实测通过的 Linux 竞态验收。
python 'E:/pentest agent/TRIDENT/scripts/test-linux.py'

# [05] 仅在 Windows C 工具链兼容时，可原生执行。
python 'E:/pentest agent/TRIDENT/scripts/test-local.py' --race
```

当前开发环境 `.env` 已生成随机数据库密码，`secrets/test-admin.json` 保存专属测试库管理员凭据，均已忽略，不在文档输出。首次在新环境使用时，复制 `.env.example` 为 `.env` 并将示例密码替换为随机值。测试脚本仅在新库首次显式 bootstrap，不重置已有身份；已有库与本地凭据不匹配时应排查配置，不能自动删库。

数据库仅绑定 **127.0.0.1:55432**，Compose 项目名 `trident-p0`，独立容器与数据卷。测试库目前使用管理员数据库账号供迁移和故障注入使用，不属于生产最小权限部署。

若只需停止专属测试容器并保留数据：

```bash
docker compose --project-directory 'E:/pentest agent/TRIDENT' -f 'E:/pentest agent/TRIDENT/compose.yaml' stop postgres
```

## 工程入口

| 路径 | 内容 |
|---|---|
| `cmd/trident/main.go`、`project.go`、`sca.go`、`audit.go`、`dataflow.go`、`findings.go`、`reach.go`、`java_model.go`、`web.go`、`patch.go`、`runtime.go`、`agent.go` | version / project / sca / audit / web / patch / runtime / agent / migrate / check / bootstrap / demo-offline |
| `internal/sca/` | 离线 Maven/Gradle 声明解析、属性/父 POM/依赖管理、公告精确/区间/别名匹配与模块树；Maven/Gradle 有效依赖树（临时副本、默认离线、显式按工具批准） |
| `internal/audit/`、`internal/authz/`、`internal/dataflow/` | Spring MVC/JAX-RS/Servlet 注解级入口清单；权限/越权控制清单；10 类 Source/Sink 有界数据流 |
| `internal/httpverify/` | 显式 origin 授权的运行时 HTTP 断言、cookie session 与有界证据 |
| `internal/findings/`、`internal/sarif/`、`internal/reach/`、`internal/javaast/` | 统一 finding/假设/证据模型；SARIF 2.1.0；类级有界入口可达性；受限 Java 语义模型与方法级调用图 |
| `internal/webui/` | 只读 Web 控制台：令牌鉴权、JSON API、嵌入的暗色前端资源 |
| `internal/sbom/` | 确定性 CycloneDX 1.5 序列化与 metadata/component/vulnerability 映射 |
| `internal/r3/` | 快照工作区复制、统一 diff 应用、策略约束、离线 Maven/javac/JUnit（XML/JaCoCo）验证、质量评分、多轮修复与 Docker/gVisor |
| `docs/sca-contract.md`、`docs/audit-contract.md`、`docs/dataflow-contract.md`、`docs/findings-contract.md`、`docs/web-console-contract.md`、`docs/sbom-contract.md`、`docs/patch-contract.md`、`docs/runtime-contract.md`、`docs/deployment.md`、`docs/benchmark-report.md`、`docs/release-checklist.md` | SCA、入口清单、数据流、证据模型、Web、SBOM、R3、运行时验证、部署、基准与发布检查表 |
| `scripts/test-sca.py`、`test-audit.py`、`test-authz.py`、`test-dataflow.py`、`test-findings.py`、`test-web.py`、`test-sbom.py`、`test-intel.py`、`test-upgrade.py`、`test-runtime.py`、`test-patch.py`、`test-artifact-hash.py`、`test-reachability.py`、`test-java-ast.py`、`verify-offline.ps1`、`benchmark.py` | 真实 CLI 与官方 Schema/真实 Java/Maven/运行时验收、离线门禁和可复现基准 |
| `internal/agent/`、`internal/tools/` | 只读主循环、受控工具与检查点/证据 |
| `internal/model/openai/` | 官方 Go SDK Chat Completions 薄适配，无隐式外发 |
| `internal/store/agent_runs*.go` | Run 所有者权限、CAS、预算与恢复 |
| `docs/development-progress.md` | 开发/验收/遗留门禁与维护接续入口 |
| `internal/project/` | SourceSnapshot、路径边界、完整性与四个只读工具 |
| `tests/fixtures/` | 合成 Java/Maven 样本、固定情报与预期断言 |
| `docs/snapshot-contract.md` | 快照与工具信任边界，不代表完整 R1 |
| `db/migrate.go` | 固定连接迁移锁、事务与历史校验 |
| `db/migrations/` | 前向 Schema 迁移，已应用文件不可改写 |
| `internal/domain/` | Scope 规范化、URL 登记检查、状态矩阵 |
| `internal/store/` | 认证、授权、Mission、预算、租约、Outbox、恢复 |
| `tests/integration/` | 真实 PostgreSQL 并发、完整性、故障测试 |
| `scripts/test-local.py` | 本地独立测试库复测入口 |
| `docs/p0-contracts.md` | 信任边界、事务约束与待完成门禁 |

## 旧路线尚未完成项（历史参考，不是新开发顺序）

1. 平台身份生命周期、认证凭据过期/轮换、合同级委托和更细粒度权限；生产数据库迁移/运行账号分权。当前人工 admin 为部署级信任根，不是组织级多租户隔离。
2. 授权事件链独立校验与外部锚定；真实执行身份撤销、进程终止和出口连接关闭须后续 Runtime 验证。
3. AuditTask / Endpoint / Defect / DependencyFinding、Evidence / Finding 的完整领域模型及保留策略。
4. 将已完成的离线请求/审批存储协议接入真正 Policy Gateway 的工作留在 P1；当前 receipt 绝不是可重用执行票据。
5. 显式期望版本的完整状态迁移 API、任务暂停/停止与模型覆盖扩展。
6. 失效结果隔离归档、账务不确定结果与崩溃/断连的完整故障矩阵。
7. Outbox 消费端持久幂等、失败迁移审计、完整备份恢复验收。

以上保留为历史缺口清单，不再要求按旧 P0 阶段全部建设后才实现新 Agent。安全边界在相应能力开放前完成：只读分析先落实路径与外发控制，修复先落实独立副本，测试执行先落实隔离和审批。**当前仍没有可对真实目标执行网络测试的工具能力。** 已交付项目快照、只读/分析工具、统一 Agent Core 的本地协议闭环、只读 Web 控制台、CycloneDX SBOM，以及隔离副本上的补丁编译/运行首片；后续仍需经明确许可的真实模型验收、JUnit/容器沙箱、AI 补丁生成与生产级运行时验证，具体以新执行方案和当前进度记录为准。

## 上游与许可

当前核心代码独立编写，只借鉴状态机、CAS 和事务等机制，未复制三个上游项目源码、SQL 或知识库。未替产品选择最终开源/商业许可；若后续复用上游代码，必须先核对并遵守对应许可。
