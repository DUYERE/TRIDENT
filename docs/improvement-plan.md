# TRIDENT 剩余功能改进计划

> 本文件把当前已知未完善项转为可验收的改进项。它是工程计划，不是生产就绪声明，也不改变
> [统一安全 Agent 执行方案 v2.0](TRIDENT_统一安全Agent执行方案_v2.0.md) 的授权边界。
> 现状事实以 [开发进度](development-progress.md) 与 [发布检查表](release-checklist.md) 为准；
> 本文件只描述“接下来做什么、做到什么程度算完成”。
>
> 实施状态（2026-11-14）：M1 的 P0-1 制品哈希与 P0-2 有界可达性已实现并通过
> `scripts/test-artifact-hash.py`、`scripts/test-reachability.py` 验收；M2 的 P0-3 第一片
> （受限 Java 语义模型 `audit java-model`、方法级调用图、v13 coverage 接入）已实现并通过
> `scripts/test-java-ast.py`、`go test ./internal/javaast` 验收，AST 尚未接入 sink/source 匹配；
> P0-4 权限链语义（`SecurityFilterChain` 顺序与 `securityMatcher` 作用域、受限方法注解 SpEL、
> context-path 外部路径）已实现并通过 `scripts/test-authz.py` 与 `go test ./internal/authz` 验收；
> P1-1 运行时角色矩阵与 CSRF（`roles`/`matrix`、`${ENV:NAME}` 凭据占位符、有界 token 提取与注入）
> 已实现并通过 `scripts/test-runtime.py` 与 `go test ./internal/httpverify` 验收；P1-2 静态—运行时关联
> （`runtime correlate` 三态关联、只读输入、独立报告）已实现并通过 `go test ./internal/correlate` 与
> `scripts/test-runtime.py` 验收；P1-3 回滚计划、质量评分版本、多模块选择与 `gradle-test` 验证 profile
> 已实现并通过 `go test ./internal/r3` 与 `scripts/test-patch.py` 验收（Gradle 使用桩工具链，真实 Gradle
> 构建未验证）；P1-4 派生索引缓存与相对基线性能门槛已实现并通过 `go test ./internal/cache`、
> `scripts/test-cache.py` 与 `scripts/benchmark.py --baseline` 验收；P2-2 Web 控制台多用户令牌文件
> （SHA-256 哈希 + mtime 热重载）、JSONL 审计访问日志、确定性 HTML 导出与 TLS 反代部署说明已实现
> 并通过 `go test ./internal/webui ./cmd/trident` 与 `scripts/test-web.py` 第二阶段验收；P2-3 本地部分
> （`/healthz` 探活、`/api/metrics` 只读计数器、Prometheus 告警规则模板文档）已实现并通过
> `go test ./internal/webui` 与 `scripts/test-web.py` 验收，生产备份演练/RTO-RPO 与真实监控系统
> 联调仍待真实生产设施；P3 可选增强中的 SARIF 规则分类细化与 GitHub code scanning 规则映射已实现
> （`security-severity`/`precision`/`tags`/确定性 `partialFingerprints`，见 findings 契约 2026-11-14 扩展）
> 并通过 `go test ./internal/sarif` 验收，SARIF 已由 CI 上传 GitHub code scanning（run 43585400725）；
> P2-1 CI 门禁已在真实 runner 验证：`offline` 与 `db-governance` job 全绿（run 43585245302、
> 43585400725），故意红灯探针可复现失败（run 43585523523，revert 恢复），`release-artifacts` job
> 已提供待打 tag 演练——tag `v0.2.0-p0.2` 已推送并全绿（run 43587721384，release-artifacts 产物
> 成功）。P3 两项已实现：SARIF GitHub 映射与 CycloneDX VEX 分析状态（见上）；P2-3 生产设施项
> 大幅推进：控制台 `/metrics` Prometheus 抓取端点、真实 Prometheus/Alertmanager 容器联调
> （`scripts/test-monitoring.py` 四项 PASS）、624 MB 数据量级备份演练实测 RTO 9.8s 与 RPO 语义
> （`scripts/test-backup-scale.py`）、容量与成本估算模型（`docs/capacity-cost.md`）。
> 记录见 [开发进度](development-progress.md) 续十一至续二十三。其余项仍为计划。

## 1. 原则与约束

1. **不伪报**：任何新增能力必须给出可执行验收命令与退出结果；未验证的能力保持
   `pending`，不得写成“已支持”。
2. **静态与运行时分离**：静态 finding 的 `runtime_status` 保持 `not_run`；运行时结论只在
   独立报告中以 `observed` 呈现，不自动回写静态 finding。
3. **默认离线、显式批准**：新增能力默认不访问网络、不执行项目代码、不调用模型；需要时使用
   `--approve-*` 显式开关，并沿用现有 origin/快照 hash/费用上限约束。
4. **只读边界**：分析只读快照；补丁只写快照外的新文件与隔离副本；原仓库不被覆盖。
5. **契约先行**：每项能力先更新对应 `docs/*-contract.md` 的输入、输出、版本号与 limitation，
   再实现；输出保持确定性（无时间戳、稳定排序）。
6. **未知即未知**：无法解析的语法、框架配置或动态行为输出 `unknown`/`inconclusive` 与
   limitation，不用启发式猜测冒充结论。

## 2. 现状基线（计划输入）

| 能力 | 已实现 | 关键缺口 |
|---|---|---|
| 快照与只读工具 | 导入/校验/列表/读取/检索，路径与资源边界 | 无增量快照、无大仓库分片 |
| SCA | Maven/Gradle 声明、离线有效树、公告精确版本/声明区间、依赖升级补丁 | 无制品哈希、无在线校验、Gradle 语义子集 |
| 入口清单 | Spring MVC/JAX-RS/Servlet 注解级 | 无 AST、无路由拼接与部署前缀 |
| 数据流 | 9 类注入 + 集合/字段/返回值传播，词法有界 | 无完整调用图、无反射/动态代理/AOP/异步 |
| 权限 | 方法注解/拦截器/filter/Security matcher 链，Ant 匹配 | 无 filter-chain 顺序语义、无 context-path/网关 |
| 统一证据 | Finding/Hypothesis、SARIF 2.1.0、SBOM 1.5 | 依赖到入口为 import 级；无 VEX |
| 补丁闭环 | 调用者/AI 补丁、隔离副本、Maven/javac/JUnit/Docker/gVisor、质量评分、5 轮修复 | 无硬件 VM、Gradle 不跑验证、无回滚/冲突处理 |
| 运行时验证 | 显式 origin、cookie session、有界断言、64 KiB 响应、角色矩阵与 CSRF 注入 | 无浏览器渲染/验证码、不自动发现账号、不跟随重定向 |
| 平台 | CLI、只读 Web 控制台、PostgreSQL Run 存储、离线 CI 模板 | CI runner 未确认、无 TLS/多用户、无监控告警 |

## 3. 改进项清单

优先级定义：**P0 = 直接影响结论可信度；P1 = 影响自动化闭环；P2 = 生产运维与产品化；P3 = 可选生态**。
每项均包含实现要点、验收标准、涉及契约与明确非目标。

### P0-1 制品哈希与来源校验

- **目标**：把“依赖声明级”提升为“可核对制品级”，为 SCA/SBOM/补丁验证提供哈希证据。
- **实现要点**：
  - `internal/sca` 新增本地制品定位：Maven 本地仓库（`~/.m2/repository` 或显式 `--maven-repo`）、
    Gradle 缓存（`--gradle-user-home` 下 `modules-2`），只读取不下载。
  - 对每个已解析 GAV 计算 jar/pom 的 SHA-256 与字节数；输出
    `artifact_hashes: observed|partial|unavailable` 与逐项 `path`、`sha256`、`bytes`、
    `source=local_repository|caller_catalog|unavailable`。
  - 支持调用者提供固定哈希清单（JSON），做精确匹配；不匹配输出 `mismatch` 证据，不自动判定漏洞。
  - SBOM 组件 `hashes` 字段写入已观测哈希；未观测仍保留 limitation。
- **验收标准**：
  - 新增 fixture 本地仓库（离线 file 仓库）与 `scripts/test-artifact-hash.py`：命中、缺失、
    哈希不匹配三种结果可复现；快照与仓库字节不变；输出确定性。
  - 契约更新 `docs/sca-contract.md`、`docs/sbom-contract.md`；新增 limitation
    `artifact_hash_local_only`、`artifact_signature_not_verified`。
- **非目标**：不做在线下载、不做 GPG 签名验证、不保证本地仓库未被篡改。

### P0-2 依赖到入口的可达性（调用图轻量版）

- **目标**：把 SCA finding 的“依赖可达入口”假设从 import 级提升为有界调用证据。
- **实现要点**：
  - 扩展 `internal/reach`：建立类→方法→被调用类型的轻量索引（字段类型、方法参数/返回值、
    `new`/静态调用、注解引用），沿入口方法做有界 BFS（深度与节点数上限，超限标记 `partial`）。
  - 输出 `reachability: reachable|unreachable|unknown`，附路径证据（入口符号→中间类→依赖包），
    每条路径带文件 SHA-256 与行号。
  - `findings` 的 `dependency_reachable` 假设改为 `supported`/`unsupported`/`unverified`；
    仍不改变 `runtime_status=not_run`。
- **验收标准**：
  - 新 fixture：控制器经 service 使用漏洞依赖（应 `reachable`）、仅声明未引用（`unreachable`）、
    经反射调用（`unknown`）；`scripts/test-reachability.py` 断言三态与路径。
  - 契约更新 `docs/findings-contract.md`、`docs/sca-contract.md`；新增 limitation
    `reachability_bounded_call_graph`、`reflection_not_resolved`。
- **非目标**：不做完整类型解析、不解析依赖 jar 内部字节码调用图，不证明运行时加载。

### P0-3 Java 语义层（AST 与调用图）

- **目标**：用语法树替换部分词法规则，降低漏报与误报，为后续跨方法污点提供稳定基础。
- **实现要点**：
  - 决策门：先做“受限 Java 子集解析器”（纯 Go，无 cgo）：编译单元、类型/方法/字段声明、
    语句与表达式核心、注解、泛型擦除后的签名；不追求完整 JLS。
  - 建立符号表与调用图：方法解析（重载、继承、接口分派）、字段类型、常量折叠、注解属性。
  - `internal/dataflow` 以 AST 为准重写 sink/source 匹配，保留现有词法实现作为回退与对照
    （通过 `analysis_kind` 区分版本）。
  - 明确无法解析构造（文本块、复杂 lambda、匿名类、反射、动态代理、AOP、异步执行器）输出边界。
- **验收标准**：
  - 现有 `tests/fixtures/java-*` 全部回归，误报不增加；新旧引擎结果差异写入
    `docs/evidence/` 对照报告。
  - 新增 `scripts/test-java-ast.py`：语法错误文件、嵌套类、泛型重载、接口分派、注解常量五类断言。
  - 版本号提升（如 `source-sink-flow-v13`），contract 更新 `docs/dataflow-contract.md`、
    `docs/audit-contract.md`。
- **非目标**：不实现完整 Java 编译器、不做字节码分析、不引入需要网络/构建的解析依赖。

### P0-4 权限链语义与上下文（已实现，2026-11-14）

- **目标**：从“匹配到控制”提升为“按框架语义判断控制是否真正覆盖入口”。
- **已实现**：
  - `SecurityFilterChain` 按方法边界分组，`@Order`/`Ordered` 排链，`securityMatcher` 限定链作用域；
    链内规则保持声明顺序，首条命中生效，`permitAll`→`hasRole`→`anyRequest().authenticated()`
    的覆盖关系按源码顺序判定。`addFilterBefore/After` 记录到 `chains[].custom_filters` 但不执行。
  - `@EnableMethodSecurity`/`@EnableGlobalMethodSecurity` 记入 `coverage.method_security`；
    `@PreAuthorize` 支持常量布尔、`permitAll/denyAll`、`isAuthenticated()/isAnonymous()`、
    `hasRole/hasAnyRole/hasAuthority/hasAnyAuthority` 与 `&&/||/!`；`hasRole` 归一化为 `ROLE_`。
    复杂 SpEL 与 `@PostAuthorize/@PreFilter/@PostFilter` 记 `unknown`。
  - `server.servlet.context-path`（properties/yml）与 `web.xml` `context-param` 只写入
    `endpoints[].external_path`，不改变相对 context path 的匹配；冲突/非字面量标记
    `context_path_unresolved`。
  - 新 limitation：`filter_chain_order_bounded`、`filter_chain_rule_order_bounded`、
    `spel_subset_only`、`context_path_unknown`。
- **验收**：新 fixture `tests/fixtures/java-authz-chain`（`@Order(1)` + `securityMatcher`、
  默认链 `permitAll`、方法注解优先级、context-path 前缀）；`python scripts/test-authz.py`
  断言 2 条链、5 protected/3 public/1 unknown、`ROLE_ADMIN`、`external_path=/app/ctx/hello`、
  快照与 fixture 字节不变；`go test ./internal/authz` 覆盖同一场景。
- **非目标**：不模拟运行时 filter 执行，不解析外部网关规则，不证明未授权访问。

### P1-1 运行时多角色矩阵与 CSRF 自动化

- **状态**：已实现（`internal/httpverify` `0.2.0-p1.1+r1-http-runtime-v2`）。
- **目标**：把现有“单计划顺序请求”扩展为可复用的多角色、多断言矩阵。
- **实现要点**：
  - 计划 schema 增加 `roles`（登录步骤、凭据占位符引用）与 `matrix`（角色 × 请求 × 期望），
    仍限制单计划请求总数与响应体上限（顶层请求 + 登录步骤 + 矩阵单元 ≤ 64）。
  - 支持有界 CSRF token 提取：从登录页 HTML `meta`/隐藏表单字段按显式选择器取值，
    在后续非 `GET/HEAD/OPTIONS` 请求注入；提取失败标记 `inconclusive`，不猜测。
  - 报告按角色聚合覆盖数，凭据与 token 一律不落报告。
- **实现结果**：
  - `roles[].login` ≤ 16 步；`${ENV:NAME}` 未设置时 `credential_placeholder_unresolved` 并停止该角色；
    角色必须使用不同 `session`，`(role, request)` 不得重复。
  - `csrf.selector` 仅接受 `meta[name=...]`/`input[name=...]`，token ≤ 512 字节，注入 `field` 或 `header`；
    缺失时 `csrf_token_not_found`，矩阵单元 `role_login_incomplete`。
  - 输出 `results[].role/matrix/csrf` 与 `coverage.roles[].login_status`；新 limitation
    `roles_caller_defined`、`csrf_token_extraction_bounded`。
  - 新增 `scripts/test-runtime.py` 矩阵/CSRF/占位符/会话隔离场景；`go test ./internal/httpverify` 覆盖同类断言。
- **验收标准**：
  - 本地测试服务新增 CSRF 端点；`scripts/test-runtime.py` 增加矩阵与 token 场景（已通过：矩阵 10/10、基础 4/4）。
  - Tomcat/MySQL 15 条请求计划未纳入仓库，本次未重跑；旧计划 schema 兼容，建议在具备环境时回归。
  - 契约更新 `docs/runtime-contract.md`；新增 limitation
    `csrf_token_extraction_bounded`、`roles_caller_defined`（已完成）。
- **非目标**：不做浏览器渲染、不自动发现账号、不绕过验证码。

### P1-2 运行时证据与静态 finding 的关联报告

- **状态**：已实现（`internal/correlate` `0.2.0-p1.2+r1-static-runtime-correlation-v1`、`trident runtime correlate`）。
- **目标**：在“不回写静态状态”的前提下，给出可审阅的静态—运行时关联。
- **实现要点**：
  - `trident runtime correlate --findings <json> --runtime <json> --out <file>` 按 route/method
    关联，输出 `correlated|not_correlated|ambiguous` 与两侧证据引用。
  - 关联报告独立文件，包含 `runtime_status=observed` 与“非利用证明”限制；不修改原 finding JSON。
- **实现结果**：
  - 仅精确比较 `endpoint.path` 与 `http_methods`；未声明方法按不受限处理并记录 wildcard 限制。
    无 endpoint 的 finding 输出 `not_correlated` + `finding_has_no_endpoint`，不静默丢弃；
    未命中任何 finding 的运行时结果进入 `unmatched_runtime[]`。
  - 报告固定 `analysis_kind=static_runtime_correlation_v1`，两侧附带文件路径与 SHA-256；
    `correlated` 只表示存在观测响应，不证明参数可控或控制缺失。
  - 输出必须为新文件且不得覆盖任一输入；未观测运行时（`runtime_status!=observed` 或无结果）、
    重复 finding ID、缺失 `id/method/path` 均失败关闭。
- **验收标准**：
  - `go test ./internal/correlate` 覆盖三态、无端点、未命中运行时结果、wildcard、拒绝条件与确定性。
  - `scripts/test-runtime.py` 增加关联断言：唯一匹配、多匹配歧义、无匹配三态；原 finding 字节不变；
    输出确定性；覆盖/缺失/未观测输入失败关闭（已通过）。
  - 契约更新 `docs/findings-contract.md`、`docs/runtime-contract.md`（已完成）。
- **非目标**：不做自动定级、不生成利用链、不替代人工复核。

### P1-3 补丁验证与回滚增强

- **状态**：已实现（`internal/r3`；Gradle profile 以桩工具链验收，真实 Gradle 构建保持未验证）。
- **目标**：让升级与修复在更多构建方式下可验证，并具备失败回退路径。
- **实现要点**：
  - `sca upgrade` 增加 Gradle 验证 profile（`gradle --offline -q test`，需 `--approve-execution`），
    超时与输出截断沿用现有机制。
  - 补丁计划增加 `rollback` 信息（reverse patch 或原文件哈希），验证失败时输出可复现的回退步骤。
  - Docker 验证固定镜像 digest 与只读依赖缓存；质量评分规则版本化（`quality_rubric_version`）。
  - 多模块补丁支持按模块选择验证目标，输出逐模块结果。
- **实现结果**：
  - 新增 `gradle-test` profile：要求 `build.gradle`/`build.gradle.kts`，执行 `gradle --offline -q test`，
    解析 `build/test-results/test` 的 JUnit XML；不需要 `--main-class`。新增限制
    `gradle_test_profile_runs_tests_only`、`gradle_profile_offline`。
  - 报告新增 `rollback`：`snapshot_hash` + 逐文件 `steps[]`（`restore_original` / `remove_created_file`、
    原始与结果 SHA-256）与人工回退说明；验证失败同样附带，不执行任何回滚命令。
  - `patch verify --module`（最多 8 个）与 `sca upgrade --module-dir` 逐模块执行同一 profile，
    `validation.modules[]`/`commands[].module` 输出逐模块结果，聚合状态取最差模块。
  - `quality.rubric_version=r3-quality-rubric-v2`；Docker 固定镜像 digest 与只读 Maven 缓存沿用既有实现。
- **验收标准**：
  - `go test ./internal/r3` 覆盖回滚计划、模块路径逃逸/数量上限与 Gradle 构建文件检测（已通过）。
  - `scripts/test-patch.py` 增加回滚、rubric、`--module .`、越界模块与 `gradle-test` 断言（已通过；
    Gradle 使用桩工具链验证命令构造、退出码与 XML 解析，不证明真实 Gradle 构建）。
  - `scripts/test-upgrade.py` 的 Gradle 依赖升级场景因缺少真实 Gradle/离线缓存仍未运行，保持未验证。
  - 契约更新 `docs/sca-contract.md`、`docs/patch-contract.md`（已完成）。
- **非目标**：不自动合并上游新版本、不做生产兼容性证明、不自动执行回滚。

### P1-4 扫描性能与增量

- **状态**：已实现（`internal/cache` + `audit endpoints --cache-dir`）。
- **目标**：让中型仓库可重复使用缓存，并给出性能回归门槛。
- **实现要点**：
  - 分析缓存键：文件 SHA-256 + 工具版本 + 参数；缓存只存派生索引（符号表/入口/控制清单），
    不存源码或密钥。
  - 快照未变化时复用索引；变化文件做局部重建，输出 `cache=hit|partial|miss`。
  - `scripts/benchmark.py` 增加断言阈值（相对基线倍数，而非绝对时间），防止性能回退。
- **实现结果**：
  - 新增 `internal/cache`：键为 `SHA-256(tool_version, kind, file_sha256)`，JSON 条目带
    `schema_version/kind/key/tool_version` 校验，损坏条目视为 miss 并在解析后原子覆盖写入。
  - `audit endpoints --cache-dir <dir>` 只缓存单文件端点元数据（路径、方法、注解、参数、行号、文件 SHA），
    不存源码；`coverage.cache` 输出 `not_used|miss|hit|partial`，并附命中/未命中/损坏计数。
    缓存与快照任一方向重叠、缓存路径为文件均失败关闭。
  - `scripts/benchmark.py` 新增 `--baseline <json>` 与 `--max-ratio <n>`，按相对中位数断言；
    新增 `audit endpoints cached` 场景。
- **验收标准**：
  - `scripts/test-cache.py`：命中/失效/损坏缓存三种结果；缓存目录不含源码；快照字节不变（已通过）。
  - `python scripts/benchmark.py 3 --baseline <baseline.json> --max-ratio 4`：相对基线通过（已运行）。
  - 契约新增 `docs/cache-contract.md`（已完成）。
- **非目标**：不做分布式缓存、不做跨机器共享、不缓存源码或完整分析报告。

### P2-1 CI 与发布流水线落地

- **状态**：核心已实现并在真实 GitHub runner 验证（2026-11-14，仓库已公开）。`offline` job（Go 测试
  + 10 个离线 CLI 验收 + SARIF 生成并上传 code scanning）与 `db-governance` job（一次性 PostgreSQL 18
  容器演练）run 43585245302、43585400725 全绿；故意红灯探针 `e1119d3` 使 `Go tests and vet` 失败
  （run 43585523523），revert 后恢复，门禁可证失败关闭。`release-artifacts` job 已提供（`v*` tag 触发）
  但尚未打 tag 演练；Java/Maven/Gradle、模型与运行时 job 仍需专用 runner 与密钥管理。
- **目标**：把模板变成可观测的真实门禁。
- **实现要点**：
  - 确认 GitHub Actions 首次运行结果；增加 PostgreSQL service job（`test-db-governance.py`）与
    Java/Maven 固定工具链 job（仅 R3 验证，需 runner 授权）。
  - SARIF 上传与 code scanning 集成；失败时保留日志 artifact。
  - 增加 release tag 触发的构建产物（二进制 + SBOM + SARIF）与校验和。
- **验收标准**：
  - 至少一次真实 runner 全绿记录（已满足：run 43585245302、43585400725）；失败路径（故意改坏测试）
    可复现红灯（已满足：run 43585523523）。
  - 更新 `docs/release-checklist.md`、`docs/deployment.md`（已完成）。
- **非目标**：不把模型/真实项目外发放进公共 CI。

### P2-2 Web 控制台与多用户

- **状态**：核心已实现（多用户令牌文件 + 审计日志 + 确定性 HTML 导出；TLS 反代部署说明已固化，
  未经真实域名/证书联调）。多快照对比、finding 状态流转与 PDF 导出明确不做（写入口与只读边界冲突）。
- **目标**：从单机只读控制台提升为可部署的团队审阅界面。
- **实现要点**：
  - TLS 反向代理部署说明与安全响应头；令牌改为可轮换的多用户令牌文件（或外部 OIDC 接入点，
    仅留接口不实现供应商）。
  - 报告导出：确定性 HTML（无外部资源）与 PDF（可选）；多快照对比与 finding 状态流转（人工）。
  - 审计访问日志与只读约束；不提供执行/修复入口。
- **验收标准**：
  - `scripts/test-web.py` 增加多用户隔离、令牌轮换/撤销、审计日志与导出确定性（两次字节一致、
    无外部 URL、无时间戳）断言（已通过；`--tokens`/`--access-log` 第二阶段）。
  - `go test ./internal/webui` 覆盖令牌文件格式校验拒绝、互斥参数与轮换热重载（已通过）。
  - 契约更新 `docs/web-console-contract.md`（§2.1/§5/§6/§8 已完成）与 `docs/deployment.md`（§2.1 已完成）。
- **非目标**：不做 SaaS 多租户、不在控制台内执行补丁。

### P2-3 生产运维门槛

- **状态**：2026-11-14 大幅推进——监控真实联调已落地（控制台 `/metrics` Prometheus 文本端点 +
  `ops/monitoring` 配置，`scripts/test-monitoring.py` 四项 PASS：真实 Prometheus v2.53.0 抓取、
  指标可查询、告警经 Alertmanager v0.27.0 webhook 端到端送达、抓取落 JSONL 审计日志）；
  **生产数据量级备份演练已实测**（`scripts/test-backup-scale.py`：624 MB/170 万行，RTO 9.8s、
  RPO 语义演示）；**容量与成本估算模型已建立**（`docs/capacity-cost.md`：RTO/RPO 外推公式、
  静态分析容量、DB 增长、模型 token 公式——模型成本未实测，live-model 仍 pending）。
  仍待真实生产设施/组织流程：生产硬件上的 RTO/RPO 承诺复测、生产级分权执行的组织审批记录
  （密钥系统登记表）、真实项目规模基准、按真实数据分布复核 DB 增长。
- **目标**：把本地演练升级为可审计的生产准备证据。
- **实现要点**：
  - 生产级分权执行记录（真实表 owner、密钥系统、审计审批）；生产数据量备份恢复演练与 RTO/RPO 记录。
  - 监控：`/healthz`、只读指标（分析耗时/失败数/Run 状态）、结构化日志；告警规则模板。
  - 容量与成本模型：按快照规模/依赖数/模型 token 给出估算方法与实测样本。
- **验收标准**：
  - 运维演练报告（脱敏）与 `docs/deployment.md` 更新（监控/备份/容量模型均已更新）；
    checklist 对应项改为"已验证"需附证据路径。
- **非目标**：不替代组织级安全评审与合规认证。

### P3 可选增强

- **状态**：两项已实现并验收（2026-11-14，仓库公开后）：SARIF 规则分类细化与 GitHub code scanning
  规则映射（已由 CI 上传）；CycloneDX VEX 分析状态（`sca sbom --package-map`，固定保守映射：
  `unreachable`→`not_affected/code_not_reachable`、`reachable`/`unknown`→`in_triage`，见 sbom 契约 §9，
  已通过 `go test ./internal/sbom` 与 `scripts/test-sbom.py` 官方 Schema 验收）。
  其余项仍为计划。
- CycloneDX VEX 导出（已知不可达/不受影响声明）——已实现。
- SARIF 规则分类细化与 GitHub code scanning 规则映射——已实现。
- 模型供应商扩展（Anthropic/Gemini 等）与工具并发；均需逐次授权与费用上限。
- 硬件 VM 或等效系统调用隔离评估（替代 gVisor 用户态边界）。

## 4. 里程碑

| 里程碑 | 内容 | 退出条件 |
|---|---|---|
| M1 证据可信度 | P0-1 制品哈希 + P0-2 可达性 | 两个新验收脚本通过，findings/SBOM 契约更新，回归全绿 |
| M2 语义层 | P0-3 Java AST 与调用图 | 现有 fixture 零新增误报，新旧对照报告归档 |
| M3 权限与运行时 | P0-4 权限链 + P1-1 多角色矩阵 | `test-authz.py`/`test-runtime.py` 扩展通过，Tomcat 回归通过 |
| M4 闭环增强 | P1-2 关联报告 + P1-3 补丁增强 + P1-4 缓存 | 对应脚本通过，性能阈值生效 |
| M5 平台化 | P2-1 CI 落地 + P2-2 控制台 + P2-3 运维 | runner 全绿记录、控制台验收、运维演练报告 |
| M6 可选 | P3 项 | 单项授权与独立验收 |

顺序原则：先提升结论可信度（M1/M2），再扩展自动化（M3/M4），最后做平台与生产（M5）。

## 5. 横向工程要求

1. **版本号**：每项能力修改 `ResolveToolVersion`/`productVersion`/`analysis_kind` 等版本标识，
   旧报告不得被新语义静默重解释。
2. **确定性**：输出无时间戳、稳定排序；同一输入字节级一致，测试用 SHA-256 断言。
3. **有界性**：所有新解析器/遍历设置节点数、深度、超时与输出上限；超限显式 `partial`。
4. **凭据**：凭据只从调用者输入或环境读取，不写报告、日志、缓存与 Git。
5. **回归**：每项至少新增一个真实 CLI 验收脚本，并加入 `scripts/verify-offline.ps1`（需要 Docker/
   网络的脚本单独列出，不混入离线门禁）。
6. **文档同步**：实现与契约同一次提交；`development-progress.md` 记录准确命令与结果，
   `release-checklist.md` 更新状态。

## 6. 风险与应对

| 风险 | 应对 |
|---|---|
| 自研 Java 子集解析器覆盖不足 | 保留词法回退引擎；以 fixture 差异报告驱动迭代；解析失败一律 `unknown` |
| 可达性误判导致过度升级 | 只输出证据路径与三态，不自动提升严重度；保留 `unverified` |
| 运行时矩阵引入凭据泄露 | 报告脱敏、凭据占位符、输出审查测试 |
| 缓存包含源码或秘密 | 缓存键哈希、只缓存派生索引、测试断言目录内容 |
| CI 加入 Java/Maven 后不稳定 | 固定镜像 digest 与工具链；失败保留日志；离线优先 |
| 生产演练触及真实数据 | 仅在显式授权的克隆库执行；先备份、后演练、可回滚 |

## 7. 需显式授权的边界

- 真实模型调用、真实项目源码外发、真实项目 AI 补丁：逐次书面授权，记录端点/模型/快照 hash/
  调用与费用上限。
- 生产数据库分权、备份恢复与迁移：需 DBA 与发布审批，先克隆演练。
- 硬件 VM 或等效隔离、TLS/多用户控制台上线：需基础设施与安全评审。
- 新增在线制品/公告源：需网络出口与数据外发批准。
