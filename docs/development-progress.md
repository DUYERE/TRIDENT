# TRIDENT 开发进度与维护入口

> 当前路线：[`TRIDENT_统一安全Agent执行方案_v2.0.md`](TRIDENT_统一安全Agent执行方案_v2.0.md)。本文件记录工程进度，不是运行时 Run 状态；运行状态以 PostgreSQL 为准。核心实现保持 Go，Java 是审计样本，Python 仅辅助验收。

## 当前能力矩阵

| 范围 | 状态 | 维护入口 |
|---|---|---|
| P0.1/P0.2 离线治理 | 已实现，历史验收记录保留 | `p0-contracts.md`、`p0-acceptance.md` |
| R0 合成 Java/Maven 样本与断言 | 已交付；未执行 Java/Maven/JUnit | `java-fixture-acceptance.md`、`tests/fixtures/java-maven/` |
| R1 快照与四项只读工具 | 已实现并完成本地验收 | `snapshot-contract.md`、`internal/project/` |
| R1 Core、Run、OpenAI 适配 | 已实现并完成本地协议验收；真实模型自主闭环仍待外发许可 | `agent-contract.md`；下方 2026-11-12 收尾记录 |
| R1 真实模型自主工具闭环 | 待明确端点、模型、数据外发和调用许可 | 不得用 Fake/本机协议测试替代 |
| R2 供应链/AST/漏洞分析 | 声明级 Maven/公告、Spring MVC 入口清单、JDBC SQL 与非 SQL 注入类别（命令注入/SSRF/路径遍历/模板注入/XSS/反序列化/XXE/LDAP 注入）Source/Sink（含 `+`/builder/`String.format`/返回值与 builder 跨方法突变/接口继承分派/字段污点/重载选择与未解析父类型边界/lambda、泛型方法与可变参数重载/集合容器传播）、统一 Finding/Hypothesis 证据模型已实现并验收；完整 AST/污点/传递树/依赖可达性未实现 | `sca-contract.md`、`audit-contract.md`、`dataflow-contract.md`、`findings-contract.md`、`internal/sca/`、`internal/audit/`、`internal/dataflow/`、`internal/findings/` |
| R3 隔离验证/补丁闭环 | 未实现 | 不执行项目构建、不改原源码 |

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

## 维护规则

1. 每个开发切片同步更新能力矩阵及日期记录；明确 implemented/verified/pending/blocked，而不是只追加“完成”。
2. 记录准确命令、平台/工具链、测试范围、退出结果和跳过原因；代码版本标识如无 Git 则明确无 commit，不能虚构 revision。
3. 保留历史结果，不用新结果覆盖旧失败/未运行事实。原始日志不包含密钥、完整 DSN、源码秘密或 HTTP 认证头。
4. 修改迁移只新增文件；变更工具/策略/恢复格式需版本化并更新契约。模型接入成功、源码漏洞确认和修复验证是不同门槛。
5. 继续开发先读 README → 本文件 → 对应契约及当前代码，不重新返回已废止的三角色/P0—P6路线。
