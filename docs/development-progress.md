# TRIDENT 开发进度与维护入口

> 当前路线：[`TRIDENT_统一安全Agent执行方案_v2.0.md`](TRIDENT_统一安全Agent执行方案_v2.0.md)。本文件记录工程进度，不是运行时 Run 状态；运行状态以 PostgreSQL 为准。核心实现保持 Go，Java 是审计样本，Python 仅辅助验收。

## 当前能力矩阵

| 范围 | 状态 | 维护入口 |
|---|---|---|
| P0.1/P0.2 离线治理 | 已实现，历史验收记录保留 | `p0-contracts.md`、`p0-acceptance.md` |
| R0 合成 Java/Maven 样本与断言 | 已交付；未执行 Java/Maven/JUnit | `java-fixture-acceptance.md`、`tests/fixtures/java-maven/` |
| R1 快照与四项只读工具 | 已实现并完成本地验收 | `snapshot-contract.md`、`internal/project/` |
| R1 Core、Run、OpenAI 适配 | 已实现并完成本地协议验收与两次真实模型只读闭环；DeepSeek `reasoning_content`/Schema 数值兼容、48 KiB 检查点确定性压缩、按工具类型的保留策略与有界结果摘要已实现 | `agent-contract.md`；下方 2026-11-12 与 2026-11-13 记录 |
| R1 真实模型自主工具闭环 | 已完成获准验收：DeepSeek `deepseek-flash` Run 43、`deepseek-v4-pro` Run 46，均仅合成样本且 `completed`；其他模型/快照需逐次授权 | `agent-contract.md` §6.1；下方 2026-11-13 记录 |
| R2 供应链/AST/漏洞分析 | 声明级 Maven/Gradle、Maven/Gradle 有效依赖树（临时副本、默认离线、显式按工具批准）、公告精确版本与调用者声明区间/别名、模块依赖树、Spring MVC/JAX-RS/Servlet 入口清单、10 类注入与非 SQL 类别（命令注入/SSRF/路径遍历/模板注入/XSS/反序列化/XXE/LDAP/上传）Source/Sink（含 `+`/builder/`format`/返回值/builder 突变/继承分派/字段污点/重载/集合与字面量元素/导入感知类型解析/`produces` 反射返回值/链式反序列化/更多 XXE）、统一 Finding/Hypothesis、SARIF 2.1.0 与 import 可达性已实现并验收；完整 AST/污点/制品哈希/依赖到入口可达性未实现 | `sca-contract.md`、`audit-contract.md`、`dataflow-contract.md`、`findings-contract.md`、`internal/sca/`、`internal/audit/`、`internal/dataflow/`、`internal/findings/`、`internal/sarif/`、`internal/reach/` |
| R2 只读 Web 分析控制台 | 已实现并完成本地验收；单快照、loopback、令牌鉴权、只读 JSON API 与嵌入前端；不改变分析语义，不提供 Agent 控制 API | `web-console-contract.md`、`internal/webui/`、`cmd/trident/web.go` |
| R2 Agent 分析工具 | 已实现并完成本地验收与真实模型/真实项目使用；5 个分析工具、分析缓存、Run 公告配置、实际读取行引用与证据账本桥接 | `agent-contract.md`、`internal/tools/analysis.go`、`internal/agent/` |
| R2 CycloneDX SBOM | 已实现并完成官方 Schema 验收；确定性 1.5 JSON、依赖声明/公告候选映射；无传递树/制品哈希/可达性 | `sbom-contract.md`、`internal/sbom/`、`cmd/trident/sca.go` |
| R3 隔离验证/补丁闭环 | 已实现调用者与 AI 生成补丁、remediation policy、隔离副本、离线 Maven（含有效依赖树）/maven-compile/maven-test/javac/JUnit、Docker/gVisor、质量评分、最多 5 轮修复、原快照复验；支持新文件/BOM/多文件补丁；真实 Java/Maven/JUnit、真实模型合成补丁、真实项目编译级补丁、集中式访问控制运行时单测与真实 Tomcat/MySQL HTTP 权限测试已完成；运行时 HTTP 验证执行器已实现（显式 origin、cookie session、有界断言）；硬件 VM 与生产验证未实现 | `patch-contract.md`、`runtime-contract.md`、`internal/r3/`、`internal/httpverify/`、`cmd/trident/patch.go`、`cmd/trident/runtime.go`、`docs/evidence/2026-11-14-market-access-control.patch` |

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

## 维护规则

1. 每个开发切片同步更新能力矩阵及日期记录；明确 implemented/verified/pending/blocked，而不是只追加“完成”。
2. 记录准确命令、平台/工具链、测试范围、退出结果和跳过原因；代码版本标识如无 Git 则明确无 commit，不能虚构 revision。
3. 保留历史结果，不用新结果覆盖旧失败/未运行事实。原始日志不包含密钥、完整 DSN、源码秘密或 HTTP 认证头。
4. 修改迁移只新增文件；变更工具/策略/恢复格式需版本化并更新契约。模型接入成功、源码漏洞确认和修复验证是不同门槛。
5. 继续开发先读 README → 本文件 → 对应契约及当前代码，不重新返回已废止的三角色/P0—P6路线。
