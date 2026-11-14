# R2 第四片：统一 Finding/Hypothesis 证据模型契约

- 日期：2026-11-13
- 状态：已实现并完成本地真实 CLI 验收；**不是完整证据图谱、可达性分析或运行时验证**。
- 入口：`trident audit findings`、`internal/findings/`、`scripts/test-findings.py`。

本片把三份既有只读结果关联为同一份证据模型：

1. `internal/sca` 的声明级 Maven 依赖与固定公告精确版本匹配；
2. `internal/audit` 的 Spring MVC 注解级入口清单；
3. `internal/dataflow` 的 JDBC SQL Source/Sink 有界数据流。

关联只提供上下文，不产生新的漏洞结论，也不把静态证据升级为运行时证据。

## 1. 输入与信任边界

1. 三份分析读取同一个已导入并通过 `snapshot_hash` 绑定的 `SourceSnapshot`；任一完整性错误直接中止。
2. `--advisories` 可选；缺省时仍输出入口清单与数据流证据，但 `sca_advisory_candidates=0` 并标记 `advisory_catalog_not_provided`。
3. 不执行 Java、编译器、Maven/Gradle、测试或数据库；不访问网络或模型；不写快照或源目录。
4. 快照内证据文件的行号与 SHA-256 来自已校验的快照 manifest，验收脚本会重新计算文件 SHA-256；公告目录是调用者提供的配置，不作为源码证据，因此 `advisory` 证据没有 file/SHA。

## 2. Finding 模型

统一 finding 的 `kind`：

| kind | 来源 | CWE | 状态语义 |
|---|---|---|---|
| `sql_injection` | dataflow | CWE-89 | 保留原 `static_confirmed` / `refuted` / `inconclusive` |
| `command_injection` | dataflow | CWE-78 | 同上；仅在该参数观察到命令执行 sink 或边界时出现 |
| `ssrf` | dataflow | CWE-918 | 同上；仅在该参数观察到出站请求 sink 或边界时出现 |
| `path_traversal` | dataflow | CWE-22 | 同上；仅在该参数观察到文件访问 sink 或边界时出现 |
| `template_injection` | dataflow | CWE-1336 | 同上；仅在该参数观察到模板求值 sink 或边界时出现 |
| `xss` | dataflow | CWE-79 | 同上；仅在该参数观察到响应写出 sink 或边界时出现 |
| `deserialization` | dataflow | CWE-502 | 同上；仅在该参数观察到反序列化读取 sink 或边界时出现 |
| `xxe` | dataflow | CWE-611 | 同上；仅在该参数观察到 XML 解析 sink 或边界时出现 |
| `ldap_injection` | dataflow | CWE-90 | 同上；仅在该参数观察到 LDAP 查询 sink 或边界时出现 |
| `missing_authentication_or_authorization` | authz | CWE-306 | 固定 `inconclusive`；未识别到控制不等于可未授权访问 |
| `vulnerable_dependency` | SCA candidate | CWE-1395 | 固定 `inconclusive`；版本命中不等于可利用 |

共同字段：

- `status` 只表示**静态**判断；`runtime_status` 在本片恒为 `not_run`。
- `severity`：数据流确认 `high`、负例 `none`、其余 `unknown`；依赖候选固定 `unknown`。
- `endpoint`：数据流 finding 的入口路径、HTTP 方法、符号、文件、SHA-256、起止行。
- `component`：依赖 finding 的模块、`group:artifact`、声明版本、声明/管理/属性 POM、公告 ID。
- `evidence[]`、`hypotheses[]`、`source_analyses[]`、`limitations[]`。

Finding ID：

- 数据流：`dataflow:<CWE>:<endpoint-path>:<parameter>`（CWE-89/78/918/22/1336/79/502/611/90）。
- 权限：`authz:<16-hex>`，由端点路径、符号与文件派生。
- 依赖：`sca:<advisory-id>:<module>:<group:artifact>:<version>`。

排序：`static_confirmed` → `inconclusive` → `refuted`，同一状态按 ID 升序。

## 3. Hypothesis 模型

每个假设都显式区分“已由静态证据支持/反驳”和“本授权范围未采集证据”：

- `supported`：有具体证据支持该静态陈述。
- `unsupported`：有具体静态证据反驳该静态陈述。
- `unverified`：缺少所需证据；不等于安全，也不等于可利用。

### 数据流 finding

1. `<id>:source_to_sink`：请求参数是否经观察到的静态流到达对应类别的 sink（JDBC SQL、OS 命令、出站请求、文件访问、模板求值、HTTP 响应写出、反序列化读取、XML 解析或 LDAP 查询）。
   - `static_confirmed` → `supported`；
   - `refuted` → `unsupported`；
   - `inconclusive` → `unverified`，`reason` 记录边界类别（如 `boundary:dynamic_invocation`、`boundary:unresolved_sink`）或 `no_closed_path_to_<kind>_sink`（`kind` 为 `sql`/`command`/`ssrf`/`path`/`template`/`xss`/`deserialization`/`xxe`/`ldap`）。
2. `<id>:runtime_exploitation`：是否在部署环境可实际利用；恒为 `unverified`，要求 `runtime_reproduction`、`deployed_route`、`authentication_and_input_context`。
3. `refuted` 额外输出 `<id>:value_binding`，仅陈述“该参数在该观察点通过值绑定，不改变 SQL 文本”，不扩大到全应用安全。

### 权限 finding

1. `<id>:missing_control`：`unverified`，陈述“该入口没有被已识别的认证/授权控制覆盖”；要求 `controller_or_filter_chain`、`deployed_security_chain`、`runtime_unauthenticated_request`。
2. `<id>:runtime_exploitation`：`unverified`，要求 `runtime_http_response`、`authentication_context`、`deployed_route`。
3. 证据：`route`、`method`、`control_absence`；`control_absence` 不含文件或摘要，因为缺少控制不是源码事实。

### 依赖 finding

1. `<id>:declared_version_matches_advisory`：`supported`，证据为相关 POM 与公告版本 case。
2. `<id>:dependency_reachable_from_http_entrypoint`：`unverified`，要求 `dependency_import_graph` 与 `request_to_component_call_path`；`reason` 说明入口数量只是上下文，没有依赖到入口的调用图。
3. `<id>:runtime_exploitation`：`unverified`，要求 `runtime_classpath`、`runtime_reproduction`、`deployment_context`。

## 4. Evidence 模型

`Evidence` 字段：`id`、`kind`、`file`、`sha256`、`start_line`、`end_line`、`anchor`、`anchor_line`、`detail`、`origin`、`origin_ref`。

`kind`：

- 数据流：`route`、`source`、`flow_step`、`sink`、`protection`、`boundary`、`method`。
- 权限：`route`、`method`、`control_absence`。
- 依赖：`pom`、`advisory`。

`id` 为 `origin + kind + file + 行范围 + anchor + detail` 的 SHA-256 前缀（`ev:<16 hex>`），同一 finding 内稳定且去重；每个 finding 最多 256 条证据，超出时不再追加并输出 `evidence_truncated` limitation。

## 5. 关联语义

1. 入口清单为数据流 finding 提供 `route` 证据；数据流本身已复用同一入口清单。
2. SCA 候选与入口清单只做**显式未验证**的关联：有入口不等同于依赖可达，缺少 import graph/调用图。
3. 不跨分析提升状态：SCA `candidate` 不会因存在入口或数据流 finding 变成 `static_confirmed`；数据流 `static_confirmed` 不会变成 `runtime_confirmed`。
4. `refuted` 只覆盖被观察的参数/值绑定/版本 case，不输出“应用安全”。
5. XSS/反序列化/XXE/LDAP 注入沿用同一装配规则：finding ID、证据、假设与 limitations 结构不变，仅多出对应 `kind`；未观察到某类别时不出该 finding，`absence_is_not_safety` 仍适用。
6. 权限 finding 只表示入口清单与已识别控制之间缺少覆盖关系；它不使用数据流，也不因存在认证注解而升级为 `static_confirmed`。

## 6. 输出契约

`trident audit findings --snapshot <dir> --snapshot-hash <sha256> [--advisories <file>]` 输出单个 JSON 对象：

- 身份：`schema_version=1`、`tool_version`、`snapshot_hash`、`analysis_kind=unified_finding_evidence_v1`、`partial`。
- `findings[]`：上述字段与假设。
- `coverage`：finding/hypothesis 状态计数；SCA 依赖与 candidate/unknown/not_affected 计数；入口数；数据流 finding 数；权限控制数、`authz_unprotected` 与权限 finding 数；`java_ast=not_available`、`sca_resolution=declaration_only`、`taint_analysis=bounded_lexical_multi_category`、`runtime_status=not_run`、`dependency_reachability=unverified`。
- `limitations[]`：固定包含 `static_runtime_separation`、`sca_declaration_only`、`advisory_exact_version_only`、`dependency_reachability_unverified`、`endpoint_inventory_annotation_only`、`dataflow_bounded_lexical`、`authz_control_inventory_lexical`、`authz_unprotected_is_inconclusive`、`absence_is_not_safety`、`correlation_not_exploitation`；子分析 partial 时追加 `sca_report_partial` / `endpoint_inventory_partial` / `dataflow_report_partial` / `authz_report_partial`。
- 参数、快照或完整性错误返回非零且不输出成功 JSON。

## 7. 验收

本轮实际执行：

- `go test ./internal/findings ./cmd/trident -count=1`：通过（3 个 findings 单测 + CLI 测试）。
- `python scripts/test-findings.py`：通过。合成样本输出 4 个 finding：
  - `/synthetic/customers/unsafe`：`static_confirmed`，`source_to_sink=supported`，证据含 `fixture:unsafe-http-source`、`fixture:sql-concatenation` 与 `statement.executeQuery` 行号 28。
  - `/synthetic/customers/parameterized`：`refuted`，`source_to_sink=unsupported`，`value_binding=supported`。
  - `/synthetic/customers/dynamic`：`inconclusive`，`source_to_sink=unverified`，原因为 `dynamic_invocation`。
  - `CVE-2022-42889` 的 `org.apache.commons:commons-text 1.9`：`vulnerable_dependency`、`inconclusive`、`severity=unknown`；版本假设 `supported`，入口可达性与运行时利用均为 `unverified`。
- 计数：confirmed=1、refuted=1、inconclusive=2；hypotheses supported=3、unsupported=1、unverified=6；SCA candidate=1、not affected=1；入口=3、数据流 finding=3。
- POM 证据 SHA-256 与实际快照文件一致；重复运行输出字节级一致。
- 负例：缺少 `--snapshot-hash`、错误摘要、缺失公告文件、快照篡改均失败关闭；快照与合成源目录不变。
- 未执行 Java/编译器/Maven、未调用真实模型、未做运行时验证或补丁。

未验证：依赖 import graph/有效依赖树/classpath、依赖到入口的可达性、跨分析去重与证据图谱、运行时复现、补丁验证。

## 2026-11-13 扩展：SARIF 与 import 可达性

- `audit sarif` 将同一份 findings 报告转换为确定性 SARIF 2.1.0；rule ID 为 `trident/<kind>`，`static_confirmed`→`warning`、`inconclusive`→`note`、`refuted`→`none`；结果和 run 属性都保留 `runtime_status=not_run`。SARIF 不是新的分析结论。
- `audit reachability` 使用显式 `--package-map` 将声明依赖映射到 Java import；`import_reachable` 仅表示观察到匹配 import，`import_not_observed` 仅表示本快照未见 import，`unverified` 表示缺少映射。三者都不证明类加载、调用路径或运行时利用。
- 数据流新增 `upload` 类别（CWE-434）与框架 SQL/SSRF sink；finding kind 为 `unrestricted_upload`，仍遵守 `runtime_status=not_run` 与 `inconclusive` 不等于安全的规则。
