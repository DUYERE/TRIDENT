# Java 合成样本与 fixture 验收

日期：2026-11-12。对应 v2.0 方案 R0 样本材料及 R1—R3 验收；其中声明级 Maven/固定公告匹配已由 R2 首片实现，但不代表有效依赖树、Java AST、污点分析、运行时验证或补丁闭环已实现。

## 1. 范围与执行边界

1. 本文覆盖 `tests/fixtures/java-maven/` 合成材料与预期；Go 快照、CLI 和工具边界另见 `snapshot-contract.md`，不以样本校验替代产品功能验收。
2. 所有业务名称、数据表、行数据均为合成内容；没有真实凭据、生产地址、RCE 载荷或外联目标。官方公告 URL 仅为情报来源。
3. **风险提示：包含故意保留的高危 SQL 注入正例，只能作为静态材料或在另行批准的隔离合成数据库中使用，禁止接入生产。** 本次没有运行 Maven、wrapper、Java 编译器、样本、JUnit 或数据库。
4. Python 校验器只读取 XML/JSON/源码文本并计算摘要，不下载依赖、不调用子进程、不执行 Java、不写入文件。其通过仅证明材料内部结构与预期一致，不能冒充 Java 行为验证。

## 2. 文件与样本

| 路径（相对仓库根） | 内容 |
|---|---|
| `tests/fixtures/java-maven/pom.xml` | 聚合父 POM；两个模块；父属性与 dependencyManagement；未来插件版本输入 |
| `tests/fixtures/java-maven/jdbc-app/pom.xml` | Commons Text 版本由父属性继承为 1.9；Spring MVC 与仅测试使用的 JUnit/H2 声明 |
| `tests/fixtures/java-maven/advisory-control/pom.xml` | 子模块覆盖同一属性为 1.10.0，仍通过父管理声明依赖 |
| `tests/fixtures/java-maven/jdbc-app/src/main/java/example/synthetic/` | MVC 路由、JDBC 正反例、反射 unknown、合成模型和无关 Commons Text 调用 |
| `tests/fixtures/java-maven/advisory-control/src/main/java/example/synthetic/control/AdvisoryControlText.java` | 1.10.0 模块的无关 API 兼容材料 |
| `tests/fixtures/java-maven/jdbc-app/src/test/java/example/synthetic/CustomerRepositoryTest.java` | 5 项业务、3 项安全测试，未来使用每例独立 H2 内存数据库 |
| `tests/fixtures/java-maven/advisory-control/src/test/java/example/synthetic/control/AdvisoryControlTextTest.java` | 1 项对照兼容测试 |
| `tests/fixtures/java-maven/advisories/CVE-2022-42889.json` | 固定范围的人工整理公告 fixture，来源、获取日期、原文摘要及禁止推论 |
| `tests/fixtures/java-maven/expected.json` | 机器可读预期：依赖、证据锚点、Source/Sink、unknown、未来测试矩阵及失败门禁 |
| `tests/fixtures/java-maven/validate_fixture.py` | 标准库只读静态材料校验器 |

未提供可启动的 Web 服务、DataSource 装配、动态处理器实现或运行配方。路由是入口识别材料，不意味着服务已经部署。Java 目标为 17；辅助依赖及插件版本是未来配方输入，不是安全背书、完整锁文件或已批准解析结果。

## 3. 依赖公告断言

官方来源：[Apache Commons Text Security Reports](https://commons.apache.org/proper/commons-text/security.html)。公告日期 2022-10-13；本次获取日期 2026-11-12。

1. fixture 来源为官方安全页面，下载时保留 TLS 证书校验，没有使用跳过证书校验的方式。复验静态 fixture 不需要再次联网；源码和样本没有发送给外部服务。
2. 获取的 HTML 字节 SHA-256 为 `622f53c01645ab1485057d508d5443a4212709d21086439403bbd98ffdb58f53`。fixture 保存来源与整理摘要，不包含原始 HTML；不能仅凭摘要重新计算此原文 Hash，官方页面后续变化也不应被误判为本 fixture 的断言变化。
3. 当前预期仅覆盖两项精确版本，不实现通用 Maven 区间比较、别名穷举或所有 CVE 扫描：

| 模块 | 声明解析 | 对 CVE-2022-42889 的预期 | 不允许的结论 |
|---|---|---|---|
| `jdbc-app` | 父 `commons-text.version=1.9` → 父管理 → 子声明 | `version_matched`；Finding 仅 `candidate` | 不能据此确认 RCE、输入可达或可利用 |
| `advisory-control` | 子属性覆盖为 `1.10.0` → 父管理 → 子声明 | 该公告**版本条件未命中**；`not_affected` 仅限此判据 | 不能宣称所有 CVE 安全、任意配置安全或运行时已验证 |

两个模块只调用 `StringEscapeUtils.escapeHtml4`，不是 `StringSubstitutor`。可见源码未找到相关插值调用不等于不可达；动态装配、缺失依赖源码、运行配置和 JVM 条件仍是限制。未执行 Maven，真实有效依赖树、传递依赖、制品 Hash 及运行时 classpath 均无法确认。dependencyManagement 不应被误报为父模块实际引入了依赖。

**2026-11-12 声明级实现：** `trident sca inspect` 已按本表两个精确版本 case 输出声明级结果（`jdbc-app` 1.9 → `version_matched/candidate`；`advisory-control` 1.10.0 → `not_affected`）。该输出只证明 POM 声明解析与精确 case 匹配，不证明 Maven 有效依赖树、相关调用点或运行时安全；契约见 `sca-contract.md`。

## 4. 源码断言

稳定定位采用 `expected.json` 中的文件、符号和唯一 `fixture:*` 注释锚点，避免把易变行号当唯一证据。

| ID | 路径与预期 | 分级和限制 |
|---|---|---|
| `jdbc-concatenation-positive` | `GET /synthetic/customers/unsafe` → `@RequestParam("name")` → `findByNameUnsafe` → 字符串拼接 → `Statement.executeQuery(sql)` | **高危 / CWE-89**；未来分析应静态确认该链，运行状态仍 `not_run`，不宣称生产已利用 |
| `jdbc-parameterized-negative` | `/parameterized` → 固定查询 `?` → `PreparedStatement.setString(1, name)` → 无参 `executeQuery()` | 针对此值参数的注入假设为 `refuted`，不得提升为确认漏洞；不是整个应用安全证明 |
| `dynamic-call-boundary` | `/dynamic` → `Class.forName` / `getMethod(...).invoke(null, name)` | `unknown` / `inconclusive`；缺失 `fixture.lookup.class` 及处理器源码，不能推断 safe、不可达、SQL 注入或 RCE |

拼接查询及负例查询均包含大写 `SELECT`，可用于只读项目搜索验收。反射类名来自未提供的配置，不是请求参数；不应把输入流向反射方法的事实偷换成攻击者控制类名。

**2026-11-12 入口清单实现：** `trident audit endpoints` 已识别表中三个 GET 路由及 `@RequestParam("name")` 参数绑定，并记录 `fixture:*` 锚点。该结果只证明注解级入口清单，不证明数据流、调用点、可达性或运行时利用；契约见 `audit-contract.md`。

**2026-11-13 JDBC 数据流实现：** `trident audit dataflow` 对 `jdbc-concatenation-positive` 输出 `static_confirmed`（跨方法拼接后 `Statement.executeQuery`，`CustomerRepository.java:28`）；对 `jdbc-parameterized-negative` 输出 `refuted`（常量 SQL + `PreparedStatement.setString`，第 39 行）；对 `dynamic-call-boundary` 输出 `inconclusive`（tainted 值到达反射 `invoke`，目标不可解析）。这些是静态证据，`runtime_status=not_run`，不证明运行时利用；契约见 `dataflow-contract.md`。

**2026-11-13 统一证据模型：** `trident audit findings` 将声明级候选、三个入口和 JDBC 数据流 finding 关联为统一证据：`jdbc-concatenation-positive` 的 `source_to_sink` 假设为 `supported`；`jdbc-parameterized-negative` 为 `unsupported`，并附受限于该观察点的值绑定假设；`dynamic-call-boundary` 为 `unverified`；Commons Text 1.9 候选的版本假设为 `supported`，依赖可达入口与运行时利用均为 `unverified`。所有 finding 的 `runtime_status=not_run`；关联不产生新的漏洞结论，也不证明可达性或运行时利用；契约见 `findings-contract.md`。

## 5. 未来业务、安全回归与补丁门禁（未执行）

风险：未来测试含 SQL 注入对照输入，仅能在另行批准的隔离环境和合成 H2 内存表中运行。没有公网数据库、TCP 监听或数据库文件。

1. 当前只提供相同测试集材料，**没有提供或验证修复补丁**。未来仅允许在独立副本修改 `CustomerRepository.findByNameUnsafe`，将拼接改为固定参数化查询及 `setString`；保持列、相等条件、排序、返回值和资源关闭行为。
2. 在基线及补丁副本执行前冻结同一套测试，不得删除、改弱或跳过用例。当前测试文件摘要如下（原始字节）：

| 测试文件 | SHA-256 |
|---|---|
| `jdbc-app/src/test/java/example/synthetic/CustomerRepositoryTest.java` | `a311f62290033b39d03b93c2286d949b2477e0874d486f55e795bffba23292f4` |
| `advisory-control/src/test/java/example/synthetic/control/AdvisoryControlTextTest.java` | `f21149cc0e6e902ae710b464c7a14574f8e0044330dc4e7c9dddbc9594fcd6d3` |

按 `expected.json.future_validation.test_files` 顺序，对每项拼接 `UTF8(相对路径) + NUL + 文件原始字节 + NUL` 后计算 SHA-256，当前 TestSuite Hash 为 `eee7c95dcdd7934c91814e48a22f28522d558cf6131c2f207c82dca9fae98faa`。

3. 预期结果是设计断言，**不是本次执行结果**：

| 阶段 | 必须实际执行 | 通过 | 失败 | 错误 | 跳过 |
|---|---:|---:|---:|---:|---:|
| 原始基线（未来） | 9 | 7 | 2 | 0 | 0 |
| 修复副本（未来） | 9 | 9 | 0 | 0 | 0 |

基线两项失败必须分别是 `unsafeTautologyMustRemainLiteral` 与 `unsafeCommentMustRemainLiteral`，且原因为断言发现额外合成行；编译失败、SQL 语法错误、环境缺失、异常或超时均不能算复现成功。其余业务用例、参数化对照和兼容测试必须在前后都实际通过。

4. 业务材料覆盖正常精确查询、无匹配结果及参数化路径对含引号姓名的保留，不可用删除合法字符的方式“修复”。安全用例期望注入字符串被当作普通值，不写“漏洞复现成功即测试通过”的反向断言。
5. 验证必须另行批准固定沙箱配方、受控依赖获取及 Hash；记录 JDK/Maven/制品、测试集摘要、实际逐用例结果、日志、退出码和原快照不变证据。零测试、必需用例跳过、编译错误、超时、缺证据都不能获得 `validated`。`failIfNoTests` 只是一个辅助设置，不能代替逐方法执行数门禁。
6. 失败矩阵也在 `expected.json` 中：动态目标缺失应维持 unknown；编译失败/零测试为验证失败；超时/依赖缺失为 inconclusive，不得把退出码 0 或模型解释当作补丁有效证据。

## 6. 本次验证

在 Git Bash 可完整复制执行的只读复验命令：

```bash
# [01] 仅解析静态材料；不运行 Maven、Java 或 JUnit。
python -B 'E:/pentest agent/TRIDENT/tests/fixtures/java-maven/validate_fixture.py'
```

本次实际结果：退出码 **0**，JSON `status=pass`、`scope=fixture_structure_only_not_java_behavior`。检查两个模块、1.9/1.10.0 继承及覆盖、3 项源码预期及唯一锚点、9 项测试方法/标签、前后预期汇总和两个测试文件摘要；`maven_executed=false`、`java_executed=false`。

`scripts/test-project.py` 实际驱动 Go CLI，覆盖项目导入、list/read/search/inspect、路径拒绝、可信摘要、内容篡改拒绝和源文件不变；只作为**项目只读工具验收**，不等于 Java 行为、AST/污点分析、漏洞利用或修复证明。

尚未验证：Maven 有效模型/构建、传递依赖树、Java 编译、JUnit/H2 行为、HTTP 装配、完整 Java AST/污点、反射目标、RCE、补丁及 R3 验证闭环。声明级 SCA、注解级入口清单、JDBC SQL Source/Sink 静态证据和统一 Finding/Hypothesis 证据模型已验证（见 §3、§4 与对应契约），但仍不能将这份样本验收写成完整 R2 或产品能力完成。
