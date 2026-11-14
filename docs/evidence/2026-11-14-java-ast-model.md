# 受限 Java 语义模型（P0-3 第一片）证据记录

- 日期：2026-11-14
- 范围：`internal/javaast`、`audit java-model`、dataflow v13 coverage 接入
- 工具链：Windows / Go 1.27.1（`go.mod` 1.26.3）/ Python 3.12
- 结论：新增受限 AST 语义模型与确定性方法级调用图；sink/source 匹配未切换，既有 finding 计数与状态不变。

## 1. 实现身份

| 组件 | 版本/标识 |
|---|---|
| `javaast` | `0.2.0-p0.3+r1-java-semantic-model-v1`，`analysis_kind=java_semantic_model_v1` |
| dataflow | `0.2.0-p0.3+r1-source-sink-flow-v13`，`analysis_scope=single_parameter_multi_category_v13` |
| findings | `0.2.0-p0.3+r1-finding-evidence-v3-reachability-ast` |

## 2. 新引擎实测：`tests/fixtures/java-ast-model`

| 指标 | 值 |
|---|---|
| 文件扫描/拒绝 | 5 / 1（`Broken.java` 单独拒绝，`partial=true`） |
| 类型/方法/字段 | 14 / 17 / 5 |
| 注解/常量折叠 | 2 / 1 |
| 调用边 | 5 观察：4 resolved、1 ambiguous、0 unresolved、1 external |
| 接口分派 | 1（`Store` → `JdbcStore#save(java.lang.String)`） |
| 歧义分派 | 1（`Handler` 双实现 → `ambiguous_dispatch`） |

关键断言：

- 嵌套类 `com.example.model.Outer.Inner` 被索引，`describe()` 未限定调用解析到外部类 `Outer#label()`。
- 泛型擦除重载：`pick("...")` → `Overloads#pick(java.lang.String)`；`pick(list)` → `Overloads#pick(java.util.List)`。
- 注解常量：`@Route(PREFIX + "/items")` → `{"kind":"string","text":"api/items"}`；`@Access(Role.ADMIN)` → `{"kind":"name","text":"com.example.model.Role.ADMIN"}`。
- 输出两次运行 JSON 完全一致；fixture 源目录字节不变。

## 3. 新旧引擎对照：`tests/fixtures/java-maven`

| 指标 | 旧（v12 词法） | 新（v13 + AST 统计） |
|---|---|---|
| `coverage.java_ast` | `not_available` | `restricted_subset` |
| AST 类型 / 方法 | — | 8 / 25 |
| dataflow `methods_parsed` | 20 | 20（未变） |
| findings | 3（confirmed 1 / refuted 1 / inconclusive 1） | 3（同左） |
| 跨方法调用解析 | 3 resolved / 0 unresolved | 3 / 0（未变） |

差异说明：AST 方法数高于词法 `methods_parsed`，因为 AST 额外计入构造器、注解元素与嵌套类型成员；这不是 finding 语义变化。两组引擎的 `analysis_kind` 仍分别为 `source_sink_multi_category_v1` 与 `java_semantic_model_v1`，未伪装成同一结论。

## 4. 回归命令与结果

| 命令 | 结果 |
|---|---|
| `go build ./...` | 通过 |
| `go vet ./internal/javaast ./internal/dataflow ./internal/findings ./cmd/trident` | 通过 |
| `go test ./internal/javaast ./internal/dataflow ./internal/findings -count=1` | 通过 |
| `python scripts/test-java-ast.py` | 通过（5 类断言、确定性、失败关闭、fixture 不变） |
| `python scripts/test-dataflow.py` | 通过（全部样本 finding 计数不变） |
| `python scripts/test-findings.py` | 通过（`coverage.java_ast` 透传） |

## 5. 未验证与边界

- AST 未接入 sink/source 匹配；控制流、别名/points-to、跨方法污点、AOP/动态代理仍未实现。
- lambda、方法引用、文本块、匿名类、初始化块为边界；常量折叠深度 ≤16、条目 ≤20000。
- 外部/JDK 接收者只计数、不出目标；反射 API 只记 `reflection_not_resolved`。
- 未编译、未运行 Java，未调用模型，未访问网络，未读取 `D:\Code\Java\market`。
