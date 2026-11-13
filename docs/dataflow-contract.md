# R2：Source/Sink 静态证据契约（JDBC SQL 与非 SQL 注入类别）

- 日期：2026-11-13（第三片建立；第五片扩展 `StringBuilder`/`StringBuffer`/`String.format`；第六片增加返回值污点与 builder 跨方法突变；第七片增加接口/继承分派与字段污点；第八片增加重载选择与未解析父类型边界；第九片增加 lambda、泛型方法与可变参数重载；第十片增加命令注入、SSRF、路径遍历与模板注入 sink；第十一片增加 XSS、反序列化、XXE 与 LDAP 注入 sink；第十二片增加集合容器污点传播；第十三片增加集合跨方法突变与 `clear`、反射型返回值边界和 `SAXReader`/`XMLReader` XXE；第十四片增加数组下标、`remove` 保守语义、字段集合 `clear`、`produces` 感知的反射型返回值、链式反序列化与更多 XXE 入口）
- 状态：已实现并完成本地真实 CLI 验收；**不是 Java AST、完整污点分析或运行时验证**。
- 入口：`trident audit dataflow`、`internal/dataflow/`、`scripts/test-dataflow.py`。

本片回答“某个 Spring MVC 请求参数是否经过可识别的简单数据流到达 JDBC SQL、OS 命令、出站请求、文件访问、模板求值、HTTP 响应写出、反序列化读取、XML 解析或 LDAP 查询点”。它不编译或运行 Java，不做分支敏感、别名/points-to、跨模块动态派发或运行时验证。静态确认不等于生产已利用；反对/未知不等于全应用安全。

## 1. 输入与信任边界

1. 复用 `trident audit endpoints` 的注解级入口清单，只分析带请求绑定参数的 endpoint。
2. 只读取已导入并通过 `snapshot_hash` 绑定的 `SourceSnapshot`；每个 `.java` 文件通过 `Snapshot.ReadFile` 重新校验大小与 SHA-256。完整性失败直接中止。
3. 不执行 Java、编译器、Maven/Gradle、测试或数据库；不访问网络或模型。
4. 源码、注释、字符串和注解参数都是不可信数据；词法扫描排除注释和字符串，避免把其中的 SQL/方法名当代码。

## 2. 被建模的 Source、Sink 与防护

### Source

- endpoint 参数上的 `@RequestParam`、`@PathVariable`、`@RequestBody`、`@RequestHeader`、`@CookieValue`、`@ModelAttribute`、`@RequestPart`、`@SessionAttribute`。
- 每个参数独立分析。SQL 类别始终生成一个 finding，ID 为 `CWE-89:<endpoint-path>:<parameter>`；非 SQL 类别仅在该参数的流中观察到该类 sink 或 sink 边界时附加 finding，ID 为 `<CWE>:<endpoint-path>:<parameter>`。

### Sink

- SQL（`CWE-89`）：`Statement.executeQuery(...)`、`executeUpdate(...)`、`execute(...)`、`addBatch(...)` 的参数含 tainted 值；`Connection.prepareStatement(...)` 的 SQL 参数含 tainted 值。

### 命令注入、SSRF、路径遍历与模板注入（第十片）

- 命令注入（`CWE-78`）：`Runtime.getRuntime().exec(tainted)`；接收者类型为 `ProcessBuilder` 时，`command(tainted)` 标记接收者，随后 `start()` 确认。
- SSRF（`CWE-918`）：`URL u = new URL(tainted)` 或 `URI u = URI.create(tainted)` 后 `u.openConnection()`/`u.openStream()`；`RestTemplate.getForObject/getForEntity/postForObject/postForEntity/put/patchForObject/delete/exchange/headForHeaders/optionsForAllow(tainted, ...)`。
- 路径遍历（`CWE-22`）：`new FileInputStream/FileOutputStream/FileReader/FileWriter/RandomAccessFile(tainted)`；`Files.readAllBytes/readString/readAllLines/newInputStream/newOutputStream/newBufferedReader/newBufferedWriter/write/copy/move/delete/deleteIfExists(tainted, ...)`。
- 模板注入（`CWE-1336`）：`SpelExpressionParser.parseExpression(tainted)`；接收者类型为 `SpringTemplateEngine`/`TemplateEngine`/`StringTemplateEngine`/`ThymeleafTemplateEngine` 时的 `process(tainted, ...)`。
- 构造器与静态工厂可传播污点：`new Type(tainted, ...)`、`Paths.get(tainted)`、`Path.of(tainted)`、`URI.create(tainted)` 的结果在赋值后带 taint；这些工厂本身不产生 `unresolved_call` 边界。
- 仅带 taint 的 `new File(...)`、`new URL(...)` 不算 sink；必须观察到实际读取/连接/执行调用。
- 接收者类型无法解析但方法名具有类别特征（`openConnection`/`openStream`、`RestTemplate` 方法、`parseExpression`）且接收者带 taint → `boundary.kind=unresolved_sink`，保持 `inconclusive`。
- 负例：常量命令/URL/路径不产生该类别 finding；未观察到路径不等于安全，SQL finding 仍会输出 `inconclusive`。

其他漏洞类别（XSS、反序列化、LDAP 注入、XXE 等）在第十一片补充建模。

### XSS、反序列化、XXE 与 LDAP 注入（第十一片）

- XSS（`CWE-79`）：接收者类型为 `PrintWriter`/`JspWriter`/`ServletOutputStream`/`Writer` 且方法名为 `write`/`print`/`println`/`append`（含 `resp.getWriter().write(...)` 链式）时，tainted 实参视为响应写出 sink。
- 反序列化（`CWE-502`）：`new ObjectInputStream(tainted)`、`new XMLDecoder(tainted)` 在构造处确认；已带 taint 的流接收者调用 `readObject()` 时再次确认；直接链式 `new ObjectInputStream(...).readObject()`/`new XMLDecoder(...).readObject()` 在 `readObject` 处确认一次（`sink.api=new ObjectInputStream(...).readObject`），构造处不重复确认（第十四片）。
- XXE（`CWE-611`）：`DocumentBuilder`/`SAXParser`/`SAXReader` 的 `parse(tainted)`；`SAXReader`/`XMLReader` 的 `read(tainted)`（第十三片）；`XMLInputFactory.createXMLStreamReader/createXMLEventReader(tainted)`；`Unmarshaller.unmarshal(tainted)`；`Transformer.transform(tainted, ...)`；`SAXBuilder.build(tainted)`、`Digester.parse(tainted)`、`DocumentHelper.parseText(tainted)`（第十四片）。
- 响应返回值型 XSS（第十三/十四片）：仅 `response_body=true`（`@RestController` 或 `@ResponseBody`）且方法返回 `String`/`CharSequence` 时检查 `return` 表达式：
  - `return` 表达式无 taint → 不产生 XSS finding；
  - `produces` 含 `text/html` 或 `application/xhtml+xml` → `static_confirmed`，`sink.api=return:<media-type>`（Spring 的 String 写出不做 HTML 转义）；
  - `produces` 为明确的非 HTML 类型（如 `application/json`、`text/plain`）→ `refuted`，`protection.api=return`、`detail` 记录 media type，仅针对该返回，不是全应用安全证明；
  - `produces` 缺失 → `boundary.kind=reflected_return` 且 `limitation=reflected_return_content_type_unverified`，保持 `inconclusive`；
  - `produces` 为非字面量/未知常量 → `produces_status=unresolved`，`boundary.kind=reflected_return` 且 `limitation=produces_unresolved`，保持 `inconclusive`；
  - 普通 `@Controller` 返回 `String` 视为视图名，不产生 XSS finding。
- LDAP 注入（`CWE-90`）：接收者类型为 `InitialDirContext`/`DirContext`/`LdapContext`/`LdapTemplate`/`LdapOperations` 时的 `search`/`lookup`/`authenticate(tainted, ...)`。
- 四类仅在对应参数观察到该类 sink 或 sink 边界时附加 finding，ID 为 `<CWE>:<endpoint-path>:<parameter>`；未观察到的类别不出 finding，报告级 limitations 明确“未观察不等于安全”。
- 构造器对非反序列化类别静默跳过，避免把普通 `new` 当作 sink；常量响应/反序列化流/XML/LDAP 查询不产生该类别 finding。
- 无法静态确认参数被消费（如 `String.format(q)` 动态格式串）时 → `boundary.kind=unresolved_sink`，保持 `inconclusive`。

### 集合污点传播（第十二片）

- 写入：接收者类型为 `List`/`ArrayList`/`LinkedList`/`Set`/`HashSet`/`LinkedHashSet`/`TreeSet`/`Map`/`HashMap`/`LinkedHashMap`/`TreeMap`/`Collection`/`Queue`/`Deque`/`ArrayDeque` 时，`add`/`addAll`/`addFirst`/`addLast`/`offer`/`push`/`put`/`putIfAbsent`/`putAll(tainted)` 将容器变量标记为 tainted（`flow.kind=collection_add`）；容器变更本身不是 sink。
- 读取：同一容器变量的 `get`/`getOrDefault`/`values`/`keySet`/`entrySet`/`toArray`/`iterator`/`peek`/`poll`/`pop`/`first`/`last` 在赋值或 sink 实参中传播 taint（`flow.kind=collection_read`）。
- 泛型声明按擦除解析类型：`Map<String, String> values` 的接收者类型记为 `Map`，`List<String>` 记为 `List`；泛型内部的逗号不会被当作声明分隔符。
- 容器污点按「局部变量或字段名」在单个 finding 内 flow-insensitive 传播；字段容器的 `add`/`put` 会写入字段污点，字段 `clear()` 会删除（第十四片）；其他对象持有的容器不建模。
- `add(String.format(q))` 等动态实参不猜测容器内容 → `limitation=collection_dynamic` 且 finding 保持 `inconclusive`；接收者类型未知的 `store.add(q)` 仍按 `boundary.kind=unresolved_call` 处理。

### 集合跨方法突变与 `clear`（第十三片）

- resolved 同项目方法收到调用方的集合局部变量，且方法体内对同名集合参数执行 tainted `add`/`put` 等写入（直接或经 resolved 调用传递）时，调用方集合被标记为 tainted（`flow.kind=collection_mutated`）；随后 `get` 等读取可继续传播到 sink。
- 方法内对集合变量调用 `clear()`：丢弃该局部容器的 taint（`flow.kind=collection_clear`）；`clear` 之后重新写入 tainted 值则重新污染。字段容器的 `clear` 在第十四片补充建模。
- resolved 方法体内对集合参数 `clear()` 会撤销该位置的突变摘要，调用方集合不再因该参数被标记。
- 仍不建模：集合内元素的独立别名、其他对象持有的容器、跨线程/实例状态。未观察到路径仍为 `inconclusive`。

### 数组下标、remove 与字段集合（第十四片）

- 数组元素写入：`values[i] = tainted`（含 `this.field[i] = tainted`）标记数组变量/字段为 tainted（`flow.kind=array_write`）；后续 `values[i]` 读取传播 taint（`flow.kind=array_read`），可直接作为 sink 实参或先赋值。
- 数组参数跨方法突变：resolved 方法内对数组参数元素写入会进入方法效果摘要，调用方数组被标记（与集合共用 `collection_mutated`）。
- `remove`/`removeAll`/`retainAll`/`removeIf`：flow-insensitive 容器模型无法证明被删除的是 tainted 元素，因此**不清除**容器污点，记录 `flow.kind=collection_remove` 与 `limitation=collection_remove_flow_insensitive`；这是保守过近似，可能保留已移除的 taint。
- 字段集合：`this.field.add/put(tainted)` 写入字段污点；`this.field.clear()` 删除字段污点（`flow.kind=collection_clear`）；同名局部变量/参数遮蔽字段，不写字段。
- 数组声明类型保留 `[]`（参数、字段与局部变量）；多维数组按同一变量名整体标记，不区分维度。

### SQL 构造（第五片）

- `StringBuilder`/`StringBuffer`：接收者类型可由局部变量声明或类字段解析时，任一带 taint 的 `append(...)` 将接收者标记为 tainted；后续 `builder.toString()` 作为 sink 参数或赋值右值时传播 taint。
- `String.format`：仅当第一个实参是字符串字面量且含转换符（如 `%s`、`%d`；`%%` 不算）时，后续实参的 taint 才进入结果。字面量不含转换符时 Java 会忽略多余实参，因此不传播（负例）。
- 计算出的格式串（变量、拼接、`Locale` 重载等）无法判断实参是否被消费 → `boundary.kind=string_format_dynamic`，结果为 `inconclusive`。
- 接收者类型未知的 `append`（如链式 `factory().append(q)`）不猜测类型，按未解析调用或边界处理。

### 防护/负例

- 常量结构 SQL 的 `PreparedStatement`（`prepareStatement` 参数不含 taint）后，`setString/setInt/setLong/setObject/setBoolean/setFloat/setDouble/setDate/setTimestamp/setBytes` 将 tainted 值作为参数绑定。
- 仅当观察到这种值绑定且没有 SQL sink 时输出 `refuted`；只针对该参数和该观察，不是全应用安全证明。
- 仅含常量 `append` 的 builder、以及无转换符的 `String.format` 不构成 sink 证据；其 finding 为 `inconclusive`（未观察到路径不等于安全）。

### 跨方法返回值与 builder 参数突变（第六片）

- 赋值右值或 sink 实参是对 resolved 同项目方法的调用时，按目标方法的参数 taint 汇总其 `return` 表达式；拼接、builder `toString()`、字面量 `format` 或被调方法继续返回的 taint 可传播（`flow.kind=return`）。
- resolved 方法收到 builder 实参，且方法体内对同名参数执行 tainted `append`（直接或经 resolved 调用传递）时，调用方 builder 被标记为 tainted（`flow.kind=builder_mutated`）。
- 目标方法无 tainted 返回值时视为清洁，不因实参 tainted 而误报；该结论只对 resolved 方法体成立。
- 目标方法内存在携带 taint 的未解析调用时输出 `return_value_unresolved` / `callee_effects_unresolved`，finding 保持 `inconclusive`。

### 接口/继承分派与字段污点（第七片）

- 父类型按简单名在同包或唯一简单名类中解析；方法解析先查当前类，再沿 `extends`/`implements` 链上溯，子类覆写优先。
- 接口或抽象方法（无方法体）调用要求恰好一个具体实现/覆写：唯一时使用该实现；多个时输出 `boundary.kind=ambiguous_dispatch` 并保持 `inconclusive`，不做任选。
- 字段写入支持 `this.field = expr` 与无同名局部变量的裸 `field = expr`；字段读取支持 `this.field`、裸字段名及跨方法读取。字段归属于声明它的类，沿类层级解析。
- 字段污点按「类 + 字段名」在单个 endpoint/finding 分析内流转，方法入口和 resolved 调用返回后重新注入；`return this.field` 可经方法效果摘要返回。
- 字段不区分实例与线程，清洁重写不撤销 taint；其他对象的字段（`obj.field`）不建模，保持未解析/无路径结论。

### 重载选择与未解析父类型（第八片）

- 重载候选按方法名与参数个数收集，沿继承链去重；同签名的子类覆写优先于基类方法。
- 用简单实参类型选择：字符串/字符/数值字面量、局部变量、字段、`(Type)` 强转、`new Type(...)`、`String.format(...)` 结果为 `String`。精确匹配优先于数值拓宽/装箱。
- 仍有多个同分候选，或实参类型无法推断且候选不唯一 → `boundary.kind=ambiguous_overload`，保持 `inconclusive`。
- 父类型在快照内无法解析时记入 `MissingParents`；方法在已知层级中不存在且存在未解析父类型 → `boundary.kind=unresolved_parent`，不把“未找到”当作不存在；`this.unknownField` 写入同理。
- 当前类自有方法或可解析父类型方法仍正常命中；未解析父类型只影响无法确认的成员。

### Lambda、泛型与可变参数重载（第九片）

- 实参类型新增 lambda/方法引用识别（`x -> ...`、`(x) -> ...`、`Type::method`）；lambda 匹配已知函数式接口（`Function`/`Consumer`/`Supplier`/`Predicate` 等）或项目中只有一个方法的接口；多个候选都能接受时输出 `ambiguous_overload`。
- lambda 方法体不做独立污点分析；lambda 捕获的 taint 仍按调用实参的保守词法扫描进入目标方法（例如 `find(x -> q)` 可把 `q` 的 taint 带入函数式参数）。
- 泛型按擦除处理：类型实参不进入匹配；方法级类型变量（如 `<T> T pass(T)`）在返回类型推断时用同名实参的已知类型替换，用于外层重载选择；泛型类参数保持未建模。
- 可变参数按“固定参数 + 组件类型”匹配：候选要求实参个数不少于固定参数，尾部实参逐个与组件类型比较；显式传入数组不建模。
- 精确匹配仍优先；无法消解时统一为 `ambiguous_overload`，不按声明顺序任选。

### 动态/未解析边界

- `invoke`、`newInstance`、`forName`、`getMethod`、`getDeclaredMethod`、`getConstructor` 收到 tainted 值，或 tainted 值进入无法解析的项目/库调用 → `inconclusive`。
- 未观察到任何路径也输出 `inconclusive`，不得输出 `refuted` 或“safe”。

## 3. 流分析语义

1. 方法内：简单赋值、字符串 `+` 拼接、builder `append`/`toString`、字面量 `String.format`、构造器与静态工厂结果传播 taint；`String sql = q;`、`String sql = "..." + q`、`String sql = sb.toString();`、`String sql = String.format("...%s", q);`、`URL u = new URL(q);`、`Path p = Paths.get(q);` 可识别。
2. 跨方法：通过字段类型/局部变量类型解析同项目方法（同包或唯一简单类名），沿继承链解析、按简单实参类型消解重载，并处理唯一接口/抽象实现，最多 8 层，visited 防环；tainted 实参映射到目标方法参数，并汇总目标方法的 tainted 返回值与 builder 参数突变。
3. 显式不建模：控制流分支敏感、循环、别名/points-to、实例/线程区分、其他对象字段与容器、lambda 方法体、泛型类型实参、显式数组实参、无法用简单类型消解的重载、快照外父类型成员、反射目标、外部库实现、框架 sanitizer、链式构造器（`new ProcessBuilder(q).start()`）、`HttpClient` builder 链、框架封装的命令/HTTP/模板调用。
4. builder 仅当接收者类型解析为 `StringBuilder`/`StringBuffer` 时建模；链式/未知接收者、非字面量 `String.format` 模式、`Locale` 重载均为边界而非猜测。
5. 返回值/突变摘要只对 resolved 同项目方法成立；重复调用使用同一摘要缓存，递归命中标记 unresolved 而不是假定清洁。
6. 字段污点按类层级、flow-insensitive 地在单个 finding 内传播；无方法体且实现数不唯一的调用输出 `ambiguous_dispatch` 边界，不猜测实现。
7. 类/方法/字段解析基于有界词法结构；嵌套类跳过并标记 partial；text block 文件拒绝并标记 partial。
8. 每个 finding 输出 endpoint、source、sink/protection/boundary、flow、evidence 和 limitations；`runtime_status` 固定 `not_run`。
9. 多类别分析对每个参数按类别独立遍历；taint 语义共享，sink 与边界按类别隔离。非 SQL 类别未观察时不出 finding，报告级 limitations 明确“未观察不等于安全”。

## 4. 输出契约

`trident audit dataflow --snapshot <dir> --snapshot-hash <sha256>` 输出单个 JSON 对象：

- 身份：`schema_version`、`tool_version`、`snapshot_hash`、`analysis_kind=source_sink_multi_category_v1`、`partial`。
- `findings[]`：
  - `status=static_confirmed | refuted | inconclusive`，`severity=high | none | unknown`，`cwe=CWE-89 | CWE-78 | CWE-918 | CWE-22 | CWE-1336 | CWE-79 | CWE-502 | CWE-611 | CWE-90`，`runtime_status=not_run`。
  - `endpoint`（路径、HTTP 方法、符号、文件、SHA、行号）。
  - `sources[]`（参数、类型、绑定注解、显式绑定名、文件、行号）。
  - `sink` / `protection` / `boundary`（互斥或按状态出现）。
  - `flow[]`（call/concat/assign/constructor/builder_append/builder_to_string/builder_mutated/command_append/string_format/string_format_dynamic/collection_add/collection_read/collection_mutated/collection_clear/collection_remove/array_write/array_read/return/field_write/field_read/reflected_return/return_content_type/sink/command_sink/ssrf_sink/path_sink/template_sink/xss_sink/deserialization_sink/xxe_sink/ldap_sink/value_binding/dynamic/ambiguous_dispatch/ambiguous_overload/unresolved_parent/unresolved_call/unresolved_sink，文件与行号）。
  - `evidence[]`（文件、SHA、方法起止行、`fixture:*` 锚点）。
  - `limitations[]`（状态相关限制）。
- `coverage`：Java 文件扫描/拒绝、方法数、endpoint 清单/分析数、confirmed/refuted/inconclusive、跨方法解析/未解析、动态边界；`java_ast=not_available`、`taint_analysis=bounded_lexical_multi_category`、`runtime_status=not_run`。
- 输出按 endpoint 路径和 finding ID 排序；参数/快照/完整性错误返回非零且不输出成功 JSON。

## 5. 验收

第三片基线（2026-11-13，仍有效）：

- `go test ./internal/dataflow ./cmd/trident -count=1`：通过（当时 4 个 dataflow 单测 + CLI 测试）。
- `python scripts/test-dataflow.py`：通过。合成样本 3 个 endpoint：
  - `/synthetic/customers/unsafe`：`static_confirmed`，跨方法 `CustomerController.unsafe → CustomerRepository.findByNameUnsafe`，字符串拼接后 `Statement.executeQuery`（`CustomerRepository.java:28`），来源 `@RequestParam("name")`。
  - `/synthetic/customers/parameterized`：`refuted`，常量 SQL + `PreparedStatement.setString`（`CustomerRepository.java:39`），仅针对该值参数。
  - `/synthetic/customers/dynamic`：`inconclusive`，tainted 值到达反射 `invoke`，目标不可解析。
- 负例：直接同方法 sink 确认；常量 SQL + 值绑定 refuted；未解析外部调用/递归/无路径为 inconclusive；字符串中的 SQL 文本不产生 sink；text block 文件拒绝并 partial；快照篡改失败关闭。
- 工程仍无 Git 仓库，无 commit。

第五片实际执行（2026-11-13，`ToolVersion=0.2.0-p0.2+r2-jdbc-sql-flow-v2`、`analysis_scope=single_parameter_jdbc_sql_v2`）：

- `go test ./internal/dataflow -count=1`：通过（6 个 dataflow 单测）。`TestAnalyzeBuilderAndFormatFlows` 覆盖 8 个 endpoint / 9 个 finding。
- `python scripts/test-dataflow.py`：通过。原 `java-maven` 样本仍为 3 个 endpoint / 3 个 finding（confirmed=1、refuted=1、inconclusive=1），未被新语义改变。
- 新独立样本 `tests/fixtures/java-builder-format`：8 个 endpoint / 9 个 finding，confirmed=4、inconclusive=5、refuted=0。
  - 正例：`/synthetic/format/builder`（`builder_append`→`sink`）、`/synthetic/format/buffer`（`builder_append`→`builder_to_string`→`sink`）、`/synthetic/format/format`（`string_format`→`sink`）、`/synthetic/format/format-sink`（sink 参数内 `String.format`）。
  - 负例：`/synthetic/format/builder-constant`（仅常量 append）、`/synthetic/format/format-constant`（无转换符，`q` 被 Java 忽略）。
  - 边界：`/synthetic/format/format-dynamic`（两种参数各一个 finding，`boundary.kind=string_format_dynamic`）、`/synthetic/format/builder-boundary`（tainted 值进入未解析 helper，`boundary.kind=unresolved_call`）。
  - 快照与源目录运行前后字节级不变；未执行 Java/Maven、未调用模型。
- `go test ./... -count=1`、`go vet ./...`、`python scripts/test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py` 通过；`test-local.py`（真实 PostgreSQL）、`test-agent.py`（loopback）、`test-linux.py`（`-race -tags=integration -p 1 ./...`）通过。
- 工程仍无 Git 仓库，无 commit。

第六片实际执行（2026-11-13，`ToolVersion=0.2.0-p0.2+r2-jdbc-sql-flow-v3`、`analysis_scope=single_parameter_jdbc_sql_v3`）：

- `go test ./internal/dataflow -count=1`：通过（7 个 dataflow 单测）。`TestAnalyzeReturnAndBuilderMutationFlows` 覆盖 6 个 endpoint / 7 个 finding。
- 新独立样本 `tests/fixtures/java-return-flow`：6 个 endpoint / 7 个 finding，confirmed=3、inconclusive=4、refuted=0。
  - 正例：`/synthetic/return/sink`（`return`→`sink`）、`/synthetic/return/sink-direct`（sink 实参内直接调用）、`/synthetic/return/builder`（`builder_mutated`→`sink`）。
  - 负例：`/synthetic/return/constant`（清洁返回值不因实参 tainted 而误报）、`/synthetic/return/builder-constant`（helper 忽略 tainted 实参）。
  - 边界：`/synthetic/return/dynamic`（两个参数各一个 finding，`boundary.kind=string_format_dynamic`）。
  - 快照与源目录运行前后字节级不变；未执行 Java/Maven、未调用模型。
- 原 `java-maven`（3 endpoint/3 finding）与 `java-builder-format`（8/9）计数不变，回归通过。
- `go test ./... -count=1`、`go vet ./...`、`test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-local.py`（真实 PostgreSQL）、`test-agent.py`（loopback）通过。
- `test-linux.py` 首轮在既有 P0 计时测试 `TestClaimRechecksDeadlineAfterPoolLock` 上失败（`deadline passed during pool wait but claim succeeded`），该测试与 dataflow 无关且未在本片修改；原命令单独重跑通过。首轮失败保留记录，未用重跑覆盖。
- 工程仍无 Git 仓库，无 commit。

第七片实际执行（2026-11-13，`ToolVersion=0.2.0-p0.2+r2-jdbc-sql-flow-v4`、`analysis_scope=single_parameter_jdbc_sql_v4`）：

- `go test ./internal/dataflow -count=1`：通过（8 个 dataflow 单测）。`TestAnalyzeDispatchAndFieldTaint` 覆盖 8 个 endpoint / 8 个 finding。
- 新独立样本 `tests/fixtures/java-dispatch-field`（9 个 Java 文件，跨文件类型解析）：8 个 endpoint / 8 个 finding，confirmed=6、inconclusive=2、refuted=0。
  - 正例：`/synthetic/dispatch/iface`（唯一接口实现）、`/synthetic/dispatch/extends`（继承方法）、`/synthetic/dispatch/override`（子类覆写）、`/synthetic/dispatch/field`（`this` 字段写→读）、`/synthetic/dispatch/field-copy`（`field_read`）、`/synthetic/dispatch/field-inherited`（基类字段跨方法写读）。
  - 负例：`/synthetic/dispatch/field-constant`（helper 只写常量，字段不 tainted）。
  - 边界：`/synthetic/dispatch/iface-ambiguous`（两个实现，`boundary.kind=ambiguous_dispatch`）。
  - 快照与源目录运行前后字节级不变；未执行 Java/Maven、未调用模型。
- 原 `java-maven`（3/3）、`java-builder-format`（8/9）、`java-return-flow`（6/7）计数不变，回归通过。
- `go test ./... -count=1`、`go vet ./...`、`test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-local.py`（真实 PostgreSQL）、`test-agent.py`（loopback，happy Run=16、corrupt Run=17）、`test-linux.py`（`-race -tags=integration -p 1 ./...`）均通过。
- 工程仍无 Git 仓库，无 commit。

第八片实际执行（2026-11-13，`ToolVersion=0.2.0-p0.2+r2-jdbc-sql-flow-v5`、`analysis_scope=single_parameter_jdbc_sql_v5`）：

- `go test ./internal/dataflow -count=1`：通过（9 个 dataflow 单测）。`TestAnalyzeOverloadAndUnresolvedParent` 覆盖 5 个 endpoint / 5 个 finding。
- 新独立样本 `tests/fixtures/java-overload-parent`（6 个 Java 文件）：5 个 endpoint / 5 个 finding，confirmed=3、inconclusive=2、refuted=0。
  - 正例：`/synthetic/overload/string`（String 重载）、`/synthetic/overload/int`（Integer 装箱重载）、`/synthetic/overload/local-parent`（自有方法优先于未解析父类型）。
  - 边界：`/synthetic/overload/object`（`Object` 实参无法匹配 String/Integer，`ambiguous_overload`）、`/synthetic/overload/parent`（方法可能继承自快照外父类型，`unresolved_parent`）。
  - 快照与源目录运行前后字节级不变；未执行 Java/Maven、未调用模型。
- 原四套样本计数不变，回归通过。
- `go test ./... -count=1`、`go vet ./...`、`test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-agent.py`（loopback，happy Run=18、corrupt Run=19）、`test-linux.py`（`-race -tags=integration -p 1 ./...`）通过。
- `test-local.py` 首轮在既有治理计时测试 `TestToolApprovalExpiryAfterLedgerLock` 失败（`expired approval admitted after ledger wait`），该测试与 dataflow 无关且本片未修改；同命令重跑通过。首轮失败保留记录，不用重跑覆盖。
- 工程仍无 Git 仓库，无 commit。

未验证：Java AST/类型系统、分支敏感/别名/points-to/实例区分、lambda/泛型重载、可变参数、快照外父类型的实际实现、反射目标、外部库实现、其他漏洞类别、运行时利用与补丁验证。

第九片实际执行（2026-11-13，`ToolVersion=0.2.0-p0.2+r2-jdbc-sql-flow-v6`、`analysis_scope=single_parameter_jdbc_sql_v6`）：

- `go test ./internal/dataflow -count=1`：通过（10 个 dataflow 单测）。`TestAnalyzeLambdaGenericVarargsOverloads` 覆盖 6 个 endpoint / 6 个 finding。
- 新独立样本 `tests/fixtures/java-lambda-generic-varargs`（5 个 Java 文件）：6 个 endpoint / 6 个 finding，confirmed=4、inconclusive=2、refuted=0。
  - 正例：lambda 选择 `Function` 重载、可变参数选择 `String...`、泛型 identity 选择与嵌套返回类型替换、泛型直接赋值。
  - 边界：`Function`/`Consumer` 双函数式接口 → `ambiguous_overload`；零可变参数双候选 → `ambiguous_overload`。
  - 快照与源目录运行前后字节级不变；未执行 Java/Maven、未调用模型。
- 原五套样本计数不变，回归通过。
- `go test ./... -count=1`、`go vet ./...`、`test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-local.py`（真实 PostgreSQL）、`test-agent.py`（loopback，happy Run=20、corrupt Run=21）、`test-linux.py`（`-race -tags=integration -p 1 ./...`）均通过。
- 工程仍无 Git 仓库，无 commit。

未验证：Java AST/类型系统、分支敏感/别名/points-to/实例区分、lambda 方法体污点、泛型类型实参与边界、显式数组实参、快照外父类型实现、反射目标、外部库实现、其他漏洞类别、运行时利用与补丁验证。

第十片实际执行（2026-11-13，`ToolVersion=0.2.0-p0.2+r2-source-sink-flow-v7`、`analysis_scope=single_parameter_multi_category_v7`）：

- `go test ./internal/dataflow -count=1`：通过（11 个 dataflow 单测）。`TestAnalyzeInjectionSinkCategories` 覆盖 12 个 endpoint / 21 个 finding。
- 新独立样本 `tests/fixtures/java-injection-sinks`（5 个 Java 文件）：12 个 endpoint / 21 个 finding，confirmed=8、inconclusive=13、refuted=0；其中 SQL finding 固定 12 个（每参数一个，全部 inconclusive）。
  - 正例：`/synthetic/inject/command`（`Runtime.getRuntime().exec`）、`/synthetic/inject/command-builder`（`command_append`→`builder.start`）、`/synthetic/inject/ssrf`（`constructor`→`URL.openConnection`）、`/synthetic/inject/ssrf-rest`（`RestTemplate.getForObject`）、`/synthetic/inject/path`（`new FileInputStream`）、`/synthetic/inject/path-files`（`Files.readAllBytes(Paths.get(...))`）、`/synthetic/inject/template`（`SpelExpressionParser.parseExpression`）、`/synthetic/inject/template-engine`（`SpringTemplateEngine.process`）。
  - 负例：`/synthetic/inject/command-constant`、`/synthetic/inject/ssrf-constant`、`/synthetic/inject/path-constant` 不产生对应类别 finding。
  - 边界：`/synthetic/inject/command-dynamic`（计算格式串进入 `exec`，`boundary.kind=unresolved_sink`）。
  - 快照与源目录运行前后字节级不变；未执行 Java/Maven、未调用模型。
- 原六套样本计数不变，回归通过。
- `go test ./... -count=1`、`go vet ./...`、`test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-local.py`（真实 PostgreSQL）、`test-agent.py`（loopback）、`test-linux.py`（`-race -tags=integration -p 1 ./...`）均通过。
- 工程仍无 Git 仓库，无 commit。

未验证（第十片后）：Java AST/类型系统、分支敏感/别名/points-to/实例区分、链式构造器与 `HttpClient` builder、框架封装调用、XSS/反序列化/LDAP/XXE 等其他类别、运行时利用与补丁验证。

第十一片实际执行（2026-11-13，`ToolVersion=0.2.0-p0.2+r2-source-sink-flow-v8`、`analysis_scope=single_parameter_multi_category_v8`）：

- `go test ./internal/dataflow -count=1`：通过（12 个 dataflow 单测）。`TestAnalyzeExtraSinkCategories` 覆盖 14 个 endpoint / 24 个 finding。
- 新独立样本 `tests/fixtures/java-extra-sinks`：14 个 endpoint / 24 个 finding，confirmed=8、inconclusive=16、refuted=0；其中 SQL finding 固定 14 个（每参数一个，全部 inconclusive）。
  - 正例：`/synthetic/extra/xss-chain`（`resp.getWriter().write`）、`/synthetic/extra/xss-writer`（`PrintWriter.write`）、`/synthetic/extra/deserialization`（`new ObjectInputStream`）、`/synthetic/extra/xml-decoder`（`new XMLDecoder`）、`/synthetic/extra/xxe-dom`（`DocumentBuilder.parse`）、`/synthetic/extra/xxe-sax`（`SAXParser.parse`）、`/synthetic/extra/ldap-search`（`InitialDirContext.search`）、`/synthetic/extra/ldap-lookup`（`InitialDirContext.lookup`）。
  - 负例：`/synthetic/extra/xss-constant`、`/synthetic/extra/deserialization-constant`、`/synthetic/extra/xxe-constant`、`/synthetic/extra/ldap-constant` 不产生对应类别 finding。
  - 边界：`/synthetic/extra/xss-dynamic`、`/synthetic/extra/xxe-dynamic`（`String.format(q)` 动态格式串，`boundary.kind=unresolved_sink`）。
  - 快照与源目录运行前后字节级不变；未执行 Java/Maven、未调用模型。
- 原七套样本计数不变（3/9/7/8/5/6/21 finding 的既有记录未回归），回归通过。
- `go test ./... -count=1`、`go vet ./...`、`test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-local.py`（真实 PostgreSQL）、`test-agent.py`（loopback）、`test-linux.py`（`-race -tags=integration -p 1 ./...`）均通过。
- 工程仍无 Git 仓库，无 commit。

未验证（第十一片后）：Java AST/类型系统、分支敏感/别名/points-to/实例区分、集合传播、反射目标、外部库实现、反序列化 gadget 链与 `new(...).readObject()` 链式构造、XXE 的 `XMLInputFactory`/`Transformer` 更多入口、响应返回值型 XSS（Controller 直接 `return` 用户输入）、运行时利用与补丁验证。未观察到的类别不出 finding，不代表应用安全。

第十二片实际执行（2026-11-13，`ToolVersion=0.2.0-p0.2+r2-source-sink-flow-v9`、`analysis_scope=single_parameter_multi_category_v9`）：

- `go test ./internal/dataflow -count=1`：通过（13 个 dataflow 单测）。`TestAnalyzeCollectionTaint` 覆盖 8 个 endpoint / 10 个 finding。
- 新独立样本 `tests/fixtures/java-collections`：8 个 endpoint / 10 个 finding，confirmed=4、inconclusive=6、refuted=0；其中 SQL finding 固定 8 个（`sql-list`/`sql-map` 两个 confirmed，其余 inconclusive）。
  - 正例：`/synthetic/collection/sql-list`（`List.add(q)`→`get`→拼接→`executeQuery`，`collection_add`/`collection_read`）、`/synthetic/collection/sql-map`（`Map.put`→`get`）、`/synthetic/collection/command-list`（`add`→`get`→`Runtime.getRuntime().exec`）、`/synthetic/collection/xss-list`（`add`→`get`→`PrintWriter.write`）。
  - 负例：`/synthetic/collection/sql-constant`（常量入容器后读取，SQL 不确认）、`/synthetic/collection/command-constant`（常量入容器后 `exec`，不产生命令 finding）。
  - 边界：`/synthetic/collection/dynamic`（`add(String.format(q))` → `collection_dynamic`，SQL inconclusive）、`/synthetic/collection/unknown-receiver`（非集合接收者 `store.add(q)` → `boundary.kind=unresolved_call`）。
  - 快照与源目录运行前后字节级不变；未执行 Java/Maven、未调用模型。
- 泛型声明类型解析修正：`Map<String, String>` 等声明中的泛型逗号不再被当作声明分隔符，接收者类型记为 `Map` 而非 `String`（既有八套样本计数不变）。
- 原八套样本计数不变（3/9/7/8/5/6/21/24 finding 的既有记录未回归），回归通过。
- `go test ./... -count=1`、`go vet ./...`、`test-project.py`、`test-sca.py`、`test-audit.py`、`test-dataflow.py`、`test-findings.py`、`test-local.py`（真实 PostgreSQL）、`test-agent.py`（loopback，happy Run=26、corrupt Run=27）通过。
- `test-linux.py` 首轮在既有治理计时测试 `TestToolApprovalExpiryAfterLedgerLock` 失败（`expired approval admitted after ledger wait`），该测试与 dataflow 无关且本片未修改；原命令重跑通过。首轮失败保留记录，不用重跑覆盖。
- 工程仍无 Git 仓库，无 commit。

未验证（第十二片后）：Java AST/类型系统、分支敏感/别名/points-to/实例区分、集合的 `clear`/`remove` 与跨方法容器内容、元素下标与泛型类型实参、反射目标、外部库实现、反序列化 gadget 链与 `new(...).readObject()` 链式构造、XXE 的 `XMLInputFactory`/`Transformer` 更多入口、响应返回值型 XSS（Controller 直接 `return` 用户输入）、运行时利用与补丁验证。未观察到的类别不出 finding，不代表应用安全。

第十三片实际执行（2026-11-13，`ToolVersion=0.2.0-p0.2+r2-source-sink-flow-v10`、`analysis_scope=single_parameter_multi_category_v10`）：

- `go test ./internal/dataflow -count=1`：通过（14 个 dataflow 单测）。`TestAnalyzeCollectionCrossMethodClearAndReflectedReturn` 覆盖 8 个 endpoint / 10 个 finding。
- 新独立样本 `tests/fixtures/java-container-reflect`：8 个 endpoint / 10 个 finding，confirmed=3、inconclusive=7、refuted=0；其中 SQL finding 固定 8 个（每参数一个）。
  - 正例：`/container/mutate`（`fill(values, name)` 内 `add` → `collection_mutated` → `get` → `executeQuery`）、`/container/clear-refill`（`add`→`clear`→再 `add` → confirmed）、`/xxe/sax-reader`（`SAXReader.read(xml)` → XXE confirmed）。
  - 负例：`/container/clear`（`add`→`clear` 后读取，无 sink，SQL 保持 inconclusive）、`/container/constant`（常量入容器不产生 `collection_add`）、`/reflect/clean`（返回常量不产生 XSS finding）。
  - 边界：`/container/helper-clear`（callee 内 `add`+`clear`，`collection_clear` 撤销突变，SQL inconclusive）、`/reflect/return`（`return q;` → `boundary.kind=reflected_return`，XSS inconclusive）。
  - 快照与源目录运行前后字节级不变；未执行 Java/Maven、未调用模型。
- 原九套样本计数不变（3/9/7/8/5/6/21/24/10 finding 的既有记录未回归），回归通过。
- `python scripts/test-dataflow.py`：通过，新增 `[11]` 块与 8 个检查项。
- 当前工作区存在 Git 仓库（`main`，HEAD `c44fb1f`），本片改动未提交。

未验证（第十三片后）：Java AST/类型系统、分支敏感/别名/points-to/实例区分、集合的 `remove`/元素下标/字段 `clear`、其他对象持有的容器、反射目标、外部库实现、反序列化 gadget 链、`XMLInputFactory`/`Transformer` 更多 XXE 入口、反射返回值的 `produces`/content-type/转义解析、运行时利用与补丁验证。未观察到的类别不出 finding，不代表应用安全。

第十四片实际执行（2026-11-13，`ToolVersion=0.2.0-p0.2+r2-source-sink-flow-v11`、`analysis_scope=single_parameter_multi_category_v11`，入口清单 `r2-endpoint-inventory-v2`）：

- `go test ./internal/audit ./internal/dataflow -count=1`：通过（audit 新增 `TestInspectProducesAndResponseBody`；dataflow 15 个单测，含 `TestAnalyzeArrayRemoveFieldClearProducesAndChains`）。
- 新独立样本 `tests/fixtures/java-flow-gaps`（2 个 Java 文件）：16 个 endpoint / 23 个 finding，confirmed=10、refuted=1、inconclusive=12。
  - 正例：`/array/write`（`array_write`→`array_read`→SQL）、`/array/helper`（数组参数跨方法突变）、`/field/keep`（字段集合 add→read）、`/reflect/html`（`produces=text/html` → `return:text/html` confirmed）、`/deserialize/chain`（`new ObjectInputStream(...).readObject`）、`/xxe/build`、`/xxe/digester`、`/xxe/helper`、`/xxe/event`。
  - 负例：`/array/constant`、`/reflect/constant-html`、`/reflect/view`（普通 `@Controller` 视图名）、`/deserialize/chain-constant`。
  - 保守语义：`/remove/keep` 保持 confirmed 并标记 `collection_remove_flow_insensitive`；`/field/clear` 在字段 `clear` 后不确认。
  - `produces` 判定：`/reflect/json` 为 `refuted`，`protection.detail` 记录 `produces=application/json`。
  - 快照与源目录运行前后字节级不变；未执行 Java/Maven、未调用模型。
- 原十套样本计数不变（3/9/7/8/5/6/21/24/10/10 finding 的既有记录未回归），回归通过。
- `python scripts/test-dataflow.py`：通过，新增 `[12]` 块与 16 个检查项。
- 当前工作区存在 Git 仓库（`main`，HEAD `c44fb1f`），本片改动未提交。

未验证（第十四片后）：Java AST/类型系统、分支敏感/别名/points-to/实例区分、集合元素级 `remove` 精度、其他对象持有的容器与字段、反射目标、外部库实现、反序列化 gadget 链与绕过、更多框架 XML 入口、`produces` 之外的内容协商/转义、运行时利用与补丁验证。未观察到的类别不出 finding，不代表应用安全。

## 第十五片：框架 sink、上传、字面量元素精度与导入感知解析（2026-11-13）

- `ToolVersion=0.2.0-p0.2+r2-source-sink-flow-v12`、`analysis_scope=single_parameter_multi_category_v12`；入口清单 `r2-endpoint-inventory-v3`，支持 JAX-RS 参数绑定。
- 新增 `upload` 类别（CWE-434）：`MultipartFile.transferTo(tainted)`、`Part.write(tainted)`；仅构造上传对象或常量目标不确认。
- SQL 扩展：`JdbcTemplate`/`NamedParameterJdbcTemplate`/`JdbcOperations` 的 `query/queryForObject/queryForList/queryForMap/queryForRowSet/update/batchUpdate/execute` 只把第一个 SQL 参数作为 sink，值绑定实参不误报；JPA `EntityManager` 与 Hibernate `Session/StatelessSession` 的 `createQuery/createNativeQuery` 同样只取 SQL/JPQL 文本。
- SSRF 扩展：`HttpRequest.newBuilder().uri(tainted)`、`WebClient`/`WebClient.Builder` 的 `uri(tainted)`；通过有界 fluent-chain 回溯识别接收者类型，未知类型仍走 unresolved/不确认。
- 元素级容器精度：字面量下标 `values[i] = tainted`、`list.set(i, tainted)`、`list.add(i, tainted)` 记录 `name[i]`；`values[i]`/`get(i)` 优先读取该元素，缺失时回退到容器聚合；`remove(i)` 删除该元素污点，若同时存在聚合污点仍保留 `collection_remove_flow_insensitive`；`clear()` 删除容器及其全部元素键。非字面量下标继续使用聚合语义。
- 导入感知类型解析：解析 `import` 与静态/通配导入；当同一简单名在项目内映射唯一时用于类解析，同一简单名被不同文件导入到不同类时不猜测。该方法用于跨包父类型、接收者与 helper 分派。
- 新样本 `tests/fixtures/java-advanced-sinks`（3 个 Java 文件、12 endpoint）：11 个分析入口、14 finding，confirmed=7、inconclusive=7、refuted=0。正例覆盖 JdbcTemplate、JPA、HttpClient/WebClient、MultipartFile、字面量元素读、import helper；负例覆盖值绑定、常量上传、未污染元素、`remove(index)` 后读取、清洁 helper。
- `python scripts/test-dataflow.py` 新增 `[13]` 块；原十套样本计数不变（3/9/7/8/5/6/21/24/10/10/23）。未执行 Java/Maven、未调用模型，快照与源目录字节级不变。
- 未验证：非字面量元素级精度、其他对象持有的容器/字段、完整 AST/别名、框架封装调用（`HttpClient.send` 链、模板/ORM 二次封装）、`produces` 之外的内容协商、运行时利用。
