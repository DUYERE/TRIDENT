# R2 第二片：Spring MVC 入口清单契约（注解级）

- 日期：2026-11-12（2026-11-13 增加 `produces` 与 `response_body`）
- 状态：已实现并完成本地真实 CLI 验收；**不是 Java AST、调用图或污点分析**。
- 入口：`trident audit endpoints`、`internal/audit/`、`scripts/test-audit.py`。

本片只回答“哪些 Spring MVC 注解方法声明了哪些路由和参数绑定”。它不编译或运行 Java，不解析类型系统、元注解、接口继承、Lombok、配置类或 context-path，也不追踪参数到 Sink 的数据流。路由声明不等于服务已部署，入口存在不等于可利用。

## 1. 输入与信任边界

1. 只读取已导入并通过 `snapshot_hash` 绑定的 `SourceSnapshot`；每个 `.java` 文件通过 `Snapshot.ReadFile` 重新校验大小与原始字节 SHA-256。完整性失败直接中止。
2. 源码、注释、字符串和注解参数都是不可信数据，不能改变工具集合、授权、输出路径或执行行为。
3. 不执行 Java、编译器、Maven/Gradle、类加载器或测试；不访问网络或模型。
4. 词法扫描排除注释和字符串字面量，避免把其中的 `@GetMapping` 当成代码；但这不是完整的 JavaParser，不能替代类型解析或语义分析。

## 2. 识别语义

1. 控制器类：`@Controller` 或 `@RestController`；类级 `@RequestMapping` 作为 base path。
2. 方法映射：`@RequestMapping`、`@GetMapping`、`@PostMapping`、`@PutMapping`、`@DeleteMapping`、`@PatchMapping`。
3. 路径来源：注解位置参数、`value`、`path`；支持字符串数组。类级与方法级路径做简单 `base + method` 拼接并展开笛卡尔积。
4. 非字面量路径（常量、字符串拼接、无法解码的转义）标记 `path_status=unresolved`，不猜测；类级路径无法解析时所有相关 endpoint 标记 `unresolved_base_path`。
5. HTTP 方法：`@GetMapping` 等固定映射；`@RequestMapping` 解析 `method=RequestMethod.*`；未声明时 `http_methods=[]`、`method_status=unspecified`，不得解释为“无路由”。
6. 参数绑定：`@RequestParam`、`@PathVariable`、`@RequestBody`、`@RequestHeader`、`@CookieValue`、`@ModelAttribute`、`@RequestPart`、`@SessionAttribute`；记录参数名、类型、绑定注解、显式绑定名、`required`（缺省 `unspecified`）和行号。
7. 注释或字符串中的注解不生效；Java text block 文件拒绝并标记 `partial`；嵌套类暂不展开，跳过并标记 `partial`；非控制器类上的映射注解只记录 `controller_marker_missing`，不产出 endpoint。
8. 重复路由按“HTTP 方法 + 路径”标记 `duplicate`；同一路径的不同方法不互斥；`unspecified` 方法使用 `*` 参与重复检测。
9. 只识别 Spring MVC 注解；Servlet、JAX-RS、WebFlux、接口继承、元注解和配置类路由不在本片范围。
10. 识别基于注解短名，未解析 import/类型系统；与 Spring 注解同名的自定义注解可能被误识别，输出限制中固定声明这一点。
11. `produces`：解析映射注解的 `produces` 属性，接受字符串字面量与已知 `MediaType.*_VALUE` 常量（`TEXT_HTML_VALUE`、`APPLICATION_XHTML_XML_VALUE`、`APPLICATION_JSON_VALUE`、`TEXT_PLAIN_VALUE`、`APPLICATION_XML_VALUE`、`ALL_VALUE`）；其他表达式标记 `produces_status=unresolved`，缺失或空值标记 `absent`，不猜测。
12. `response_body`：`@RestController` 或方法级 `@ResponseBody` 为 true；普通 `@Controller` 方法返回 `String` 视为视图名，不是响应体。该标记供数据流判断反射型返回值，不改变路由清单语义。

## 3. 输出契约

`trident audit endpoints --snapshot <dir> --snapshot-hash <sha256>` 输出单个 JSON 对象：

- 身份：`schema_version`、`tool_version`、`snapshot_hash`、`analysis_kind=http_annotation_inventory`、`partial`。
- `controllers[]`：文件、包、类、符号、文件 SHA-256、注解、base paths/status、起止行。
- `endpoints[]`：完整路径、base/relative 路径、HTTP 方法、方法状态、`produces`/`produces_status`、`response_body`、文件/包/类/方法/符号、文件 SHA-256、注解、起止行、方法行、参数、`path_status`/`path_reason`、`fixture:*` 锚点（若存在）、`duplicate`。
- `coverage`：扫描/拒绝的 Java 文件数、控制器/入口数、未解析路径、重复路由、跳过的嵌套类；`java_ast=not_available`、`taint_analysis=not_run`、`runtime_status=not_run`。
- `limitations[]`：固定说明无 AST/类型解析、无 Source/Sink/污点、路径拼接近似、常量折叠不支持、仅 Spring MVC、运行时未验证。

输出按文件、起始行、路径排序。参数错误、快照不可信或完整性失败返回非零且不输出成功 JSON。

## 4. 验收

本轮实际执行：

- `go test ./internal/audit ./cmd/trident -count=1`：通过。
- `python scripts/test-audit.py`：通过。合成样本扫描 8 个 Java 文件，识别 1 个 `CustomerController` 和 3 个 GET 入口：
  - `/synthetic/customers/unsafe`，`fixture:unsafe-http-source`
  - `/synthetic/customers/parameterized`，`fixture:safe-http-source`
  - `/synthetic/customers/dynamic`，`fixture:dynamic-http-source`
  - 三个入口均识别 `@RequestParam("name") String name`。
- 负例：注释/字符串中的注解不匹配；多路径数组展开；`RequestMapping` 多 HTTP 方法；常量路径标记 unresolved；text block 文件拒绝并 partial；嵌套类跳过并 partial；非控制器映射只记 limitation；非法转义路径 unresolved；快照内容篡改失败关闭。
- 未执行 Java/编译器/Maven、未调用模型，源与快照不变。
- Linux race：此前一次尝试因 Docker Desktop 引擎未运行未完成；重新启动 Docker Desktop 并启动专属 `trident-p0-postgres-1` 后补跑，`python scripts/test-linux.py` 通过（固定镜像，`-race -tags=integration -p 1 ./...`，包含 `internal/audit` 与历史数据库回归）。

未验证：Java AST/类型解析、调用图、Source/Sink、Sanitizer、跨方法污点、反射/动态调用、WebFlux、元注解/接口继承、context-path、部署与运行时利用。

## 5. 2026-11-13 扩展（JAX-RS/Servlet、SARIF、import 可达性）

1. 入口识别新增 JAX-RS `@Path` 类资源、`@GET/@POST/@PUT/@DELETE/@PATCH/@HEAD/@OPTIONS` 方法、`@Path` 方法子路径、`@Produces` 与 `@QueryParam/@PathParam/@FormParam/@HeaderParam/@CookieParam/@MatrixParam/@BeanParam` 参数；`@Path` 类默认 `response_body=true`。
2. 入口识别新增 `@WebServlet` 类与 `doGet/doPost/doPut/doDelete/doHead/doOptions`；Servlet 参数不绑定 `HttpServletRequest.getParameter`，因此只进入入口清单、不产生请求 source。
3. `audit sarif` 从统一 findings 导出确定性 SARIF 2.1.0；`static_confirmed=warning`、`inconclusive=note`、`refuted=none`，结果属性与 run 属性始终 `runtime_status=not_run`。
4. `audit reachability` 用显式 `--package-map` 将 `group:artifact` 映射到包前缀，并在类级 import/同包类型引用图上做有界 BFS；三态 `reachable/unreachable/unknown` 的语义见第 7 节。import 命中本身不是调用证明，未配置映射时全部 `unknown`。
5. 新增验收 `python scripts/test-intel.py`：SARIF 2.1.0、3 条结果、有界可达性三态计数、无映射全部 unknown、错误哈希与不安全 package map 拒绝；`go test ./internal/audit` 覆盖 JAX-RS/Servlet 入口。

## 6. 2026-11-14 权限/越权控制清单 `audit authz`

- 输入仍是同一个可信快照；`authz.Analyze` 复用 `audit.Inspect` 的入口清单，再扫描 `.java` 与 `.xml` 文本。不编译、不运行、不访问网络。
- 识别的控制：
  - Spring Security 方法/类注解：`@PreAuthorize`、`@PostAuthorize`、`@Secured`、`@RolesAllowed`、`@PermitAll`、`@DenyAll`、`@PreFilter`、`@PostFilter`。
  - XML：`<mvc:interceptor>` 的 mapping/exclude-mapping/ref 与 bean class、`<security:intercept-url pattern/access>`、`web.xml` 的 filter-mapping 与 security-constraint。
  - Java：`@WebFilter(urlPatterns)`、`WebMvcConfigurer.addInterceptor().addPathPatterns()/excludePathPatterns()`、`HttpSecurity.authorizeRequests()`/`authorizeHttpRequests()` 的 matcher 链与 `anyRequest()`。
  - 控制类认证性：解析到源码后，仅当同时观察到 `HandlerInterceptor`/`Filter`/`OncePerRequestFilter` 或 `doFilter` 以及 session/redirect/SecurityContext 等 token 时，才把该类视为认证控制；否则为 `unknown`。
- 决策：`protected`（唯一匹配的安全控制为 authenticated/role/deny）、`public`（permitAll/登录路径/显式放行）、`unprotected`（没有任何已识别控制）、`unknown`（控制类/路径无法解析、手工 session 检查或控制冲突）。Spring Security 匹配按声明顺序取第一个命中；独立 interceptor/filter 仍可把 permitAll 路由标为 protected。
- 输出：`controls[]`（kind/file/line/paths/excluded/requirement/source_class/status）、`endpoints[]`（path/decision/reason/matched_controls/runtime_status）、`findings[]`（CWE-306、`status=inconclusive`、`runtime_status=not_run`）与 `coverage`。`partial=true` 表示存在未解析控制或入口。
- 限制：不评估 Spring EL 表达式、filter-chain 全局顺序、自定义 AOP/网关、context-path、重写规则或部署配置；`unprotected` 是静态缺省证据，不是未授权访问证明。
- 验收：`go test ./internal/authz` 与 `python scripts/test-authz.py`。fixture 中 MVC interceptor、servlet filter（注解与 web.xml）、Spring Security Java/XML、方法注解分别覆盖 6 个 protected 入口，登录/permitAll 为 2 个 public，2 个无控制入口为 unprotected，手工 session 检查为 unknown；2 条 finding 均为 `inconclusive`、`CWE-306`、`runtime_status=not_run`，快照与 fixture 字节级不变。

## 7. 2026-11-14 依赖到入口的有界可达性 `audit reachability`

- 输入：可信快照 + 显式 `--package-map`（`{"schema_version":1,"dependencies":{"group:artifact":["pkg.prefix"]}}`，≤64 KiB、≤256 项、前缀不含路径分隔符）。没有映射时全部 `unknown`，不根据包名猜测。
- 类级调用图：解析 `.java` 的 package、import、首个类型声明、大写类型标识符与反射标记；边只有 `import`（import 名精确匹配快照内 FQCN）与 `same_package`（同包类型名在源码中被引用）。不解析方法签名、重载、继承、接口分派、AOP、异步或字节码。
- BFS 从 `audit.Inspect` 的入口文件出发，深度 ≤8、节点 ≤4000、边 ≤20000、路径 ≤5/依赖；任一上限触发 `partial=true`、`reachability_graph_limit`/`reachability_traversal_limit`，未证明项降为 `unknown`。
- 三态：
  - `reachable`：在入口所属模块内找到入口文件→中间类→依赖 import 的路径；`paths[]` 含入口符号/文件/行号、每一步的文件 SHA-256 与行号，以及命中的 import。
  - `unreachable`：该模块存在入口、图未超限、版本已解析，且没有路径。它只是本快照有界静态图的结论，不排除反射、动态代理、框架装配或运行时生成代码。
  - `unknown`：缺少映射、模块无入口、版本未解析、反射命中（`reflection_not_resolved`）或图超限。
- 模块作用域：路径命中只归属于入口文件所在模块；跨模块调用视为边界外，避免把共享模块的 import 直接算到另一个模块。
- 输出：`entrypoints[]`、`dependencies[]`（三态、reason、prefixes、matched_imports、paths）、`coverage{java_files_scanned,java_files_rejected,imports_parsed,entrypoints,classes_indexed,graph_edges,dependencies,reachable,unreachable,unknown}`、`limitations[]`；`runtime_status=not_run` 恒定。
- 验收：`python scripts/test-reachability.py`。`java-reachability` fixture 三个模块共 3 个入口：经 service 使用依赖为 `reachable` 且路径为 2 步并带 SHA-256/行号，仅声明未引用为 `unreachable`，`Class.forName` 为 `unknown/reflection_not_resolved`；无映射全部 `unknown`；输出确定性、fixture 与快照不变。

## 8. 2026-11-14 受限 Java 语义模型 `audit java-model`

- 输入：同一个可信快照；`javaast.Analyze` 用 `text/scanner` 解析受限 Java 子集。不编译、不运行、不反编译、不访问网络，不读取 `D:\Code\Java\market` 之外的依赖源码。
- 建模内容：
  - 文件：package、import（含 static/通配）、类型声明；非法文件单独拒绝并记录 `parse_error`，其余文件继续分析。
  - 类型：类/接口/枚举/记录/注解/嵌套类，FQN、修饰符、注解、擦除后的 extends/implements（`Extends`/`Implements` 为解析结果，`*_raw` 为源文本）。
  - 字段：类型、修饰符、注解、枚举常量名；常量值按需折叠。
  - 方法：擦除后的符号 `pkg.Type#name(paramTypes)`、返回类型、构造器、类型参数、参数（含 varargs 与注解）、起止行、是否有方法体。
  - 注解实参：字面量、同类型/静态导入 `static final` 常量、字符串拼接、整数加法、class literal、枚举常量与数组。
  - 调用图：方法体内的 `name(...)`、`this/super.name(...)`、`recv.name(...)`、`new Type(...)`；接收者按局部变量/参数/字段/类型/外部类型解析。
- 解析与消歧：
  - 泛型按擦除比较（`List<String>` → `java.util.List`），重载按实参字面量/局部变量/`new`/cast 推断类型；无唯一最优候选记 `ambiguous/ambiguous_overload`。
  - 继承链与接口参与方法查找；无方法体的接口/抽象方法仅在快照内存在唯一具体实现时记 `resolved/interface_dispatch`，多个实现记 `ambiguous/ambiguous_dispatch`，零实现记 `unresolved/no_concrete_implementation`。
  - 内部类可解析到外部类实例方法；父类型在快照外记 `unresolved/parent_outside_snapshot`；反射 API（`Class.forName`、`Method.invoke`、`Proxy.newProxyInstance` 等）只记边界，不猜目标。
- 输出：`schema_version`、`tool_version=0.2.0-p0.3+r1-java-semantic-model-v1`、`snapshot_hash`、`analysis_kind=java_semantic_model_v1`、`partial`、`files[]`、`types[]`、`calls[]`、`coverage`、`limitations[]`；`runtime_status=not_run` 恒定。
- `calls[]` 只包含可定位到调用行的直接调用；JDK/库接收者只计入 `coverage.external_calls`，不生成伪造目标。每条边携带调用者/文件/SHA-256/行号、接收者、API、实参文本与推断类型、目标符号、目标文件/SHA-256、`status=resolved|ambiguous|unresolved` 与 `reason`。
- 限制：不建模控制流、别名/points-to、跨方法污点、AOP/动态代理、注解默认值求值、完整 JLS；lambda、方法引用、文本块、匿名类为边界；常量折叠深度 ≤16、条目 ≤20000；调用边 ≤`MaxCalls`（当前 100000）。
- 验收：`go test ./internal/javaast` 与 `python scripts/test-java-ast.py`。`java-ast-model` fixture 5 个文件：1 个语法错误文件单独拒绝且 `partial=true`；嵌套类 `Outer.Inner` 索引并解析到外部类 `label()`；`pick(String)`/`pick(List)` 泛型擦除重载分别命中；`Store` 唯一实现解析为 `JdbcStore#save`、`Handler` 双实现为 `ambiguous_dispatch`；`@Route(PREFIX + "/items")` 折叠为 `api/items`、`@Access(Role.ADMIN)` 保留枚举常量；输出确定性、fixture 字节不变。
