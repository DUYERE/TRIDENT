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
4. `audit reachability` 解析 Java import，并用显式 `--package-map` 将 `group:artifact` 映射到包前缀；分类只有 `import_reachable/import_not_observed/unverified`。import 命中不是调用可达性，未配置映射时全部 `unverified`。
5. 新增验收 `python scripts/test-intel.py`：SARIF 2.1.0、3 条结果、import 可达 2 条、无映射全部 unverified、错误哈希与不安全 package map 拒绝；`go test ./internal/audit` 覆盖 JAX-RS/Servlet 入口。
