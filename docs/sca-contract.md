# R2 首片：Maven 声明级分析与固定公告匹配契约

- 日期：2026-11-12
- 状态：已实现并完成本地真实 CLI 验收；不是完整 R2。
- 入口：`trident sca inspect`、`internal/sca/`、`scripts/test-sca.py`。

本片只回答“POM 里声明了什么、按本地继承规则解析出的版本是什么、固定公告的精确版本判据是否命中”。它**不执行 Maven**，不生成有效依赖树，不访问仓库，不做 Java AST/污点分析，也不确认调用点、输入可达性或运行时利用。

## 1. 输入与信任边界

1. 只读取已导入并通过 `snapshot_hash` 绑定的 `SourceSnapshot`；每个 POM 通过 `Snapshot.ReadFile` 重新校验大小和原始字节 SHA-256。快照完整性失败直接中止，不输出成功报告。
2. 仓库中的 POM、属性、注释和模块名都是不可信数据，不能改变工具集合、公告来源或授权。解析失败只影响该 POM 并标记 `partial`，不静默跳过。
3. 公告目录必须由调用者通过 `--advisories` 显式指定为本地普通文件；不从快照、环境变量、网络或默认路径自动加载。公告是数据，不是执行许可。
4. 不执行 Maven/wrapper、Java、插件、脚本或测试；不下载依赖；不把源码发送给任何模型或外部服务。

## 2. 解析语义（声明级）

1. 识别快照中所有 `pom.xml`；上限 512 个 POM、单个 512 KiB、XML 深度 64、单 POM 依赖/管理项各 4096；超限失败或标记 partial。
2. 拒绝 DTD/directive、多个根元素、尾随内容和畸形 XML；不支持 XML 外部实体，也不依赖解析器默认行为。
3. 父 POM 仅按本地 `relativePath`（缺省 `../pom.xml`）解析，必须位于快照内且 `groupId/artifactId/version` 与声明匹配；环、缺失或坐标不符标记 `parent_cycle/parent_missing/parent_coordinates_mismatch`，不伪造继承。显式空 `<relativePath/>` 与缺省在 XML 结构中不可区分，本片按缺省处理，这是已知限制。
4. 子 POM 继承父 `groupId` 与 `version`，不继承 `artifactId`；属性由子覆盖父，并记录每个生效属性的定义 POM；`dependencyManagement` 同样子覆盖父。
5. 依赖版本解析顺序：显式 `<version>` → 请求模块的有效 `dependencyManagement`。管理项中的版本表达式使用**请求模块**的有效属性插值，因此子模块覆盖属性会影响其被管理依赖的版本。
6. `scope` 缺省 `compile`，`type` 缺省 `jar`；管理项可提供 scope。`dependencyManagement` 本身不产生依赖，只有模块的 `<dependencies>` 才计入声明依赖。
7. 重复声明标记 `duplicate`，不静默合并；不解析传递依赖、BOM import、profiles、version ranges、settings、冲突仲裁或制品 Hash。
8. 属性插值有深度/长度/环限制；无法解析时输出 `version_status=unresolved` 和固定原因（如 `unresolved_property:<name>`、`missing_version`），不猜测版本。

## 3. 公告匹配语义

1. 公告 fixture 采用 `tests/fixtures/java-maven/advisories/CVE-2022-42889.json` 的字段格式；严格 JSON，拒绝未知字段、重复版本 case、非 Maven 生态、坐标缺失或来源摘要格式错误。
2. 只做**精确版本 case** 匹配，不做区间、别名、传递依赖或仓库解析：
   - 精确命中且 `version_matched=true`：`supply_chain_status=version_matched`、`finding_status=candidate`。
   - 精确命中且 `version_matched=false`：`supply_chain_status=not_affected`，并保留公告的 `assessment_scope`。
   - 版本已解析但没有对应 case：`unknown`，原因 `no_exact_version_case`。
   - 版本未解析：`unknown`，原因 `unresolved_version`。
3. 所有匹配固定 `runtime_status=not_run`、`input_reachability=unknown`；没有源码调用点证据时不得升级为 `callsite_found/input_reachable/runtime_confirmed`。
4. `version_matched` 只是候选风险，不等于 RCE 或可利用；`not_affected` 只针对该公告的精确版本判据，不是“所有 CVE 安全”或“任意配置安全”。
5. 没有显式公告目录时不进行匹配，输出 `coverage.advisories_loaded=0` 和 `advisory_matching_disabled` 限制。

## 4. 输出契约

`trident sca inspect --snapshot <dir> --snapshot-hash <sha256> [--advisories <file>]` 输出单个 JSON 对象：

- 身份与绑定：`schema_version`、`tool_version`、`snapshot_hash`、`analysis_kind`（`maven_declaration_inventory`、`gradle_declaration_inventory` 或 `maven_gradle_declaration_inventory`）、`partial`。
- 项目：`project.build_system/root_poms/root_gradle_files/gradle_file_count/module_count/pom_count`。
- 模块：`modules[]`（POM、目录、坐标、packaging、父 POM、aggregator、声明模块目录）。
- 依赖：`dependencies[]`（模块、坐标、版本、scope/type/optional、直接声明、声明/管理/属性来源、`version_status`/`version_reason`、duplicate）。
- 公告：`advisories[]` 与 `advisory_matches[]`。
- 覆盖：`coverage` 明确 `poms_scanned/poms_rejected/dependencies_*`、`transitive_tree=not_available`、`artifact_hashes=not_available`、`maven_executed=false`、`runtime_status=not_run`。
- `limitations[]` 固定说明未执行、无传递树、无制品 Hash、无 AST/污点、公告仅调用者声明判据。

输出排序固定（POM 路径、依赖坐标、公告 ID/模块），便于差异比较。CLI 参数错误、快照不可信、公告非法或完整性失败返回非零且不输出成功 JSON。

## 5. 验收

本轮实际执行：

- `go test ./internal/sca ./cmd/trident -count=1`：通过。
- `python scripts/test-sca.py`：通过。合成样本识别 3 个 POM、2 个模块、6 条直接声明依赖；`jdbc-app` 的 Commons Text 解析为 1.9（父属性 + 父管理 + 子声明），`advisory-control` 解析为 1.10.0（子属性覆盖）；公告匹配 2 条，分别为 `version_matched/candidate` 与 `not_affected`；未执行 Maven/Java、未调用模型，源与快照不变。
- 负例：DTD POM 被拒绝并标记 partial；父 POM 环终止并标记 partial；管理项不被误报为实际依赖；重复声明标记 duplicate；无公告目录时不虚构匹配；非法公告、错误摘要、快照内容篡改均失败关闭。
- `python scripts/test-linux.py`：通过（固定 Linux 镜像，`-race -tags=integration -p 1 ./...`；SCA 包与历史数据库回归均通过）。并行包执行时遗留 `TestToolApprovalExpiryAfterLedgerLock` 出现 wall-clock/DB-lock 时序抖动；单独与串行包均通过，脚本改为串行包调度，未放宽断言。

未验证：Maven/Gradle 在线有效依赖树、外部传递依赖、BOM/profiles、制品 Hash、Java AST/入口/Source-Sink、调用点与输入可达性、运行时利用、补丁与隔离验证。

## 6. 2026-11-13 扩展（Gradle、区间/别名、模块树）

1. `sca inspect` 在不执行 Gradle 的前提下解析 `build.gradle`/`build.gradle.kts` 的常见字符串与 map 依赖声明、`group`/`version` 和 `project(':x')` 边；插件、settings 求值、version catalog、BOM/platform 与传递 configuration 仍不可用，遇到时记录 limitation。
2. 公告 `version_cases[]` 每项二选一：`version`（精确）或 `version_range`；区间支持 `>=1.9,<1.10`、`[1.9,1.10)` 和单版本 `[1.9]`。匹配结果新增 `matched_by=exact|range|range_excluded`；区间外但存在漏洞区间时为 `not_affected`，没有任何可用判据时仍为 `unknown/no_exact_version_case`。
3. `advisories[]`/`advisory_matches[]` 输出 `aliases`、`aliases_complete` 与 `range_case_count`；别名不改变版本判据。
4. `trident sca tree` 只输出快照内模块边、Gradle `project()` 边和同快照 GAV 匹配；外部依赖是叶子，`coverage.transitive_tree=module_edges_only`，不是 Maven 有效依赖树，也不证明 classpath 或可达性。
5. 新增验收 `python scripts/test-intel.py`：区间/别名、区间外负例、Gradle 5 条声明（4 resolved/1 dynamic unresolved）、Maven/Gradle 模块树、错误哈希与不安全 package map 均按预期。

## 7. 有效依赖树 `sca resolve`（2026-11-14）

- Maven：在快照的临时副本上执行 `mvn -B dependency:tree -DoutputType=text`，默认 `-o` 离线，只有显式 `--approve-network` 才允许联网；必须显式 `--approve-maven`。
- 输出 `resolution_mode=offline|online`、`maven.executed/duration_ms/repo_local`、`modules[]`（root coordinate、POM 映射、`dependencies[]`）与 `coverage`（direct/transitive/omitted）。
- 解析 `+-`/`\-` 深度、scope、classifier、`version managed from`、`omitted for conflict`、`optional` 注记；无法解析时 `status=failed` 并输出有界 `[ERROR]` 摘要。
- `runtime_status` 恒为 `not_run`、`artifact_hashes=not_available`、`classpath_verified=false`。有效树是构建解析观测，不证明类加载、调用可达性或运行时利用。
- Maven POM 是不可信输入；`dependency:tree` 仍可能解析插件/扩展。实现使用临时副本、环境变量白名单与超时，但不是沙箱；高信任要求下应在一次性容器/VM 中运行。
- 验收 `python scripts/test-resolve.py`：离线缓存可用时得到 3 个模块、31 条依赖、25 条传递依赖，commons-lang3 深度 2，快照与 fixture 字节级不变；缓存缺失时报告 skip，不伪造结果。

## 8. Gradle 有效依赖树 `sca resolve --tool gradle`（2026-11-14）

- 在快照临时副本上按模块执行 `gradle --offline --no-daemon --console=plain -q -p <module> dependencies`；必须显式 `--approve-gradle`。`--gradle` 指定绝对路径，`--gradle-user-home` 与 `--gradle-init-script` 用于隔离缓存和挂载离线仓库。
- 每个模块优先选择 `runtimeClasspath`，其次 `compileClasspath`，再按 `*RuntimeClasspath`/`*CompileClasspath` 后缀回退，最后合并全部配置；`coverage.effective_tree=gradle_dependency_report_observed`，`gradle.configurations` 记录实际选择。
- 解析 `+---`/`\---` 深度、`project :x` 边、`a:b:1.0 -> 1.2` 版本升级、`(*)` 省略、`(c)` 约束、`(n)` 未解析与 `FAILED`；依赖输出 `failed` 和 `note`。部分模块失败时 `status=partial`、`partial=true` 并保留已解析模块；全部失败时 `status=failed`。
- `runtime_status` 恒为 `not_run`、`artifact_hashes=not_available`。Gradle 构建脚本是可执行输入，`dependencies` 报告不是 classpath 加载证明；不解释 Android variant、version catalog、BOM/platform 语义或插件脚本副作用。
- 验收 `python scripts/test-gradle-resolve.py`：Gradle 8.14.3 + JDK 17 + 离线 file 仓库，3 个模块、5 条依赖、2 条传递；`jdbc-app` 含 `project :common`、`commons-text:1.9` 直接边与 `commons-lang3` 深度 2；快照与 fixture 字节级不变。
