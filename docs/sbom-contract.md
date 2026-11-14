# CycloneDX SBOM 契约（R2 第十四片）

## 1. 定位

`trident sca sbom` 把声明级 Maven 报告转换为 **CycloneDX 1.5 JSON**，供供应链交付和后续工具消费。它只读取已 pin 的快照与调用者显式指定的本地公告目录，不执行 Maven/Java、不解析传递依赖、不访问仓库、不调用模型。

SBOM 是**声明级清单**：包含 POM 中直接声明的模块与依赖、固定公告的精确版本匹配、调用者本地仓库可选观测到的制品哈希和静态限制说明；不是有效依赖树、运行时 classpath、来源签名或可达性证明。

## 2. 输出与确定性

- `bomFormat="CycloneDX"`、`specVersion="1.5"`、`version=1`。
- `serialNumber` 由快照 SHA-256 派生 UUID，确定性；不写墙钟时间戳。
- 相同快照、公告目录与工具版本生成字节级一致 JSON。
- 调用 `--advisories` 时使用该本地文件；未提供时仍输出依赖组件，但不产生 vulnerability 条目。

```bash
trident sca sbom --snapshot <dir> --snapshot-hash <sha256> \
  [--advisories <local-advisory.json>] \
  [--maven-repo <dir>] [--gradle-user-home <dir>] [--hash-catalog <file>]
```

Web 控制台 `GET /api/sbom` 返回同一文档，`Content-Disposition` 为 `trident-sbom-<hash12>.cdx.json`。

## 3. 字段映射

| CycloneDX 字段 | 来源与语义 |
|---|---|
| `metadata.component` | 快照应用组件；`version` 为完整快照 SHA-256 |
| `metadata.tools.components` | TRIDENT 构建版本 |
| `metadata.properties` | `trident:snapshot_hash`、`runtime_status=not_run`、`sca_resolution=declaration_only`、`transitive_tree=not_available`、`dependency_reachability=unverified`、`trident:artifact_hashes=observed\|partial\|unavailable`、`partial`、每条限制 |
| `components[]` | 每个唯一 Maven GAV；`type=library`、`group/name/version`、可用时 `purl=pkg:maven/group/artifact@version` |
| component `hashes[]` | 仅本地观测到的 `status=observed` jar/pom：`{"alg":"SHA-256","content":"<64 hex>"}`；同一组件多个文件去重并稳定排序 |
| component properties | `trident:module`、`trident:declaration_pom`、`trident:version_status`、`trident:runtime_status=not_run` |
| `dependencies[]` | 根引用指向全部组件；每个组件声明为空依赖节点；不展开传递关系 |
| `vulnerabilities[]` | 仅 `finding_status=candidate` 的公告匹配；`source.name=TRIDENT local advisory catalog`、`analysis.state=in_triage`、`ratings[].severity=unknown`、`affects[].ref` 指向对应组件 |
`in_triage` 明确表示尚未完成运行时/可达性分析；`unknown` 不是严重度结论，`affects` 不是可利用性证明。

## 4. 限制

- 无传递依赖、BOM import、profiles、版本区间/别名、仓库解析和 classpath。
- 制品哈希只来自调用者显式本地仓库/缓存并仅覆盖已存在的字节；不验证 GPG/签名，不证明制品来源或未被篡改。
- 有界入口调用图与可达性不写入 SBOM。
- 公告匹配仅精确版本 case；公告目录不是快照内容，不能由 snapshot hash 自证。
- 组件去重按 GAV；同一 GAV 在多个模块声明时，模块信息保存在 properties，不生成重复组件。
- 无运行时验证；不得把 SBOM 中的 candidate 当作已确认漏洞。

## 5. Schema 校验

- 官方 Schema：CycloneDX 1.5 JSON Schema，Apache License 2.0，来源 `https://cyclonedx.org/schema/bom-1.5.schema.json`，固定副本位于 `tests/schemas/bom-1.5.schema.json`。
- `scripts/test-sbom.py` 使用 Python `jsonschema`（Draft 7）对真实 CLI 输出执行完整校验。
- Schema 文件仅用于验收，不参与运行时分析；运行时不访问网络。

## 6. 验收（2026-11-13）

- `go test ./internal/sbom ./internal/webui ./cmd/trident -count=1`：通过。
- `python scripts/test-sbom.py`：通过；5 个唯一组件、1 个候选 vulnerability、2 次输出字节级一致、官方 Schema 校验通过；未加载公告目录时无 vulnerability；错误快照摘要失败关闭；快照与 fixture 前后 SHA-256 一致。
- 未运行：Maven/Java、传递依赖解析、制品哈希、运行时可达性验证、真实模型。

## 7. 2026-11-13 扩展

- 输入 SCA 报告现在可包含 Gradle 声明与调用者声明区间/别名；SBOM 组件仍按唯一 GAV 去重，Gradle 声明的来源文件写入 `trident:declaration_pom`，不生成 Gradle 有效依赖树。
- 公告候选仍只映射 `FindingStatus=candidate`；`matched_by=exact|range` 不改变 CycloneDX `analysis.state=in_triage`、`severity=unknown` 与 `runtime_status=not_run`。
- `trident:transitive_tree=not_available`、`dependency_reachability=unverified` 保持不变；有界可达性不会写回 SBOM 或升级为运行时可利用。

## 8. 2026-11-14 扩展：本地制品哈希

- `sca sbom` 复用 `sca inspect` 的 `--maven-repo`/`--gradle-user-home`/`--hash-catalog`；SBOM 只写 `status=observed` 且来源为本地仓库的 SHA-256，不写 `caller_catalog` 或 `mismatch` 记录。
- `metadata.properties` 增加 `trident:artifact_hashes`；未配置仓库时为 `unavailable`，部分命中或 mismatch 为 `partial`，并沿用 `artifact_hash_local_only`、`artifact_signature_not_verified` 限制。
- 验收：`scripts/test-artifact-hash.py` 断言 commons-text 组件含 jar/pom 两个 SHA-256 且与实际 fixture 字节一致；官方 Schema 校验由 `scripts/test-sbom.py` 保持通过。

## 9. 2026-11-14 扩展：VEX 分析状态（P3）

`sca sbom` 新增 `--package-map <file>`（仅 sbom 子命令有效，其余子命令拒绝）。提供时在本次进程内运行 `audit reachability` 的有界调用图，并按以下**固定保守映射**把每个公告候选的 `analysis` 升级为 VEX 声明；不提供时行为与 §3 完全一致（全部 `in_triage`）。

| reachability | `analysis.state` | `analysis.justification` | 说明 |
|---|---|---|---|
| `unreachable` | `not_affected` | `code_not_reachable` | 有界 import/type-ref 图（≤8 跳）内无任何入口路径；detail 写明反射/动态分派/框架装配/外部配置不在声明范围内 |
| `reachable` | `in_triage` | （无） | 静态可达**永不**升级为 `exploitable`；detail 写明路径数与运行时未验证 |
| `unknown`（反射/缺映射/超限/无入口/版本未解析） | `in_triage` | （无） | detail 写明具体 `reason` |

- 证据属性：每个 vulnerability 附 `trident:reachability=<status>`、`trident:reachability_tool=not_run`、`trident:reachability_claim=<reason>`；`metadata.properties` 增加 `trident:vex_basis`（提供 map 时 `bounded_entry_call_graph`，否则 `unverified`）。
- **声明边界**：`not_affected` 只表达"本快照有界图中不可达"，不证明类加载、运行时利用或供应链完整性；`runtime_status=not_run` 永不改变。这是 VEX 声明的最小可信形态，下游消费者应结合 detail 与 `trident:reachability_claim` 解读。
- 确定性：同一快照 + 同一 package-map + 同一公告目录 → 字节一致（无时间戳）。
- 验收：`go test ./internal/sbom`（三态映射与边界文案）与 `scripts/test-sbom.py` [04]（官方 Schema 校验 `not_affected/code_not_reachable`、确定性、flag 仅限 sbom 子命令）。
