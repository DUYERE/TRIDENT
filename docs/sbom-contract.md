# CycloneDX SBOM 契约（R2 第十四片）

## 1. 定位

`trident sca sbom` 把声明级 Maven 报告转换为 **CycloneDX 1.5 JSON**，供供应链交付和后续工具消费。它只读取已 pin 的快照与调用者显式指定的本地公告目录，不执行 Maven/Java、不解析传递依赖、不访问仓库、不调用模型。

SBOM 是**声明级清单**：包含 POM 中直接声明的模块与依赖、固定公告的精确版本匹配和静态限制说明；不是有效依赖树、运行时 classpath、制品哈希或可达性证明。

## 2. 输出与确定性

- `bomFormat="CycloneDX"`、`specVersion="1.5"`、`version=1`。
- `serialNumber` 由快照 SHA-256 派生 UUID，确定性；不写墙钟时间戳。
- 相同快照、公告目录与工具版本生成字节级一致 JSON。
- 调用 `--advisories` 时使用该本地文件；未提供时仍输出依赖组件，但不产生 vulnerability 条目。

```bash
trident sca sbom --snapshot <dir> --snapshot-hash <sha256> \
  [--advisories <local-advisory.json>]
```

Web 控制台 `GET /api/sbom` 返回同一文档，`Content-Disposition` 为 `trident-sbom-<hash12>.cdx.json`。

## 3. 字段映射

| CycloneDX 字段 | 来源与语义 |
|---|---|
| `metadata.component` | 快照应用组件；`version` 为完整快照 SHA-256 |
| `metadata.tools.components` | TRIDENT 构建版本 |
| `metadata.properties` | `trident:snapshot_hash`、`runtime_status=not_run`、`sca_resolution=declaration_only`、`transitive_tree=not_available`、`dependency_reachability=unverified`、`partial`、每条限制 |
| `components[]` | 每个唯一 Maven GAV；`type=library`、`group/name/version`、可用时 `purl=pkg:maven/group/artifact@version` |
| component properties | `trident:module`、`trident:declaration_pom`、`trident:version_status`、`trident:runtime_status=not_run` |
| `dependencies[]` | 根引用指向全部组件；每个组件声明为空依赖节点；不展开传递关系 |
| `vulnerabilities[]` | 仅 `finding_status=candidate` 的公告匹配；`source.name=TRIDENT local advisory catalog`、`analysis.state=in_triage`、`ratings[].severity=unknown`、`affects[].ref` 指向对应组件 |

`in_triage` 明确表示尚未完成运行时/可达性分析；`unknown` 不是严重度结论，`affects` 不是可利用性证明。

## 4. 限制

- 无传递依赖、BOM import、profiles、版本区间/别名、仓库解析、制品哈希和 classpath。
- 依赖到入口的 import graph 与可达性未实现。
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
- `trident:transitive_tree=not_available`、`dependency_reachability=unverified` 保持不变；import 可达性不会写回 SBOM 或升级为运行时可利用。
