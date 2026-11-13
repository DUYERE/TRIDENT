# TRIDENT 发布与验收检查表（R6 草稿）

本文件是发布前检查入口，不是生产就绪声明。运行时状态与验证事实以
[`development-progress.md`](development-progress.md) 为准。

## 1. 固定版本与工具链

| 组件 | 固定版本 | 说明 |
|---|---|---|
| Go | `go 1.26.3`（本机验证 `go1.27.1`） | `go build ./...`、`go test ./...`、`go vet ./...` |
| PostgreSQL | `postgres:18@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42` | `compose.yaml`，仅绑定 `127.0.0.1:55432` |
| Java | Temurin 17.0.16 | 仅 R3 验证；分析命令不执行 Java |
| Maven | 3.9.9 | R3 `maven` profile，离线 `-o` |
| JUnit | 4.12 | 调用者提供 classpath；不依赖 Surefire |
| Docker 验证镜像 | `maven:3.9.9-eclipse-temurin-17@sha256:f58d59b6273e785ac0a4477f6e9b5ba1d7731c75b906c0f7b34076f1851318cc` | `patch verify/propose` 的 docker/gvisor 沙箱 |
| gVisor | `runsc`（可选） | 未注册时 `--sandbox gvisor` 失败关闭 |
| CycloneDX Schema | 1.5，固定副本 `tests/schemas/bom-1.5.schema.json` | Python `jsonschema` Draft 7 验收 |
| SARIF | 2.1.0 | `audit sarif`，不写时间戳，输出确定 |

所有快照、fixture、策略与公告目录均为本地显式路径；运行时不访问网络（模型和 R3 执行除外，且需显式批准）。

## 2. 构建、启动与备份

```bash
# [01] 只读分析：不需要数据库或模型密钥。
go build -o bin/trident ./cmd/trident
bin/trident version

# [02] Agent/Run：需要 PostgreSQL 与显式迁移。
export TRIDENT_DATABASE_URL='postgres://.../trident_test'
export TRIDENT_MIGRATION_ACTOR='release-operator'
bin/trident migrate
bin/trident check

# [03] 测试库启动（专用测试环境）。
# compose.yaml 要求 .env 中设置 TRIDENT_POSTGRES_PASSWORD。
docker compose -f compose.yaml up -d

# [04] 备份：由数据库管理员执行；本工具不会自动备份或删除数据。
pg_dump --format=custom --file=trident.dump "$TRIDENT_DATABASE_URL"
```

Agent 表是 append-only；`agent export` 只读导出，不做物理删除。数据库清理、凭据轮换、服务账号分权仍属部署方职责。

## 3. 可复现基准

```bash
python scripts/benchmark.py 3
```

本机 2026-11-13、Go 1.27.1、2 次迭代的实际结果（合成样本）：

| 样本 | 命令 | 中位耗时 |
|---|---|---|
| `java-maven` | `sca inspect` | 约 122 ms |
| `java-maven` | `audit dataflow` | 约 229 ms |
| `java-maven` | `audit findings` | 约 151 ms |
| `java-advanced-sinks` | `audit dataflow` | 约 106 ms |
| `java-flow-gaps` | `audit findings` | 约 100 ms |
| `gradle-basic` | `sca inspect` | 约 109 ms |

基准只测 wall-clock 与输出字节，不包含数据库、模型、网络、Maven/Java；样本很小，不能外推大型项目成本。

## 4. 可复现验收

| 门槛 | 命令 | 当前状态 |
|---|---|---|
| 快照与只读工具 | `python scripts/test-project.py` | 通过 |
| SCA/Gradle/区间/树 | `python scripts/test-sca.py`、`python scripts/test-intel.py` | 通过 |
| 入口清单 | `python scripts/test-audit.py` | 通过 |
| 数据流/元素精度/框架 sink | `python scripts/test-dataflow.py` | 通过 |
| 统一证据与 SARIF | `python scripts/test-findings.py`、`python scripts/test-intel.py` | 通过 |
| SBOM 官方 Schema | `python scripts/test-sbom.py` | 通过 |
| 只读 Web 控制台 | `python scripts/test-web.py` | 通过 |
| 真实 PostgreSQL/Agent | `python scripts/test-local.py`、`python scripts/test-agent.py` | 通过 |
| R3 真实 Java/Maven/JUnit | `python scripts/test-patch.py` | 通过 |
| R3 AI 补丁 + Docker | `python scripts/test-patch-ai.py` | 通过（loopback 模型） |
| Linux race | `python scripts/test-linux.py` | 通过（固定 `golang:1.26.3-bookworm`） |
| 真实模型只读 | Run 43/46/48 记录 | 已获准并通过，其他模型/快照需重新授权 |
| 真实项目 AI 补丁 | — | 未执行，需逐次外发与执行授权 |
| 硬件 VM/系统调用隔离 | — | 未实现；gVisor 是用户态内核 |
| Maven/Gradle 在线有效依赖树 | — | 未实现 |

## 5. 版本兼容与已知边界

- Windows 11 与 Linux（`openat2`/`statx` Mount ID 5.8+）快照路径语义不同；不支持网络/FUSE/无法安全判断的文件系统。
- `agent` 检查点 v2；v1 不自动恢复。模型适配只承诺 Chat Completions 子集，不支持所有供应商扩展。
- 公告区间是调用者声明判据，不是 Maven 版本语义的完整实现；`import_reachable` 不是调用可达性。
- 静态 finding 的 `runtime_status` 恒为 `not_run`；R3 的 `runtime_status=isolated_validation_only`。
- gVisor 需要 Docker 注册 `runsc`；Docker 不是硬件 VM。

## 6. 发布门槛

1. 所有第 4 节可在本机离线复现的门槛通过，且工作区有对应 Git commit。
2. 真实模型、真实项目快照外发、真实项目 AI 补丁分别取得逐次书面授权，并记录端点、模型、快照 hash、调用上限与费用上限。
3. 若声明“生产可用”，还需独立完成部署、备份恢复演练、凭据分权、监控、SARIF/CI 集成和硬件 VM 或等效隔离评审。
4. 不得把合成样本、loopback 模型、静态分析或隔离副本结果表述为生产漏洞利用或修复上线证明。
